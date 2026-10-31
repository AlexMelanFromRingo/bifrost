// VPN egress / ingress for bifrost-vpnd.
//
// Two roles share this module:
//
//   * EXIT side runs `start_exit`. It creates a TUN device (default
//     `bifrost-eg0`), pins it to a private IPv4 subnet (default
//     10.55.0.0/24), tells the kernel to MASQUERADE that subnet out
//     the public interface, then waits for inbound `Open(Egress)`
//     streams from any mesh peer. Each accepted stream is paired
//     with an allocated address from the subnet; the exit pipes
//     raw IP frames from the mesh into the TUN, and pipes responses
//     out of the TUN back through the matching peer stream.
//
//   * CLIENT side runs `start_client`. It opens a single egress
//     stream to a configured exit peer, reads the allocated address
//     from the exit's initial reply, brings up its own TUN with that
//     address, points its default route at the exit's gateway, and
//     pipes IP packets bidirectionally between the TUN and the mesh
//     stream.
//
// The 5-tuple → mesh-peer reverse mapping that conntrack-aware NATs
// usually maintain in userspace is replaced here by per-stream
// address allocation: each client owns exactly one address inside
// the egress subnet for the lifetime of its session, and the kernel
// handles conntrack natively because the TUN packets carry the real
// allocated source IP.

use anyhow::{Context, Result};
use bifrost_core::{
    dst_filter::Cidr,
    frame::OpenTarget,
    mux::{AcceptedStream, MeshMux},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, error, info, trace, warn};

/// Header the exit sends as the very first Data frame of every
/// accepted egress stream. The client reads it before forwarding any
/// IP traffic.
///
/// v2 wire layout (50 bytes, big-endian):
///   magic         (4 bytes, "BFEG")
///   version       (1 byte, currently 2)
///   v4_alloc      (4 bytes)
///   v4_gateway    (4 bytes)
///   v4_prefix     (1 byte)
///   v6_present    (1 byte, 0 or 1)
///   v6_alloc      (16 bytes — zeros if not present)
///   v6_gateway    (16 bytes — zeros if not present)
///   v6_prefix     (1 byte — 0 if not present)
///   mtu_in_16     (1 byte — MTU/16, multiples of 16 bytes)
///   pad           (1 byte — reserved for future flags, must be zero)
pub const EGRESS_HELLO_MAGIC: &[u8; 4] = b"BFEG";
pub const EGRESS_HELLO_VERSION: u8 = 3;
pub const EGRESS_HELLO_SIZE: usize = 52;

/// Bit flags carried in `EgressHello::capabilities`. Both sides must
/// advertise a flag for the corresponding feature to activate; if
/// either is missing, the data plane falls back to the pre-v3
/// behaviour for that feature.
///
/// `VNET_HDR` (0x0001) — the per-packet wire format carries a 10-byte
/// `virtio_net_hdr` prefix in front of every IP packet inside the
/// `Frame::Datagram` batches. Necessary for TSO/USO offload (the
/// kernel encodes super-segments in this header).
pub const EGRESS_CAP_VNET_HDR: u16 = 0x0001;

/// Hard cap on a single relayed packet. Comfortably larger than any
/// real-world MTU (v6 jumbograms top out at 9180 bytes; we round to
/// 16 KB). Frames larger than this are treated as a protocol error
/// and tear the stream down — protects against a malicious peer
/// sending u16::MAX-length headers to make us allocate 64 KB per
/// packet.
/// Maximum size of a single wire-format slot `[vhdr | IP packet]`.
///
/// Sized to accommodate a TSO super-segment under default Linux
/// `dev->gso_max_size` (64 KiB) without truncating; we leave a
/// small margin for the vhdr and miscellaneous TLV growth.
pub const MAX_RELAYED_PACKET: usize = 60 * 1024;

/// Maximum number of IP packets coalesced into a single Datagram
/// payload. 16 is a sweet spot on real WAN testing: small enough to
/// keep the worst-case `tun_writer.lock()` hold time inside the
/// receive loop bounded (~16 × 30 μs each on Linux), large enough
/// to amortise mesh encrypt + TCP send across a typical TCP burst.
pub const MAX_COALESCED_PACKETS: usize = 16;

/// Soft budget on the *byte* size of one coalesced batch. Stops a
/// pathological burst of jumbo-frames from queueing 256 KB before
/// flush. Picked at 32 KiB so a full batch + length headers stays
/// comfortably under the mux's 64 KiB chunk_size and one TCP write.
pub const COALESCE_BYTE_BUDGET: usize = 32 * 1024;

/// Window inside which `tun.read()` continuations are gathered into
/// the same batch before flush. Picked empirically: at the
/// ~50 Mbit/s ceiling of a typical WAN hop, IP packets arrive every
/// ~220 μs, so a 100 μs window would miss most of them and the
/// coalescer would be a no-op (verified on the 2026-05-19 UA↔NL
/// bench — VPN stayed at 10 Mbit/s with the short timer). 500 μs
/// catches the trailing packets of a typical TCP burst (cwnd ≥ 2
/// segments) while adding bounded jitter: a *single* ping packet
/// pays ~0.5 ms extra latency, which is in the noise of the
/// 55 ms WAN RTT.
pub const COALESCE_DRAIN_TIMEOUT: Duration = Duration::from_micros(500);

/// Encode a non-empty slice of IP packets into one Datagram payload.
/// Wire format: `count: u8` followed by `count` × (`len: u16 BE` +
/// `payload bytes`). The encoder doesn't take ownership of the
/// packets to keep the hot path zero-copy on the input side.
pub fn encode_packet_batch(pkts: &[&[u8]]) -> Vec<u8> {
    debug_assert!(!pkts.is_empty());
    debug_assert!(pkts.len() <= u8::MAX as usize);
    let total: usize = pkts.iter().map(|p| 2 + p.len()).sum::<usize>() + 1;
    let mut out = Vec::with_capacity(total);
    out.push(pkts.len() as u8);
    for p in pkts {
        out.extend_from_slice(&(p.len() as u16).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

/// Iterator over `(packet_bytes_borrowed)` items from a coalesced
/// Datagram payload. Skips silently on any truncation — the
/// upper-layer drops a stub end of a malformed batch rather than
/// tearing the whole session down (a single bad batch is no reason
/// to drop the tunnel; subsequent batches are independent).
pub struct PacketBatchIter<'a> {
    buf: &'a [u8],
    remaining: u8,
    idx: usize,
}

impl<'a> PacketBatchIter<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        let remaining = buf.first().copied().unwrap_or(0);
        Self { buf, remaining, idx: 1 }
    }
}

impl<'a> Iterator for PacketBatchIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.remaining == 0 || self.idx + 2 > self.buf.len() {
            return None;
        }
        let len = u16::from_be_bytes([self.buf[self.idx], self.buf[self.idx + 1]]) as usize;
        self.idx += 2;
        if len == 0 || self.idx + len > self.buf.len() || len > MAX_RELAYED_PACKET {
            self.remaining = 0;
            return None;
        }
        let pkt = &self.buf[self.idx..self.idx + len];
        self.idx += len;
        self.remaining -= 1;
        Some(pkt)
    }
}

/// Reads one length-prefixed packet from a mesh stream into `dst`.
/// Wire format: 2-byte big-endian length, followed by that many bytes
/// of opaque payload (an IP packet or an `EgressHello`).
///
/// Returns `Ok(Some(n))` for a successful read, `Ok(None)` if the
/// stream closed cleanly at a frame boundary, and `Err` for any
/// other I/O failure or a length that won't fit `dst` or exceeds
/// `MAX_RELAYED_PACKET`.
async fn read_framed<R: AsyncRead + Unpin>(
    r: &mut R, dst: &mut [u8],
) -> std::io::Result<Option<usize>> {
    let mut hdr = [0u8; 2];
    // Hand-rolled read so we can distinguish "clean EOF before any
    // header byte" from "EOF in the middle of a header" — the first
    // is normal teardown, the second is a torn stream.
    let mut got = 0;
    while got < hdr.len() {
        match r.read(&mut hdr[got..]).await? {
            0 if got == 0 => return Ok(None),
            0 => return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "stream closed mid-frame-header",
            )),
            n => got += n,
        }
    }
    let len = u16::from_be_bytes(hdr) as usize;
    if len == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zero-length framed packet",
        ));
    }
    if len > dst.len() || len > MAX_RELAYED_PACKET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("framed packet too large: {len} bytes"),
        ));
    }
    r.read_exact(&mut dst[..len]).await?;
    Ok(Some(len))
}

/// Writes one length-prefixed packet to a mesh stream. Mirrors the
/// format consumed by `read_framed`. `pkt` must be non-empty and
/// no larger than `MAX_RELAYED_PACKET`.
#[cfg(feature = "tun")]
async fn write_framed<W: AsyncWrite + Unpin>(
    w: &mut W, pkt: &[u8],
) -> std::io::Result<()> {
    if pkt.is_empty() || pkt.len() > MAX_RELAYED_PACKET {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("framed packet size out of range: {}", pkt.len()),
        ));
    }
    // Coalesce the length + payload into one syscall to keep the
    // small-packet pipeline tight. Two write_all calls would still be
    // correct, just chattier.
    let mut hdr_and_pkt = Vec::with_capacity(2 + pkt.len());
    hdr_and_pkt.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    hdr_and_pkt.extend_from_slice(pkt);
    w.write_all(&hdr_and_pkt).await
}

#[derive(Debug, Clone, Copy)]
pub struct EgressHello {
    pub allocated_v4: Ipv4Addr,
    pub gateway_v4: Ipv4Addr,
    pub v4_prefix: u8,
    /// IPv6 lease — None if the exit is v4-only.
    pub allocated_v6: Option<Ipv6Addr>,
    pub gateway_v6: Option<Ipv6Addr>,
    pub v6_prefix: u8,
    pub mtu: u16,
    /// Bitmask of supported features (see `EGRESS_CAP_*` constants).
    /// New in v3; v2 callers see this slot as zeros.
    pub capabilities: u16,
}

impl EgressHello {
    pub fn encode(&self) -> [u8; EGRESS_HELLO_SIZE] {
        let mut out = [0u8; EGRESS_HELLO_SIZE];
        out[..4].copy_from_slice(EGRESS_HELLO_MAGIC);
        out[4] = EGRESS_HELLO_VERSION;
        out[5..9].copy_from_slice(&self.allocated_v4.octets());
        out[9..13].copy_from_slice(&self.gateway_v4.octets());
        out[13] = self.v4_prefix;
        out[14] = self.allocated_v6.is_some() as u8;
        if let Some(v6) = self.allocated_v6 {
            out[15..31].copy_from_slice(&v6.octets());
        }
        if let Some(gw6) = self.gateway_v6 {
            out[31..47].copy_from_slice(&gw6.octets());
        }
        out[47] = self.v6_prefix;
        out[48] = ((self.mtu / 16).min(255)) as u8;
        // out[49] reserved.
        out[50..52].copy_from_slice(&self.capabilities.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < EGRESS_HELLO_SIZE {
            anyhow::bail!("egress hello: buffer too short ({} bytes)", buf.len());
        }
        if &buf[..4] != EGRESS_HELLO_MAGIC {
            anyhow::bail!("egress hello: bad magic {:?}", &buf[..4]);
        }
        if buf[4] != EGRESS_HELLO_VERSION {
            anyhow::bail!(
                "egress hello: unsupported version {} (this build expects {})",
                buf[4], EGRESS_HELLO_VERSION
            );
        }
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&buf[5..9]);
        let mut gw4 = [0u8; 4];
        gw4.copy_from_slice(&buf[9..13]);
        let v4_prefix = buf[13];
        let has_v6 = buf[14] != 0;
        let (allocated_v6, gateway_v6, v6_prefix) = if has_v6 {
            let mut v6 = [0u8; 16];
            v6.copy_from_slice(&buf[15..31]);
            let mut gw6 = [0u8; 16];
            gw6.copy_from_slice(&buf[31..47]);
            (Some(Ipv6Addr::from(v6)), Some(Ipv6Addr::from(gw6)), buf[47])
        } else {
            (None, None, 0)
        };
        let mtu = (buf[48] as u16) * 16;
        let capabilities = u16::from_be_bytes([buf[50], buf[51]]);
        Ok(Self {
            allocated_v4: v4.into(),
            gateway_v4: gw4.into(),
            v4_prefix,
            allocated_v6,
            gateway_v6,
            v6_prefix,
            mtu,
            capabilities,
        })
    }

    /// Sanity-check an exit-supplied hello before it configures the client's
    /// kernel TUN + routes. The exit is untrusted to a VPN client (it chooses
    /// the lease), so reject values that would otherwise reach `ip` / the
    /// `subnet_*_cidr_str` shift math as garbage (e.g. a v4 prefix > 32).
    ///
    /// Route-hijack defence: the client installs `ip route replace
    /// <lease subnet> dev <tun>`, so the lease subnet must not cover address
    /// space the exit has no business capturing. The gateway must sit in the
    /// same subnet as the lease, and that subnet must lie inside RFC1918 /
    /// CGNAT 100.64/10 (v4) or ULA fc00::/7 (v6) unless `policy` explicitly
    /// allows a CIDR that contains it.
    pub fn validate(&self, policy: &LeasePolicy) -> Result<()> {
        if !(16..=30).contains(&self.v4_prefix) {
            anyhow::bail!("egress hello: v4 prefix /{} out of range [16,30]", self.v4_prefix);
        }
        if self.allocated_v4.is_unspecified()
            || self.allocated_v4.is_loopback()
            || self.allocated_v4.is_multicast()
            || self.allocated_v4.is_broadcast()
        {
            anyhow::bail!("egress hello: bogus allocated v4 {}", self.allocated_v4);
        }
        if self.allocated_v6.is_some() && !(64..=126).contains(&self.v6_prefix) {
            anyhow::bail!("egress hello: v6 prefix /{} out of range [64,126]", self.v6_prefix);
        }
        if let Some(v6) = self.allocated_v6
            && (v6.is_unspecified() || v6.is_loopback() || v6.is_multicast())
        {
            anyhow::bail!("egress hello: bogus allocated v6 {v6}");
        }
        // MTU is decoded as buf[48]*16 (so ≤ 4080); require at least a minimal
        // IPv4 datagram so the client never set_mtu's a 0/degenerate value.
        if !(576..=4080).contains(&self.mtu) {
            anyhow::bail!("egress hello: implausible mtu {}", self.mtu);
        }

        // ── v4: gateway in the lease subnet, subnet in allowed space ──
        let v4_subnet = Cidr::parse(&subnet_v4_cidr_str(self.allocated_v4, self.v4_prefix))?;
        if !v4_subnet.contains(IpAddr::V4(self.gateway_v4)) {
            anyhow::bail!(
                "egress hello: gateway {} is outside the lease subnet of {}/{}",
                self.gateway_v4, self.allocated_v4, self.v4_prefix
            );
        }
        let host_mask = (1u32 << (32 - self.v4_prefix as u32)) - 1;
        for (what, a) in [("lease", self.allocated_v4), ("gateway", self.gateway_v4)] {
            let host = u32::from(a) & host_mask;
            if host == 0 || host == host_mask {
                anyhow::bail!("egress hello: {what} {a} is the network/broadcast address");
            }
        }
        if self.gateway_v4 == self.allocated_v4 {
            anyhow::bail!("egress hello: gateway equals the leased address {}", self.allocated_v4);
        }
        if !policy.permits(&v4_subnet) {
            anyhow::bail!(
                "egress hello: lease subnet {} is not private (RFC1918 / 100.64/10) and not in \
                 [client].allowed_lease_cidrs — refusing to route it into the tunnel",
                subnet_v4_cidr_str(self.allocated_v4, self.v4_prefix)
            );
        }

        // ── v6: same rules, ULA by default ──
        if let Some(v6) = self.allocated_v6 {
            let Some(gw6) = self.gateway_v6 else {
                anyhow::bail!("egress hello: v6 lease without a v6 gateway");
            };
            let v6_subnet = Cidr::parse(&subnet_v6_cidr_str(v6, self.v6_prefix))?;
            if !v6_subnet.contains(IpAddr::V6(gw6)) {
                anyhow::bail!(
                    "egress hello: v6 gateway {gw6} is outside the lease subnet of {v6}/{}",
                    self.v6_prefix
                );
            }
            if gw6 == v6 {
                anyhow::bail!("egress hello: v6 gateway equals the leased address {v6}");
            }
            if !policy.permits(&v6_subnet) {
                anyhow::bail!(
                    "egress hello: v6 lease subnet {} is not ULA (fc00::/7) and not in \
                     [client].allowed_lease_cidrs — refusing to route it into the tunnel",
                    subnet_v6_cidr_str(v6, self.v6_prefix)
                );
            }
        }
        Ok(())
    }
}

/// Which address space a VPN client lets an (untrusted) exit place its lease
/// subnet in. Private ranges are always permitted; `allowed_lease_cidrs` adds
/// more. See [`EgressHello::validate`].
#[derive(Debug, Clone, Default)]
pub struct LeasePolicy {
    extra: Vec<Cidr>,
}

impl LeasePolicy {
    /// RFC1918 + CGNAT (v4) and ULA (v6) — the only ranges an exit may use
    /// without explicit client opt-in.
    const PRIVATE: [&'static str; 5] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "fc00::/7",
    ];

    pub fn new(allowed_lease_cidrs: &[String]) -> Result<Self> {
        let extra = allowed_lease_cidrs
            .iter()
            .map(|c| Cidr::parse(c).with_context(|| format!("[client].allowed_lease_cidrs {c:?}")))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { extra })
    }

    /// True if the whole `subnet` lies inside a private range or one of the
    /// explicitly allowed CIDRs.
    pub fn permits(&self, subnet: &Cidr) -> bool {
        Self::PRIVATE
            .iter()
            .map(|c| Cidr::parse(c).expect("static CIDR"))
            .chain(self.extra.iter().copied())
            .any(|c| c.contains_cidr(subnet))
    }
}

// ── Address allocator ─────────────────────────────────────────────────────

/// A paired IPv4/IPv6 lease handed out to one client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
}

/// Allocates IPv4 (and optionally IPv6) addresses out of a paired
/// subnet for incoming egress streams. The host index inside the v4
/// subnet drives the v6 host part too, so each client gets a single
/// unambiguous slot in both stacks. .1 is reserved for the gateway;
/// .2 .. .max-1 are handed out; the broadcast slot is skipped.
#[derive(Debug)]
pub struct AddressPool {
    v4_base: Ipv4Addr,
    v4_prefix: u8,
    v6_base: Option<Ipv6Addr>,
    v6_prefix: u8,
    /// Bit vector of taken host indices. Index 0 is the network address,
    /// index 1 is the gateway. Bit set = in use.
    in_use: Vec<bool>,
}

impl AddressPool {
    pub fn new(
        v4_base: Ipv4Addr,
        v4_prefix: u8,
        v6_base: Option<Ipv6Addr>,
        v6_prefix: u8,
    ) -> Result<Self> {
        if !(16..=30).contains(&v4_prefix) {
            anyhow::bail!("address pool: v4 prefix /{v4_prefix} not in [16, 30]");
        }
        if v6_base.is_some() && !(64..=126).contains(&v6_prefix) {
            anyhow::bail!("address pool: v6 prefix /{v6_prefix} not in [64, 126]");
        }
        let host_bits = 32 - v4_prefix as u32;
        let n_hosts = 1u32 << host_bits;
        let mut in_use = vec![false; n_hosts as usize];
        in_use[0] = true;                  // network
        in_use[1] = true;                  // gateway
        in_use[(n_hosts - 1) as usize] = true; // broadcast
        Ok(Self { v4_base, v4_prefix, v6_base, v6_prefix, in_use })
    }

    pub fn gateway_v4(&self) -> Ipv4Addr {
        let mut octets = self.v4_base.octets();
        octets[3] += 1;
        octets.into()
    }

    pub fn gateway_v6(&self) -> Option<Ipv6Addr> {
        self.host_index_to_v6(1)
    }

    pub fn v4_prefix(&self) -> u8 {
        self.v4_prefix
    }

    pub fn v6_prefix(&self) -> u8 {
        self.v6_prefix
    }

    /// True if this pool was configured with both v4 and v6 ranges.
    /// Used by tests; production callers infer dual-stack from
    /// `gateway_v6().is_some()`.
    #[cfg(test)]
    pub fn dual_stack(&self) -> bool {
        self.v6_base.is_some()
    }

    fn host_index_to_v6(&self, host: u32) -> Option<Ipv6Addr> {
        let base = self.v6_base?;
        let mut octets = base.octets();
        // Add host index to the lowest 4 bytes of the v6 address. This
        // keeps the v6 host portion identical to the v4 host portion so
        // /whoami output from either stack maps back to the same lease.
        let last4 = u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]])
            .wrapping_add(host);
        octets[12..16].copy_from_slice(&last4.to_be_bytes());
        Some(Ipv6Addr::from(octets))
    }

    fn host_index_to_v4(&self, host: u32) -> Ipv4Addr {
        let combined = u32::from_be_bytes(self.v4_base.octets()) + host;
        combined.to_be_bytes().into()
    }

    pub fn allocate(&mut self) -> Option<Lease> {
        for (i, used) in self.in_use.iter_mut().enumerate() {
            if !*used {
                *used = true;
                let host = i as u32;
                return Some(Lease {
                    v4: self.host_index_to_v4(host),
                    v6: self.host_index_to_v6(host),
                });
            }
        }
        None
    }

    pub fn release(&mut self, lease: Lease) {
        let host = u32::from_be_bytes(lease.v4.octets())
            .wrapping_sub(u32::from_be_bytes(self.v4_base.octets())) as usize;
        if host < self.in_use.len() {
            self.in_use[host] = false;
        }
    }

    /// Mark a specific lease as taken. Used by the persistent
    /// lease store to reseed the pool at startup so that already-
    /// allocated v4 addresses are not handed out a second time to
    /// a new peer.
    ///
    /// Returns:
    ///
    /// * `Ok(())` — the lease lies inside the pool's range and
    ///   the slot has now been marked taken (whether it was
    ///   already taken or not).
    /// * `Err(_)` — the lease points to a host outside the
    ///   configured range (operator changed `pool_base` /
    ///   `pool_prefix` since the file was written, or the file is
    ///   from a different deployment). The caller should drop the
    ///   entry from the loaded set and let the peer get a fresh
    ///   lease on reconnect.
    pub fn reserve(&mut self, lease: Lease) -> Result<()> {
        let host = u32::from_be_bytes(lease.v4.octets())
            .checked_sub(u32::from_be_bytes(self.v4_base.octets()))
            .ok_or_else(|| anyhow::anyhow!(
                "lease {:?} is below pool base {:?}", lease.v4, self.v4_base
            ))? as usize;
        if host >= self.in_use.len() {
            anyhow::bail!(
                "lease {:?} (host index {host}) is outside pool of {} hosts",
                lease.v4, self.in_use.len()
            );
        }
        // .0 (network), .1 (gateway), and .max-1 (broadcast) are
        // reserved by `new`; reserving them from the lease store
        // would mean the file was written against a different
        // pool layout. Refuse rather than corrupt the pool.
        if host == 0 || host == 1 || host == self.in_use.len() - 1 {
            anyhow::bail!(
                "lease {:?} (host {host}) is a pool-reserved slot — refusing to reuse",
                lease.v4
            );
        }
        self.in_use[host] = true;
        Ok(())
    }
}

// ── Reverse table ─────────────────────────────────────────────────────────

/// Reverse-routing table for the egress exit role. The TUN reader
/// looks up the destination IP here to find which peer to send the
/// packet to; the datagram receiver looks up the source peer's
/// allocated lease here to anti-spoof.
///
/// Two maps so each direction is one O(1) lookup. A dual-stack lease
/// registers two `peer_by_ip` entries (one per family) so packets in
/// either direction route correctly.
///
/// Each lease also carries bookkeeping for its lifecycle:
///
/// * `sessions` — how many live egress control streams currently use it.
///   Two handshakes from one peer can overlap (reconnect racing a stale
///   stream); a rollback or disconnect only drops *its* reference, so a
///   failing handshake can never free a lease another session still uses.
/// * `generation` — unique per insert. A session remembers the generation it
///   joined; if the entry was evicted / reclaimed / re-allocated since,
///   the stale session's end is a no-op instead of touching the new owner.
/// * `last_active` — unix seconds of the last handshake / disconnect;
///   drives least-recently-active reclamation and is persisted.
#[derive(Default)]
pub struct EgressTable {
    /// allocated IP → owning peer
    peer_by_ip: std::collections::HashMap<IpAddr, bifrost_core::PubKey>,
    /// peer → its allocated lease + lifecycle bookkeeping
    lease_by_peer: std::collections::HashMap<bifrost_core::PubKey, LeaseEntry>,
    next_generation: u64,
}

#[derive(Debug, Clone, Copy)]
struct LeaseEntry {
    lease: Lease,
    sessions: u32,
    last_active: u64,
    generation: u64,
}

impl EgressTable {
    /// Register `peer → lease` with no live session (e.g. a sticky lease
    /// reseeded from disk). Replaces any prior entry for `peer`.
    pub fn insert(&mut self, peer: bifrost_core::PubKey, lease: Lease) -> u64 {
        self.insert_with_activity(peer, lease, 0)
    }

    /// Like [`insert`](Self::insert) with an explicit `last_active` stamp.
    /// Returns the entry's generation.
    pub fn insert_with_activity(
        &mut self,
        peer: bifrost_core::PubKey,
        lease: Lease,
        last_active: u64,
    ) -> u64 {
        // Drop the old IP mappings first so a replaced lease can't leave a
        // dangling `peer_by_ip` entry routing someone else's address here.
        self.remove_peer(&peer);
        self.peer_by_ip.insert(IpAddr::V4(lease.v4), peer);
        if let Some(v6) = lease.v6 {
            self.peer_by_ip.insert(IpAddr::V6(v6), peer);
        }
        self.next_generation += 1;
        let generation = self.next_generation;
        self.lease_by_peer.insert(peer, LeaseEntry { lease, sessions: 0, last_active, generation });
        generation
    }

    pub fn remove_peer(&mut self, peer: &bifrost_core::PubKey) -> Option<Lease> {
        let lease = self.lease_by_peer.remove(peer)?.lease;
        self.peer_by_ip.remove(&IpAddr::V4(lease.v4));
        if let Some(v6) = lease.v6 {
            self.peer_by_ip.remove(&IpAddr::V6(v6));
        }
        Some(lease)
    }

    pub fn peer_for_ip(&self, ip: &IpAddr) -> Option<bifrost_core::PubKey> {
        self.peer_by_ip.get(ip).copied()
    }

    pub fn lease_of(&self, peer: &bifrost_core::PubKey) -> Option<Lease> {
        self.lease_by_peer.get(peer).map(|e| e.lease)
    }

    /// Number of live egress sessions holding `peer`'s lease.
    pub fn sessions_of(&self, peer: &bifrost_core::PubKey) -> u32 {
        self.lease_by_peer.get(peer).map_or(0, |e| e.sessions)
    }

    /// Last-activity stamp (unix seconds) of `peer`'s lease.
    pub fn last_active_of(&self, peer: &bifrost_core::PubKey) -> Option<u64> {
        self.lease_by_peer.get(peer).map(|e| e.last_active)
    }

    /// All `(peer, lease)` pairs currently in the table — used by
    /// the admin layer for the `Leases` endpoint.
    pub fn snapshot(&self) -> Vec<(bifrost_core::PubKey, Lease)> {
        self.lease_by_peer.iter().map(|(p, e)| (*p, e.lease)).collect()
    }

    /// `(peer, lease, last_active)` for persistence, in a stable order
    /// (by v4 address) so the file diff is readable.
    pub fn persist_snapshot(&self) -> Vec<(bifrost_core::PubKey, Lease, u64)> {
        let mut v: Vec<_> = self
            .lease_by_peer
            .iter()
            .map(|(p, e)| (*p, e.lease, e.last_active))
            .collect();
        v.sort_by_key(|(_, l, _)| u32::from(l.v4));
        v
    }

    /// Join `peer`'s existing lease as one more live session.
    pub(crate) fn join(&mut self, peer: &bifrost_core::PubKey, now: u64) -> Option<(Lease, u64)> {
        let e = self.lease_by_peer.get_mut(peer)?;
        e.sessions += 1;
        e.last_active = e.last_active.max(now);
        Some((e.lease, e.generation))
    }

    /// The reclamation victim when the pool is full: the least-recently-
    /// active lease with no live session whose peer isn't connected. Never
    /// a lease in use. Ties break on the lower v4 address (deterministic).
    fn reclaim_victim(
        &self,
        connected: &std::collections::HashSet<bifrost_core::PubKey>,
    ) -> Option<bifrost_core::PubKey> {
        self.lease_by_peer
            .iter()
            .filter(|(p, e)| e.sessions == 0 && !connected.contains(*p))
            .min_by_key(|(_, e)| (e.last_active, u32::from(e.lease.v4)))
            .map(|(p, _)| *p)
    }
}

/// Unix seconds now (0 if the clock is before the epoch).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub type SharedTable = Arc<Mutex<EgressTable>>;
pub type SharedPool = Arc<Mutex<AddressPool>>;

// ── Kernel-config helpers ─────────────────────────────────────────────────

/// Run `ip` / `iptables` once and surface the error if the command
/// doesn't return 0. Logs the full argv at debug so an operator can
/// reproduce manually if NetEm or capability issues surface.
fn run_cmd(prog: &str, args: &[&str]) -> Result<()> {
    debug!("run: {prog} {}", args.join(" "));
    let status = Command::new(prog)
        .args(args)
        .status()
        .with_context(|| format!("spawning {prog}"))?;
    if !status.success() {
        anyhow::bail!("`{prog} {}` exited with {:?}", args.join(" "), status.code());
    }
    Ok(())
}

/// Idempotently install a single iptables/ip6tables rule. The `-C`
/// (check) variant runs first; only on a non-zero return (rule missing
/// or chain doesn't exist yet) do we try the `-A` insert. Lets the
/// daemon restart without piling up duplicate rules.
///
/// `-A` may sit anywhere in the args (e.g. `-t nat -A POSTROUTING …`),
/// so we scan and replace ANY `-A` with `-C` rather than only the
/// first arg. The older "args[0] = "-C"" shortcut blew up on
/// `iptables -t nat -A …` because that put `-C` next to `-t nat`,
/// which the kernel rejected as "Cannot use -A with -C".
fn ensure_rule(prog: &str, args: &[&str]) -> Result<()> {
    let check_args: Vec<&str> = args
        .iter()
        .map(|&a| if a == "-A" { "-C" } else { a })
        .collect();
    debug_assert!(check_args.contains(&"-C"),
                  "ensure_rule: caller must include an -A flag to rewrite");
    let already = Command::new(prog)
        .args(&check_args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !already {
        run_cmd(prog, args)?;
    }
    Ok(())
}

/// Bring up the egress TUN with the v4 gateway (and v6 gateway if
/// dual-stack), enable forwarding, and add the matching iptables /
/// ip6tables MASQUERADE + FORWARD-ACCEPT rules.
pub fn configure_exit_kernel(
    tun_name: &str,
    gateway_v4: Ipv4Addr,
    v4_prefix: u8,
    gateway_v6: Option<Ipv6Addr>,
    v6_prefix: u8,
    egress_iface: &str,
) -> Result<()> {
    let v4_cidr = format!("{}/{}", gateway_v4, v4_prefix);
    let v4_subnet = subnet_v4_cidr_str(gateway_v4, v4_prefix);
    run_cmd("ip", &["link", "set", tun_name, "up"])?;
    let v4_exists = Command::new("ip")
        .args(["addr", "show", "dev", tun_name, "to", &v4_cidr])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if !v4_exists {
        run_cmd("ip", &["addr", "add", &v4_cidr, "dev", tun_name])?;
    }
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");

    // IPv4 NAT + FORWARD rules.
    ensure_rule("iptables", &[
        "-t", "nat", "-A", "POSTROUTING",
        "-s", &v4_subnet, "-o", egress_iface, "-j", "MASQUERADE",
    ])?;
    ensure_rule("iptables", &[
        "-A", "FORWARD", "-i", tun_name, "-o", egress_iface, "-j", "ACCEPT",
    ])?;
    ensure_rule("iptables", &[
        "-A", "FORWARD", "-o", tun_name, "-i", egress_iface,
        "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
    ])?;

    // MSS clamp on the egress TUN: without this, TCP sessions inside
    // the tunnel send 1460-byte segments based on the host MTU and
    // then either fragment at the IP layer or stall waiting for an
    // ICMP-needed that won't come from CGNAT. Clamping rewrites
    // outgoing SYNs so the inner TCP negotiates MSS ≤ tunnel-MTU - 40,
    // avoiding fragmentation entirely. This is the canonical OpenVPN /
    // WireGuard recipe and is essentially free at runtime.
    ensure_rule("iptables", &[
        "-t", "mangle", "-A", "FORWARD",
        "-o", tun_name,
        "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ])?;
    ensure_rule("iptables", &[
        "-t", "mangle", "-A", "FORWARD",
        "-i", tun_name,
        "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
        "-j", "TCPMSS", "--clamp-mss-to-pmtu",
    ])?;

    // IPv6 NAT66 + FORWARD rules (skip if v4-only).
    if let Some(gw6) = gateway_v6 {
        let v6_cidr = format!("{}/{}", gw6, v6_prefix);
        let v6_subnet = subnet_v6_cidr_str(gw6, v6_prefix);
        let v6_exists = Command::new("ip")
            .args(["-6", "addr", "show", "dev", tun_name, "to", &v6_cidr])
            .output()
            .map(|o| !o.stdout.is_empty())
            .unwrap_or(false);
        if !v6_exists {
            run_cmd("ip", &["-6", "addr", "add", &v6_cidr, "dev", tun_name])?;
        }
        let _ = std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1");
        ensure_rule("ip6tables", &[
            "-t", "nat", "-A", "POSTROUTING",
            "-s", &v6_subnet, "-o", egress_iface, "-j", "MASQUERADE",
        ])?;
        ensure_rule("ip6tables", &[
            "-A", "FORWARD", "-i", tun_name, "-o", egress_iface, "-j", "ACCEPT",
        ])?;
        ensure_rule("ip6tables", &[
            "-A", "FORWARD", "-o", tun_name, "-i", egress_iface,
            "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT",
        ])?;
        // Same MSS clamping logic as the v4 side — see comment above.
        ensure_rule("ip6tables", &[
            "-t", "mangle", "-A", "FORWARD",
            "-o", tun_name,
            "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])?;
        ensure_rule("ip6tables", &[
            "-t", "mangle", "-A", "FORWARD",
            "-i", tun_name,
            "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])?;
    }
    Ok(())
}

/// Configure the client-side TUN with the assigned v4 (and v6 if the
/// exit provided one). install_default_route, when true, replaces the
/// system default route in BOTH stacks where applicable.
#[allow(clippy::too_many_arguments)] // mirrors the v4+v6 lease layout
pub fn configure_client_kernel(
    tun_name: &str,
    v4_addr: Ipv4Addr,
    v4_prefix: u8,
    gateway_v4: Ipv4Addr,
    v6_addr: Option<Ipv6Addr>,
    v6_prefix: u8,
    gateway_v6: Option<Ipv6Addr>,
    install_default_route: bool,
) -> Result<()> {
    // Routes are derived from the LEASED address; `EgressHello::validate`
    // has already pinned the gateway into that same (private or
    // explicitly allowed) subnet, so the exit can't steer this route.
    let v4_cidr = format!("{}/{}", v4_addr, v4_prefix);
    let v4_subnet = subnet_v4_cidr_str(v4_addr, v4_prefix);
    run_cmd("ip", &["link", "set", tun_name, "up"])?;
    let _ = Command::new("ip").args(["addr", "add", &v4_cidr, "dev", tun_name]).status();
    let _ = Command::new("ip").args(["route", "replace", &v4_subnet, "dev", tun_name]).status();

    // The v6 gateway is on-link inside `v6_subnet` (validated).
    if let (Some(v6), Some(_)) = (v6_addr, gateway_v6) {
        let v6_cidr = format!("{}/{}", v6, v6_prefix);
        let v6_subnet = subnet_v6_cidr_str(v6, v6_prefix);
        let _ = Command::new("ip").args(["-6", "addr", "add", &v6_cidr, "dev", tun_name]).status();
        let _ = Command::new("ip").args(["-6", "route", "replace", &v6_subnet, "dev", tun_name]).status();
    }

    if install_default_route {
        run_cmd("ip", &["route", "replace", "default",
                        "via", &gateway_v4.to_string(), "dev", tun_name])?;
        if let Some(gw6) = gateway_v6 {
            // Best-effort v6 default; if the kernel has no v6 default
            // configured (common in v4-only docker bridges) this can
            // fail harmlessly so we don't treat the error as fatal.
            let _ = Command::new("ip")
                .args(["-6", "route", "replace", "default",
                       "via", &gw6.to_string(), "dev", tun_name])
                .status();
        }
    }
    Ok(())
}

fn subnet_v4_cidr_str(any_in_subnet: Ipv4Addr, prefix_len: u8) -> String {
    let mask = !((1u32 << (32 - prefix_len as u32)) - 1);
    let net_u32 = u32::from_be_bytes(any_in_subnet.octets()) & mask;
    let net: Ipv4Addr = net_u32.to_be_bytes().into();
    format!("{net}/{prefix_len}")
}

fn subnet_v6_cidr_str(any_in_subnet: Ipv6Addr, prefix_len: u8) -> String {
    let mut octets = any_in_subnet.octets();
    let full_bytes = (prefix_len / 8) as usize;
    let rem_bits = prefix_len % 8;
    // Clear bits beyond the prefix.
    for byte in octets.iter_mut().skip(full_bytes + 1) {
        *byte = 0;
    }
    if full_bytes < 16 {
        let mask = if rem_bits == 0 { 0u8 } else { 0xff_u8 << (8 - rem_bits) };
        octets[full_bytes] &= mask;
    }
    let net = Ipv6Addr::from(octets);
    format!("{net}/{prefix_len}")
}

// ── Stream <-> TUN bridge for exit role ──────────────────────────────────

#[cfg(feature = "tun")]
#[allow(clippy::too_many_arguments)] // matches the v4/v6 pool config layout
pub async fn start_exit(
    mux: Arc<MeshMux>,
    mut accept_rx: mpsc::Receiver<AcceptedStream>,
    tun_name: String,
    v4_pool_base: Ipv4Addr,
    v4_pool_prefix: u8,
    v6_pool_base: Option<Ipv6Addr>,
    v6_pool_prefix: u8,
    egress_iface: String,
    lease_persistence_path: String,
    admin_socket: String,
    dst_filter: Arc<crate::dst_filter::DstFilter>,
    admission: Arc<crate::admission::ExitAdmission>,
) -> Result<()> {
    if admission.is_open() {
        warn!(
            "egress exit: OPEN exit — [exit].allowed_clients is empty, so any mesh key \
             can obtain a sticky lease{}. Keys are free to mint; set allowed_clients \
             (and/or min_client_pow_bits) unless this is intentional.",
            if admission.min_pow_bits() > 0 {
                format!(" (subject to min_client_pow_bits = {})", admission.min_pow_bits())
            } else {
                String::new()
            }
        );
    } else {
        info!(
            "egress exit: client allowlist active ({} key(s)), min_client_pow_bits = {}",
            admission.allowlist_len(),
            admission.min_pow_bits()
        );
    }
    let pool = Arc::new(Mutex::new(
        AddressPool::new(v4_pool_base, v4_pool_prefix, v6_pool_base, v6_pool_prefix)
            .with_context(|| format!(
                "address pool {v4_pool_base}/{v4_pool_prefix} (+v6 {v6_pool_base:?})"
            ))?,
    ));
    let (gw4, prefix4, gw6, prefix6) = {
        let p = pool.lock().unwrap();
        (p.gateway_v4(), p.v4_prefix(), p.gateway_v6(), p.v6_prefix())
    };

    // ── Lease persistence (sticky reconnects across restart) ─────
    //
    // Load any prior `peer → lease` mappings from disk and reseed
    // both the AddressPool (so we don't double-allocate a held v4)
    // and the EgressTable (so the first handshake from a returning
    // peer finds an existing lease and skips a fresh allocation).
    // Entries whose v4 doesn't fit the configured pool are dropped
    // with a warning — operator probably changed pool_base /
    // pool_prefix between restarts; the peer will pick up a new
    // slot on reconnect.
    let lease_store = Arc::new(Mutex::new(
        crate::lease_store::LeaseStore::new(lease_persistence_path.clone())
    ));
    let table: SharedTable = Arc::new(Mutex::new(EgressTable::default()));
    if !lease_persistence_path.is_empty() {
        let loaded = crate::lease_store::load_with_warn(
            std::path::Path::new(&lease_persistence_path)
        );
        let (reseeded, dropped, refused) = reseed_leases(&pool, &table, &admission, loaded);
        // Mirror the reseeded table into the store and write the cleaned
        // set back (dropped / no-longer-admitted entries gone) so the file
        // reflects what the exit actually holds.
        if let Err(e) = persist_leases(&table, &lease_store) {
            warn!("lease store: rewriting reseeded store failed: {e:#}");
        }
        if dropped + refused > 0 {
            debug!("lease store: removed {} stale entr(y/ies) from disk", dropped + refused);
        }
        info!(
            "lease store: reseeded {reseeded} sticky lease(s) from {:?}{}{}",
            lease_persistence_path,
            if dropped > 0 {
                format!(" ({dropped} dropped as out-of-range)")
            } else {
                String::new()
            },
            if refused > 0 {
                format!(" ({refused} dropped: peer no longer admitted)")
            } else {
                String::new()
            }
        );
    } else {
        info!("lease store: disabled (set [exit].lease_persistence_path to enable)");
    }

    // Bring up the vpnd admin socket before the data plane so an
    // operator running `bifrost-ctl leases` against a freshly-started
    // exit sees the reseeded entries immediately, even if no client
    // has connected yet. Non-fatal: the admin RPC is an operator
    // convenience and must not take the data plane down with it.
    if let Err(e) = crate::admin::spawn_listener(
        admin_socket.into(),
        crate::admin::AdminState {
            conn: mux.conn().clone(),
            mode: crate::admin::AdminMode::Exit,
            started_at: std::time::Instant::now(),
            pool: Some(pool.clone()),
            table: Some(table.clone()),
            lease_store: Some(lease_store.clone()),
            self_lease: None,
        },
    ) {
        warn!(
            "vpnd admin socket unavailable ({e:#}); set [exit].admin_socket to a \
             writable path, or \"\" to disable it"
        );
    }

    let dev = crate::tun_dev::OffloadTun::open(
        &tun_name,
        1400,
        crate::tun_dev::OffloadTun::DEFAULT_OFFLOAD,
    )
    .with_context(|| format!("creating egress TUN {tun_name}"))?;
    configure_exit_kernel(&tun_name, gw4, prefix4, gw6, prefix6, &egress_iface)?;
    info!(
        "egress exit: tun={tun_name} v4_gw={gw4}/{prefix4} v6_gw={} \
         egress_iface={egress_iface} offload_active={}",
        gw6.map(|g| format!("{g}/{prefix6}")).unwrap_or_else(|| "<none>".into()),
        dev.offload_active()
    );

    let (tun_reader, tun_writer) = tokio::io::split(dev);
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));
    // `table` was created above (alongside the lease store
    // reseed); from here on it's the shared routing/anti-spoof
    // map used by the datagram receivers and the handshake
    // workers.

    // Register the IP-packet datagram channel. Each Frame::Datagram
    // landing on DATAGRAM_CHANNEL_EGRESS is one IP packet from a
    // client; the read loop owns lookup-by-peer + anti-spoof + TUN
    // write. Capacity 8192 matches the per-peer write channel; on
    // overflow the mux drops packets (best-effort by design).
    let mut datagram_rx = mux
        .register_datagram_channel(bifrost_core::mux::DATAGRAM_CHANNEL_EGRESS, 8192)
        .context("registering egress datagram channel")?;

    // datagram → TUN: client batches land here. Anti-spoof each
    // packet against the peer's lease, then write to the egress
    // TUN. The kernel handles NAT (MASQUERADE) + routing. We hold
    // the TUN-writer lock across an entire batch so a 16-packet
    // burst is one lock acquire instead of 16 — important once the
    // sender side is coalescing aggressively.
    let table_for_in = table.clone();
    let tun_writer_in = tun_writer.clone();
    let dst_filter_in = dst_filter.clone();
    tokio::spawn(async move {
        let mut write_failures: u64 = 0;
        while let Some(recv) = datagram_rx.recv().await {
            let bifrost_core::mux::DatagramRecv { from, payload } = recv;
            if payload.is_empty() { continue; }
            let lease = table_for_in.lock().unwrap().lease_of(&from);
            let Some(lease) = lease else {
                trace!(
                    "egress exit: datagram from unknown peer {} (no lease) — drop",
                    hex::encode(&from[..8])
                );
                continue;
            };
            // Acquire the TUN writer once per batch; iterate the
            // coalesced packets inside the lock so we never write
            // halfway-through a packet.
            let mut w = tun_writer_in.lock().await;
            for slot in PacketBatchIter::new(&payload) {
                // Each slot is `[10-byte vhdr | IP packet]`. Anti-
                // spoof reads from the IP part; the vhdr stays
                // attached for the TUN write so the receiving
                // kernel sees the same `gso_type` the sender's
                // kernel produced.
                let ip = match ip_part(slot) { Some(p) => p, None => continue };
                // `ip` can be empty: a vhdr-only (10-byte) slot yields a
                // zero-length IP part. src_is_spoofed handles that without
                // indexing; the routable-dst log below is guarded too, so a
                // hostile short packet from a leased client can't panic the
                // exit (which, under panic=abort, would drop every client).
                if src_is_spoofed(ip, &lease) {
                    if !ip.is_empty() && is_routable_dst(ip[0] >> 4, ip) {
                        debug!(
                            "egress exit: spoofed packet from {} (ver={}), drop",
                            hex::encode(&from[..8]), ip[0] >> 4
                        );
                    }
                    continue;
                }
                // SSRF defence: drop client packets whose destination the
                // egress policy forbids (loopback / link-local / cloud
                // metadata always; private ranges unless the operator opted
                // out or allowlisted them) BEFORE the kernel routes them out.
                // Fail closed: an unparseable destination is dropped too.
                match crate::dst_filter::DstFilter::dst_of(ip) {
                    Some(dst) if dst_filter_in.allows(dst) => {}
                    _ => {
                        trace!(
                            "egress exit: dst blocked by policy (from {}), drop",
                            hex::encode(&from[..8])
                        );
                        continue;
                    }
                }
                // The vhdr is client-supplied: drop one the kernel would
                // reject (EINVAL) rather than hand it to the shared TUN.
                if !crate::tun_offload::slot_vhdr_is_sane(slot) {
                    trace!(
                        "egress exit: invalid virtio_net_hdr from {}, drop",
                        hex::encode(&from[..8])
                    );
                    continue;
                }
                // A write error is per-packet: log + drop, never tear down
                // this loop — it is the uplink for EVERY client.
                if let Err(e) = w.write_all(slot).await {
                    note_tun_write_error("egress exit", &mut write_failures, &e);
                }
            }
        }
        warn!("egress exit: datagram receiver exited");
    });

    // TUN → datagram with per-peer coalescing. The TUN reader drains
    // up to MAX_COALESCED_PACKETS / COALESCE_BYTE_BUDGET worth of
    // packets, bucketed by destination peer, then flushes one
    // Datagram per peer. Each batch encodes via `encode_packet_batch`
    // and the receiver iterates with `PacketBatchIter`.
    //
    // Bucketing matters on the exit side because TUN packets belong
    // to different clients; a per-peer flush keeps the wire-side
    // batches dense without forcing cross-client ordering.
    let table_for_tun = table.clone();
    let mux_for_tun = mux.clone();
    tokio::spawn(async move {
        let mut reader = tun_reader;
        let mut buf = vec![0u8; 65536];
        // Per-peer slot buffers + running byte total. The total
        // covers all peers so the global budget can't be exceeded
        // by collisions on a busy bridge.
        let mut buckets: std::collections::HashMap<
            bifrost_core::PubKey, Vec<Vec<u8>>
        > = std::collections::HashMap::new();
        loop {
            // First read in this cycle: blocking.
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buckets.clear();
            let mut total_bytes: usize = 0;
            push_to_bucket(&table_for_tun, &mut buckets, &mut total_bytes, &buf[..n]);

            // Opportunistic drain.
            while total_bytes < COALESCE_BYTE_BUDGET {
                let next = tokio::time::timeout(
                    COALESCE_DRAIN_TIMEOUT,
                    reader.read(&mut buf),
                ).await;
                let n2 = match next {
                    Ok(Ok(0)) | Ok(Err(_)) => { buckets.clear(); break; }
                    Err(_) => break,
                    Ok(Ok(n)) => n,
                };
                push_to_bucket(&table_for_tun, &mut buckets, &mut total_bytes, &buf[..n2]);
                // Stop early if any single bucket reached the per-peer
                // packet cap (keeps batch encode latency bounded).
                if buckets.values().any(|v| v.len() >= MAX_COALESCED_PACKETS) {
                    break;
                }
            }

            // Flush each non-empty bucket as one Datagram. `send_datagram`
            // is a single non-waiting attempt: this one task serves every
            // client, so an offline peer's batch is dropped, not retried —
            // it must never stall downlink for the others.
            for (peer, slots) in buckets.iter().filter(|(_, v)| !v.is_empty()) {
                let refs: Vec<&[u8]> = slots.iter().map(|v| v.as_slice()).collect();
                let payload = encode_packet_batch(&refs);
                if let Err(e) = mux_for_tun
                    .send_datagram(peer, bifrost_core::mux::DATAGRAM_CHANNEL_EGRESS, &payload)
                    .await
                {
                    trace!("egress exit: datagram send to {} failed: {e}", hex::encode(&peer[..8]));
                }
            }
        }
        warn!("egress exit: tun reader exited");
    });

    // Accept loop: pair each incoming Open(Egress) with a lease. The
    // accepted MeshStream stays alive for the session's lifetime as
    // a control channel — its half-close on disconnect triggers
    // lease release. No data ever flows through the stream after the
    // handshake; the per-stream ARQ is wasted on bulk packet traffic.
    while let Some(acc) = accept_rx.recv().await {
        if !matches!(acc.target, OpenTarget::Egress) {
            continue;
        }
        let pool = pool.clone();
        let table = table.clone();
        let lease_store = lease_store.clone();
        let mux = mux.clone();
        let admission = admission.clone();
        tokio::spawn(async move {
            handle_egress_handshake(
                acc, mux, admission, pool, table, lease_store,
                gw4, prefix4, gw6, prefix6,
            ).await;
        });
    }
    warn!("egress exit: accept channel closed");
    Ok(())
}

/// Handshake half of the exit-side state machine. Each accepted
/// MeshStream becomes a *control channel only* — it carries OpenAck,
/// the framed EgressHello, and the eventual half-close that signals
/// disconnect. IP-packet bulk traffic rides on `Frame::Datagram`
/// over the same MeshMux, looked up via the shared `EgressTable`.
///
/// This decouples reliable lease lifecycle (1-shot, must arrive)
/// from best-effort packet relay (millions of frames, retransmits
/// already happen at the TCP/QUIC layer *inside* the tunnel — doing
/// them again in our ARQ caps single-flow throughput at ~5 Mbit/s).
#[cfg(feature = "tun")]
#[allow(clippy::too_many_arguments)] // v4+v6 gateway layout + persistence handle
async fn handle_egress_handshake(
    acc: AcceptedStream,
    mux: Arc<MeshMux>,
    admission: Arc<crate::admission::ExitAdmission>,
    pool: SharedPool,
    table: SharedTable,
    lease_store: Arc<Mutex<crate::lease_store::LeaseStore>>,
    gateway_v4: Ipv4Addr,
    v4_prefix: u8,
    gateway_v6: Option<Ipv6Addr>,
    v6_prefix: u8,
) {
    let mut mesh = acc.stream;
    let peer = acc.from;
    let peer_short = hex::encode(&peer[..8]);

    // Admission BEFORE any lease state is touched: keys are free to mint,
    // so an un-gated exit hands every throwaway identity a sticky slot.
    if let Err(why) = admission.check(&peer) {
        warn!("egress exit: refusing peer {peer_short}: {why}");
        let _ = mesh.send_open_ack(bifrost_core::stream::reply::NOT_ALLOWED).await;
        return;
    }

    // Sticky-lease lookup / allocation / reclamation, atomically, and
    // register this handshake as a live session on the lease. `None` means
    // the pool is full of leases that are all in use.
    let acquired = lease_lookup_or_allocate(&pool, &table, peer, unix_now(), || {
        mux.conn().get_peer_stats().into_iter().map(|s| s.key).collect()
    });
    let Some(acq) = acquired else {
        warn!(
            "egress exit: address pool exhausted for peer {peer_short} \
             (every lease has a live session or connected owner)"
        );
        let _ = mesh.send_open_ack(bifrost_core::stream::reply::GENERAL_FAILURE).await;
        return;
    };
    let lease = acq.lease;
    let session = LeaseSession::new(pool.clone(), table.clone(), peer, &acq);

    let alloc_desc = match lease.v6 {
        Some(v6) => format!("{} + {}", lease.v4, v6),
        None => lease.v4.to_string(),
    };
    if let Some((victim, old)) = acq.reclaimed {
        info!(
            "egress exit: pool full — reclaimed idle lease {} from peer {}",
            old.v4, hex::encode(&victim[..8])
        );
    }
    if acq.was_sticky {
        info!("egress exit: sticky-resume {alloc_desc} for peer {peer_short}");
    } else {
        info!("egress exit: allocated {alloc_desc} for peer {peer_short}");
    }
    // Persist immediately (new mapping / reclaimed victim / fresh
    // last_active) so a crash between here and the next save doesn't lose
    // the lease the client is about to be told about.
    if let Err(e) = persist_leases(&table, &lease_store) {
        warn!(
            "egress exit: persisting lease for {peer_short} failed: {e:#} \
             (lease is live in memory; will retry on next change)"
        );
    }

    // Rollback on a failed handshake: drop only THIS session's reference.
    // The lease is freed only if this handshake allocated it and no other
    // session (a concurrent handshake from the same peer) joined it — the
    // old unconditional release freed a lease still in use.
    let rollback = |session: LeaseSession| {
        if let Rollback::Released(_) = session.rollback()
            && let Err(e) = persist_leases(&table, &lease_store)
        {
            warn!("egress exit: persisting rollback for {peer_short} failed: {e:#}");
        }
    };

    if let Err(e) = mesh.send_open_ack(bifrost_core::stream::reply::SUCCESS).await {
        warn!("egress exit: OpenAck failed for {peer_short}: {e}");
        rollback(session);
        return;
    }
    let hello = EgressHello {
        allocated_v4: lease.v4,
        gateway_v4,
        v4_prefix,
        allocated_v6: lease.v6,
        gateway_v6,
        v6_prefix,
        mtu: 1400,
        // v3: we always speak the vhdr wire format. The bit is
        // informational here — the version check on the receiving
        // side already enforces compatibility.
        capabilities: EGRESS_CAP_VNET_HDR,
    };
    if let Err(e) = write_framed(&mut mesh, &hello.encode()).await {
        warn!("egress exit: hello send failed for {peer_short} ({alloc_desc}): {e}");
        rollback(session);
        return;
    }

    // Park here until the client half-closes (or its TCP dies). The
    // mesh stream carries no further data — it's purely a session
    // lifecycle marker.
    //
    // We do NOT release the lease on disconnect: it stays sticky so the
    // peer resumes onto the same IP. Ending the session only drops the
    // live-session count and stamps `last_active`, which makes the lease
    // eligible for least-recently-active reclamation under pool pressure.
    let discarded = drain_to_eof(&mut mesh).await;
    if discarded > 0 {
        // Old clients (pre-datagram) sent IP packets through the
        // stream; loudly flag those so the operator can roll forward.
        warn!(
            "egress exit: peer {} sent {} bytes on the control stream — \
             expected datagram-path client (post-2026-05-19 build)",
            peer_short, discarded
        );
    }
    session.end();
    if let Err(e) = persist_leases(&table, &lease_store) {
        debug!("egress exit: persisting last_active for {peer_short} failed: {e:#}");
    }
    info!(
        "egress exit: client {peer_short} disconnected (lease {alloc_desc} held sticky)"
    );
}

// ── Stream <-> TUN bridge for client role ────────────────────────────────

#[cfg(feature = "tun")]
pub async fn start_client(
    mux: Arc<MeshMux>,
    exit_peer: [u8; 32],
    tun_name: String,
    install_default_route: bool,
    admin_socket: String,
    lease_policy: LeasePolicy,
) -> Result<()> {
    let (mesh, hello) = client_handshake(mux.clone(), exit_peer, &lease_policy).await?;
    let self_lease = Lease {
        v4: hello.allocated_v4,
        v6: hello.allocated_v6,
    };
    if let Err(e) = crate::admin::spawn_listener(
        admin_socket.into(),
        crate::admin::AdminState {
            conn: mux.conn().clone(),
            mode: crate::admin::AdminMode::Client,
            started_at: std::time::Instant::now(),
            pool: None,
            table: None,
            lease_store: None,
            self_lease: Some(self_lease),
        },
    ) {
        warn!(
            "vpnd admin socket unavailable ({e:#}); set [client].admin_socket to a \
             writable path, or \"\" to disable it"
        );
    }
    let dev = crate::tun_dev::OffloadTun::open(
        &tun_name,
        hello.mtu,
        crate::tun_dev::OffloadTun::DEFAULT_OFFLOAD,
    )
    .with_context(|| format!("creating client egress TUN {tun_name}"))?;
    info!(
        "egress client: tun={tun_name} mtu={} offload_active={}",
        hello.mtu, dev.offload_active()
    );
    configure_client_kernel(
        &tun_name,
        hello.allocated_v4,
        hello.v4_prefix,
        hello.gateway_v4,
        hello.allocated_v6,
        hello.v6_prefix,
        hello.gateway_v6,
        install_default_route,
    )?;
    let (tun_reader, tun_writer) = tokio::io::split(dev);
    run_client_pump(
        tun_reader, tun_writer, mux, exit_peer, hello.allocated_v4, mesh, lease_policy,
    ).await
}

/// Run the client → exit handshake: wait for the peer to be
/// reachable on the mesh, open an Egress stream, await the
/// OpenAck, and read the framed [`EgressHello`]. Returns the live
/// control stream + the parsed hello. Used by `start_client` and
/// by `bifrost-ffi` (mobile shim). `lease_policy` bounds which address
/// space the exit may put the lease in (see [`EgressHello::validate`]).
pub async fn client_handshake(
    mux: Arc<MeshMux>,
    exit_peer: bifrost_core::PubKey,
    lease_policy: &LeasePolicy,
) -> Result<(bifrost_core::stream::MeshStream, EgressHello)> {
    info!(
        "egress client: opening tunnel to exit {}",
        hex::encode(&exit_peer[..8])
    );
    // Wait until the underlying transport reports a connection to
    // the exit peer (handshake done, session manager has the entry).
    // Without this poll, mux.open's session-wait races the very
    // first dial and burns its retry budget on a connection that
    // didn't exist yet.
    let wait_started = std::time::Instant::now();
    loop {
        let stats = mux.conn().get_peer_stats();
        if stats.iter().any(|p| p.key == exit_peer) {
            debug!(
                "egress client: peer {} appeared after {:?} — giving the session 2s to settle",
                hex::encode(&exit_peer[..8]),
                wait_started.elapsed()
            );
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            break;
        }
        if wait_started.elapsed() > std::time::Duration::from_secs(60) {
            anyhow::bail!(
                "egress client: peer {} not reachable after 60s",
                hex::encode(&exit_peer[..8])
            );
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    let mut mesh = mux
        .open(exit_peer, OpenTarget::Egress)
        .await
        .context("opening egress mesh stream")?;
    let ack = timeout(Duration::from_secs(15), mesh.await_open_ack())
        .await
        .context("waiting for egress OpenAck")?
        .context("egress OpenAck error")?;
    if ack != 0 {
        anyhow::bail!("exit refused egress with code 0x{ack:02x}");
    }
    // `MAX_RELAYED_PACKET` is 60 KiB to accommodate TSO super-frames
    // on the data plane; the hello itself is 52 bytes. Allocate on
    // the heap so the future stays small (this is hot only at
    // tunnel setup, never on the per-packet path).
    let mut hello_buf = vec![0u8; MAX_RELAYED_PACKET];
    let hello_len = read_framed(&mut mesh, &mut hello_buf)
        .await
        .context("reading framed egress hello")?
        .ok_or_else(|| anyhow::anyhow!("exit closed stream before sending hello"))?;
    if hello_len != EGRESS_HELLO_SIZE {
        anyhow::bail!(
            "egress hello has unexpected length {hello_len} (want {EGRESS_HELLO_SIZE})"
        );
    }
    let hello = EgressHello::decode(&hello_buf[..EGRESS_HELLO_SIZE])?;
    // The exit is untrusted to a VPN client: validate the announced lease/MTU
    // before feeding it to kernel TUN/route config. Out-of-range values
    // (e.g. v4_prefix > 32) otherwise reach `subnet_v4_cidr_str`'s shift math.
    hello.validate(lease_policy)?;
    let v6_desc = hello
        .allocated_v6
        .map(|v6| format!(" + {v6}/{}", hello.v6_prefix))
        .unwrap_or_default();
    info!(
        "egress client: allocated {}{} (v4 gw={})",
        hello.allocated_v4, v6_desc, hello.gateway_v4
    );
    Ok((mesh, hello))
}

/// Spawn the client-side data plane over a caller-provided TUN
/// device split into `AsyncRead` / `AsyncWrite` halves. Used by
/// `start_client` (with an `OffloadTun`) and by `bifrost-ffi`
/// (with the host-provided VpnService / NEPacketTunnelProvider fd).
///
/// `mesh` is the control stream from `client_handshake`; a
/// supervisor task holds it open and, whenever it dies, re-runs the
/// handshake so the tunnel survives transport drops (Wi-Fi↔LTE
/// roams, laptop sleep, flaky uplinks) without the caller noticing.
/// `lease_v4` is the address the host has already pinned its TUN to —
/// the supervisor verifies every re-lease still matches it.
///
/// The two real data tasks are spawned and own the tunnel from here
/// on — this function returns once they're scheduled.
pub async fn run_client_pump<R, W>(
    mut tun_reader: R,
    tun_writer: W,
    mux: Arc<MeshMux>,
    exit_peer: bifrost_core::PubKey,
    lease_v4: Ipv4Addr,
    mesh: bifrost_core::stream::MeshStream,
    lease_policy: LeasePolicy,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));

    // Register the IP-packet datagram channel for inbound traffic
    // from the exit. Same channel tag both sides use; the mux
    // dispatches by tag, so other subsystems on the same node
    // (bifrost-socks5d on a different stream id) don't collide.
    let mut datagram_rx = mux
        .register_datagram_channel(bifrost_core::mux::DATAGRAM_CHANNEL_EGRESS, 8192)
        .context("registering egress datagram channel")?;

    // datagram → TUN: write every inbound IP packet from the exit
    // straight to the local TUN. Each datagram carries a coalesced
    // batch of 1..=MAX_COALESCED_PACKETS packets; we iterate the
    // batch inside one TUN-writer lock acquire to keep the per-batch
    // syscall count down. PacketConn authenticates the peer so we
    // don't need a second-layer signature, but we still filter by
    // source pub-key so unrelated peers can't shove packets at our
    // TUN.
    let tun_writer_clone = tun_writer.clone();
    tokio::spawn(async move {
        let mut write_failures: u64 = 0;
        while let Some(recv) = datagram_rx.recv().await {
            if recv.from != exit_peer {
                trace!(
                    "egress client: dropping datagram from unexpected peer {}",
                    hex::encode(&recv.from[..8])
                );
                continue;
            }
            let mut w = tun_writer_clone.lock().await;
            for pkt in PacketBatchIter::new(&recv.payload) {
                // Per-packet failure (e.g. an exit-supplied vhdr the kernel
                // rejects): drop it, keep the downlink alive.
                if let Err(e) = w.write_all(pkt).await {
                    note_tun_write_error("egress client", &mut write_failures, &e);
                }
            }
        }
        warn!("egress client: datagram receiver exited");
    });

    // TUN → datagram with coalescing: the first packet of a batch is
    // pulled with a blocking read; then we try to opportunistically
    // drain more packets within COALESCE_DRAIN_TIMEOUT (≤ 100 μs) up
    // to MAX_COALESCED_PACKETS / COALESCE_BYTE_BUDGET. Result: one
    // mesh-frame encrypt + one TCP write per N IP packets instead of
    // per packet. On a long-fat WAN with 1400-byte MTU, this lifts
    // single-flow VPN throughput from ~10 Mbit/s (1 pkt/RTT-slot)
    // toward TCP-cap because each round of CPU work moves N×
    // more bytes per unit time.
    //
    // The other end (start_exit's datagram receiver) iterates the
    // batch via PacketBatchIter, anti-spoofs each packet, and writes
    // them one-by-one to the TUN.
    let mux_for_tun = mux.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        let mut slots: Vec<Vec<u8>> = Vec::with_capacity(MAX_COALESCED_PACKETS);
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            slots.clear();
            if let Some(pkt) = extract_routable(&buf[..n]) {
                slots.push(pkt.to_vec());
            }
            let mut bytes_acc: usize = slots.iter().map(|p| p.len() + 2).sum::<usize>() + 1;
            while slots.len() < MAX_COALESCED_PACKETS && bytes_acc < COALESCE_BYTE_BUDGET {
                let next = tokio::time::timeout(
                    COALESCE_DRAIN_TIMEOUT,
                    tun_reader.read(&mut buf),
                ).await;
                let n2 = match next {
                    Ok(Ok(0)) | Ok(Err(_)) => { slots.clear(); break; }
                    Err(_) => break,
                    Ok(Ok(n)) => n,
                };
                if let Some(pkt) = extract_routable(&buf[..n2]) {
                    bytes_acc += pkt.len() + 2;
                    slots.push(pkt.to_vec());
                }
            }
            if slots.is_empty() {
                continue;
            }
            let refs: Vec<&[u8]> = slots.iter().map(|v| v.as_slice()).collect();
            let payload = encode_packet_batch(&refs);
            if let Err(e) = mux_for_tun
                .send_datagram(&exit_peer, bifrost_core::mux::DATAGRAM_CHANNEL_EGRESS, &payload)
                .await
            {
                trace!("egress client: datagram send failed: {e}");
            }
        }
        warn!("egress client: tun reader exited");
    });

    // ── Auto-reconnect supervisor ────────────────────────────────────
    //
    // The two datagram pump tasks above are transport-agnostic: they
    // ride the long-lived mux datagram channel, which norn re-attaches
    // on its own once `dial()` re-establishes the peer link after a
    // drop (a Wi-Fi↔LTE roam, laptop sleep, a flaky uplink). What does
    // NOT survive a drop is the egress *control* stream and, with it,
    // the exit-side session + address lease: the exit stops routing
    // datagrams to a client whose `Open(Egress)` stream has reset.
    //
    // So this supervisor holds the control stream and, whenever it
    // dies, re-runs `client_handshake` to rebuild the exit-side
    // session. `client_handshake` itself waits (up to 60s) for the
    // peer to be reachable again, so it naturally rides out the
    // transport reconnect without us polling here. The address lease
    // is sticky by pub-key, so the host's already-configured TUN
    // address stays valid across the reconnect — verified below.
    tokio::spawn(async move {
        let mut mesh = mesh;
        let mut backoff = Duration::from_secs(1);
        loop {
            // Block until the current control stream dies. Both EOF
            // (exit released the lease) and reset (peer-reconnect
            // retired a stale stream) end the read here.
            drain_to_eof(&mut mesh).await;
            warn!("egress client: control stream down — rebuilding tunnel");

            match client_handshake(mux.clone(), exit_peer, &lease_policy).await {
                Ok((new_mesh, hello)) => {
                    if hello.allocated_v4 != lease_v4 {
                        // The host committed its TUN to `lease_v4` and
                        // cannot re-address it without a full restart.
                        // Sticky-by-pubkey leases should make this
                        // impossible; shout if the invariant breaks.
                        error!(
                            "egress client: exit re-leased {} but the TUN is pinned to \
                             {lease_v4} — traffic will black-hole until a restart",
                            hello.allocated_v4
                        );
                    } else {
                        info!(
                            "egress client: tunnel rebuilt — lease {lease_v4} still valid"
                        );
                    }
                    mesh = new_mesh;
                    backoff = Duration::from_secs(1);
                }
                Err(e) => {
                    warn!("egress client: tunnel rebuild failed: {e:#} — retry in {backoff:?}");
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    // `mesh` is still the dead stream; its `drain_to_eof`
                    // at the top of the loop returns at once, so we go
                    // straight back into another handshake attempt.
                }
            }
        }
    });

    Ok(())
}

/// Outcome of [`lease_lookup_or_allocate`].
#[cfg_attr(not(any(feature = "tun", test)), allow(dead_code))]
#[derive(Debug, Clone, Copy)]
pub(crate) struct Acquired {
    pub lease: Lease,
    /// Generation of the table entry this session joined.
    pub generation: u64,
    /// True if the peer already held this lease (sticky resume / a
    /// concurrent handshake), false if this call allocated it.
    pub was_sticky: bool,
    /// Peer whose idle lease was reclaimed to make room, if any.
    pub reclaimed: Option<(bifrost_core::PubKey, Lease)>,
}

/// Return `peer`'s existing lease (`was_sticky = true`) or allocate and
/// register a fresh one, as ONE atomic step, and count the caller as a live
/// session on it. A check-then-allocate split across two critical sections
/// let two concurrent `Open(Egress)` from the same peer both miss the lookup
/// and both allocate; the second `insert` overwrote the first, whose pool
/// slot then leaked forever.
///
/// Pool exhausted → reclaim the least-recently-active lease that has no live
/// session and whose peer is not in `connected()` (computed lazily, only when
/// needed). If every lease is in use the caller gets `None` and refuses.
///
/// Lock order is pool → table, matching the startup reseed; no await while
/// held. The lease store is NOT touched here — the caller persists a table
/// snapshot afterwards ([`persist_leases`]).
#[cfg_attr(not(any(feature = "tun", test)), allow(dead_code))]
fn lease_lookup_or_allocate(
    pool: &SharedPool,
    table: &SharedTable,
    peer: bifrost_core::PubKey,
    now: u64,
    connected: impl FnOnce() -> std::collections::HashSet<bifrost_core::PubKey>,
) -> Option<Acquired> {
    let mut p = pool.lock().unwrap();
    let mut t = table.lock().unwrap();
    if let Some((lease, generation)) = t.join(&peer, now) {
        return Some(Acquired { lease, generation, was_sticky: true, reclaimed: None });
    }
    let mut reclaimed = None;
    let lease = match p.allocate() {
        Some(l) => l,
        None => {
            let victim = t.reclaim_victim(&connected())?;
            let old = t.remove_peer(&victim).expect("victim is in the table");
            p.release(old);
            reclaimed = Some((victim, old));
            p.allocate().expect("a slot was just released")
        }
    };
    let generation = t.insert_with_activity(peer, lease, now);
    t.join(&peer, now);
    Some(Acquired { lease, generation, was_sticky: false, reclaimed })
}

/// A live egress session's hold on its lease. Dropping it ends the session
/// (refcount −1, `last_active` stamped) but keeps the lease sticky; call
/// [`rollback`](Self::rollback) instead when the handshake never completed.
/// The `Drop` path also covers a panicking / cancelled handshake task, so a
/// lease can't be left marked "live" (and thus unreclaimable) forever.
#[cfg_attr(not(any(feature = "tun", test)), allow(dead_code))]
pub(crate) struct LeaseSession {
    pool: SharedPool,
    table: SharedTable,
    peer: bifrost_core::PubKey,
    generation: u64,
    /// This session's handshake allocated the lease (vs. joined it).
    allocated: bool,
    done: bool,
}

/// What [`LeaseSession::rollback`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rollback {
    /// Lease freed: this handshake allocated it and nobody else uses it.
    Released(Lease),
    /// Another session (or a sticky prior owner) still holds the lease.
    Kept,
    /// The entry was evicted / reclaimed / re-allocated meanwhile.
    Stale,
}

#[cfg_attr(not(any(feature = "tun", test)), allow(dead_code))]
impl LeaseSession {
    pub(crate) fn new(pool: SharedPool, table: SharedTable, peer: bifrost_core::PubKey, acq: &Acquired) -> Self {
        Self { pool, table, peer, generation: acq.generation, allocated: !acq.was_sticky, done: false }
    }

    /// Handshake failed before the client got its lease. Drop this
    /// session's reference; free the lease only if this handshake created
    /// it AND no other session joined it meanwhile (generation-checked).
    pub(crate) fn rollback(mut self) -> Rollback {
        self.done = true;
        let mut p = self.pool.lock().unwrap();
        let mut t = self.table.lock().unwrap();
        let Some(e) = t.lease_by_peer.get_mut(&self.peer) else { return Rollback::Stale };
        if e.generation != self.generation {
            return Rollback::Stale;
        }
        e.sessions = e.sessions.saturating_sub(1);
        if self.allocated && e.sessions == 0 {
            let lease = t.remove_peer(&self.peer).expect("entry present");
            p.release(lease);
            Rollback::Released(lease)
        } else {
            Rollback::Kept
        }
    }

    /// Normal session end (control stream closed): the lease stays sticky.
    pub(crate) fn end(mut self) {
        self.end_inner();
    }

    fn end_inner(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        let mut t = self.table.lock().unwrap();
        if let Some(e) = t.lease_by_peer.get_mut(&self.peer)
            && e.generation == self.generation
        {
            e.sessions = e.sessions.saturating_sub(1);
            e.last_active = e.last_active.max(unix_now());
        }
    }
}

impl Drop for LeaseSession {
    fn drop(&mut self) {
        self.end_inner();
    }
}

/// Reseed pool + table from persisted `(peer, lease, last_active)` entries.
/// Entries outside the configured pool are dropped (operator changed
/// `pool_base`/`pool_prefix`), as are entries of peers the current admission
/// policy refuses — otherwise a key removed from `allowed_clients` would keep
/// its lease, and the datagram path forwards for any leased peer.
/// Returns `(reseeded, dropped_out_of_range, dropped_not_admitted)`.
#[cfg_attr(not(any(feature = "tun", test)), allow(dead_code))]
fn reseed_leases(
    pool: &SharedPool,
    table: &SharedTable,
    admission: &crate::admission::ExitAdmission,
    loaded: Vec<(bifrost_core::PubKey, Lease, u64)>,
) -> (usize, usize, usize) {
    let (mut reseeded, mut dropped, mut refused) = (0, 0, 0);
    let mut p = pool.lock().unwrap();
    let mut t = table.lock().unwrap();
    for (peer, lease, last_active) in loaded {
        if let Err(why) = admission.check(&peer) {
            warn!(
                "lease store: dropping {} (peer {}): {why}",
                lease.v4, hex::encode(&peer[..8])
            );
            refused += 1;
            continue;
        }
        match p.reserve(lease) {
            Ok(()) => {
                t.insert_with_activity(peer, lease, last_active);
                reseeded += 1;
            }
            Err(e) => {
                warn!(
                    "lease store: dropping {} (peer {}): {e}",
                    lease.v4, hex::encode(&peer[..8])
                );
                dropped += 1;
            }
        }
    }
    (reseeded, dropped, refused)
}

/// Mirror the table into the lease store and flush it. The store lock is
/// taken FIRST and held across the table snapshot so two concurrent savers
/// can't write their snapshots out of order (a stale file). Nothing else
/// nests these two locks in the opposite order.
#[cfg_attr(not(any(feature = "tun", test)), allow(dead_code))]
pub(crate) fn persist_leases(
    table: &SharedTable,
    store: &Mutex<crate::lease_store::LeaseStore>,
) -> Result<()> {
    let mut s = store.lock().unwrap();
    let snap = table.lock().unwrap().persist_snapshot();
    s.replace_all(snap);
    s.save()
}

/// Wait for the control stream to end, discarding anything the peer sends
/// on it. Reads through a fixed buffer — `read_to_end` into a `Vec` let a
/// peer stream unbounded data into our memory. Returns the discarded count.
async fn drain_to_eof<R: AsyncRead + Unpin>(r: &mut R) -> u64 {
    let mut buf = [0u8; 4096];
    let mut discarded = 0u64;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => return discarded,
            Ok(n) => discarded += n as u64,
        }
    }
}

/// Per-packet TUN write failure: log and drop, never end the pump (one bad
/// packet must not cut the tunnel for everyone). Warns on the 1st, 2nd, 4th,
/// 8th, … failure so a persistently broken device stays visible without a
/// log line per packet.
fn note_tun_write_error(role: &str, failures: &mut u64, e: &std::io::Error) {
    *failures += 1;
    if failures.is_power_of_two() {
        warn!("{role}: TUN write failed ({failures} so far), dropping packet: {e}");
    } else {
        trace!("{role}: TUN write failed, dropping packet: {e}");
    }
}

/// Parse one TUN read, look up the destination peer in the egress
/// table, and append the (vhdr+IP) bytes to that peer's coalesce
/// bucket. Used by the exit-side TUN reader; the client-side reader
/// has only one destination so it doesn't bucket.
#[cfg(feature = "tun")]
fn push_to_bucket(
    table: &SharedTable,
    buckets: &mut std::collections::HashMap<bifrost_core::PubKey, Vec<Vec<u8>>>,
    total_bytes: &mut usize,
    raw: &[u8],
) {
    let Some(slot) = extract_routable(raw) else { return; };
    let ip = match ip_part(slot) { Some(p) => p, None => return };
    let dst: IpAddr = if ip[0] >> 4 == 4 && ip.len() >= 20 {
        Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]).into()
    } else if ip[0] >> 4 == 6 && ip.len() >= 40 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&ip[24..40]);
        Ipv6Addr::from(octets).into()
    } else {
        return;
    };
    let Some(peer) = table.lock().unwrap().peer_for_ip(&dst) else {
        trace!("egress exit: drop packet to unknown peer {dst}");
        return;
    };
    *total_bytes += slot.len() + 2;
    buckets.entry(peer).or_default().push(slot.to_vec());
}

/// Split a wire-format slot `[virtio_net_hdr | ip_packet]` into the
/// IP-only tail. Returns None if the slot can't hold a vhdr — the
/// caller should drop it.
fn ip_part(slot: &[u8]) -> Option<&[u8]> {
    if slot.len() < crate::tun_offload::VIRTIO_NET_HDR_LEN {
        return None;
    }
    Some(&slot[crate::tun_offload::VIRTIO_NET_HDR_LEN..])
}

/// Filter a raw TUN read for forwarding. Inputs always start with
/// the kernel's 10-byte `virtio_net_hdr`; we hand the IP part to
/// the routability check and, on a pass, return the FULL `[vhdr |
/// IP]` slot so the receiver can write it back to its own TUN
/// verbatim (preserving `gso_type` for TSO/USO segmentation).
fn extract_routable(buf: &[u8]) -> Option<&[u8]> {
    let ip = ip_part(buf)?;
    if ip.is_empty() {
        return None;
    }
    let version_nibble = ip[0] >> 4;
    if !is_routable_dst(version_nibble, ip) {
        return None;
    }
    Some(buf)
}

/// Anti-spoof check for one slot's IP bytes against the sender's lease.
///
/// Returns true (= drop) for anything we cannot positively validate as
/// belonging to `lease`: a source address that doesn't match, an unknown IP
/// version, or a packet too short to hold the source field. **Fail-closed.**
///
/// `ip` may be empty (a vhdr-only slot yields a zero-length IP part); we use
/// `ip.first()` rather than `ip[0]` so a hostile short packet is dropped, not
/// a panic.
fn src_is_spoofed(ip: &[u8], lease: &Lease) -> bool {
    match ip.first().map(|b| b >> 4) {
        Some(4) if ip.len() >= 20 => Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]) != lease.v4,
        Some(6) if ip.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&ip[8..24]);
            Some(Ipv6Addr::from(octets)) != lease.v6
        }
        _ => true,
    }
}

/// True if the packet's destination address is sensible to forward
/// across the egress tunnel. Filters out multicast, link-local, and
/// loopback — those belong on the local link and would be dropped
/// (noisily) on the exit side anyway. `pkt` is the **IP** slice
/// (caller has already stripped the vhdr via [`ip_part`]).
fn is_routable_dst(version_nibble: u8, pkt: &[u8]) -> bool {
    match version_nibble {
        4 if pkt.len() >= 20 => {
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            !(dst.is_multicast() || dst.is_loopback() || dst.is_link_local() || dst.is_broadcast())
        }
        6 if pkt.len() >= 40 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[24..40]);
            let dst = Ipv6Addr::from(octets);
            !(dst.is_multicast()
                || dst.is_loopback()
                // is_unicast_link_local() is unstable; manual check.
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80))
        }
        _ => false,
    }
}

#[cfg(not(feature = "tun"))]
#[allow(clippy::too_many_arguments)] // mirrors the real `start_exit` signature so callers don't branch
pub async fn start_exit(
    _mux: Arc<MeshMux>,
    _accept_rx: mpsc::Receiver<AcceptedStream>,
    _tun_name: String,
    _v4_pool_base: Ipv4Addr,
    _v4_pool_prefix: u8,
    _v6_pool_base: Option<Ipv6Addr>,
    _v6_pool_prefix: u8,
    _egress_iface: String,
    _lease_persistence_path: String,
    _admin_socket: String,
    _dst_filter: Arc<crate::dst_filter::DstFilter>,
    _admission: Arc<crate::admission::ExitAdmission>,
) -> Result<()> {
    anyhow::bail!("egress exit requires the `tun` feature (rebuild with --features tun)")
}

#[cfg(not(feature = "tun"))]
pub async fn start_client(
    _mux: Arc<MeshMux>,
    _exit_peer: [u8; 32],
    _tun_name: String,
    _install_default_route: bool,
    _admin_socket: String,
    _lease_policy: LeasePolicy,
) -> Result<()> {
    anyhow::bail!("egress client requires the `tun` feature (rebuild with --features tun)")
}

// Silence dead-code warnings on no-tun builds — the kernel helpers
// are used only by the cfg(feature = "tun") paths.
#[cfg(not(feature = "tun"))]
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = (
        configure_exit_kernel
            as fn(&str, Ipv4Addr, u8, Option<Ipv6Addr>, u8, &str) -> Result<()>,
        configure_client_kernel
            as fn(&str, Ipv4Addr, u8, Ipv4Addr,
                  Option<Ipv6Addr>, u8, Option<Ipv6Addr>, bool) -> Result<()>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn v6(s: &str) -> Ipv6Addr { s.parse().unwrap() }

    /// Concurrent `Open(Egress)` from one peer must share ONE lease: the old
    /// check-then-allocate split let both handshakes allocate and leak a slot.
    #[test]
    fn lease_lookup_or_allocate_is_atomic_per_peer() {
        let pool: SharedPool = Arc::new(Mutex::new(
            AddressPool::new(Ipv4Addr::new(10, 55, 0, 0), 24, None, 0).unwrap(),
        ));
        let table: SharedTable = Arc::new(Mutex::new(EgressTable::default()));
        let peer = [0x5a; 32];
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let handles: Vec<_> = (0..16)
            .map(|_| {
                let (pool, table, barrier) = (pool.clone(), table.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let a = lease_lookup_or_allocate(&pool, &table, peer, 1, Default::default)
                        .unwrap();
                    (a.lease, a.was_sticky)
                })
            })
            .collect();
        let results: Vec<(Lease, bool)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let first = results[0].0;
        assert!(results.iter().all(|(l, _)| *l == first), "every racer sees the same lease");
        assert_eq!(results.iter().filter(|(_, sticky)| !sticky).count(), 1, "exactly one allocation");
        // Exactly one pool slot consumed: the next allocation is the slot after it.
        let next = pool.lock().unwrap().allocate().unwrap();
        assert_eq!(u32::from(next.v4), u32::from(first.v4) + 1, "no leaked slot");
        assert_eq!(table.lock().unwrap().sessions_of(&peer), 16, "every racer is a live session");
    }

    // ── Lease reclamation / session lifecycle ───────────────────────

    type Connected = std::collections::HashSet<bifrost_core::PubKey>;

    /// /29 → 5 usable client slots (.2–.6).
    fn small_pool() -> (SharedPool, SharedTable) {
        (
            Arc::new(Mutex::new(AddressPool::new(Ipv4Addr::new(10, 55, 0, 0), 29, None, 0).unwrap())),
            Arc::new(Mutex::new(EgressTable::default())),
        )
    }

    fn key(b: u8) -> bifrost_core::PubKey { [b; 32] }

    /// Fill the /29 with five peers whose sessions have ENDED at
    /// last_active = 100 + i (so key(1) is the least recently active).
    fn fill_idle(pool: &SharedPool, table: &SharedTable) {
        for i in 1..=5u8 {
            let a = lease_lookup_or_allocate(pool, table, key(i), 100 + i as u64, Connected::new)
                .unwrap();
            let mut t = table.lock().unwrap();
            let e = t.lease_by_peer.get_mut(&key(i)).unwrap();
            assert_eq!(e.generation, a.generation);
            e.sessions = 0;
        }
    }

    /// Regression (sybil pool exhaustion): `allocate()` returned None when
    /// full, so ~253 throwaway keys locked out every future client. A full
    /// pool must reclaim the least-recently-active idle lease.
    #[test]
    fn full_pool_reclaims_least_recently_active_idle_lease() {
        let (pool, table) = small_pool();
        fill_idle(&pool, &table);
        let victim_lease = table.lock().unwrap().lease_of(&key(1)).unwrap();
        let a = lease_lookup_or_allocate(&pool, &table, key(9), 500, Connected::new)
            .expect("full pool of idle leases must reclaim, not refuse");
        assert_eq!(a.reclaimed, Some((key(1), victim_lease)), "oldest idle lease reclaimed");
        assert_eq!(a.lease, victim_lease, "newcomer gets the freed slot");
        let t = table.lock().unwrap();
        assert!(t.lease_of(&key(1)).is_none());
        assert_eq!(t.peer_for_ip(&IpAddr::V4(victim_lease.v4)), Some(key(9)));
    }

    /// Never reclaim a lease with a live session or whose peer is currently
    /// connected; with every lease in use the newcomer is refused.
    #[test]
    fn reclamation_never_takes_a_live_or_connected_lease() {
        let (pool, table) = small_pool();
        fill_idle(&pool, &table);
        // key(1) (oldest) has a live session again; key(2) is connected at
        // the transport layer → the victim must be key(3).
        table.lock().unwrap().join(&key(1), 50);
        // join() bumps last_active to max(old, now) = old, so key(1) stays oldest.
        let connected = || Connected::from([key(2)]);
        let a = lease_lookup_or_allocate(&pool, &table, key(9), 500, connected).unwrap();
        assert_eq!(a.reclaimed.map(|(p, _)| p), Some(key(3)));

        // Now make everything live: refuse rather than evict an active client.
        for i in [2u8, 4, 5] {
            table.lock().unwrap().join(&key(i), 600);
        }
        assert!(
            lease_lookup_or_allocate(&pool, &table, key(10), 700, Connected::new).is_none(),
            "all leases live → refuse the newcomer"
        );
        for i in [1u8, 2, 4, 5, 9] {
            assert!(table.lock().unwrap().lease_of(&key(i)).is_some(), "live lease {i} kept");
        }
    }

    /// Regression (rollback race): two handshakes from one peer overlap and
    /// the first (the allocator) fails. Its rollback used to free the lease
    /// the second handshake was still using.
    #[test]
    fn rollback_does_not_free_a_lease_another_session_uses() {
        let (pool, table) = small_pool();
        let peer = key(7);
        let a = lease_lookup_or_allocate(&pool, &table, peer, 1, Connected::new).unwrap();
        let b = lease_lookup_or_allocate(&pool, &table, peer, 1, Connected::new).unwrap();
        assert!(!a.was_sticky && b.was_sticky && a.lease == b.lease);
        let sa = LeaseSession::new(pool.clone(), table.clone(), peer, &a);
        let sb = LeaseSession::new(pool.clone(), table.clone(), peer, &b);

        assert_eq!(sa.rollback(), Rollback::Kept, "B still uses it");
        assert_eq!(table.lock().unwrap().lease_of(&peer), Some(a.lease), "lease survives");
        assert_eq!(table.lock().unwrap().sessions_of(&peer), 1);
        // The slot is still taken: a different peer must not get it.
        let other = lease_lookup_or_allocate(&pool, &table, key(8), 1, Connected::new).unwrap();
        assert_ne!(other.lease, a.lease, "in-use slot must not be handed out again");

        sb.end();
        assert_eq!(table.lock().unwrap().sessions_of(&peer), 0);
        assert_eq!(table.lock().unwrap().lease_of(&peer), Some(a.lease), "sticky after end");
    }

    /// A sole allocating handshake that fails does free its fresh lease.
    #[test]
    fn rollback_of_sole_new_session_releases_the_slot() {
        let (pool, table) = small_pool();
        let a = lease_lookup_or_allocate(&pool, &table, key(7), 1, Connected::new).unwrap();
        let s = LeaseSession::new(pool.clone(), table.clone(), key(7), &a);
        assert_eq!(s.rollback(), Rollback::Released(a.lease));
        assert!(table.lock().unwrap().lease_of(&key(7)).is_none());
        let next = pool.lock().unwrap().allocate().unwrap();
        assert_eq!(next, a.lease, "slot returned to the pool");
    }

    /// A stale session (its entry was evicted and re-allocated meanwhile)
    /// must not touch the new entry — generation check.
    #[test]
    fn stale_session_end_and_rollback_are_noops() {
        let (pool, table) = small_pool();
        let peer = key(7);
        let a = lease_lookup_or_allocate(&pool, &table, peer, 1, Connected::new).unwrap();
        let old = LeaseSession::new(pool.clone(), table.clone(), peer, &a);
        // Operator evicts; the peer reconnects and gets a new entry.
        {
            let mut p = pool.lock().unwrap();
            let l = table.lock().unwrap().remove_peer(&peer).unwrap();
            p.release(l);
        }
        let b = lease_lookup_or_allocate(&pool, &table, peer, 2, Connected::new).unwrap();
        assert_ne!(a.generation, b.generation);
        assert_eq!(old.rollback(), Rollback::Stale);
        assert_eq!(table.lock().unwrap().lease_of(&peer), Some(b.lease));
        assert_eq!(table.lock().unwrap().sessions_of(&peer), 1, "new session untouched");
    }

    /// Dropping a session without end()/rollback() (task cancelled /
    /// panicked) still releases its live-session count, so the lease can't
    /// stay unreclaimable forever.
    #[test]
    fn dropped_session_ends_itself() {
        let (pool, table) = small_pool();
        let a = lease_lookup_or_allocate(&pool, &table, key(7), 1, Connected::new).unwrap();
        drop(LeaseSession::new(pool.clone(), table.clone(), key(7), &a));
        assert_eq!(table.lock().unwrap().sessions_of(&key(7)), 0);
        assert!(table.lock().unwrap().last_active_of(&key(7)).unwrap() > 1, "stamped now");
    }

    /// last_active survives an exit restart via the lease store, so the
    /// reclamation order is preserved; reseed also drops leases of peers
    /// the (new) admission policy refuses.
    #[test]
    fn reclamation_order_and_admission_survive_restart() {
        let dir = std::env::temp_dir().join(format!(
            "bifrost-egress-reclaim-{}-{:?}", std::process::id(), std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("leases.json");
        let store = Mutex::new(crate::lease_store::LeaseStore::new(&path));
        {
            let (pool, table) = small_pool();
            fill_idle(&pool, &table);
            persist_leases(&table, &store).unwrap();
        }
        // "Restart": fresh pool/table from disk. key(5) is no longer allowed.
        let allowed: Vec<String> = (1..=4u8).chain([9]).map(|i| hex::encode(key(i))).collect();
        let admission = crate::admission::ExitAdmission::new(&allowed, 0).unwrap();
        let (pool, table) = small_pool();
        let loaded = crate::lease_store::load_with_warn(&path);
        assert_eq!(loaded.len(), 5);
        let (reseeded, dropped, refused) = reseed_leases(&pool, &table, &admission, loaded);
        assert_eq!((reseeded, dropped, refused), (4, 0, 1));
        assert!(table.lock().unwrap().lease_of(&key(5)).is_none(), "non-admitted lease dropped");
        assert_eq!(table.lock().unwrap().last_active_of(&key(1)), Some(101));
        // key(5)'s slot is free again; take it, then the pool is full and the
        // next newcomer must reclaim key(1) — the oldest by persisted stamp.
        let a = lease_lookup_or_allocate(&pool, &table, key(9), 900, Connected::new).unwrap();
        assert!(a.reclaimed.is_none());
        let b = lease_lookup_or_allocate(&pool, &table, key(10), 901, Connected::new).unwrap();
        assert_eq!(b.reclaimed.map(|(p, _)| p), Some(key(1)));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The control-stream drain must not buffer what the peer sends.
    #[tokio::test]
    async fn drain_to_eof_discards_without_buffering() {
        let (mut a, mut b) = duplex(1024);
        let writer = tokio::spawn(async move {
            let chunk = [0xabu8; 1000];
            for _ in 0..4096 {
                a.write_all(&chunk).await.unwrap();
            }
            // dropping `a` delivers EOF
        });
        assert_eq!(drain_to_eof(&mut b).await, 4096 * 1000);
        writer.await.unwrap();
    }

    #[test]
    fn antispoof_drops_vhdr_only_slot_without_panic() {
        // Regression: a 10-byte slot (vhdr only, zero IP bytes) reaches the
        // exit ingress loop as `Some(&[])` from `ip_part`. The old code did
        // `ip[0] >> 4` and panicked — under panic=abort that kills the exit
        // and drops every client, and any leased peer could trigger it.
        let lease = Lease { v4: Ipv4Addr::new(10, 55, 0, 2), v6: None };
        let slot = [0u8; crate::tun_offload::VIRTIO_NET_HDR_LEN];
        let ip = ip_part(&slot).expect("10-byte slot has a (zero-length) ip part");
        assert!(ip.is_empty(), "vhdr-only slot has empty IP part");
        assert!(src_is_spoofed(ip, &lease), "empty IP must fail closed (drop)");
    }

    #[test]
    fn antispoof_accepts_matching_src_rejects_mismatch_and_truncation() {
        let lease = Lease { v4: Ipv4Addr::new(10, 55, 0, 7), v6: None };
        // Minimal 20-byte IPv4 header; src at [12..16], dst at [16..20].
        let mut ip: [u8; 20] = [
            0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            10, 55, 0, 7, // src == lease.v4
            8, 8, 8, 8,   // dst
        ];
        assert!(!src_is_spoofed(&ip, &lease), "matching src must pass");
        ip[15] = 9; // src → 10.55.0.9, no longer the leased address
        assert!(src_is_spoofed(&ip, &lease), "mismatched src must be dropped");
        assert!(src_is_spoofed(&ip[..19], &lease), "short IPv4 must fail closed");
    }

    // ── Length-prefix framing round-trips ───────────────────────────

    #[tokio::test]
    async fn framed_single_packet_roundtrip() {
        let (mut a, mut b) = duplex(64 * 1024);
        let pkt = (0..1400u16).map(|i| i as u8).collect::<Vec<_>>();
        write_framed(&mut a, &pkt).await.unwrap();
        a.shutdown().await.unwrap();
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        let n = read_framed(&mut b, &mut buf).await.unwrap().unwrap();
        assert_eq!(n, pkt.len());
        assert_eq!(&buf[..n], &pkt[..]);
        // Next read should report graceful EOF.
        let eof = read_framed(&mut b, &mut buf).await.unwrap();
        assert!(eof.is_none(), "expected None at EOF, got {eof:?}");
    }

    #[tokio::test]
    async fn framed_split_writes_dont_split_packets() {
        // Mesh streams may chunk reads across packet boundaries —
        // this is the exact failure mode that capped vpnd at
        // 0.9 Mbit/s before framing. We simulate it here by writing
        // three packets back-to-back, then reading them through a
        // duplex pipe that batches in arbitrary chunks.
        let (mut a, mut b) = duplex(8);
        let packets = vec![
            vec![0x45u8; 60],
            vec![0x46u8; 1400],
            vec![0x47u8; 200],
        ];
        let pkts_clone = packets.clone();
        let w = tokio::spawn(async move {
            for p in &pkts_clone {
                write_framed(&mut a, p).await.unwrap();
            }
            a.shutdown().await.unwrap();
        });
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        for expected in &packets {
            let n = read_framed(&mut b, &mut buf).await.unwrap().unwrap();
            assert_eq!(n, expected.len());
            assert_eq!(&buf[..n], &expected[..]);
        }
        assert!(read_framed(&mut b, &mut buf).await.unwrap().is_none());
        w.await.unwrap();
    }

    #[tokio::test]
    async fn framed_rejects_oversized_length_header() {
        let (mut a, mut b) = duplex(64 * 1024);
        // Write a header claiming a packet larger than MAX_RELAYED_PACKET.
        let claim = (MAX_RELAYED_PACKET as u32 + 1) as u16;
        a.write_all(&claim.to_be_bytes()).await.unwrap();
        a.shutdown().await.unwrap();
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        let err = read_framed(&mut b, &mut buf).await
            .expect_err("oversized header must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn framed_torn_header_is_an_error() {
        let (mut a, mut b) = duplex(64 * 1024);
        // Send exactly one byte of the 2-byte length header, then close.
        a.write_all(&[0x05]).await.unwrap();
        a.shutdown().await.unwrap();
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        let err = read_framed(&mut b, &mut buf).await
            .expect_err("torn header must be flagged, not silently EOF");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn framed_rejects_zero_length_packet() {
        let (mut a, mut b) = duplex(64 * 1024);
        a.write_all(&0u16.to_be_bytes()).await.unwrap();
        a.shutdown().await.unwrap();
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        let err = read_framed(&mut b, &mut buf).await
            .expect_err("len=0 frames must be rejected");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn egress_hello_v4_only_roundtrip() {
        let h = EgressHello {
            allocated_v4: Ipv4Addr::new(10, 55, 0, 17),
            gateway_v4: Ipv4Addr::new(10, 55, 0, 1),
            v4_prefix: 24,
            allocated_v6: None,
            gateway_v6: None,
            v6_prefix: 0,
            mtu: 1408,
            capabilities: EGRESS_CAP_VNET_HDR,
        };
        let back = EgressHello::decode(&h.encode()).unwrap();
        assert_eq!(back.allocated_v4, h.allocated_v4);
        assert_eq!(back.gateway_v4, h.gateway_v4);
        assert_eq!(back.v4_prefix, h.v4_prefix);
        assert!(back.allocated_v6.is_none(), "v6_present=0 → None");
        assert_eq!(back.mtu, 1408);
        assert_eq!(back.capabilities & EGRESS_CAP_VNET_HDR, EGRESS_CAP_VNET_HDR);
    }

    #[test]
    fn egress_hello_dual_stack_roundtrip() {
        let h = EgressHello {
            allocated_v4: Ipv4Addr::new(10, 55, 0, 42),
            gateway_v4: Ipv4Addr::new(10, 55, 0, 1),
            v4_prefix: 24,
            allocated_v6: Some(v6("fd55:0:0:1::2a")),
            gateway_v6: Some(v6("fd55:0:0:1::1")),
            v6_prefix: 64,
            mtu: 1408,
            capabilities: EGRESS_CAP_VNET_HDR,
        };
        let back = EgressHello::decode(&h.encode()).unwrap();
        assert_eq!(back.allocated_v6, h.allocated_v6);
        assert_eq!(back.gateway_v6, h.gateway_v6);
        assert_eq!(back.v6_prefix, 64);
        assert_eq!(back.capabilities, h.capabilities);
    }

    #[test]
    fn egress_hello_rejects_bad_magic() {
        let mut bytes = EgressHello {
            allocated_v4: Ipv4Addr::new(0, 0, 0, 0),
            gateway_v4: Ipv4Addr::new(0, 0, 0, 0),
            v4_prefix: 24,
            allocated_v6: None,
            gateway_v6: None,
            v6_prefix: 0,
            mtu: 1400,
            capabilities: 0,
        }
        .encode();
        bytes[0] = b'X';
        assert!(EgressHello::decode(&bytes).is_err());
    }

    #[test]
    fn egress_hello_validate_rejects_bogus_exit_values() {
        let good = EgressHello {
            allocated_v4: Ipv4Addr::new(10, 55, 0, 2),
            gateway_v4: Ipv4Addr::new(10, 55, 0, 1),
            v4_prefix: 24,
            allocated_v6: None,
            gateway_v6: None,
            v6_prefix: 0,
            mtu: 1392,
            capabilities: 0,
        };
        let strict = LeasePolicy::default();
        assert!(good.validate(&strict).is_ok(), "a normal exit hello must validate");
        // Out-of-range v4 prefix — the subnet_v4_cidr_str shift hazard.
        let mut bad = good;
        bad.v4_prefix = 200;
        assert!(bad.validate(&strict).is_err(), "v4 prefix > 32 must be rejected");
        // Bogus allocated address.
        let mut bad = good;
        bad.allocated_v4 = Ipv4Addr::UNSPECIFIED;
        assert!(bad.validate(&strict).is_err(), "0.0.0.0 lease must be rejected");
        // Degenerate MTU.
        let mut bad = good;
        bad.mtu = 0;
        assert!(bad.validate(&strict).is_err(), "mtu 0 must be rejected");
    }

    /// Regression (route hijack): a malicious exit could announce a lease in
    /// public space and/or a gateway in another subnet, and the client would
    /// `ip route replace <subnet>/16 dev tun`, capturing e.g. 8.8.0.0/16.
    #[test]
    fn egress_hello_validate_blocks_route_hijack() {
        let good = EgressHello {
            allocated_v4: Ipv4Addr::new(10, 55, 0, 2),
            gateway_v4: Ipv4Addr::new(10, 55, 0, 1),
            v4_prefix: 24,
            allocated_v6: Some(v6("fd55:0:0:1::2")),
            gateway_v6: Some(v6("fd55:0:0:1::1")),
            v6_prefix: 64,
            mtu: 1392,
            capabilities: 0,
        };
        let strict = LeasePolicy::default();
        assert!(good.validate(&strict).is_ok());

        // Public lease subnet (8.8.0.0/16) — the hijack.
        let mut bad = good;
        bad.allocated_v4 = Ipv4Addr::new(8, 8, 4, 4);
        bad.gateway_v4 = Ipv4Addr::new(8, 8, 0, 1);
        bad.v4_prefix = 16;
        assert!(bad.validate(&strict).is_err(), "public lease subnet must be refused");
        // …unless the client explicitly allows that CIDR.
        let allow = LeasePolicy::new(&["8.8.0.0/16".into()]).unwrap();
        assert!(bad.validate(&allow).is_ok());
        // An allowed CIDR must cover the WHOLE subnet, not just the address.
        let narrow = LeasePolicy::new(&["8.8.4.0/24".into()]).unwrap();
        assert!(bad.validate(&narrow).is_err());

        // Gateway outside the lease subnet.
        let mut bad = good;
        bad.gateway_v4 = Ipv4Addr::new(10, 56, 0, 1);
        assert!(bad.validate(&strict).is_err(), "gateway must share the lease subnet");
        // A /16 that straddles out of 172.16/12 is refused; one inside is fine.
        let mut bad = good;
        bad.allocated_v4 = Ipv4Addr::new(172, 32, 0, 2);
        bad.gateway_v4 = Ipv4Addr::new(172, 32, 0, 1);
        bad.v4_prefix = 16;
        assert!(bad.validate(&strict).is_err(), "172.32/16 is not RFC1918");
        let mut ok = bad;
        ok.allocated_v4 = Ipv4Addr::new(172, 31, 0, 2);
        ok.gateway_v4 = Ipv4Addr::new(172, 31, 0, 1);
        assert!(ok.validate(&strict).is_ok());
        // CGNAT is allowed by default.
        let mut ok = good;
        ok.allocated_v4 = Ipv4Addr::new(100, 64, 7, 2);
        ok.gateway_v4 = Ipv4Addr::new(100, 64, 7, 1);
        assert!(ok.validate(&strict).is_ok());
        // Gateway == lease, or lease on the network address.
        let mut bad = good;
        bad.gateway_v4 = bad.allocated_v4;
        assert!(bad.validate(&strict).is_err());
        let mut bad = good;
        bad.allocated_v4 = Ipv4Addr::new(10, 55, 0, 0);
        assert!(bad.validate(&strict).is_err());

        // v6: non-ULA subnet, gateway in another subnet, missing gateway.
        let mut bad = good;
        bad.allocated_v6 = Some(v6("2001:db8::2"));
        bad.gateway_v6 = Some(v6("2001:db8::1"));
        assert!(bad.validate(&strict).is_err(), "global v6 lease must be refused");
        let mut bad = good;
        bad.gateway_v6 = Some(v6("fd55:0:0:2::1"));
        assert!(bad.validate(&strict).is_err(), "v6 gateway must share the subnet");
        let mut bad = good;
        bad.gateway_v6 = None;
        assert!(bad.validate(&strict).is_err());
        assert!(LeasePolicy::new(&["not-a-cidr".into()]).is_err());
    }

    #[test]
    fn address_pool_v4_only_sequence() {
        let mut pool = AddressPool::new(Ipv4Addr::new(10, 55, 0, 0), 24, None, 0).unwrap();
        assert_eq!(pool.gateway_v4(), Ipv4Addr::new(10, 55, 0, 1));
        assert!(!pool.dual_stack());
        let a = pool.allocate().unwrap();
        assert_eq!(a.v4, Ipv4Addr::new(10, 55, 0, 2));
        assert!(a.v6.is_none());
        let b = pool.allocate().unwrap();
        assert_eq!(b.v4, Ipv4Addr::new(10, 55, 0, 3));
        pool.release(a);
        let c = pool.allocate().unwrap();
        assert_eq!(c.v4, Ipv4Addr::new(10, 55, 0, 2), "released slot reused");
    }

    #[test]
    fn address_pool_dual_stack_pairs_host_indices() {
        let mut pool = AddressPool::new(
            Ipv4Addr::new(10, 55, 0, 0), 24,
            Some(v6("fd55:0:0:1::")), 64,
        ).unwrap();
        assert!(pool.dual_stack());
        assert_eq!(pool.gateway_v4(), Ipv4Addr::new(10, 55, 0, 1));
        assert_eq!(pool.gateway_v6(), Some(v6("fd55:0:0:1::1")));
        let a = pool.allocate().unwrap();
        assert_eq!(a.v4, Ipv4Addr::new(10, 55, 0, 2));
        assert_eq!(a.v6, Some(v6("fd55:0:0:1::2")), "host index 2 in both stacks");
        let b = pool.allocate().unwrap();
        assert_eq!(b.v4, Ipv4Addr::new(10, 55, 0, 3));
        assert_eq!(b.v6, Some(v6("fd55:0:0:1::3")));
    }

    #[test]
    fn address_pool_skips_broadcast_and_gateway() {
        let mut pool = AddressPool::new(Ipv4Addr::new(192, 168, 0, 0), 30, None, 0).unwrap();
        let a = pool.allocate().unwrap();
        assert_eq!(a.v4, Ipv4Addr::new(192, 168, 0, 2));
        assert!(pool.allocate().is_none(), "no more usable hosts");
    }

    #[test]
    fn address_pool_rejects_bad_prefixes() {
        // v4 outside [16,30]
        assert!(AddressPool::new(Ipv4Addr::new(10, 0, 0, 0), 31, None, 0).is_err());
        // v6 outside [64,126]
        assert!(AddressPool::new(
            Ipv4Addr::new(10, 0, 0, 0), 24,
            Some(v6("fd55::")), 32
        ).is_err());
    }

    #[test]
    fn subnet_v4_cidr_correctly_masks() {
        assert_eq!(subnet_v4_cidr_str(Ipv4Addr::new(10, 55, 0, 17), 24), "10.55.0.0/24");
        assert_eq!(subnet_v4_cidr_str(Ipv4Addr::new(192, 168, 5, 5), 16), "192.168.0.0/16");
    }

    #[test]
    fn subnet_v6_cidr_correctly_masks() {
        assert_eq!(subnet_v6_cidr_str(v6("fd55:0:0:1::5"), 64), "fd55:0:0:1::/64");
        assert_eq!(subnet_v6_cidr_str(v6("fd55:0:0:1::5"), 48), "fd55::/48");
    }

    // ── Packet-batch encode / decode round-trips ────────────────────

    #[test]
    fn packet_batch_single_packet_roundtrip() {
        let pkt: Vec<u8> = (0..1400).map(|i| i as u8).collect();
        let payload = encode_packet_batch(&[&pkt]);
        let mut iter = PacketBatchIter::new(&payload);
        let got = iter.next().expect("one packet");
        assert_eq!(got, &pkt[..]);
        assert!(iter.next().is_none(), "iterator should be exhausted");
    }

    #[test]
    fn packet_batch_many_packets_roundtrip() {
        // Mixed-size batch — covers the typical TCP-burst shape.
        let pkts: Vec<Vec<u8>> = vec![
            vec![0x45u8; 60],   // small ACK
            vec![0x46u8; 1400], // full segment
            vec![0x47u8; 532],  // mid-size
            vec![0x48u8; 1500], // close to MTU
        ];
        let refs: Vec<&[u8]> = pkts.iter().map(|v| v.as_slice()).collect();
        let payload = encode_packet_batch(&refs);
        // Decode and compare in order.
        let decoded: Vec<&[u8]> = PacketBatchIter::new(&payload).collect();
        assert_eq!(decoded.len(), pkts.len());
        for (got, want) in decoded.iter().zip(pkts.iter()) {
            assert_eq!(*got, &want[..]);
        }
    }

    #[test]
    fn packet_batch_iter_stops_on_truncated_tail() {
        // Encode 3 packets, then chop off the last byte so the
        // third can't be fully recovered. Iterator must yield the
        // first 2 cleanly and stop — not panic, not return a
        // malformed slice.
        let pkts = [vec![1u8; 100], vec![2u8; 200], vec![3u8; 300]];
        let refs: Vec<&[u8]> = pkts.iter().map(|v| v.as_slice()).collect();
        let mut payload = encode_packet_batch(&refs);
        payload.truncate(payload.len() - 1);
        let decoded: Vec<&[u8]> = PacketBatchIter::new(&payload).collect();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0], &pkts[0][..]);
        assert_eq!(decoded[1], &pkts[1][..]);
    }

    #[test]
    fn packet_batch_iter_rejects_oversized_packet() {
        // Hand-craft a payload whose declared length is larger than
        // MAX_RELAYED_PACKET — iterator must stop.
        let mut payload = vec![1u8]; // count=1
        let huge_len = (MAX_RELAYED_PACKET as u32 + 1) as u16;
        payload.extend_from_slice(&huge_len.to_be_bytes());
        payload.extend_from_slice(&vec![0u8; 1000]);
        let decoded: Vec<&[u8]> = PacketBatchIter::new(&payload).collect();
        assert!(decoded.is_empty(),
            "iterator should reject oversized length, got {decoded:?}");
    }

    #[test]
    fn packet_batch_iter_rejects_empty_payload() {
        let mut iter = PacketBatchIter::new(&[]);
        assert!(iter.next().is_none());
    }
}
