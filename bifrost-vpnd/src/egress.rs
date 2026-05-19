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
    frame::OpenTarget,
    mux::{AcceptedStream, MeshMux},
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, trace, warn};

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
/// Two maps so each direction is one O(1) lookup. They are kept in
/// sync by `handle_egress_handshake` and never go stale because the
/// same handshake task that registers also owns the cleanup on stream
/// close. A dual-stack lease registers two `peer_by_ip` entries
/// (one per family) so packets in either direction route correctly.
#[derive(Default)]
pub struct EgressTable {
    /// allocated IP → owning peer
    peer_by_ip: std::collections::HashMap<IpAddr, bifrost_core::PubKey>,
    /// peer → its allocated lease (for src-spoofing validation)
    lease_by_peer: std::collections::HashMap<bifrost_core::PubKey, Lease>,
}

impl EgressTable {
    pub fn insert(&mut self, peer: bifrost_core::PubKey, lease: Lease) {
        self.peer_by_ip.insert(IpAddr::V4(lease.v4), peer);
        if let Some(v6) = lease.v6 {
            self.peer_by_ip.insert(IpAddr::V6(v6), peer);
        }
        self.lease_by_peer.insert(peer, lease);
    }

    pub fn remove_peer(&mut self, peer: &bifrost_core::PubKey) -> Option<Lease> {
        let lease = self.lease_by_peer.remove(peer)?;
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
        self.lease_by_peer.get(peer).copied()
    }

    /// All `(peer, lease)` pairs currently in the table — used by
    /// the admin layer for the `Leases` endpoint.
    pub fn snapshot(&self) -> Vec<(bifrost_core::PubKey, Lease)> {
        self.lease_by_peer.iter().map(|(p, l)| (*p, *l)).collect()
    }
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
    let v4_cidr = format!("{}/{}", v4_addr, v4_prefix);
    let v4_subnet = subnet_v4_cidr_str(gateway_v4, v4_prefix);
    run_cmd("ip", &["link", "set", tun_name, "up"])?;
    let _ = Command::new("ip").args(["addr", "add", &v4_cidr, "dev", tun_name]).status();
    let _ = Command::new("ip").args(["route", "replace", &v4_subnet, "dev", tun_name]).status();

    if let (Some(v6), Some(gw6)) = (v6_addr, gateway_v6) {
        let v6_cidr = format!("{}/{}", v6, v6_prefix);
        let v6_subnet = subnet_v6_cidr_str(gw6, v6_prefix);
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
) -> Result<()> {
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
        let mut reseeded = 0usize;
        let mut dropped  = 0usize;
        {
            let mut p = pool.lock().unwrap();
            let mut t = table.lock().unwrap();
            let mut s = lease_store.lock().unwrap();
            for (peer, lease) in loaded {
                match p.reserve(lease) {
                    Ok(()) => {
                        t.insert(peer, lease);
                        s.insert(peer, lease);
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
        }
        info!(
            "lease store: reseeded {reseeded} sticky lease(s) from {:?}{}",
            lease_persistence_path,
            if dropped > 0 {
                format!(" ({dropped} dropped as out-of-range)")
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
    // has connected yet.
    crate::admin::spawn_listener(
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
    )
    .context("starting vpnd admin socket")?;

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
    tokio::spawn(async move {
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
            let mut batch_failed = false;
            for slot in PacketBatchIter::new(&payload) {
                // Each slot is `[10-byte vhdr | IP packet]`. Anti-
                // spoof reads from the IP part; the vhdr stays
                // attached for the TUN write so the receiving
                // kernel sees the same `gso_type` the sender's
                // kernel produced.
                let ip = match ip_part(slot) { Some(p) => p, None => continue };
                let version_nibble = ip[0] >> 4;
                let spoofed = match version_nibble {
                    4 if ip.len() >= 20 => {
                        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                        src != lease.v4
                    }
                    6 if ip.len() >= 40 => {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(&ip[8..24]);
                        let src = Ipv6Addr::from(octets);
                        Some(src) != lease.v6
                    }
                    _ => true,
                };
                if spoofed {
                    if is_routable_dst(version_nibble, ip) {
                        debug!(
                            "egress exit: spoofed packet from {} (ver={version_nibble}), drop",
                            hex::encode(&from[..8])
                        );
                    }
                    continue;
                }
                if let Err(e) = w.write_all(slot).await {
                    warn!("egress exit: TUN write failed: {e}");
                    batch_failed = true;
                    break;
                }
            }
            if batch_failed { break; }
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

            // Flush each non-empty bucket as one Datagram.
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
        tokio::spawn(async move {
            handle_egress_handshake(
                acc, pool, table, lease_store,
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

    // Sticky-lease lookup. If we have an existing entry in the
    // shared table (loaded from disk at startup or installed by
    // a prior session that's since disconnected), reuse it. This
    // is the whole point of the persistence layer — returning
    // clients keep their address across exit restarts and across
    // client TCP reconnects within a single exit lifetime.
    //
    // Pool was already reserved for sticky leases at startup, so
    // we just need to make sure the table has the entry and we
    // don't double-allocate.
    // Two-step lookup so we never hold the MutexGuard across an
    // await: first peek for an existing lease; if absent, allocate
    // and insert in a fresh critical section. `None` means pool
    // exhaustion — handled below by send_open_ack outside any lock.
    let lookup: Option<(Lease, bool)> = {
        let t = table.lock().unwrap();
        t.lease_of(&peer).map(|l| (l, true))
    };
    let (lease, was_sticky) = match lookup {
        Some(found) => found,
        None => {
            let fresh = pool.lock().unwrap().allocate();
            match fresh {
                Some(l) => {
                    table.lock().unwrap().insert(peer, l);
                    (l, false)
                }
                None => {
                    warn!("egress exit: address pool exhausted for peer {peer_short}");
                    let _ = mesh.send_open_ack(0x01 /* general failure */).await;
                    return;
                }
            }
        }
    };

    let alloc_desc = match lease.v6 {
        Some(v6) => format!("{} + {}", lease.v4, v6),
        None => lease.v4.to_string(),
    };
    if was_sticky {
        info!("egress exit: sticky-resume {alloc_desc} for peer {peer_short}");
    } else {
        info!("egress exit: allocated {alloc_desc} for peer {peer_short}");
        // Persist the new mapping immediately so a crash between
        // here and the next save doesn't lose the lease (the
        // client will already be holding it from EgressHello).
        let save_result = {
            let mut s = lease_store.lock().unwrap();
            s.insert(peer, lease);
            s.save()
        };
        if let Err(e) = save_result {
            warn!(
                "egress exit: persisting lease for {peer_short} failed: {e:#} \
                 (lease is live in memory; will retry on next change)"
            );
        }
    }
    if let Err(e) = mesh.send_open_ack(0x00).await {
        warn!("egress exit: OpenAck failed for {peer_short}: {e}");
        // OpenAck failed: we never actually got past the
        // handshake. Roll back the in-memory state so the next
        // attempt sees a clean slate, but leave the persistent
        // store untouched for sticky-lease purposes — if the
        // peer comes back later, they should still resume.
        if !was_sticky {
            table.lock().unwrap().remove_peer(&peer);
            pool.lock().unwrap().release(lease);
            lease_store.lock().unwrap().remove(&peer);
            let _ = lease_store.lock().unwrap().save();
        }
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
        if !was_sticky {
            table.lock().unwrap().remove_peer(&peer);
            pool.lock().unwrap().release(lease);
            lease_store.lock().unwrap().remove(&peer);
            let _ = lease_store.lock().unwrap().save();
        }
        return;
    }

    // Park here until the client half-closes (or its TCP dies). The
    // mesh stream carries no further data — it's purely a session
    // lifecycle marker. read_to_end completes on graceful Close;
    // unexpected EOF / errors also fall through.
    //
    // Critically: we do NOT release the lease here. The sticky
    // policy keeps `EgressTable` + persistence intact so the peer
    // resumes onto the same IP on next reconnect. Without
    // persistence the in-memory `table` would still survive the
    // peer's TCP teardown but only until the exit restarts;
    // persistence extends that lifetime across daemon restarts.
    let mut throwaway = Vec::new();
    let _ = mesh.read_to_end(&mut throwaway).await;
    if !throwaway.is_empty() {
        // Old clients (pre-datagram) sent IP packets through the
        // stream; loudly flag those so the operator can roll forward.
        warn!(
            "egress exit: peer {} sent {} bytes on the control stream — \
             expected datagram-path client (post-2026-05-19 build)",
            peer_short, throwaway.len()
        );
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
) -> Result<()> {
    let (mesh, hello) = client_handshake(mux.clone(), exit_peer).await?;
    let self_lease = Lease {
        v4: hello.allocated_v4,
        v6: hello.allocated_v6,
    };
    crate::admin::spawn_listener(
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
    )
    .context("starting vpnd admin socket")?;
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
    run_client_pump(tun_reader, tun_writer, mux, exit_peer, mesh).await
}

/// Run the client → exit handshake: wait for the peer to be
/// reachable on the mesh, open an Egress stream, await the
/// OpenAck, and read the framed [`EgressHello`]. Returns the live
/// control stream + the parsed hello. Used by `start_client` and
/// by `bifrost-ffi` (mobile shim).
pub async fn client_handshake(
    mux: Arc<MeshMux>,
    exit_peer: bifrost_core::PubKey,
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
/// `mesh` is the control stream from `client_handshake`; we hold
/// it open in a background task and surface its EOF as a log line.
/// The two real data tasks are spawned and own the tunnel from here
/// on — this function returns once they're scheduled.
pub async fn run_client_pump<R, W>(
    mut tun_reader: R,
    tun_writer: W,
    mux: Arc<MeshMux>,
    exit_peer: bifrost_core::PubKey,
    mesh: bifrost_core::stream::MeshStream,
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
        while let Some(recv) = datagram_rx.recv().await {
            if recv.from != exit_peer {
                trace!(
                    "egress client: dropping datagram from unexpected peer {}",
                    hex::encode(&recv.from[..8])
                );
                continue;
            }
            let mut w = tun_writer_clone.lock().await;
            let mut batch_failed = false;
            for pkt in PacketBatchIter::new(&recv.payload) {
                if let Err(e) = w.write_all(pkt).await {
                    warn!("egress client: TUN write failed: {e}");
                    batch_failed = true;
                    break;
                }
            }
            if batch_failed { break; }
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

    // Hold the control MeshStream alive in the background. Half-close
    // by the exit on lease release surfaces as EOF here; for now we
    // just log and let the TUN sit (process exit cleans up properly).
    // A future revision could trigger a graceful TUN teardown.
    tokio::spawn(async move {
        let mut mesh = mesh;
        let mut throwaway = Vec::new();
        let _ = mesh.read_to_end(&mut throwaway).await;
        warn!("egress client: control stream closed by exit");
    });

    Ok(())
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
