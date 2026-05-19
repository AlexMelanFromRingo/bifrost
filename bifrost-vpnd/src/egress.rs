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
use tracing::{debug, info, warn};

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
pub const EGRESS_HELLO_VERSION: u8 = 2;
pub const EGRESS_HELLO_SIZE: usize = 50;

/// Hard cap on a single relayed packet. Comfortably larger than any
/// real-world MTU (v6 jumbograms top out at 9180 bytes; we round to
/// 16 KB). Frames larger than this are treated as a protocol error
/// and tear the stream down — protects against a malicious peer
/// sending u16::MAX-length headers to make us allocate 64 KB per
/// packet.
pub const MAX_RELAYED_PACKET: usize = 16 * 1024;

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
        Ok(Self {
            allocated_v4: v4.into(),
            gateway_v4: gw4.into(),
            v4_prefix,
            allocated_v6,
            gateway_v6,
            v6_prefix,
            mtu,
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
}

// ── Reverse table ─────────────────────────────────────────────────────────

/// Maps an allocated IPv4 OR IPv6 address back to the channel that
/// delivers outgoing packets to the right client. The exit-side TUN
/// reader looks up the dst IP of each packet (v4 or v6) in this table
/// to find which MeshStream to write to. A dual-stack lease registers
/// twice — once per family — so packets in either direction find their
/// peer with a single lookup.
#[derive(Default)]
pub struct EgressTable {
    by_ip: std::collections::HashMap<IpAddr, mpsc::Sender<Vec<u8>>>,
}

impl EgressTable {
    pub fn insert(&mut self, ip: IpAddr, tx: mpsc::Sender<Vec<u8>>) {
        self.by_ip.insert(ip, tx);
    }

    pub fn remove(&mut self, ip: &IpAddr) {
        self.by_ip.remove(ip);
    }

    pub fn lookup(&self, ip: &IpAddr) -> Option<mpsc::Sender<Vec<u8>>> {
        self.by_ip.get(ip).cloned()
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
    debug_assert!(check_args.iter().any(|&a| a == "-C"),
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
pub async fn start_exit(
    _mux: Arc<MeshMux>,
    mut accept_rx: mpsc::Receiver<AcceptedStream>,
    tun_name: String,
    v4_pool_base: Ipv4Addr,
    v4_pool_prefix: u8,
    v6_pool_base: Option<Ipv6Addr>,
    v6_pool_prefix: u8,
    egress_iface: String,
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

    let mut tun_cfg = tun2::Configuration::default();
    tun_cfg.tun_name(&tun_name).mtu(1400);
    let dev = tun2::create_as_async(&tun_cfg)
        .with_context(|| format!("creating egress TUN {tun_name}"))?;
    configure_exit_kernel(&tun_name, gw4, prefix4, gw6, prefix6, &egress_iface)?;
    info!(
        "egress exit: tun={tun_name} v4_gw={gw4}/{prefix4} v6_gw={} egress_iface={egress_iface}",
        gw6.map(|g| format!("{g}/{prefix6}")).unwrap_or_else(|| "<none>".into())
    );

    let (tun_reader, tun_writer) = tokio::io::split(dev);
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));
    let table: SharedTable = Arc::new(Mutex::new(EgressTable::default()));

    // TUN → mesh: parse v4 OR v6 packets, look up dst in the table,
    // forward to the right MeshStream.
    let table_for_tun = table.clone();
    tokio::spawn(async move {
        let mut reader = tun_reader;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            // tun2 may prepend a 4-byte PI header on Linux — detect by
            // checking the version nibble of the first byte.
            let (offset, version_nibble) = if buf[0] >> 4 == 4 || buf[0] >> 4 == 6 {
                (0, buf[0] >> 4)
            } else if n > 4 && (buf[4] >> 4 == 4 || buf[4] >> 4 == 6) {
                (4, buf[4] >> 4)
            } else {
                continue;
            };
            let pkt = &buf[offset..n];
            let dst: IpAddr = match version_nibble {
                4 if pkt.len() >= 20 => {
                    Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]).into()
                }
                6 if pkt.len() >= 40 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&pkt[24..40]);
                    Ipv6Addr::from(octets).into()
                }
                _ => continue,
            };
            // Filter out link-local multicasts the kernel generates on
            // any new IPv6 interface (router/neighbour solicitations,
            // MLDv2 reports). They have no peer behind them and would
            // otherwise spam debug logs at boot.
            let is_multicast = match &dst {
                IpAddr::V4(v) => v.is_multicast(),
                IpAddr::V6(v) => v.is_multicast(),
            };
            if is_multicast {
                continue;
            }
            let tx = table_for_tun.lock().unwrap().lookup(&dst);
            if let Some(tx) = tx {
                let _ = tx.send(pkt.to_vec()).await;
            } else {
                debug!("egress exit: drop packet to unknown peer {dst}");
            }
        }
        warn!("egress exit: tun reader exited");
    });

    // Accept loop: pair each incoming Open(Egress) with a lease.
    while let Some(acc) = accept_rx.recv().await {
        if !matches!(acc.target, OpenTarget::Egress) {
            continue;
        }
        let pool = pool.clone();
        let table = table.clone();
        let tun_writer = tun_writer.clone();
        tokio::spawn(async move {
            handle_egress_stream(
                acc, pool, table, tun_writer,
                gw4, prefix4, gw6, prefix6,
            ).await;
        });
    }
    warn!("egress exit: accept channel closed");
    Ok(())
}

#[cfg(feature = "tun")]
async fn handle_egress_stream(
    acc: AcceptedStream,
    pool: SharedPool,
    table: SharedTable,
    tun_writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tun2::AsyncDevice>>>,
    gateway_v4: Ipv4Addr,
    v4_prefix: u8,
    gateway_v6: Option<Ipv6Addr>,
    v6_prefix: u8,
) {
    let mut mesh = acc.stream;
    let peer_short = hex::encode(&acc.from[..8]);
    let lease = pool.lock().unwrap().allocate();
    let lease = match lease {
        Some(l) => l,
        None => {
            warn!("egress exit: address pool exhausted for peer {peer_short}");
            let _ = mesh.send_open_ack(0x01 /* general failure */).await;
            return;
        }
    };
    let alloc_desc = match lease.v6 {
        Some(v6) => format!("{} + {}", lease.v4, v6),
        None => lease.v4.to_string(),
    };
    info!("egress exit: allocated {alloc_desc} for peer {peer_short}");
    if let Err(e) = mesh.send_open_ack(0x00).await {
        warn!("egress exit: OpenAck failed for {peer_short}: {e}");
        pool.lock().unwrap().release(lease);
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
    };
    if let Err(e) = write_framed(&mut mesh, &hello.encode()).await {
        warn!("egress exit: hello send failed for {peer_short} ({alloc_desc}): {e}");
        pool.lock().unwrap().release(lease);
        return;
    }

    // Register reverse-routing entries for both stacks the lease holds.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    {
        let mut t = table.lock().unwrap();
        t.insert(IpAddr::V4(lease.v4), out_tx.clone());
        if let Some(v6) = lease.v6 {
            t.insert(IpAddr::V6(v6), out_tx);
        }
    }

    let (mut mesh_reader, mut mesh_writer) = tokio::io::split(mesh);

    // mesh → TUN
    let tun_writer_clone = tun_writer.clone();
    let lease_for_in = lease;
    let peer_short_for_in = peer_short.clone();
    let in_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        loop {
            let n = match read_framed(&mut mesh_reader, &mut buf).await {
                Ok(Some(n)) => n,
                Ok(None) => break,
                Err(e) => {
                    warn!(
                        "egress exit: framed read failed for {}: {e}",
                        peer_short_for_in
                    );
                    break;
                }
            };
            // Reject anything that doesn't look like an IP packet, and
            // anti-spoof: confirm the src address matches the lease
            // we handed this peer.
            let version_nibble = buf[0] >> 4;
            let spoofed = match version_nibble {
                4 if n >= 20 => {
                    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                    src != lease_for_in.v4
                }
                6 if n >= 40 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[8..24]);
                    let src = Ipv6Addr::from(octets);
                    Some(src) != lease_for_in.v6
                }
                _ => true,
            };
            if spoofed {
                // Skip the noisy debug for obvious kernel chatter
                // (multicast, link-local, broadcast) — only log when
                // the src address truly doesn't match the lease.
                if is_routable_dst(version_nibble, &buf[..n]) {
                    debug!(
                        "egress exit: peer {} sent spoofed packet (ver={version_nibble}), drop",
                        peer_short_for_in
                    );
                }
                continue;
            }
            let mut w = tun_writer_clone.lock().await;
            if let Err(e) = w.write_all(&buf[..n]).await {
                warn!("egress exit: TUN write failed for {}: {e}", peer_short_for_in);
                break;
            }
        }
    });

    // TUN → mesh
    let out_handle = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if let Err(e) = write_framed(&mut mesh_writer, &pkt).await {
                debug!("egress exit: mesh write failed: {e}");
                break;
            }
        }
        let _ = mesh_writer.shutdown().await;
    });

    let _ = in_handle.await;
    let _ = out_handle.await;
    {
        let mut t = table.lock().unwrap();
        t.remove(&IpAddr::V4(lease.v4));
        if let Some(v6) = lease.v6 {
            t.remove(&IpAddr::V6(v6));
        }
    }
    pool.lock().unwrap().release(lease);
    info!("egress exit: closed stream for {peer_short} ({alloc_desc})");
}

// ── Stream <-> TUN bridge for client role ────────────────────────────────

#[cfg(feature = "tun")]
pub async fn start_client(
    mux: Arc<MeshMux>,
    exit_peer: [u8; 32],
    tun_name: String,
    install_default_route: bool,
) -> Result<()> {
    info!(
        "egress client: opening tunnel to exit {}",
        hex::encode(&exit_peer[..8])
    );
    // Wait until the underlying transport reports a connection to the
    // exit peer (handshake done, session manager has the entry). Without
    // this poll, mux.open's session-wait races the very first dial and
    // burns its retry budget on a connection that didn't exist yet.
    let wait_started = std::time::Instant::now();
    loop {
        let stats = mux.conn().get_peer_stats();
        if stats.iter().any(|p| p.key == exit_peer) {
            debug!(
                "egress client: peer {} appeared after {:?} — giving the session 2s to settle",
                hex::encode(&exit_peer[..8]),
                wait_started.elapsed()
            );
            // The peer-stats entry appears once handle_conn starts; the
            // ChaCha20 session takes a few SessionInit/Response round-
            // trips after that. Sleeping briefly avoids burning the
            // mux.open retry budget on guaranteed-fail attempts.
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
    // Read the EgressHello — framed like everything else on this stream.
    let mut hello_buf = [0u8; MAX_RELAYED_PACKET];
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
    let v6_desc = hello.allocated_v6
        .map(|v6| format!(" + {v6}/{}", hello.v6_prefix))
        .unwrap_or_default();
    info!(
        "egress client: allocated {}{} (v4 gw={})",
        hello.allocated_v4, v6_desc, hello.gateway_v4
    );

    let mut tun_cfg = tun2::Configuration::default();
    tun_cfg.tun_name(&tun_name).mtu(hello.mtu);
    let dev = tun2::create_as_async(&tun_cfg)
        .with_context(|| format!("creating client egress TUN {tun_name}"))?;
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

    let (mut tun_reader, tun_writer) = tokio::io::split(dev);
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));
    let (mut mesh_reader, mut mesh_writer) = tokio::io::split(mesh);

    // mesh → TUN
    let tun_writer_clone = tun_writer.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        loop {
            let n = match read_framed(&mut mesh_reader, &mut buf).await {
                Ok(Some(n)) => n,
                Ok(None) => break,
                Err(e) => {
                    warn!("egress client: framed read failed: {e}");
                    break;
                }
            };
            let mut w = tun_writer_clone.lock().await;
            if let Err(e) = w.write_all(&buf[..n]).await {
                warn!("egress client: TUN write failed: {e}");
                break;
            }
        }
    });

    // TUN → mesh (both IPv4 and IPv6).
    //
    // We drop link-local / multicast / loopback destinations at the
    // client side: those packets are kernel chatter (IPv6 ND, mDNS,
    // ARP-equivalents) that have no peer on the exit, would always
    // get rejected as spoofed, and pollute the wire. Keeping them
    // local is also a tiny privacy win — the exit operator never
    // sees the client's link-local solicitations.
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_RELAYED_PACKET];
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let (offset, version_nibble) = if buf[0] >> 4 == 4 || buf[0] >> 4 == 6 {
                (0, buf[0] >> 4)
            } else if n > 4 && (buf[4] >> 4 == 4 || buf[4] >> 4 == 6) {
                (4, buf[4] >> 4)
            } else {
                continue;
            };
            let pkt = &buf[offset..n];
            if !is_routable_dst(version_nibble, pkt) {
                continue;
            }
            if let Err(e) = write_framed(&mut mesh_writer, pkt).await {
                debug!("egress client: mesh write failed: {e}");
                break;
            }
        }
        let _ = mesh_writer.shutdown().await;
    });

    Ok(())
}

/// True if the packet's destination address is sensible to forward
/// across the egress tunnel. Filters out multicast, link-local, and
/// loopback — those belong on the local link and would be dropped
/// (noisily) on the exit side anyway.
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
pub async fn start_exit(
    _mux: Arc<MeshMux>,
    _accept_rx: mpsc::Receiver<AcceptedStream>,
    _tun_name: String,
    _v4_pool_base: Ipv4Addr,
    _v4_pool_prefix: u8,
    _v6_pool_base: Option<Ipv6Addr>,
    _v6_pool_prefix: u8,
    _egress_iface: String,
) -> Result<()> {
    anyhow::bail!("egress exit requires the `tun` feature (rebuild with --features tun)")
}

#[cfg(not(feature = "tun"))]
pub async fn start_client(
    _mux: Arc<MeshMux>,
    _exit_peer: [u8; 32],
    _tun_name: String,
    _install_default_route: bool,
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
        };
        let back = EgressHello::decode(&h.encode()).unwrap();
        assert_eq!(back.allocated_v4, h.allocated_v4);
        assert_eq!(back.gateway_v4, h.gateway_v4);
        assert_eq!(back.v4_prefix, h.v4_prefix);
        assert!(back.allocated_v6.is_none(), "v6_present=0 → None");
        assert_eq!(back.mtu, 1408);
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
        };
        let back = EgressHello::decode(&h.encode()).unwrap();
        assert_eq!(back.allocated_v6, h.allocated_v6);
        assert_eq!(back.gateway_v6, h.gateway_v6);
        assert_eq!(back.v6_prefix, 64);
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
}
