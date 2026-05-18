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
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

/// Header the exit sends as the very first Data frame of every
/// accepted egress stream. The client reads it before forwarding any
/// IP traffic.
///
/// Wire layout (15 bytes, big-endian):
///   magic         (4 bytes, "BFEG")
///   version       (1 byte, currently 1)
///   allocated_ip  (4 bytes, IPv4)
///   gateway_ip    (4 bytes, IPv4)
///   prefix_len    (1 byte)
///   mtu           (1 byte, MTU/16 — encodes 256..65280 in 16-byte steps)
pub const EGRESS_HELLO_MAGIC: &[u8; 4] = b"BFEG";
pub const EGRESS_HELLO_VERSION: u8 = 1;
pub const EGRESS_HELLO_SIZE: usize = 15;

#[derive(Debug, Clone, Copy)]
pub struct EgressHello {
    pub allocated_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub prefix_len: u8,
    pub mtu: u16,
}

impl EgressHello {
    pub fn encode(&self) -> [u8; EGRESS_HELLO_SIZE] {
        let mut out = [0u8; EGRESS_HELLO_SIZE];
        out[..4].copy_from_slice(EGRESS_HELLO_MAGIC);
        out[4] = EGRESS_HELLO_VERSION;
        out[5..9].copy_from_slice(&self.allocated_ip.octets());
        out[9..13].copy_from_slice(&self.gateway_ip.octets());
        out[13] = self.prefix_len;
        // MTU encoded as (mtu / 16) clamped to a single byte. Restricts
        // the negotiated MTU to multiples of 16; plenty of resolution.
        out[14] = ((self.mtu / 16).min(255)) as u8;
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
            anyhow::bail!("egress hello: unsupported version {}", buf[4]);
        }
        let mut alloc = [0u8; 4];
        alloc.copy_from_slice(&buf[5..9]);
        let mut gw = [0u8; 4];
        gw.copy_from_slice(&buf[9..13]);
        let prefix_len = buf[13];
        let mtu = (buf[14] as u16) * 16;
        Ok(Self {
            allocated_ip: alloc.into(),
            gateway_ip: gw.into(),
            prefix_len,
            mtu,
        })
    }
}

// ── Address allocator ─────────────────────────────────────────────────────

/// Allocates IPv4 addresses out of a /24 subnet for incoming egress
/// streams. .1 is reserved for the gateway (the exit's own TUN end);
/// .2 .. .254 are handed out sequentially; .255 is broadcast.
#[derive(Debug)]
pub struct AddressPool {
    base: Ipv4Addr,
    prefix_len: u8,
    /// Bit vector of taken host indices. Index 0 is the network address,
    /// index 1 is the gateway. Bit set = in use.
    in_use: Vec<bool>,
}

impl AddressPool {
    pub fn new(base: Ipv4Addr, prefix_len: u8) -> Result<Self> {
        if prefix_len < 16 || prefix_len > 30 {
            anyhow::bail!("address pool: prefix /{prefix_len} not in [16, 30]");
        }
        let host_bits = 32 - prefix_len as u32;
        let n_hosts = 1u32 << host_bits;
        let mut in_use = vec![false; n_hosts as usize];
        in_use[0] = true;                  // network
        in_use[1] = true;                  // gateway
        in_use[(n_hosts - 1) as usize] = true; // broadcast
        Ok(Self { base, prefix_len, in_use })
    }

    pub fn gateway(&self) -> Ipv4Addr {
        let mut octets = self.base.octets();
        octets[3] += 1;
        octets.into()
    }

    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        for (i, used) in self.in_use.iter_mut().enumerate() {
            if !*used {
                *used = true;
                let mut octets = self.base.octets();
                // Increment the host part (only works correctly up to /24,
                // which is what we recommend).
                let host = i as u32;
                let combined = u32::from_be_bytes(octets) + host;
                octets = combined.to_be_bytes();
                return Some(octets.into());
            }
        }
        None
    }

    pub fn release(&mut self, ip: Ipv4Addr) {
        let host = u32::from_be_bytes(ip.octets())
            .wrapping_sub(u32::from_be_bytes(self.base.octets())) as usize;
        if host < self.in_use.len() {
            self.in_use[host] = false;
        }
    }
}

// ── Reverse table ─────────────────────────────────────────────────────────

/// Maps an allocated IPv4 address back to the channel that delivers
/// outgoing packets to the right client. The exit-side TUN reader
/// looks up the dst IP of each packet in this table to find which
/// MeshStream to write to.
#[derive(Default)]
pub struct EgressTable {
    by_ip: std::collections::HashMap<Ipv4Addr, mpsc::Sender<Vec<u8>>>,
}

impl EgressTable {
    pub fn insert(&mut self, ip: Ipv4Addr, tx: mpsc::Sender<Vec<u8>>) {
        self.by_ip.insert(ip, tx);
    }

    pub fn remove(&mut self, ip: &Ipv4Addr) {
        self.by_ip.remove(ip);
    }

    pub fn lookup(&self, ip: &Ipv4Addr) -> Option<mpsc::Sender<Vec<u8>>> {
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

/// Bring up the egress TUN with the gateway address and add the
/// MASQUERADE rule on `egress_iface`. Idempotent enough that re-running
/// the daemon after a clean shutdown is safe; existing rules with the
/// same predicates are skipped via `-C` checks.
pub fn configure_exit_kernel(
    tun_name: &str,
    gateway: Ipv4Addr,
    prefix_len: u8,
    egress_iface: &str,
) -> Result<()> {
    let cidr = format!("{}/{}", gateway, prefix_len);
    let subnet_cidr = subnet_cidr_str(gateway, prefix_len);
    run_cmd("ip", &["link", "set", tun_name, "up"])?;
    // `ip addr add` returns 2 if the address already exists; treat that as ok.
    let already = Command::new("ip")
        .args(["addr", "show", "dev", tun_name, "to", &cidr])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);
    if !already {
        run_cmd("ip", &["addr", "add", &cidr, "dev", tun_name])?;
    }
    // Enable forwarding so the kernel will route between the TUN and
    // egress_iface. Without this MASQUERADE alone does nothing.
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
    // Add MASQUERADE if not already present.
    let check = Command::new("iptables")
        .args(["-t", "nat", "-C", "POSTROUTING", "-s", &subnet_cidr,
               "-o", egress_iface, "-j", "MASQUERADE"])
        .status();
    if check.map(|s| !s.success()).unwrap_or(true) {
        run_cmd("iptables", &[
            "-t", "nat", "-A", "POSTROUTING",
            "-s", &subnet_cidr, "-o", egress_iface, "-j", "MASQUERADE",
        ])?;
    }
    // Allow forwarding in both directions for the egress subnet —
    // some distros default to FORWARD DROP and silently black-hole us.
    for args in [
        &["-A", "FORWARD", "-i", tun_name, "-o", egress_iface, "-j", "ACCEPT"][..],
        &["-A", "FORWARD", "-o", tun_name, "-i", egress_iface,
          "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"][..],
    ] {
        // -C variant to skip dup-insert
        let mut check_args: Vec<&str> = args.iter().copied().collect();
        check_args[0] = "-C";
        if Command::new("iptables").args(&check_args).status().map(|s| !s.success()).unwrap_or(true) {
            run_cmd("iptables", args)?;
        }
    }
    Ok(())
}

/// Bring up the client-side TUN with the allocated address. Doesn't
/// touch the default route — the operator opts in to that separately
/// via the daemon config (see `default_route` flag).
pub fn configure_client_kernel(
    tun_name: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    install_default_route: bool,
) -> Result<()> {
    let cidr = format!("{}/{}", addr, prefix_len);
    let subnet_cidr = subnet_cidr_str(gateway, prefix_len);
    run_cmd("ip", &["link", "set", tun_name, "up"])?;
    let _ = Command::new("ip").args(["addr", "add", &cidr, "dev", tun_name]).status();
    // Direct route to the egress subnet so we reach the exit's gateway.
    let _ = Command::new("ip").args(["route", "replace", &subnet_cidr, "dev", tun_name]).status();
    if install_default_route {
        // Replace default so all unspecified traffic goes via the TUN.
        // Use `replace` so we update an existing default instead of failing.
        run_cmd("ip", &["route", "replace", "default", "via", &gateway.to_string(), "dev", tun_name])?;
    }
    Ok(())
}

fn subnet_cidr_str(any_in_subnet: Ipv4Addr, prefix_len: u8) -> String {
    let mask = !((1u32 << (32 - prefix_len as u32)) - 1);
    let net_u32 = u32::from_be_bytes(any_in_subnet.octets()) & mask;
    let net: Ipv4Addr = net_u32.to_be_bytes().into();
    format!("{net}/{prefix_len}")
}

// ── Stream <-> TUN bridge for exit role ──────────────────────────────────

#[cfg(feature = "tun")]
pub async fn start_exit(
    _mux: Arc<MeshMux>,
    mut accept_rx: mpsc::Receiver<AcceptedStream>,
    tun_name: String,
    pool_base: Ipv4Addr,
    pool_prefix: u8,
    egress_iface: String,
) -> Result<()> {
    let pool = Arc::new(Mutex::new(
        AddressPool::new(pool_base, pool_prefix)
            .with_context(|| format!("address pool {pool_base}/{pool_prefix}"))?,
    ));
    let gateway = pool.lock().unwrap().gateway();
    let prefix = pool.lock().unwrap().prefix_len();

    // Make the TUN device, assign the gateway, set MASQUERADE.
    let mut tun_cfg = tun2::Configuration::default();
    tun_cfg.tun_name(&tun_name).mtu(1400);
    let dev = tun2::create_as_async(&tun_cfg)
        .with_context(|| format!("creating egress TUN {tun_name}"))?;
    configure_exit_kernel(&tun_name, gateway, prefix, &egress_iface)?;
    info!(
        "egress exit: tun={tun_name} gw={gateway}/{prefix} egress_iface={egress_iface}"
    );

    let (tun_reader, tun_writer) = tokio::io::split(dev);
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));
    let table: SharedTable = Arc::new(Mutex::new(EgressTable::default()));

    // TUN → mesh: parse each outgoing IP packet, look up its dst in
    // the table, forward to the right MeshStream.
    let table_for_tun = table.clone();
    tokio::spawn(async move {
        let mut reader = tun_reader;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let pkt = if buf[0] >> 4 == 4 {
                &buf[..n]
            } else if n > 4 && buf[4] >> 4 == 4 {
                // Some Linux builds prepend a 4-byte PI header. Skip it.
                &buf[4..n]
            } else {
                // Not IPv4 (could be IPv6 ND etc.) — drop.
                continue;
            };
            if pkt.len() < 20 {
                continue;
            }
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            let tx = table_for_tun.lock().unwrap().lookup(&dst);
            if let Some(tx) = tx {
                let _ = tx.send(pkt.to_vec()).await;
            } else {
                debug!("egress exit: drop packet to unknown peer {dst}");
            }
        }
        warn!("egress exit: tun reader exited");
    });

    // Accept loop: pair each incoming Open(Egress) with an address.
    while let Some(acc) = accept_rx.recv().await {
        if !matches!(acc.target, OpenTarget::Egress) {
            // Non-egress stream — drop. (Operator might be running
            // SOCKS5 mode on the same node; that should be a separate
            // daemon.)
            continue;
        }
        let pool = pool.clone();
        let table = table.clone();
        let tun_writer = tun_writer.clone();
        let gateway_addr = gateway;
        let prefix_len = prefix;
        tokio::spawn(async move {
            handle_egress_stream(acc, pool, table, tun_writer, gateway_addr, prefix_len).await;
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
    gateway: Ipv4Addr,
    prefix_len: u8,
) {
    let mut mesh = acc.stream;
    let peer_short = hex::encode(&acc.from[..8]);
    let allocated = pool.lock().unwrap().allocate();
    let allocated = match allocated {
        Some(ip) => ip,
        None => {
            warn!("egress exit: address pool exhausted for peer {peer_short}");
            let _ = mesh.send_open_ack(0x01 /* general failure */).await;
            return;
        }
    };
    info!("egress exit: allocated {allocated} for peer {peer_short}");
    if let Err(e) = mesh.send_open_ack(0x00).await {
        warn!("egress exit: OpenAck failed for {peer_short}: {e}");
        pool.lock().unwrap().release(allocated);
        return;
    }
    // Send the EgressHello as the first Data frame so the client can
    // configure its TUN.
    let hello = EgressHello {
        allocated_ip: allocated,
        gateway_ip: gateway,
        prefix_len,
        mtu: 1400,
    };
    if let Err(e) = mesh.write_all(&hello.encode()).await {
        warn!("egress exit: hello send failed for {peer_short} ({allocated}): {e}");
        pool.lock().unwrap().release(allocated);
        return;
    }

    // Set up a channel for TUN → mesh delivery toward this peer.
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(256);
    table.lock().unwrap().insert(allocated, out_tx);

    // Split mesh into read + write halves so the two directions can
    // run concurrently.
    let (mut mesh_reader, mut mesh_writer) = tokio::io::split(mesh);

    // mesh → TUN
    let tun_writer_clone = tun_writer.clone();
    let allocated_for_in = allocated;
    let in_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match mesh_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            // Accept any IPv4 packet from this stream; validate src to
            // catch peers trying to spoof someone else's address.
            if n < 20 || buf[0] >> 4 != 4 {
                debug!("egress exit: non-v4 from {allocated_for_in}, drop");
                continue;
            }
            let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
            if src != allocated_for_in {
                debug!(
                    "egress exit: peer {allocated_for_in} sent spoofed src {src}, dropping"
                );
                continue;
            }
            let mut w = tun_writer_clone.lock().await;
            if let Err(e) = w.write_all(&buf[..n]).await {
                warn!("egress exit: TUN write failed for {allocated_for_in}: {e}");
                break;
            }
        }
    });

    // TUN → mesh
    let out_handle = tokio::spawn(async move {
        while let Some(pkt) = out_rx.recv().await {
            if let Err(e) = mesh_writer.write_all(&pkt).await {
                debug!("egress exit: mesh write failed for {allocated}: {e}");
                break;
            }
        }
        let _ = mesh_writer.shutdown().await;
    });

    let _ = in_handle.await;
    let _ = out_handle.await;
    table.lock().unwrap().remove(&allocated);
    pool.lock().unwrap().release(allocated);
    info!("egress exit: closed stream for {peer_short} ({allocated})");
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
    // Read the EgressHello.
    let mut hello_buf = [0u8; EGRESS_HELLO_SIZE];
    mesh.read_exact(&mut hello_buf)
        .await
        .context("reading egress hello")?;
    let hello = EgressHello::decode(&hello_buf)?;
    info!(
        "egress client: allocated {} gw={} prefix=/{}",
        hello.allocated_ip, hello.gateway_ip, hello.prefix_len
    );

    let mut tun_cfg = tun2::Configuration::default();
    tun_cfg.tun_name(&tun_name).mtu(hello.mtu);
    let dev = tun2::create_as_async(&tun_cfg)
        .with_context(|| format!("creating client egress TUN {tun_name}"))?;
    configure_client_kernel(
        &tun_name,
        hello.allocated_ip,
        hello.prefix_len,
        hello.gateway_ip,
        install_default_route,
    )?;

    let (mut tun_reader, tun_writer) = tokio::io::split(dev);
    let tun_writer = Arc::new(tokio::sync::Mutex::new(tun_writer));
    let (mut mesh_reader, mut mesh_writer) = tokio::io::split(mesh);

    // mesh → TUN
    let tun_writer_clone = tun_writer.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match mesh_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut w = tun_writer_clone.lock().await;
            if let Err(e) = w.write_all(&buf[..n]).await {
                warn!("egress client: TUN write failed: {e}");
                break;
            }
        }
    });

    // TUN → mesh
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let pkt = if buf[0] >> 4 == 4 {
                &buf[..n]
            } else if n > 4 && buf[4] >> 4 == 4 {
                &buf[4..n]
            } else {
                continue;
            };
            if let Err(e) = mesh_writer.write_all(pkt).await {
                debug!("egress client: mesh write failed: {e}");
                break;
            }
        }
        let _ = mesh_writer.shutdown().await;
    });

    Ok(())
}

#[cfg(not(feature = "tun"))]
pub async fn start_exit(
    _mux: Arc<MeshMux>,
    _accept_rx: mpsc::Receiver<AcceptedStream>,
    _tun_name: String,
    _pool_base: Ipv4Addr,
    _pool_prefix: u8,
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
        configure_exit_kernel as fn(&str, Ipv4Addr, u8, &str) -> Result<()>,
        configure_client_kernel as fn(&str, Ipv4Addr, u8, Ipv4Addr, bool) -> Result<()>,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_hello_roundtrip() {
        let h = EgressHello {
            allocated_ip: Ipv4Addr::new(10, 55, 0, 17),
            gateway_ip: Ipv4Addr::new(10, 55, 0, 1),
            prefix_len: 24,
            mtu: 1408,
        };
        let bytes = h.encode();
        let back = EgressHello::decode(&bytes).unwrap();
        assert_eq!(back.allocated_ip, h.allocated_ip);
        assert_eq!(back.gateway_ip, h.gateway_ip);
        assert_eq!(back.prefix_len, h.prefix_len);
        // MTU is encoded as mtu/16, so 1408 → 88 → 1408 — exact.
        assert_eq!(back.mtu, 1408);
    }

    #[test]
    fn egress_hello_rejects_bad_magic() {
        let mut bytes = EgressHello {
            allocated_ip: Ipv4Addr::new(0, 0, 0, 0),
            gateway_ip: Ipv4Addr::new(0, 0, 0, 0),
            prefix_len: 24,
            mtu: 1400,
        }
        .encode();
        bytes[0] = b'X';
        assert!(EgressHello::decode(&bytes).is_err());
    }

    #[test]
    fn address_pool_allocate_release_sequence() {
        let mut pool = AddressPool::new(Ipv4Addr::new(10, 55, 0, 0), 24).unwrap();
        assert_eq!(pool.gateway(), Ipv4Addr::new(10, 55, 0, 1));
        let a = pool.allocate().unwrap();
        assert_eq!(a, Ipv4Addr::new(10, 55, 0, 2));
        let b = pool.allocate().unwrap();
        assert_eq!(b, Ipv4Addr::new(10, 55, 0, 3));
        pool.release(a);
        let c = pool.allocate().unwrap();
        assert_eq!(c, Ipv4Addr::new(10, 55, 0, 2), "released slot reused");
    }

    #[test]
    fn address_pool_skips_broadcast_and_gateway() {
        let mut pool = AddressPool::new(Ipv4Addr::new(192, 168, 0, 0), 30).unwrap();
        // /30 = 4 addrs: network(.0), gw(.1), one allocatable(.2), broadcast(.3)
        let a = pool.allocate().unwrap();
        assert_eq!(a, Ipv4Addr::new(192, 168, 0, 2));
        assert!(pool.allocate().is_none(), "no more usable hosts");
    }

    #[test]
    fn subnet_cidr_correctly_masks() {
        assert_eq!(subnet_cidr_str(Ipv4Addr::new(10, 55, 0, 17), 24), "10.55.0.0/24");
        assert_eq!(subnet_cidr_str(Ipv4Addr::new(192, 168, 5, 5), 16), "192.168.0.0/16");
    }
}
