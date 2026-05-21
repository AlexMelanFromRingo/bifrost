//! `wss://host:port` transport — a real TLS 1.3 session carrying a real
//! WebSocket. To a DPI box the link is an ordinary HTTPS connection; the
//! norn-rs NRN1 handshake and frames ride *inside* the WebSocket.
//!
//! `bifrost-cloak` brings up the disguised byte pipe; norn-rs owns the
//! mesh logic. Once the WebSocket is established, the stream pair is
//! handed to `norn_rs::transport::serve_authenticated_link`, which runs
//! the identity handshake and the connection exactly like the built-in
//! `tcp://` / `quic://` transports.
//!
//! Phase 1 scope: real TLS + real WebSocket handshake, self-signed cert
//! (TLS 1.3 keeps the cert off the wire), and a probe defence — any
//! connection that does not present the mesh path is served a plain web
//! page. Traffic shaping and TLS-fingerprint hardening are later phases.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context as _, Result};
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use norn_rs::transport::{serve_authenticated_link, ConnectedPeers};
use norn_rs::PacketConn;

/// Budget for TLS + the HTTP/WebSocket upgrade. The NRN1 handshake that
/// follows has its own timeout inside `serve_authenticated_link`.
const WSS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// RFC 6455 magic GUID for the `Sec-WebSocket-Accept` digest.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
/// Reject a WebSocket frame whose advertised payload exceeds this — a
/// malicious peer must not be able to make us buffer unbounded memory.
const MAX_WS_FRAME: usize = 16 * 1024 * 1024;

// ── Traffic shaping (Phase 2) ─────────────────────────────────────────────

/// Traffic-shaping parameters for outbound frames. Sender-local: the
/// receiver strips padding unconditionally, so the two ends need not
/// agree and there is no wire negotiation.
#[derive(Clone)]
struct ShapeConfig {
    /// Ascending WS-frame-payload size buckets. An outbound frame is
    /// padded up to the smallest bucket that fits it; a frame larger
    /// than every bucket is left as-is. Empty = no padding.
    pad_buckets: Vec<usize>,
    /// When `Some((min, max))` the write pump slips an opcode-0x3 cover
    /// frame onto the wire after a random write-idle gap in `[min, max]`,
    /// so the link never has the "bulk then dead silence" shape of a VPN.
    /// `None` = no cover traffic.
    cover: Option<(Duration, Duration)>,
}

impl ShapeConfig {
    /// No shaping — frames go out at their natural size (still carrying
    /// the 4-byte inner length prefix, which is unconditional) and there
    /// is no cover traffic.
    fn off() -> Self {
        ShapeConfig { pad_buckets: Vec::new(), cover: None }
    }

    /// Full Phase-2 shaping: size-bucket padding plus idle cover traffic.
    /// Small / control frames round up to a handful of discrete sizes;
    /// bulk frames (already large) are left alone, so steady throughput
    /// is barely affected.
    fn padded() -> Self {
        ShapeConfig {
            pad_buckets: vec![256, 512, 1024, 2048, 4096, 8192, 16384],
            cover: Some((Duration::from_secs(15), Duration::from_secs(45))),
        }
    }

    /// Smallest bucket ≥ `len`, or `len` itself if it exceeds every bucket.
    fn bucket_for(&self, len: usize) -> usize {
        self.pad_buckets.iter().copied().find(|&b| b >= len).unwrap_or(len)
    }

    /// A random delay within the cover-idle range, re-rolled per fire so
    /// a long idle never produces metronomic cover frames.
    fn next_cover_delay(&self) -> Duration {
        let (min, max) = self
            .cover
            .unwrap_or((Duration::from_secs(20), Duration::from_secs(20)));
        min + max.saturating_sub(min).mul_f64(rand::random::<f64>())
    }

    /// A cover frame's payload: random bytes of a randomised small size,
    /// roughly keepalive-shaped. The peer drops opcode 0x3 outright, so
    /// the content does not matter.
    fn cover_payload(&self) -> Vec<u8> {
        let len = 32 + (rand::random::<u32>() as usize % 480); // 32..=511 bytes
        let mut v = vec![0u8; len];
        rand::rngs::OsRng.fill_bytes(&mut v);
        v
    }

    /// Wrap `data` as an inner record `[real_len: u32 BE][data][pad]`,
    /// padding the record up to a size bucket. The 4-byte length prefix
    /// is always present — it is how the receiver finds the real data;
    /// `pad` is empty when shaping is off.
    fn wrap(&self, data: &[u8]) -> Vec<u8> {
        let body = 4 + data.len();
        let target = self.bucket_for(body);
        let mut out = Vec::with_capacity(target);
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        if target > body {
            let pad_start = out.len();
            out.resize(target, 0);
            rand::rngs::OsRng.fill_bytes(&mut out[pad_start..]);
        }
        out
    }
}

/// Traffic-shaping mode from the environment. `BIFROST_WSS_SHAPE=1`
/// turns on size-bucket padding for outbound frames — a deliberate
/// opt-in that trades a little bandwidth for a less VPN-shaped frame
/// size distribution. Unset (the default) → no shaping. A proper config
/// field will eventually replace the env var.
fn shape_from_env() -> ShapeConfig {
    match std::env::var("BIFROST_WSS_SHAPE") {
        Ok(v) if !v.is_empty() && v != "0" => ShapeConfig::padded(),
        _ => ShapeConfig::off(),
    }
}

/// Parse a `wss://host:port` URI to its bare `host:port`.
pub fn parse_wss_uri(uri: &str) -> Result<String> {
    uri.strip_prefix("wss://")
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("unsupported URI scheme (expected wss://): {}", uri))
}

// ── TLS configuration ─────────────────────────────────────────────────────

/// TLS 1.3 server config: self-signed cert (encrypted in TLS 1.3, so
/// invisible to a passive observer), no client-cert request (browsers
/// don't send one), `http/1.1` ALPN (a real `wss://` negotiates it).
fn server_tls() -> Result<TlsAcceptor> {
    let (cert, key) = crate::tls::self_signed_cert()?;
    let mut crypto = rustls::ServerConfig::builder_with_provider(crate::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("rustls TLS1.3-only")?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("rustls with_single_cert")?;
    crypto.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(crypto)))
}

/// TLS 1.3 client config: accepts any server cert (NRN1 binds identity
/// at the application layer), `http/1.1` ALPN.
fn client_tls() -> Result<TlsConnector> {
    let mut crypto = rustls::ClientConfig::builder_with_provider(crate::tls::provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("rustls TLS1.3-only")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(crate::tls::AcceptAnyServerCert))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(crypto)))
}

// ── small helpers ─────────────────────────────────────────────────────────

/// Standard base64 encode (no line breaks). We only ever encode short
/// values (a 16-byte nonce, a 20-byte SHA-1), so a tiny hand-rolled
/// encoder keeps the dependency surface minimal.
fn b64(input: &[u8]) -> String {
    const A: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b0 = c[0];
        let b1 = c.get(1).copied().unwrap_or(0);
        let b2 = c.get(2).copied().unwrap_or(0);
        out.push(A[(b0 >> 2) as usize] as char);
        out.push(A[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if c.len() > 1 {
            A[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 { A[(b2 & 0x3f) as usize] as char } else { '=' });
    }
    out
}

/// `Sec-WebSocket-Accept` = base64(SHA-1(key ‖ GUID)) — RFC 6455 §4.2.2.
fn ws_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID.as_bytes());
    b64(h.finalize().as_slice())
}

/// The HTTP path that gates a mesh upgrade. Derived from the obfuscation
/// PSK when one is set — so it is not guessable from the (open) source —
/// else a default. A request to any other path is served a web page.
fn mesh_path(psk: Option<[u8; 32]>) -> String {
    match psk {
        Some(key) => {
            use blake2::{Blake2b512, Digest};
            let mut h = Blake2b512::new();
            h.update(b"norn-wss-path-v1");
            h.update(key);
            format!("/{}", hex::encode(&h.finalize()[..16]))
        }
        None => "/ws".to_string(),
    }
}

// ── HTTP request handling ─────────────────────────────────────────────────

struct HttpRequest {
    path: String,
    ws_key: Option<String>,
    ws_upgrade: bool,
}

/// Read an HTTP request/response head — bytes up to and including the
/// terminating CRLFCRLF. Byte-at-a-time so we never consume WebSocket
/// frame data that follows it. Capped to bound abuse.
async fn read_http_head<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if s.read(&mut byte).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "eof in http head"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
        if buf.len() > 8192 {
            return Err(io::Error::other("http head too large"));
        }
    }
}

/// Parse an HTTP request head into the fields the upgrade gate needs.
fn parse_request(head: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let mut rl = lines.next()?.split(' ');
    let _method = rl.next()?;
    let path = rl.next()?.to_string();

    let mut ws_key = None;
    let mut upgrade_ws = false;
    let mut connection_upgrade = false;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue; // tolerate a malformed header line
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "sec-websocket-key" => ws_key = Some(value.to_string()),
            "upgrade" => upgrade_ws = value.to_ascii_lowercase().contains("websocket"),
            "connection" => {
                connection_upgrade = value.to_ascii_lowercase().contains("upgrade")
            }
            _ => {}
        }
    }
    Some(HttpRequest {
        path,
        ws_key,
        ws_upgrade: upgrade_ws && connection_upgrade,
    })
}

// ── Listener ──────────────────────────────────────────────────────────────

/// Start a `wss://` listener: accept TCP, complete TLS, and either
/// upgrade a mesh peer or serve a probe a plain web page. `psk` is the
/// shared obfuscation secret (the path-deriving key); `None` falls back
/// to a guessable default path.
pub async fn listen(uri: &str, conn: Arc<PacketConn>, psk: Option<[u8; 32]>) -> Result<()> {
    let addr = parse_wss_uri(uri)?;
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding wss listener on {}", addr))?;
    let acceptor = server_tls()?;
    let path = mesh_path(psk);
    if psk.is_none() {
        warn!(
            "wss listener on {} has no obfuscation PSK — the mesh path is the \
             default `/ws` and a prober can guess it; set obfuscation_psk",
            addr
        );
    }
    info!("wss listener on {}", addr);
    let shape = shape_from_env();
    if shape.cover.is_some() {
        info!("wss: traffic shaping ON — size-bucket padding + idle cover traffic");
    }

    // One shared link-count map for the per-peer cap within this listener.
    let connected: ConnectedPeers = Arc::new(Mutex::new(HashMap::new()));

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("wss accept error: {}", e);
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let conn = conn.clone();
        let connected = connected.clone();
        let path = path.clone();
        let shape = shape.clone();
        tokio::spawn(async move {
            if let Err(e) =
                serve_one(tcp, peer, acceptor, conn, connected, path, shape).await
            {
                debug!("wss serve from {}: {:#}", peer, e);
            }
        });
    }
}

async fn serve_one(
    tcp: TcpStream,
    peer: std::net::SocketAddr,
    acceptor: TlsAcceptor,
    conn: Arc<PacketConn>,
    connected: ConnectedPeers,
    mesh_path: String,
    shape: ShapeConfig,
) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    // TLS handshake + HTTP head, under the handshake budget.
    let (mut tls, req) = timeout(WSS_HANDSHAKE_TIMEOUT, async {
        let mut tls = acceptor.accept(tcp).await.context("wss TLS accept")?;
        let head = read_http_head(&mut tls).await.context("wss read http head")?;
        Ok::<_, anyhow::Error>((tls, parse_request(&head)))
    })
    .await
    .map_err(|_| anyhow!("wss handshake timed out"))??;

    let is_mesh = req
        .as_ref()
        .is_some_and(|r| r.ws_upgrade && r.path == mesh_path && r.ws_key.is_some());
    if !is_mesh {
        // Probe / stray client — behave like a plain web server.
        serve_probe_page(&mut tls).await;
        return Ok(());
    }

    let key = req.unwrap().ws_key.unwrap();
    let resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        ws_accept(&key),
    );
    tls.write_all(resp.as_bytes()).await.context("wss 101 send")?;
    tls.flush().await.context("wss 101 flush")?;

    // Established — the server role does not mask outgoing frames.
    if shape.cover.is_some() {
        // Cover traffic on: a write pump owns the TLS write side so it
        // can slip cover frames in during idle; norn writes to a duplex.
        let (tls_r, tls_w) = tokio::io::split(tls);
        let reader = WsStream::new(tls_r, false, ShapeConfig::off());
        let (norn_side, pump_side) = tokio::io::duplex(64 * 1024);
        tokio::spawn(write_pump(pump_side, tls_w, false, shape));
        serve_authenticated_link(
            conn,
            connected,
            peer.to_string(),
            Box::new(reader),
            Box::new(norn_side),
        )
        .await;
    } else {
        let (r, w) = tokio::io::split(WsStream::new(tls, false, shape));
        serve_authenticated_link(conn, connected, peer.to_string(), Box::new(r), Box::new(w))
            .await;
    }
    Ok(())
}

/// Serve a plain, boring, consistent web page to a non-mesh connection.
async fn serve_probe_page<S: AsyncWrite + Unpin>(s: &mut S) {
    const BODY: &str = "<!doctype html><html><head><title>Welcome</title></head>\
                        <body><h1>It works!</h1></body></html>";
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
        BODY.len(),
        BODY,
    );
    let _ = s.write_all(resp.as_bytes()).await;
    let _ = s.flush().await;
}

// ── Dialer ────────────────────────────────────────────────────────────────

/// Dial a `wss://` peer, reconnecting with backoff — symmetric to
/// norn-rs's `transport::dial` / `quic::dial`.
pub async fn dial(uri: &str, conn: Arc<PacketConn>, psk: Option<[u8; 32]>) {
    let addr = match parse_wss_uri(uri) {
        Ok(a) => a,
        Err(e) => {
            warn!("bad wss URI {}: {}", uri, e);
            return;
        }
    };
    let connector = match client_tls() {
        Ok(c) => c,
        Err(e) => {
            warn!("wss client TLS config: {:#}", e);
            return;
        }
    };
    let path = mesh_path(psk);
    let shape = shape_from_env();
    if shape.cover.is_some() {
        info!("wss: traffic shaping ON — size-bucket padding + idle cover traffic");
    }
    let connected: ConnectedPeers = Arc::new(Mutex::new(HashMap::new()));

    let mut delay = Duration::from_secs(1);
    loop {
        match dial_once(&addr, &connector, &path, &conn, &connected, &shape).await {
            Ok(()) => delay = Duration::from_secs(5),
            Err(e) => debug!("wss dial {}: {:#}", addr, e),
        }
        tokio::time::sleep(delay).await;
        let jitter = 0.8 + rand::random::<f64>() * 0.4;
        delay = Duration::from_millis((delay.as_millis() as f64 * 2.0 * jitter) as u64)
            .min(Duration::from_secs(60));
    }
}

/// Spawn a cloak transport task for each given URI: `listen_uris`
/// become `wss://` listeners, `peer_uris` become `wss://` dialers, all
/// bound to `conn`. Non-`wss://` URIs are skipped (norn-rs owns those),
/// so a caller may pass its full lists. Must be called from within a
/// Tokio runtime. This is the single entry point a consuming binary
/// (bifrost-vpnd / bifrost-ffi) calls after `node.start()`.
pub fn spawn_wss(
    conn: Arc<PacketConn>,
    listen_uris: Vec<String>,
    peer_uris: Vec<String>,
    psk: Option<[u8; 32]>,
) {
    for uri in listen_uris {
        if !uri.starts_with("wss://") {
            continue;
        }
        let conn = conn.clone();
        tokio::spawn(async move {
            if let Err(e) = listen(&uri, conn, psk).await {
                tracing::error!("wss listener {}: {:#}", uri, e);
            }
        });
    }
    for uri in peer_uris {
        if !uri.starts_with("wss://") {
            continue;
        }
        let conn = conn.clone();
        tokio::spawn(async move {
            dial(&uri, conn, psk).await;
        });
    }
}

async fn dial_once(
    addr: &str,
    connector: &TlsConnector,
    path: &str,
    conn: &Arc<PacketConn>,
    connected: &ConnectedPeers,
    shape: &ShapeConfig,
) -> Result<()> {
    // host for the SNI / Host header — strip the port and IPv6 brackets.
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');

    let tls = timeout(WSS_HANDSHAKE_TIMEOUT, async {
        let tcp = TcpStream::connect(addr).await.context("wss TCP connect")?;
        let _ = tcp.set_nodelay(true);
        // `ServerName::try_from` on an IP literal yields the IpAddress
        // variant → rustls sends NO SNI extension (correct for an
        // IP-addressed endpoint; a blank SNI is unremarkable).
        let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
            .context("wss server name")?;
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .context("wss TLS connect")?;

        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\n\
             Upgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n\
             User-Agent: Mozilla/5.0\r\n\r\n",
            b64(&nonce),
        );
        tls.write_all(req.as_bytes()).await.context("wss upgrade send")?;
        tls.flush().await.context("wss upgrade flush")?;

        let head = read_http_head(&mut tls).await.context("wss read response")?;
        if !head.starts_with(b"HTTP/1.1 101") {
            bail!("peer did not upgrade (served a page? wrong mesh path / PSK)");
        }
        Ok::<_, anyhow::Error>(tls)
    })
    .await
    .map_err(|_| anyhow!("wss handshake timed out"))??;

    // The client role masks outgoing frames (RFC 6455).
    if shape.cover.is_some() {
        let (tls_r, tls_w) = tokio::io::split(tls);
        let reader = WsStream::new(tls_r, false, ShapeConfig::off());
        let (norn_side, pump_side) = tokio::io::duplex(64 * 1024);
        tokio::spawn(write_pump(pump_side, tls_w, true, shape.clone()));
        serve_authenticated_link(
            conn.clone(),
            connected.clone(),
            addr.to_string(),
            Box::new(reader),
            Box::new(norn_side),
        )
        .await;
    } else {
        let (r, w) = tokio::io::split(WsStream::new(tls, true, shape.clone()));
        serve_authenticated_link(
            conn.clone(),
            connected.clone(),
            addr.to_string(),
            Box::new(r),
            Box::new(w),
        )
        .await;
    }
    Ok(())
}

/// Drive the write side when cover traffic is on: frame norn's byte
/// stream into WebSocket data frames and, in write-idle gaps, slip in
/// opcode-0x3 cover frames the peer silently drops — so the link never
/// shows the "bulk then dead silence" shape of a VPN. Runs as its own
/// task; ends when norn closes its side or a TLS write fails.
async fn write_pump<R, W>(mut from_norn: R, mut tls_w: W, mask_tx: bool, shape: ShapeConfig)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 32 * 1024];
    let mut frame = Vec::new();
    loop {
        tokio::select! {
            biased;
            // Real data takes priority — it is never delayed for cover.
            r = from_norn.read(&mut buf) => {
                let n = match r {
                    Ok(0) | Err(_) => break, // norn closed its side / pipe error
                    Ok(n) => n,
                };
                frame.clear();
                encode_frame(0x2, &shape.wrap(&buf[..n]), mask_tx, &mut frame);
                if tls_w.write_all(&frame).await.is_err() || tls_w.flush().await.is_err() {
                    break;
                }
            }
            // Write-idle for a randomised gap → emit one cover frame.
            _ = tokio::time::sleep(shape.next_cover_delay()) => {
                frame.clear();
                encode_frame(0x3, &shape.cover_payload(), mask_tx, &mut frame);
                if tls_w.write_all(&frame).await.is_err() || tls_w.flush().await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = tls_w.shutdown().await;
}

// ── WebSocket framing ─────────────────────────────────────────────────────

/// One decoded WebSocket frame.
struct WsFrame {
    opcode: u8,
    payload: Vec<u8>,
}

/// Append one unfragmented WebSocket frame (FIN=1) to `dst`. `mask` =
/// true for the client role (RFC 6455 requires client→server masking).
fn encode_frame(opcode: u8, payload: &[u8], mask: bool, dst: &mut Vec<u8>) {
    dst.push(0x80 | (opcode & 0x0f)); // FIN + opcode
    let mask_bit = if mask { 0x80 } else { 0x00 };
    let len = payload.len();
    if len < 126 {
        dst.push(mask_bit | len as u8);
    } else if len <= u16::MAX as usize {
        dst.push(mask_bit | 126);
        dst.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        dst.push(mask_bit | 127);
        dst.extend_from_slice(&(len as u64).to_be_bytes());
    }
    if mask {
        let mut key = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut key);
        dst.extend_from_slice(&key);
        for (i, b) in payload.iter().enumerate() {
            dst.push(b ^ key[i & 3]);
        }
    } else {
        dst.extend_from_slice(payload);
    }
}

/// Try to parse one frame off the front of `buf`. `Ok(None)` = need more
/// bytes; `Ok(Some(_))` consumes the frame from `buf`; `Err` = a
/// protocol violation (an oversized frame).
fn try_parse_frame(buf: &mut Vec<u8>) -> io::Result<Option<WsFrame>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let opcode = buf[0] & 0x0f;
    let masked = buf[1] & 0x80 != 0;
    let len7 = (buf[1] & 0x7f) as usize;
    let mut off = 2;
    let payload_len = match len7 {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            off = 4;
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            off = 10;
            let l = u64::from_be_bytes(buf[2..10].try_into().unwrap());
            if l > MAX_WS_FRAME as u64 {
                return Err(io::Error::other("oversized WebSocket frame"));
            }
            l as usize
        }
        n => n,
    };
    if payload_len > MAX_WS_FRAME {
        return Err(io::Error::other("oversized WebSocket frame"));
    }
    let mask_key = if masked {
        if buf.len() < off + 4 {
            return Ok(None);
        }
        let k = [buf[off], buf[off + 1], buf[off + 2], buf[off + 3]];
        off += 4;
        Some(k)
    } else {
        None
    };
    if buf.len() < off + payload_len {
        return Ok(None);
    }
    let mut payload = buf[off..off + payload_len].to_vec();
    if let Some(k) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= k[i & 3];
        }
    }
    buf.drain(0..off + payload_len);
    Ok(Some(WsFrame { opcode, payload }))
}

/// A WebSocket message stream presented to norn as a plain byte pipe.
/// Outgoing bytes become Binary frames; incoming data-frame payloads are
/// concatenated into the read stream (norn does its own framing inside,
/// so WebSocket message boundaries are irrelevant). Ping/Pong frames are
/// ignored — both ends are norn nodes and never send them; a Close frame
/// (or an inner EOF) ends the stream.
struct WsStream<S> {
    inner: S,
    mask_tx: bool,
    shape: ShapeConfig,
    in_raw: Vec<u8>,
    in_data: Vec<u8>,
    in_pos: usize,
    eof: bool,
    out_buf: Vec<u8>,
    out_pos: usize,
}

impl<S> WsStream<S> {
    fn new(inner: S, mask_tx: bool, shape: ShapeConfig) -> Self {
        WsStream {
            inner,
            mask_tx,
            shape,
            in_raw: Vec::new(),
            in_data: Vec::new(),
            in_pos: 0,
            eof: false,
            out_buf: Vec::new(),
            out_pos: 0,
        }
    }
}

impl<S: AsyncWrite + Unpin> WsStream<S> {
    /// Push `out_buf[out_pos..]` into `inner`. `Ready(Ok)` only when the
    /// buffer is fully drained.
    fn drain_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.out_buf[self.out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "wss: inner writer accepted zero bytes",
                    )));
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out_buf.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            // Hand over already-decoded payload bytes.
            if me.in_pos < me.in_data.len() {
                let n = (me.in_data.len() - me.in_pos).min(buf.remaining());
                buf.put_slice(&me.in_data[me.in_pos..me.in_pos + n]);
                me.in_pos += n;
                return Poll::Ready(Ok(()));
            }
            me.in_data.clear();
            me.in_pos = 0;
            // Decode the next frame already buffered.
            match try_parse_frame(&mut me.in_raw) {
                Err(e) => return Poll::Ready(Err(e)),
                Ok(Some(frame)) => {
                    match frame.opcode {
                        0x0..=0x2 => {
                            // data frame: payload is [real_len: u32 BE][data][pad].
                            let p = &frame.payload;
                            if p.len() < 4 {
                                return Poll::Ready(Err(io::Error::other(
                                    "wss: data frame shorter than its length prefix",
                                )));
                            }
                            let real_len =
                                u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
                            if 4 + real_len > p.len() {
                                return Poll::Ready(Err(io::Error::other(
                                    "wss: inner length exceeds the frame",
                                )));
                            }
                            if real_len > 0 {
                                me.in_data = frame.payload;
                                me.in_data.truncate(4 + real_len);
                                me.in_pos = 4; // skip the length prefix
                            }
                            continue;
                        }
                        0x8 => {
                            me.eof = true; // Close → EOF
                            return Poll::Ready(Ok(()));
                        }
                        _ => continue, // ping / pong / other — ignore
                    }
                }
                Ok(None) => {} // need more bytes
            }
            if me.eof {
                return Poll::Ready(Ok(())); // already at EOF, no full frame
            }
            // Pull more raw bytes from the inner stream.
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let got = rb.filled();
                    if got.is_empty() {
                        me.eof = true;
                        return Poll::Ready(Ok(())); // inner EOF
                    }
                    me.in_raw.extend_from_slice(got);
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Flush any leftover from a previous backpressured write first.
        match me.drain_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Wrap as an inner record [real_len][data][pad], then frame it.
        let payload = me.shape.wrap(buf);
        encode_frame(0x2, &payload, me.mask_tx, &mut me.out_buf);
        // Best-effort flush; whatever doesn't go now drains on the next call.
        if let Poll::Ready(Err(e)) = me.drain_out(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.drain_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.drain_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_wss_uri_ok_and_err() {
        assert_eq!(parse_wss_uri("wss://1.2.3.4:9000").unwrap(), "1.2.3.4:9000");
        assert!(parse_wss_uri("tcp://1.2.3.4:9000").is_err());
        assert!(parse_wss_uri("").is_err());
    }

    #[test]
    fn base64_known_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foob"), "Zm9vYg==");
        assert_eq!(b64(b"fooba"), "Zm9vYmE=");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn ws_accept_rfc6455_vector() {
        // RFC 6455 §1.3 worked example.
        assert_eq!(
            ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        );
    }

    #[test]
    fn mesh_path_psk_derived_and_default() {
        assert_eq!(mesh_path(None), "/ws");
        let p = mesh_path(Some([7u8; 32]));
        assert!(p.starts_with('/') && p.len() == 33, "32 hex chars after the slash");
        assert_ne!(p, "/ws");
        assert_eq!(mesh_path(Some([7u8; 32])), p, "PSK-derived path is deterministic");
    }

    #[test]
    fn frame_round_trips_unmasked_and_masked() {
        let edge = [0xCDu8; 126]; // exactly the 7-bit → 16-bit length boundary
        let mid = [0xABu8; 130];
        let big = vec![0x5Au8; 70_000]; // crosses the 16-bit → 64-bit boundary
        for mask in [false, true] {
            for payload in [
                b"".as_slice(),
                b"hello".as_slice(),
                edge.as_slice(),
                mid.as_slice(),
                big.as_slice(),
            ] {
                let mut buf = Vec::new();
                encode_frame(0x2, payload, mask, &mut buf);
                let frame = try_parse_frame(&mut buf).unwrap().unwrap();
                assert_eq!(frame.opcode, 0x2);
                assert_eq!(frame.payload, payload);
                assert!(buf.is_empty(), "the frame must be fully consumed");
            }
        }
    }

    #[test]
    fn try_parse_frame_needs_more_bytes() {
        let mut full = Vec::new();
        encode_frame(0x2, b"the quick brown fox", true, &mut full);
        // One byte short → "need more".
        let mut partial = full[..full.len() - 1].to_vec();
        assert!(try_parse_frame(&mut partial).unwrap().is_none());
        // The final byte completes it.
        partial.push(*full.last().unwrap());
        let frame = try_parse_frame(&mut partial).unwrap().unwrap();
        assert_eq!(frame.payload, b"the quick brown fox");
    }

    #[test]
    fn parse_request_extracts_ws_upgrade() {
        let head = b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Key: abc\r\n\r\n";
        let r = parse_request(head).unwrap();
        assert_eq!(r.path, "/ws");
        assert!(r.ws_upgrade);
        assert_eq!(r.ws_key.as_deref(), Some("abc"));

        let plain = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(!parse_request(plain).unwrap().ws_upgrade);

        // Both `Upgrade: websocket` AND `Connection: Upgrade` are
        // required — one header alone is not a WebSocket upgrade.
        let no_conn = b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\nSec-WebSocket-Key: k\r\n\r\n";
        assert!(!parse_request(no_conn).unwrap().ws_upgrade);
        let no_upg = b"GET /ws HTTP/1.1\r\nConnection: Upgrade\r\nSec-WebSocket-Key: k\r\n\r\n";
        assert!(!parse_request(no_upg).unwrap().ws_upgrade);
    }

    #[tokio::test]
    async fn wsstream_round_trips_over_a_pipe() {
        // A client-role WsStream and a server-role WsStream over an
        // in-memory duplex — exercises the real poll_read / poll_write.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = WsStream::new(a, true, ShapeConfig::off()); // masks
        let mut server = WsStream::new(b, false, ShapeConfig::off()); // does not mask

        let msg = b"NRN1 ... a chunk of mesh bytes crossing frame sizes ".repeat(40);
        let sent = msg.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.flush().await.unwrap();
            client
        });
        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        let _client = writer.await.unwrap();
        assert_eq!(got, msg, "the wss byte pipe must round-trip losslessly");
    }

    /// End-to-end: two real norn nodes, one running a `wss://` listener
    /// and the other dialling it. The full TLS 1.3 + WebSocket + NRN1
    /// chain must link them. Mirrors `quic.rs`'s `end_to_end_quic_handshake`.
    #[tokio::test]
    async fn wss_links_two_real_nodes() {
        use norn_rs::config::NodeConfig;
        use norn_rs::node::Node;

        fn cfg(key_hex: &str) -> NodeConfig {
            // Minimal config — empty listen/peers (the wss transport is
            // driven by hand below), no TUN, admin socket disabled.
            serde_json::from_str(&format!(
                r#"{{"private_key":"{key_hex}","listen":[],"peers":[],"tun_name":null,
                    "multicast_enabled":false,"mdns_enabled":false,"peer_cache_path":"",
                    "admin_socket":""}}"#
            ))
            .expect("minimal NodeConfig must deserialize")
        }

        let mut ka = [0u8; 32];
        let mut kb = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ka);
        rand::rngs::OsRng.fill_bytes(&mut kb);
        let node_a = Node::new(cfg(&hex::encode(ka))).await.expect("node A");
        let node_b = Node::new(cfg(&hex::encode(kb))).await.expect("node B");
        node_a.start().await.expect("node A start");
        node_b.start().await.expect("node B start");
        let pub_b = node_b.conn.pub_key;

        // Random high port so parallel test runs don't collide.
        let port = 34000 + (rand::random::<u16>() % 4000);
        let uri = format!("wss://127.0.0.1:{port}");

        let conn_a = node_a.conn.clone();
        let listen_uri = uri.clone();
        let listener = tokio::spawn(async move {
            let _ = listen(&listen_uri, conn_a, None).await;
        });
        tokio::time::sleep(Duration::from_millis(250)).await;

        let conn_b = node_b.conn.clone();
        let dialer = tokio::spawn(async move {
            dial(&uri, conn_b, None).await;
        });

        // Up to ~6s for the TLS + WebSocket + NRN1 handshakes to land.
        let mut linked = false;
        for _ in 0..60 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let a_sees = node_a.conn.get_peer_stats().iter().any(|p| p.key == pub_b);
            let b_sees = !node_b.conn.get_peer_stats().is_empty();
            if a_sees && b_sees {
                linked = true;
                break;
            }
        }
        listener.abort();
        dialer.abort();
        assert!(linked, "wss:// transport must link the two nodes within ~6s");
    }

    #[test]
    fn encode_frame_uses_minimal_length_field() {
        // A <126-byte payload must use the 7-bit length form (2-byte
        // header), not a needlessly-wide extended length.
        let mut small = Vec::new();
        encode_frame(0x2, b"hello", false, &mut small);
        assert_eq!(small.len(), 2 + 5, "small payload → 7-bit length header");
        // 126..=65535 → the 16-bit length form (4-byte header).
        let mut mid = Vec::new();
        encode_frame(0x2, &[0u8; 200], false, &mut mid);
        assert_eq!(mid.len(), 4 + 200, "mid payload → 16-bit length header");
        // A masked frame carries the extra 4-byte masking key.
        let mut masked = Vec::new();
        encode_frame(0x2, b"hello", true, &mut masked);
        assert_eq!(masked.len(), 2 + 4 + 5, "masked frame includes the 4-byte key");
    }

    #[test]
    fn try_parse_frame_partial_lengths_and_oversize() {
        // A 16-bit-length frame with the length field cut short → need more.
        let mut p16 = vec![0x82u8, 126, 0x00];
        assert!(try_parse_frame(&mut p16).unwrap().is_none());
        // A 64-bit-length frame with the length field cut short → need more.
        let mut p64 = vec![0x82u8, 127, 0, 0, 0];
        assert!(try_parse_frame(&mut p64).unwrap().is_none());
        // A 64-bit length claiming more than MAX_WS_FRAME → hard error.
        let mut huge = vec![0x82u8, 127];
        huge.extend_from_slice(&(MAX_WS_FRAME as u64 + 1).to_be_bytes());
        assert!(try_parse_frame(&mut huge).is_err(), "oversize frame must error");
    }

    #[tokio::test]
    async fn wsstream_delivers_payload_across_small_reads() {
        // Read the decoded payload out in buffers smaller than the
        // message — exercises the in_pos advance across poll_reads.
        let (a, b) = tokio::io::duplex(64 * 1024);
        let mut client = WsStream::new(a, true, ShapeConfig::off());
        let mut server = WsStream::new(b, false, ShapeConfig::off());
        let msg = vec![0x41u8; 5000];
        let sent = msg.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.flush().await.unwrap();
            client
        });
        let mut got = Vec::new();
        let mut chunk = [0u8; 64];
        while got.len() < msg.len() {
            let n = server.read(&mut chunk).await.unwrap();
            assert!(n > 0, "unexpected EOF before the message completed");
            got.extend_from_slice(&chunk[..n]);
        }
        let _ = writer.await.unwrap();
        assert_eq!(got, msg);
    }

    #[tokio::test]
    async fn wsstream_close_frame_surfaces_as_eof() {
        // A Close frame ends the read stream even while the underlying
        // socket stays open (i.e. it is the Close, not a socket EOF).
        let (mut raw, inner) = tokio::io::duplex(4096);
        let mut close = Vec::new();
        encode_frame(0x8, b"", false, &mut close);
        raw.write_all(&close).await.unwrap();
        raw.flush().await.unwrap();
        let mut ws = WsStream::new(inner, false, ShapeConfig::off());
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf)).await;
        assert!(matches!(r, Ok(Ok(0))), "a Close frame must surface as EOF");
        drop(raw);
    }

    #[test]
    fn shape_config_pads_to_buckets() {
        // off: just the 4-byte length prefix, no pad.
        assert_eq!(ShapeConfig::off().wrap(b"hello").len(), 4 + 5);
        let on = ShapeConfig::padded();
        // a small payload rounds up to the first bucket.
        let small = on.wrap(b"hi");
        assert_eq!(small.len(), 256, "small frame padded to the 256-byte bucket");
        // the declared inner length is still the real 2 bytes.
        assert_eq!(u32::from_be_bytes([small[0], small[1], small[2], small[3]]), 2);
        // a payload larger than every bucket is left unpadded.
        let big = on.wrap(&[0u8; 40_000]);
        assert_eq!(big.len(), 4 + 40_000, "oversize frame is not padded");
    }

    #[tokio::test]
    async fn wsstream_round_trips_with_padding() {
        // Padding is sender-local: a padded client and an unpadded
        // server still round-trip — the receiver strips it regardless.
        let (a, b) = tokio::io::duplex(256 * 1024);
        let mut client = WsStream::new(a, true, ShapeConfig::padded());
        let mut server = WsStream::new(b, false, ShapeConfig::off());
        let msg = b"a short control-sized message ".repeat(4);
        let sent = msg.clone();
        let writer = tokio::spawn(async move {
            client.write_all(&sent).await.unwrap();
            client.flush().await.unwrap();
            client
        });
        let mut got = vec![0u8; msg.len()];
        server.read_exact(&mut got).await.unwrap();
        let _ = writer.await.unwrap();
        assert_eq!(got, msg, "padded frames must round-trip losslessly");
    }

    #[tokio::test]
    async fn write_pump_frames_data_and_injects_cover() {
        // Tiny cover-idle range so cover frames appear within the test.
        let shape = ShapeConfig {
            pad_buckets: Vec::new(),
            cover: Some((Duration::from_millis(30), Duration::from_millis(60))),
        };
        let (mut norn_side, pump_side) = tokio::io::duplex(64 * 1024);
        let (tls_side, mut wire) = tokio::io::duplex(64 * 1024);
        tokio::spawn(write_pump(pump_side, tls_side, false, shape));

        norn_side.write_all(b"hello mesh").await.unwrap();
        norn_side.flush().await.unwrap();

        let mut raw = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut data_ok = false;
        let mut cover_ok = false;
        for _ in 0..40 {
            if data_ok && cover_ok {
                break;
            }
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(50), wire.read(&mut chunk)).await
            {
                if n == 0 {
                    break;
                }
                raw.extend_from_slice(&chunk[..n]);
            }
            while let Some(frame) = try_parse_frame(&mut raw).unwrap() {
                match frame.opcode {
                    0x2 => {
                        let p = &frame.payload;
                        let real = u32::from_be_bytes([p[0], p[1], p[2], p[3]]) as usize;
                        if &p[4..4 + real] == b"hello mesh" {
                            data_ok = true;
                        }
                    }
                    0x3 => cover_ok = true,
                    _ => {}
                }
            }
        }
        assert!(data_ok, "norn's bytes must arrive as an 0x2 data frame");
        assert!(cover_ok, "an idle pump must emit 0x3 cover frames");
    }

    #[tokio::test]
    async fn wsstream_drops_cover_frames() {
        // An opcode-0x3 cover frame between data frames is silently
        // dropped — it must never reach norn's byte stream.
        let (mut raw, inner) = tokio::io::duplex(8192);
        let mut wire = Vec::new();
        encode_frame(0x3, b"cover padding bytes", false, &mut wire);
        encode_frame(0x2, &ShapeConfig::off().wrap(b"real"), false, &mut wire);
        raw.write_all(&wire).await.unwrap();
        raw.flush().await.unwrap();
        let mut ws = WsStream::new(inner, false, ShapeConfig::off());
        let mut got = [0u8; 4];
        ws.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"real", "cover frames must not reach the byte stream");
        drop(raw);
    }
}
