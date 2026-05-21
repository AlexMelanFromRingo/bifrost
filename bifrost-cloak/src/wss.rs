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
        tokio::spawn(async move {
            if let Err(e) = serve_one(tcp, peer, acceptor, conn, connected, path).await {
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
    let (r, w) = tokio::io::split(WsStream::new(tls, false));
    serve_authenticated_link(conn, connected, peer.to_string(), Box::new(r), Box::new(w)).await;
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
    let connected: ConnectedPeers = Arc::new(Mutex::new(HashMap::new()));

    let mut delay = Duration::from_secs(1);
    loop {
        match dial_once(&addr, &connector, &path, &conn, &connected).await {
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
) -> Result<()> {
    // host for the SNI / Host header — strip the port and IPv6 brackets.
    let host = addr.rsplit_once(':').map_or(addr, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');

    let ws = timeout(WSS_HANDSHAKE_TIMEOUT, async {
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
        Ok::<_, anyhow::Error>(WsStream::new(tls, true))
    })
    .await
    .map_err(|_| anyhow!("wss handshake timed out"))??;

    // The client role masks outgoing frames (RFC 6455).
    let (r, w) = tokio::io::split(ws);
    serve_authenticated_link(
        conn.clone(),
        connected.clone(),
        addr.to_string(),
        Box::new(r),
        Box::new(w),
    )
    .await;
    Ok(())
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
    in_raw: Vec<u8>,
    in_data: Vec<u8>,
    in_pos: usize,
    eof: bool,
    out_buf: Vec<u8>,
    out_pos: usize,
}

impl<S> WsStream<S> {
    fn new(inner: S, mask_tx: bool) -> Self {
        WsStream {
            inner,
            mask_tx,
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
                            // data frame (continuation/text/binary) — take payload
                            if !frame.payload.is_empty() {
                                me.in_data = frame.payload;
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
        encode_frame(0x2, buf, me.mask_tx, &mut me.out_buf);
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
        let mut client = WsStream::new(a, true); // masks
        let mut server = WsStream::new(b, false); // does not mask

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
        let mut client = WsStream::new(a, true);
        let mut server = WsStream::new(b, false);
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
        let mut ws = WsStream::new(inner, false);
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_secs(2), ws.read(&mut buf)).await;
        assert!(matches!(r, Ok(Ok(0))), "a Close frame must surface as EOF");
        drop(raw);
    }
}
