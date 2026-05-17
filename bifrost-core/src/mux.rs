// MeshMux — one read loop over a shared norn-rs PacketConn, demultiplexing
// inbound frames into per-stream channels and surfacing accepted Open
// requests to a single accept queue.
//
// Outgoing writes go directly through Arc<PacketConn>::write_to — the
// session layer inside norn-rs is itself async and lock-managed, so we
// don't need our own writer task. Each MeshStream just hands frames off.

use anyhow::Result;
use norn_rs::PacketConn;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

/// Max retries while waiting for the ChaCha20-Poly1305 session handshake
/// to complete on the first packet to a fresh peer. write_to errors with
/// "session not established" until handshake bytes flow both ways; the
/// init message is queued by write_to as a side effect, so each retry
/// nudges the handshake forward.
const SESSION_WAIT_RETRIES: usize = 50;
const SESSION_WAIT_INTERVAL: Duration = Duration::from_millis(100);

use crate::frame::{Frame, OpenTarget};
use crate::stream::{MeshStream, StreamEvent, INBOUND_CHAN_DEPTH};
use crate::{PubKey, StreamId};

/// Anything the mux needs to push at a stream — buffered bytes or a
/// half-close signal.
type StreamSender = mpsc::Sender<StreamEvent>;

#[derive(Default)]
struct StreamTable {
    entries: HashMap<(PubKey, StreamId), StreamSender>,
    next_sid: u32,
}

impl StreamTable {
    fn allocate(&mut self) -> StreamId {
        // Stream IDs are simple monotonic counters — wrap protection isn't
        // necessary for any plausible single-process lifetime, but make
        // wrap explicit so the assumption is documented.
        let sid = self.next_sid;
        self.next_sid = self.next_sid.wrapping_add(1);
        sid
    }
}

pub struct MeshMux {
    conn: Arc<PacketConn>,
    table: Arc<Mutex<StreamTable>>,
    accept_tx: mpsc::Sender<AcceptedStream>,
}

/// One newly-arrived `Open` from a peer, ready to be turned into a stream.
pub struct AcceptedStream {
    pub from: PubKey,
    pub target: OpenTarget,
    pub stream: MeshStream,
}

impl MeshMux {
    /// Wrap a PacketConn in a mux. The returned receiver yields accepted
    /// streams (server side). Drop the receiver to ignore inbound Opens
    /// entirely (client-only deployments).
    pub fn new(conn: Arc<PacketConn>) -> (Arc<Self>, mpsc::Receiver<AcceptedStream>) {
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let mux = Arc::new(Self {
            conn: conn.clone(),
            table: Arc::new(Mutex::new(StreamTable::default())),
            accept_tx,
        });
        tokio::spawn(read_loop(mux.clone()));
        (mux, accept_rx)
    }

    pub fn conn(&self) -> &Arc<PacketConn> {
        &self.conn
    }

    /// Open a new outbound stream toward `peer`. The returned MeshStream
    /// is usable immediately for writes; the OpenAck reply is delivered
    /// as a StreamEvent::OpenAck on the read side so callers can wait
    /// for SOCKS5-style success/failure before forwarding application
    /// bytes.
    pub async fn open(self: &Arc<Self>, peer: PubKey, target: OpenTarget) -> Result<MeshStream> {
        let (tx, rx) = mpsc::channel(INBOUND_CHAN_DEPTH);
        let sid = {
            let mut t = self.table.lock().expect("StreamTable mutex poisoned");
            let sid = t.allocate();
            t.entries.insert((peer, sid), tx);
            sid
        };
        let stream = MeshStream::new(self.clone(), peer, sid, rx);
        let frame = Frame::Open { sid, target };
        let bytes = frame.encode()?;
        if let Err(e) = write_with_session_wait(&self.conn, &peer, &bytes).await {
            // Roll the entry back so the SID isn't leaked.
            self.drop_stream(&peer, sid);
            anyhow::bail!("write_to(open): {e}");
        }
        Ok(stream)
    }

    /// Send a raw frame for an existing stream. Used by MeshStream's
    /// AsyncWrite / shutdown paths. Retries through the brief window
    /// while a session is mid-handshake (see SESSION_WAIT_RETRIES).
    pub async fn send_frame(&self, peer: &PubKey, frame: Frame) -> Result<()> {
        let bytes = frame.encode()?;
        write_with_session_wait(&self.conn, peer, &bytes).await
    }

    /// Forget an entry — called by MeshStream on Drop or after a Reset.
    pub fn drop_stream(&self, peer: &PubKey, sid: StreamId) {
        if let Ok(mut t) = self.table.lock() {
            t.entries.remove(&(*peer, sid));
        }
    }

    /// Server-side accept-completion: hand a Sender to the mux so future
    /// DATA/CLOSE/RESET frames for that (peer, sid) flow back. Returns
    /// false if a competing entry already exists (duplicate Open).
    fn install_inbound(&self, peer: PubKey, sid: StreamId, tx: StreamSender) -> bool {
        let mut t = self.table.lock().expect("StreamTable mutex poisoned");
        if t.entries.contains_key(&(peer, sid)) {
            return false;
        }
        t.entries.insert((peer, sid), tx);
        true
    }
}

async fn read_loop(mux: Arc<MeshMux>) {
    let conn = mux.conn.clone();
    loop {
        let pkt = match conn.read_from().await {
            Ok(p) => p,
            Err(e) => {
                warn!("mux read_loop: read_from error: {e} — exiting");
                return;
            }
        };
        let frame = match Frame::decode(&pkt.payload) {
            Ok(f) => f,
            Err(e) => {
                trace!("mux: drop undecodable frame from {}: {}", hex::encode(&pkt.from[..8]), e);
                continue;
            }
        };
        let peer = pkt.from;
        match frame {
            Frame::Open { sid, target } => {
                let (tx, rx) = mpsc::channel(INBOUND_CHAN_DEPTH);
                if !mux.install_inbound(peer, sid, tx) {
                    debug!(
                        "mux: duplicate open from {} sid={sid} — dropping",
                        hex::encode(&peer[..8])
                    );
                    continue;
                }
                let stream = MeshStream::new(mux.clone(), peer, sid, rx);
                let accepted = AcceptedStream { from: peer, target, stream };
                if mux.accept_tx.send(accepted).await.is_err() {
                    // No accept consumer — drop the new entry; the
                    // remote will see a closed stream on first Data.
                    mux.drop_stream(&peer, sid);
                }
            }
            Frame::OpenAck { sid, code } => deliver(&mux, &peer, sid, StreamEvent::OpenAck(code)).await,
            Frame::Data { sid, data } => deliver(&mux, &peer, sid, StreamEvent::Data(data)).await,
            Frame::Close { sid } => deliver(&mux, &peer, sid, StreamEvent::Close).await,
            Frame::Reset { sid, code } => {
                deliver(&mux, &peer, sid, StreamEvent::Reset(code)).await;
                mux.drop_stream(&peer, sid);
            }
        }
    }
}

async fn deliver(mux: &Arc<MeshMux>, peer: &PubKey, sid: StreamId, ev: StreamEvent) {
    let sender = {
        let t = mux.table.lock().expect("StreamTable mutex poisoned");
        t.entries.get(&(*peer, sid)).cloned()
    };
    match sender {
        Some(tx) => {
            if tx.send(ev).await.is_err() {
                mux.drop_stream(peer, sid);
            }
        }
        None => {
            // Unknown stream — typically the local side already closed it.
            // Send a Reset back so the peer learns to give up.
            let _ = mux.send_frame(peer, Frame::Reset { sid, code: 0x01 }).await;
        }
    }
}

/// Retrying wrapper around `PacketConn::write_to` that absorbs the
/// transient "session not established" error returned during the
/// first packet to a fresh peer. The retry interval gives the norn
/// handshake (init → response → install) time to land both ways.
async fn write_with_session_wait(conn: &Arc<PacketConn>, peer: &PubKey, bytes: &[u8]) -> Result<()> {
    let mut last: Option<anyhow::Error> = None;
    for _ in 0..SESSION_WAIT_RETRIES {
        match conn.write_to(bytes, peer).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                let s = e.to_string();
                if s.contains("session not established") || s.contains("no route to") {
                    last = Some(e);
                    tokio::time::sleep(SESSION_WAIT_INTERVAL).await;
                    continue;
                }
                return Err(e);
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("session-wait: timed out without progress")))
}

/// Convenience: convert a `mpsc::Receiver<AcceptedStream>` into an async
/// for-each helper. Returns when the mux drops the sender (read loop dead).
pub async fn accept_streams<F, Fut>(mut rx: mpsc::Receiver<AcceptedStream>, mut handler: F)
where
    F: FnMut(AcceptedStream) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    while let Some(acc) = rx.recv().await {
        let fut = handler(acc);
        tokio::spawn(fut);
    }
}
