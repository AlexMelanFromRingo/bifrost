// MeshMux — one read loop over a shared norn-rs PacketConn, demultiplexing
// inbound frames into per-stream channels and surfacing accepted Open
// requests to a single accept queue.
//
// v0.2 adds an ARQ layer: each stream owns an Arc<Mutex<Reliability>>
// that both this mux and the MeshStream consult. A second background
// task (`retransmit_tick`) wakes every 50 ms, walks every live stream,
// and resends Data frames whose RTO has expired.
//
// Outgoing application writes still go directly through Arc<PacketConn>
// from MeshStream::poll_write; the mux only handles ACKs and retransmits
// so that paths the user never polls (idle background streams) still
// recover from loss.

use anyhow::Result;
use norn_rs::PacketConn;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use crate::frame::{Frame, OpenTarget};
use crate::reliability::Reliability;
use crate::stream::{MeshStream, StreamEvent, INBOUND_CHAN_DEPTH};
use crate::{PubKey, StreamId};

/// Max retries while waiting for the ChaCha20-Poly1305 session handshake
/// to complete on the first packet to a fresh peer. Covers cold-start
/// ordering: a local node may boot before its peer is dialable, and
/// norn-rs's own connect-backoff keeps the TCP from settling instantly.
/// 60 s also gives dual-stack docker bridges enough room for the SLAAC /
/// RA chatter that occasionally races our first session-init exchange.
/// Dominated upstream by the caller's own timeout (SOCKS5: 15 s on
/// CONNECT; VPN client: 30 s on its egress Open).
const SESSION_WAIT_RETRIES: usize = 600;
const SESSION_WAIT_INTERVAL: Duration = Duration::from_millis(100);
/// How often the retransmit task scans all live streams. 50 ms gives
/// sub-second response to losses without thrashing on idle muxes.
const RETRANSMIT_TICK: Duration = Duration::from_millis(50);

type StreamSender = mpsc::Sender<StreamEvent>;

#[derive(Clone)]
pub(crate) struct StreamEntry {
    pub tx: StreamSender,
    pub reliability: Arc<Mutex<Reliability>>,
    pub peer: PubKey,
    pub sid: StreamId,
}

#[derive(Default)]
struct StreamTable {
    entries: HashMap<(PubKey, StreamId), StreamEntry>,
    next_sid: u32,
}

impl StreamTable {
    fn allocate(&mut self) -> StreamId {
        let sid = self.next_sid;
        self.next_sid = self.next_sid.wrapping_add(1);
        sid
    }
}

/// Per-channel handler for `Frame::Datagram` frames. Each registered
/// channel gets one sender; the read loop dispatches by the 1-byte
/// channel tag carried in the frame's `sid` low byte.
type DatagramSender = mpsc::Sender<DatagramRecv>;

/// Inbound datagram delivered to a registered channel handler. Mirrors
/// `Frame::Datagram` plus the source pub-key the PacketConn already
/// authenticated for us.
#[derive(Debug, Clone)]
pub struct DatagramRecv {
    pub from: PubKey,
    pub payload: Vec<u8>,
}

pub struct MeshMux {
    conn: Arc<PacketConn>,
    table: Arc<Mutex<StreamTable>>,
    accept_tx: mpsc::Sender<AcceptedStream>,
    /// Channel-tag → handler. Registered once at startup by subsystems
    /// (vpnd uses `DATAGRAM_CHANNEL_EGRESS`); read_loop snapshots a
    /// clone per inbound Datagram so registration is lock-free on the
    /// hot path.
    datagram_handlers: Arc<Mutex<HashMap<u8, DatagramSender>>>,
}

/// Channel tag for `bifrost-vpnd`'s raw IP-packet fast path. Each TUN
/// packet rides a `Frame::Datagram { channel: DATAGRAM_CHANNEL_EGRESS }`
/// directly through MeshMux's read loop, skipping the per-stream ARQ
/// in `MeshStream`. Tags ≤ 0xff are reserved; new subsystems should
/// pick a stable value here so we can't collide across deployments.
pub const DATAGRAM_CHANNEL_EGRESS: u8 = 0x01;

/// One newly-arrived `Open` from a peer, ready to be turned into a stream.
pub struct AcceptedStream {
    pub from: PubKey,
    pub target: OpenTarget,
    pub stream: MeshStream,
}

impl MeshMux {
    /// Wrap a PacketConn in a mux. Returns the mux + an accept-stream
    /// receiver. The mux spawns two tokio tasks: the demux read loop and
    /// the retransmit tick.
    pub fn new(conn: Arc<PacketConn>) -> (Arc<Self>, mpsc::Receiver<AcceptedStream>) {
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let mux = Arc::new(Self {
            conn: conn.clone(),
            table: Arc::new(Mutex::new(StreamTable::default())),
            accept_tx,
            datagram_handlers: Arc::new(Mutex::new(HashMap::new())),
        });
        tokio::spawn(read_loop(mux.clone()));
        tokio::spawn(retransmit_tick(mux.clone()));
        (mux, accept_rx)
    }

    /// Subscribe to inbound `Frame::Datagram` frames carrying `channel`.
    /// Returns a `Receiver<DatagramRecv>` the caller drains; the channel
    /// is bounded so a slow consumer back-pressures the mux read loop
    /// (preferable to unbounded growth — VPN packets are best-effort
    /// anyway, the kernel's TCP/QUIC inside the tunnel handles loss).
    ///
    /// Re-registration on an existing tag replaces the previous handler;
    /// callers must call this once at startup. Returns an error if
    /// `channel` is 0 (reserved as a "no datagrams" sentinel).
    pub fn register_datagram_channel(
        self: &Arc<Self>,
        channel: u8,
        capacity: usize,
    ) -> Result<mpsc::Receiver<DatagramRecv>> {
        if channel == 0 {
            anyhow::bail!("datagram channel 0 is reserved");
        }
        let (tx, rx) = mpsc::channel(capacity);
        let mut h = self.datagram_handlers.lock()
            .expect("datagram_handlers mutex poisoned");
        h.insert(channel, tx);
        Ok(rx)
    }

    /// Send one datagram to `peer` on `channel`. Returns when the
    /// PacketConn has accepted the bytes for transmission; no per-stream
    /// state is touched and there is no retransmit — the caller is
    /// responsible for any reliability they need on top.
    ///
    /// Cheap relative to `mux.send_frame(Frame::Data {...})`: skips
    /// reliability bookkeeping, no seq allocation, no window check, no
    /// retransmit-task entry. The hot path for L3 VPN traffic.
    pub async fn send_datagram(
        &self,
        peer: &PubKey,
        channel: u8,
        payload: &[u8],
    ) -> Result<()> {
        if channel == 0 {
            anyhow::bail!("datagram channel 0 is reserved");
        }
        let frame = Frame::Datagram { channel, payload: payload.to_vec() };
        let bytes = frame.encode()?;
        write_with_session_wait(&self.conn, peer, &bytes).await
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
        let reliability = Arc::new(Mutex::new(Reliability::default()));
        let sid = {
            let mut t = self.table.lock().expect("StreamTable mutex poisoned");
            let sid = t.allocate();
            t.entries.insert(
                (peer, sid),
                StreamEntry { tx, reliability: reliability.clone(), peer, sid },
            );
            sid
        };
        let stream = MeshStream::new(self.clone(), peer, sid, rx, reliability);
        let frame = Frame::Open { sid, target };
        let bytes = frame.encode()?;
        if let Err(e) = write_with_session_wait(&self.conn, &peer, &bytes).await {
            self.drop_stream(&peer, sid);
            anyhow::bail!("write_to(open): {e}");
        }
        Ok(stream)
    }

    /// Send a raw frame for an existing stream. Used by MeshStream's
    /// AsyncWrite / shutdown paths.
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

    /// Server-side accept-completion. Returns false on duplicate Open.
    fn install_inbound(
        &self,
        peer: PubKey,
        sid: StreamId,
        tx: StreamSender,
        reliability: Arc<Mutex<Reliability>>,
    ) -> bool {
        let mut t = self.table.lock().expect("StreamTable mutex poisoned");
        if t.entries.contains_key(&(peer, sid)) {
            return false;
        }
        t.entries
            .insert((peer, sid), StreamEntry { tx, reliability, peer, sid });
        true
    }

    fn lookup_entry(&self, peer: &PubKey, sid: StreamId) -> Option<StreamEntry> {
        let t = self.table.lock().expect("StreamTable mutex poisoned");
        t.entries.get(&(*peer, sid)).cloned()
    }

    fn snapshot_entries(&self) -> Vec<StreamEntry> {
        let t = self.table.lock().expect("StreamTable mutex poisoned");
        t.entries.values().cloned().collect()
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
                let reliability = Arc::new(Mutex::new(Reliability::default()));
                if !mux.install_inbound(peer, sid, tx, reliability.clone()) {
                    debug!(
                        "mux: duplicate open from {} sid={sid} — dropping",
                        hex::encode(&peer[..8])
                    );
                    continue;
                }
                let stream = MeshStream::new(mux.clone(), peer, sid, rx, reliability);
                let accepted = AcceptedStream { from: peer, target, stream };
                if mux.accept_tx.send(accepted).await.is_err() {
                    mux.drop_stream(&peer, sid);
                }
            }
            Frame::OpenAck { sid, code } => {
                signal(&mux, &peer, sid, StreamEvent::OpenAck(code)).await
            }
            Frame::Data { sid, seq, data } => handle_data(&mux, peer, sid, seq, data),
            Frame::Ack { sid, ack, win } => handle_ack(&mux, peer, sid, ack, win),
            Frame::Close { sid, seq } => handle_close(&mux, peer, sid, seq),
            Frame::Reset { sid, code } => {
                signal(&mux, &peer, sid, StreamEvent::Reset(code)).await;
                mux.drop_stream(&peer, sid);
            }
            Frame::Datagram { channel, payload } => {
                // Snapshot the handler clone with the lock held briefly
                // to avoid blocking the read loop on a slow consumer.
                let handler = {
                    let h = mux.datagram_handlers
                        .lock()
                        .expect("datagram_handlers mutex poisoned");
                    h.get(&channel).cloned()
                };
                if let Some(tx) = handler {
                    // Use try_send so a wedged subsystem can't stall the
                    // mux read loop, taking the whole node down with it.
                    // Datagrams are best-effort by contract — dropped
                    // packets are the upper layer's problem (TCP/QUIC
                    // inside a VPN tunnel handles loss end-to-end).
                    let recv = DatagramRecv { from: peer, payload };
                    if let Err(e) = tx.try_send(recv) {
                        match e {
                            mpsc::error::TrySendError::Full(_) => {
                                trace!(
                                    "mux: datagram channel {} full, dropping packet from {}",
                                    channel, hex::encode(&peer[..8])
                                );
                            }
                            mpsc::error::TrySendError::Closed(_) => {
                                debug!(
                                    "mux: datagram channel {} receiver gone — unregistering",
                                    channel
                                );
                                let mut h = mux.datagram_handlers
                                    .lock()
                                    .expect("datagram_handlers mutex poisoned");
                                h.remove(&channel);
                            }
                        }
                    }
                } else {
                    trace!(
                        "mux: dropping datagram from {} on unregistered channel {}",
                        hex::encode(&peer[..8]), channel
                    );
                }
            }
        }
    }
}

fn handle_data(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, seq: u32, data: Vec<u8>) {
    let Some(entry) = mux.lookup_entry(&peer, sid) else {
        // Unknown stream — tell the peer to give up. Fire-and-forget
        // so the read loop doesn't stall on outbound writes.
        let mux2 = mux.clone();
        tokio::spawn(async move {
            let _ = mux2
                .send_frame(&peer, Frame::Reset { sid, code: 0x01 })
                .await;
        });
        return;
    };
    let (outcome, ack_state) = {
        let mut r = entry.reliability.lock().expect("Reliability mutex poisoned");
        let out = r.on_recv_data(seq, data);
        (out, r.ack_state())
    };
    if outcome.send_ack {
        let (ack, win) = ack_state;
        let mux2 = mux.clone();
        tokio::spawn(async move {
            let _ = mux2.send_frame(&peer, Frame::Ack { sid, ack, win }).await;
        });
    }
    if outcome.rx_buf_grew || outcome.eof_ready {
        let _ = entry.tx.try_send(StreamEvent::WakeRead);
    }
}

fn handle_ack(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, ack: u32, win: u32) {
    let Some(entry) = mux.lookup_entry(&peer, sid) else { return; };
    let opened = {
        let mut r = entry.reliability.lock().expect("Reliability mutex poisoned");
        let before_win = r.write_window_available();
        let before_close = r.close_pending();
        r.on_recv_ack(ack, win, std::time::Instant::now());
        let after_win = r.write_window_available();
        let after_close = r.close_pending();
        if before_close && !after_close {
            debug!(
                "ack: close ACKed peer={} sid={} ack={} win={}",
                hex::encode(&peer[..8]), sid, ack, win
            );
        }
        // Wake whenever the window grew OR the FIN got acknowledged.
        after_win > before_win || (before_close && !after_close)
    };
    if opened {
        let _ = entry.tx.try_send(StreamEvent::WakeWrite);
    }
}

fn handle_close(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, seq: u32) {
    let Some(entry) = mux.lookup_entry(&peer, sid) else {
        let mux2 = mux.clone();
        tokio::spawn(async move {
            let _ = mux2
                .send_frame(&peer, Frame::Reset { sid, code: 0x01 })
                .await;
        });
        return;
    };
    let (outcome, ack_state) = {
        let mut r = entry.reliability.lock().expect("Reliability mutex poisoned");
        let out = r.on_recv_close(seq);
        (out, r.ack_state())
    };
    debug!(
        "close: rx peer={} sid={} close_seq={} → ack={} win={}",
        hex::encode(&peer[..8]), sid, seq, ack_state.0, ack_state.1
    );
    if outcome.send_ack {
        let (ack, win) = ack_state;
        let mux2 = mux.clone();
        tokio::spawn(async move {
            let _ = mux2.send_frame(&peer, Frame::Ack { sid, ack, win }).await;
        });
    }
    let _ = entry.tx.try_send(StreamEvent::PeerClose);
    if outcome.eof_ready {
        let _ = entry.tx.try_send(StreamEvent::WakeRead);
    }
}

async fn signal(mux: &Arc<MeshMux>, peer: &PubKey, sid: StreamId, ev: StreamEvent) {
    let Some(entry) = mux.lookup_entry(peer, sid) else { return; };
    if entry.tx.send(ev).await.is_err() {
        mux.drop_stream(peer, sid);
    }
}

async fn retransmit_tick(mux: Arc<MeshMux>) {
    let mut interval = tokio::time::interval(RETRANSMIT_TICK);
    // Skip first immediate tick; we wake when there's actually something to send.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        let entries = mux.snapshot_entries();
        if entries.is_empty() {
            continue;
        }
        let now = Instant::now();
        for entry in entries {
            let jobs = {
                let mut r = entry.reliability.lock().expect("Reliability mutex poisoned");
                r.retransmit_due(now)
            };
            match jobs {
                Err(seq) => {
                    debug!(
                        "mux retransmit: stream {}/{} seq={} exhausted retries — reset",
                        hex::encode(&entry.peer[..8]),
                        entry.sid,
                        seq
                    );
                    let mux2 = mux.clone();
                    let peer = entry.peer;
                    let sid = entry.sid;
                    tokio::spawn(async move {
                        let _ = mux2
                            .send_frame(&peer, Frame::Reset { sid, code: 0x06 })
                            .await;
                    });
                    let _ = entry.tx.try_send(StreamEvent::Reset(0x06));
                    mux.drop_stream(&entry.peer, entry.sid);
                }
                Ok(due) => {
                    for job in due.data_jobs {
                        let frame = Frame::Data {
                            sid: entry.sid,
                            seq: job.seq,
                            data: job.data,
                        };
                        let mux2 = mux.clone();
                        let peer = entry.peer;
                        tokio::spawn(async move {
                            let _ = mux2.send_frame(&peer, frame).await;
                        });
                    }
                    if let Some(job) = due.close_job {
                        debug!(
                            "close: retransmit peer={} sid={} seq={}",
                            hex::encode(&entry.peer[..8]), entry.sid, job.seq
                        );
                        let frame = Frame::Close { sid: entry.sid, seq: job.seq };
                        let mux2 = mux.clone();
                        let peer = entry.peer;
                        tokio::spawn(async move {
                            let _ = mux2.send_frame(&peer, frame).await;
                        });
                    }
                }
            }
        }
    }
}

/// Retrying wrapper around `PacketConn::write_to` that absorbs the
/// transient "session not established" error during the initial
/// handshake. Also retries when no route exists yet.
async fn write_with_session_wait(
    conn: &Arc<PacketConn>,
    peer: &PubKey,
    bytes: &[u8],
) -> Result<()> {
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
