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
use tokio::sync::{mpsc, Semaphore};
use tracing::{debug, trace, warn};

use crate::frame::{Frame, OpenTarget};
use crate::reliability::Reliability;
use crate::stream::{MeshStream, StreamEvent, StreamLatch, INBOUND_CHAN_DEPTH};
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

/// Max concurrent live streams a single peer may have open at once. An
/// authenticated peer flooding `Open` frames would otherwise grow the stream
/// table + spawn a handler per Open without bound. Past the cap we refuse new
/// Opens with a `Reset` (drop gracefully — bifrost's documented posture). Set
/// high enough that no legitimate client (a busy browser opens a few hundred
/// concurrent CONNECTs; a VPN egress uses exactly one) ever hits it.
const MAX_STREAMS_PER_PEER: u32 = 1024;

/// Bounds concurrent fire-and-forget control-frame sends (ACK / Reset). Without
/// it, an inbound Data/Open flood spawns one send task per frame; if the
/// outbound path wedges they pile up unboundedly. Best-effort: when exhausted
/// we DROP the control frame (cumulative ACKs self-heal; a dropped Reset only
/// defers peer-side cleanup). Data retransmits do NOT use this path — they must
/// not be dropped, and are already bounded by the per-stream send window.
const MAX_INFLIGHT_CONTROL_SENDS: usize = 2048;

type StreamSender = mpsc::Sender<StreamEvent>;

#[derive(Clone)]
pub(crate) struct StreamEntry {
    pub tx: StreamSender,
    pub reliability: Arc<Mutex<Reliability>>,
    pub peer: PubKey,
    pub sid: StreamId,
    /// Monotonic install generation. The `(peer, sid)` key is *not*
    /// unique over time: a peer that drops and reconnects restarts its
    /// `next_sid` sequence from 0, so its fresh `Open` collides with
    /// the entry from the dead connection. The generation lets
    /// `drop_stream` tell a stale stream's `Drop` apart from the live
    /// successor that now owns the same key — without it, a retired
    /// stream's teardown silently evicts its replacement.
    pub generation: u64,
    /// Lock-free hint: "this stream has at least one Data/Close frame
    /// awaiting an ACK from the peer". The retransmit task reads this
    /// once per stream per tick (50 ms) and skips the
    /// `reliability.lock() + retransmit_due()` path entirely when it
    /// reads false. Empty-stream churn at the 50 ms tick was 22 % of
    /// user-mode CPU under load (see
    /// `bifrost-wan-test-2026-05-18/perf-findings-iter11.md`).
    ///
    /// Writers flip it true on `allocate_seq + record_sent`;
    /// the ACK handler flips it false once `unacked_empty &&
    /// !close_pending`. False-positive is benign (we'd just do the
    /// extra mutex acquire); false-negative is the bug we must
    /// prevent (would never retransmit a lost frame), so flips are
    /// always done with the reliability mutex held.
    pub has_unacked: Arc<std::sync::atomic::AtomicBool>,
    /// Latched OpenAck / Reset values shared with the MeshStream.
    pub latch: Arc<StreamLatch>,
}

impl StreamEntry {
    /// Deliver an event WITHOUT ever blocking the read loop on this
    /// stream's consumer. OpenAck / Reset are latched first so a full
    /// channel can't lose them (see `StreamLatch`); wake hints are
    /// coalescable and safe to drop. Returns false iff the consumer is
    /// gone (receiver dropped).
    fn deliver(&self, ev: StreamEvent) -> bool {
        match ev {
            StreamEvent::OpenAck(code) => self.latch.set_open_ack(code),
            StreamEvent::Reset(code) => self.latch.set_reset(code),
            _ => {}
        }
        !matches!(self.tx.try_send(ev), Err(mpsc::error::TrySendError::Closed(_)))
    }
}

#[derive(Default)]
struct StreamTable {
    entries: HashMap<(PubKey, StreamId), StreamEntry>,
    /// Live stream count per peer, kept in sync with `entries` so the per-peer
    /// cap check is O(1) instead of an O(n) scan of `entries` on every Open
    /// (an O(n) scan would itself be an Open-flood amplifier).
    per_peer: HashMap<PubKey, u32>,
    next_sid: u32,
    next_generation: u64,
}

impl StreamTable {
    fn allocate(&mut self) -> StreamId {
        let sid = self.next_sid;
        self.next_sid = self.next_sid.wrapping_add(1);
        sid
    }

    fn inc_peer(&mut self, peer: PubKey) {
        *self.per_peer.entry(peer).or_insert(0) += 1;
    }

    /// Decrement on stream removal; drop the entry at zero so the map can't
    /// grow unbounded from churned peers.
    fn dec_peer(&mut self, peer: &PubKey) {
        if let Some(c) = self.per_peer.get_mut(peer) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.per_peer.remove(peer);
            }
        }
    }

    /// Hand out the next install generation (see `StreamEntry::generation`).
    /// Starts at 1 so 0 is free as a "never installed" sentinel; a `u64`
    /// counter cannot realistically wrap within a process lifetime.
    fn allocate_generation(&mut self) -> u64 {
        self.next_generation += 1;
        self.next_generation
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
    /// Permits for in-flight fire-and-forget control sends (ACK / Reset).
    /// Bounds the task/memory amplification of an inbound frame flood.
    control_sends: Arc<Semaphore>,
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
    ///
    /// A node that doesn't serve inbound Opens must DROP the receiver (not
    /// park it in a `_rx` binding): the mux then refuses every Open with a
    /// Reset instead of queueing streams nobody will ever accept.
    pub fn new(conn: Arc<PacketConn>) -> (Arc<Self>, mpsc::Receiver<AcceptedStream>) {
        let (accept_tx, accept_rx) = mpsc::channel(64);
        let mux = Arc::new(Self {
            conn: conn.clone(),
            table: Arc::new(Mutex::new(StreamTable::default())),
            accept_tx,
            datagram_handlers: Arc::new(Mutex::new(HashMap::new())),
            control_sends: Arc::new(Semaphore::new(MAX_INFLIGHT_CONTROL_SENDS)),
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
    /// Single attempt, no session-wait: datagrams are best-effort, and the
    /// callers are shared fan-out loops (vpnd's exit TUN reader serves
    /// every client). Riding `write_with_session_wait` here let ONE offline
    /// peer park that loop for up to 60 s and stall downlink for all. A
    /// failed attempt still kicks off session re-establishment inside
    /// `PacketConn::write_to`; the packet itself is dropped (TCP/QUIC inside
    /// the tunnel recovers).
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
        self.conn.write_to(&bytes, peer).await
    }

    pub fn conn(&self) -> &Arc<PacketConn> {
        &self.conn
    }

    /// Fire-and-forget a control frame (ACK / Reset) with bounded concurrency.
    /// Spawning a task per inbound frame is unbounded under a flood; this caps
    /// the in-flight count via a semaphore and DROPS the frame when exhausted.
    /// Safe to drop: cumulative ACKs self-heal on the next data frame, and a
    /// dropped Reset only defers the peer's own cleanup. NOT for data
    /// retransmits (those must not be dropped — see retransmit_tick).
    pub(crate) fn spawn_control_send(self: &Arc<Self>, peer: PubKey, frame: Frame) {
        let Ok(permit) = self.control_sends.clone().try_acquire_owned() else {
            trace!(
                "mux: control-send backlog full ({} max), dropping {:?} to {}",
                MAX_INFLIGHT_CONTROL_SENDS, frame.kind(), hex::encode(&peer[..8])
            );
            return;
        };
        let mux = self.clone();
        tokio::spawn(async move {
            let _permit = permit; // released when the send future completes
            let _ = mux.send_frame(&peer, frame).await;
        });
    }

    /// Open a new outbound stream toward `peer`. The returned MeshStream
    /// is usable immediately for writes; the OpenAck reply is delivered
    /// as a StreamEvent::OpenAck on the read side so callers can wait
    /// for SOCKS5-style success/failure before forwarding application
    /// bytes.
    pub async fn open(self: &Arc<Self>, peer: PubKey, target: OpenTarget) -> Result<MeshStream> {
        let (tx, rx) = mpsc::channel(INBOUND_CHAN_DEPTH);
        let reliability = Arc::new(Mutex::new(Reliability::default()));
        let has_unacked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let latch = Arc::new(StreamLatch::default());
        let (sid, generation) = {
            let mut t = self.table.lock().expect("StreamTable mutex poisoned");
            let sid = t.allocate();
            let generation = t.allocate_generation();
            t.entries.insert(
                (peer, sid),
                StreamEntry {
                    tx, reliability: reliability.clone(), peer, sid, generation,
                    has_unacked: has_unacked.clone(), latch: latch.clone(),
                },
            );
            // Outbound streams count toward the per-peer total too (no cap is
            // enforced here — these are locally initiated, not attacker-driven).
            t.inc_peer(peer);
            (sid, generation)
        };
        let stream = MeshStream::new(
            self.clone(), peer, sid, generation, rx, reliability, has_unacked, latch,
        );
        let frame = Frame::Open { sid, target };
        let bytes = frame.encode()?;
        if let Err(e) = write_with_session_wait(&self.conn, &peer, &bytes).await {
            self.drop_stream(&peer, sid, generation);
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
    /// `generation` guards against a *stale* stream (one already
    /// replaced by a reconnecting peer, see `StreamEntry::generation`)
    /// evicting the live successor that now holds the same `(peer, sid)`.
    pub fn drop_stream(&self, peer: &PubKey, sid: StreamId, generation: u64) {
        if let Ok(mut t) = self.table.lock()
            && t.entries.get(&(*peer, sid)).is_some_and(|e| e.generation == generation)
        {
            t.entries.remove(&(*peer, sid));
            t.dec_peer(peer);
        }
    }

    /// Server-side accept-completion. Installs the inbound stream and
    /// returns its generation. If an entry for `(peer, sid)` already
    /// existed it is *replaced* — the peer reconnected and re-opened
    /// from a fresh `next_sid` sequence — and the displaced stale entry
    /// is returned so the caller can retire its orphaned stream.
    fn install_inbound(
        &self,
        peer: PubKey,
        sid: StreamId,
        tx: StreamSender,
        reliability: Arc<Mutex<Reliability>>,
        has_unacked: Arc<std::sync::atomic::AtomicBool>,
        latch: Arc<StreamLatch>,
    ) -> Option<(u64, Option<StreamEntry>)> {
        let mut t = self.table.lock().expect("StreamTable mutex poisoned");
        let stale = t.entries.remove(&(peer, sid));
        if stale.is_none() {
            // A genuinely new stream for this peer (not a reconnect replacing a
            // still-live entry). Enforce the per-peer cap so an Open flood can't
            // grow the table unbounded; the caller refuses the Open with a Reset.
            if t.per_peer.get(&peer).copied().unwrap_or(0) >= MAX_STREAMS_PER_PEER {
                return None;
            }
            t.inc_peer(peer);
        }
        let generation = t.allocate_generation();
        t.entries.insert(
            (peer, sid),
            StreamEntry { tx, reliability, peer, sid, generation, has_unacked, latch },
        );
        Some((generation, stale))
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
            Frame::Open { sid, target } => handle_open(&mux, peer, sid, target),
            Frame::OpenAck { sid, code } => signal(&mux, &peer, sid, StreamEvent::OpenAck(code)),
            Frame::Data { sid, seq, data } => handle_data(&mux, peer, sid, seq, data),
            Frame::Ack { sid, ack, win } => handle_ack(&mux, peer, sid, ack, win),
            Frame::Close { sid, seq } => handle_close(&mux, peer, sid, seq),
            Frame::Reset { sid, code } => {
                if let Some(entry) = mux.lookup_entry(&peer, sid) {
                    entry.deliver(StreamEvent::Reset(code));
                    mux.drop_stream(&peer, sid, entry.generation);
                }
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

/// Install an inbound `Open` and hand it to the accept queue. Never awaits:
/// the queue is fed with `try_send`, and an Open that can't be queued — the
/// acceptor is backlogged, or this node doesn't serve Opens at all (client /
/// mesh modes drop the receiver) — is refused with a Reset. Awaiting a full
/// queue here froze the whole read loop, i.e. every stream on the node, on
/// 65 Opens from any peer.
fn handle_open(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, target: OpenTarget) {
    let (tx, rx) = mpsc::channel(INBOUND_CHAN_DEPTH);
    let reliability = Arc::new(Mutex::new(Reliability::default()));
    let has_unacked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let latch = Arc::new(StreamLatch::default());
    let Some((generation, stale)) = mux.install_inbound(
        peer, sid, tx, reliability.clone(), has_unacked.clone(), latch.clone(),
    ) else {
        // Peer is at its per-peer stream cap — refuse this Open with
        // a Reset rather than growing unbounded state (drop gracefully).
        debug!(
            "mux: peer {} at stream cap ({}), refusing Open sid={sid}",
            hex::encode(&peer[..8]), MAX_STREAMS_PER_PEER
        );
        mux.spawn_control_send(peer, Frame::Reset { sid, code: 0x01 });
        return;
    };
    if let Some(stale) = stale {
        // The peer re-opened a sid that was still live on our
        // side: it reconnected (a restarted process resets
        // `next_sid` to 0) and its previous transport
        // connection died without a Close. Retire the
        // orphaned stream so its handler task unwinds and
        // frees whatever it held (e.g. an egress IP lease) —
        // otherwise every reconnect from this peer collides
        // here forever and never gets an OpenAck. Reset wakes
        // the parked handler; the stream marks itself
        // write-closed so its Drop won't fire a spurious
        // Reset frame at the now-reconnected peer.
        debug!(
            "mux: re-open from {} sid={sid} — peer reconnected, retiring stale stream",
            hex::encode(&peer[..8])
        );
        stale.deliver(StreamEvent::Reset(0x01));
    }
    let stream = MeshStream::new(
        mux.clone(), peer, sid, generation, rx, reliability, has_unacked, latch,
    );
    let accepted = AcceptedStream { from: peer, target, stream };
    if let Err(e) = mux.accept_tx.try_send(accepted) {
        let (why, acc) = match e {
            mpsc::error::TrySendError::Full(a) => ("accept queue full", a),
            mpsc::error::TrySendError::Closed(a) => ("not accepting streams", a),
        };
        debug!("mux: {why}, refusing Open sid={sid} from {}", hex::encode(&peer[..8]));
        let mut stream = acc.stream;
        // Send the refusal through the bounded control path; dropping the
        // stream then just frees its table entry (generation-checked).
        stream.disarm_drop_reset();
        mux.spawn_control_send(peer, Frame::Reset { sid, code: 0x01 });
    }
}

fn handle_data(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, seq: u32, data: Vec<u8>) {
    let Some(entry) = mux.lookup_entry(&peer, sid) else {
        // Unknown stream — tell the peer to give up. Bounded fire-and-forget so
        // a flood of Data for unknown sids can't spawn unbounded Reset tasks.
        mux.spawn_control_send(peer, Frame::Reset { sid, code: 0x01 });
        return;
    };
    let (outcome, ack_state) = {
        let mut r = entry.reliability.lock().expect("Reliability mutex poisoned");
        let out = r.on_recv_data(seq, data);
        (out, if out.send_ack { r.advertise_ack() } else { r.ack_state() })
    };
    if outcome.send_ack {
        let (ack, win) = ack_state;
        mux.spawn_control_send(peer, Frame::Ack { sid, ack, win });
    }
    if outcome.rx_buf_grew || outcome.eof_ready {
        let _ = entry.tx.try_send(StreamEvent::WakeRead);
    }
}

fn handle_ack(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, ack: u32, win: u32) {
    let Some(entry) = mux.lookup_entry(&peer, sid) else { return; };
    let (opened, now_idle) = {
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
        let opened = after_win > before_win || (before_close && !after_close);
        // For the retransmit_tick fast-path hint: this stream has no
        // more retransmit work iff there's nothing unacked, no pending
        // close, AND it isn't stalled on a zero window (that needs the
        // persist probe). Compute under the mutex so the write to
        // `has_unacked` can never race a concurrent allocate_seq.
        let idle = r.unacked_empty() && !r.close_pending() && !r.zero_window_stalled();
        (opened, idle)
    };
    if now_idle {
        entry.has_unacked.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    if opened {
        let _ = entry.tx.try_send(StreamEvent::WakeWrite);
    }
}

fn handle_close(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId, seq: u32) {
    let Some(entry) = mux.lookup_entry(&peer, sid) else {
        // Unknown stream — bounded fire-and-forget Reset (see handle_data).
        mux.spawn_control_send(peer, Frame::Reset { sid, code: 0x01 });
        return;
    };
    let (outcome, ack_state) = {
        let mut r = entry.reliability.lock().expect("Reliability mutex poisoned");
        let out = r.on_recv_close(seq);
        (out, if out.send_ack { r.advertise_ack() } else { r.ack_state() })
    };
    debug!(
        "close: rx peer={} sid={} close_seq={} → ack={} win={}",
        hex::encode(&peer[..8]), sid, seq, ack_state.0, ack_state.1
    );
    if outcome.send_ack {
        let (ack, win) = ack_state;
        mux.spawn_control_send(peer, Frame::Ack { sid, ack, win });
    }
    let _ = entry.tx.try_send(StreamEvent::PeerClose);
    if outcome.eof_ready {
        let _ = entry.tx.try_send(StreamEvent::WakeRead);
    }
}

/// Deliver a per-stream event from the read loop. Non-blocking: a flood
/// of OpenAck frames at one stream whose consumer isn't polling must not
/// park demux for every other stream (see `StreamEntry::deliver`).
fn signal(mux: &Arc<MeshMux>, peer: &PubKey, sid: StreamId, ev: StreamEvent) {
    let Some(entry) = mux.lookup_entry(peer, sid) else { return; };
    if !entry.deliver(ev) {
        mux.drop_stream(peer, sid, entry.generation);
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
            // Fast path: skip streams whose unacked queue is empty and
            // have no close pending. Saves the reliability mutex lock
            // + retransmit_due walk on every idle stream — perf
            // showed this was 22 % of user-mode CPU under load
            // before this check.
            if !entry.has_unacked.load(std::sync::atomic::Ordering::Relaxed) {
                continue;
            }
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
                    mux.spawn_control_send(entry.peer, Frame::Reset { sid: entry.sid, code: 0x06 });
                    entry.deliver(StreamEvent::Reset(0x06));
                    mux.drop_stream(&entry.peer, entry.sid, entry.generation);
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
                    if let Some(seq) = due.probe {
                        // Zero-window persist probe: an empty Data frame
                        // the peer answers with an ACK carrying its window.
                        // Droppable — the persist timer re-probes.
                        trace!(
                            "mux persist: probing zero window peer={} sid={} seq={}",
                            hex::encode(&entry.peer[..8]), entry.sid, seq
                        );
                        mux.spawn_control_send(
                            entry.peer,
                            Frame::Data { sid: entry.sid, seq, data: Vec::new() },
                        );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mux() -> Arc<MeshMux> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let conn = Arc::new(PacketConn::new(sk));
        MeshMux::new(conn).0
    }

    /// Spoof what `read_loop` builds for an inbound `Open`.
    fn inbound_parts() -> (
        StreamSender,
        Arc<Mutex<Reliability>>,
        Arc<std::sync::atomic::AtomicBool>,
        Arc<StreamLatch>,
    ) {
        let (tx, _rx) = mpsc::channel(INBOUND_CHAN_DEPTH);
        (
            tx,
            Arc::new(Mutex::new(Reliability::default())),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            Arc::new(StreamLatch::default()),
        )
    }

    /// A peer that drops and reconnects re-opens the same `(peer, sid)`
    /// from a fresh `next_sid` sequence. The mux must *replace* the stale
    /// entry (not reject the Open as a duplicate — that deadlocked every
    /// reconnect), and the retired stream's `Drop` — which fires
    /// `drop_stream` with the *old* generation — must not evict the live
    /// successor.
    #[tokio::test]
    async fn reopen_replaces_stale_entry_without_evicting_successor() {
        let mux = test_mux();
        let peer: PubKey = [0x42; 32];
        let sid: StreamId = 0;

        // First Open from this peer.
        let (tx, r, h, l) = inbound_parts();
        let (gen1, stale) = mux.install_inbound(peer, sid, tx, r, h, l).expect("first install under cap");
        assert!(stale.is_none(), "first open has no predecessor");

        // Peer reconnects, re-opens the same sid.
        let (tx, r, h, l) = inbound_parts();
        let (gen2, stale) =
            mux.install_inbound(peer, sid, tx, r, h, l).expect("reopen install under cap");
        let stale = stale.expect("re-open must surface the displaced stale entry");
        assert_eq!(stale.generation, gen1, "stale entry carries the old generation");
        assert_ne!(gen1, gen2, "the re-opened stream gets a fresh generation");

        // The orphaned stream's Drop runs with the OLD generation.
        mux.drop_stream(&peer, sid, gen1);
        let live = mux.lookup_entry(&peer, sid).expect("live successor survives stale Drop");
        assert_eq!(live.generation, gen2);

        // The live stream's own Drop (current generation) does evict it.
        mux.drop_stream(&peer, sid, gen2);
        assert!(mux.lookup_entry(&peer, sid).is_none(), "live Drop removes the entry");
    }

    /// `drop_stream` with a non-matching generation is a no-op.
    #[tokio::test]
    async fn drop_stream_ignores_a_stale_generation() {
        let mux = test_mux();
        let peer: PubKey = [0x07; 32];
        let sid: StreamId = 3;

        let (tx, r, h, l) = inbound_parts();
        let (generation, _) = mux.install_inbound(peer, sid, tx, r, h, l).expect("install under cap");

        mux.drop_stream(&peer, sid, generation.wrapping_sub(1));
        assert!(mux.lookup_entry(&peer, sid).is_some(), "wrong-gen drop must not evict");

        mux.drop_stream(&peer, sid, generation);
        assert!(mux.lookup_entry(&peer, sid).is_none(), "matching-gen drop evicts");
    }

    #[tokio::test]
    async fn per_peer_stream_cap_refuses_excess_opens() {
        let mux = test_mux();
        let peer: PubKey = [0x11; 32];
        // Fill exactly the cap with distinct sids; remember sid 0's generation.
        let mut gen0 = 0u64;
        for sid in 0..MAX_STREAMS_PER_PEER {
            let (tx, r, h, l) = inbound_parts();
            let (g, _) = mux.install_inbound(peer, sid, tx, r, h, l).expect("install under cap");
            if sid == 0 {
                gen0 = g;
            }
        }
        // The next NEW sid is refused (None → read_loop sends a Reset).
        let (tx, r, h, l) = inbound_parts();
        assert!(
            mux.install_inbound(peer, MAX_STREAMS_PER_PEER, tx, r, h, l).is_none(),
            "Open beyond the per-peer cap must be refused"
        );
        // The cap is per-peer: a different peer is unaffected.
        let other: PubKey = [0x22; 32];
        let (tx, r, h, l) = inbound_parts();
        assert!(
            mux.install_inbound(other, 0, tx, r, h, l).is_some(),
            "cap is per-peer, not global"
        );
        // Freeing one of the saturated peer's slots admits a new Open again.
        mux.drop_stream(&peer, 0, gen0);
        let (tx, r, h, l) = inbound_parts();
        assert!(
            mux.install_inbound(peer, MAX_STREAMS_PER_PEER, tx, r, h, l).is_some(),
            "a freed slot must admit a new Open"
        );
    }

    fn conn() -> Arc<PacketConn> {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        Arc::new(PacketConn::new(sk))
    }

    /// Install an inbound stream directly and return the live MeshStream
    /// plus a sender into its event channel (to simulate a flood).
    fn inbound_stream(mux: &Arc<MeshMux>, peer: PubKey, sid: StreamId) -> (MeshStream, StreamSender) {
        let (tx, rx) = mpsc::channel(INBOUND_CHAN_DEPTH);
        let (_, r, h, l) = inbound_parts();
        let (generation, _) = mux
            .install_inbound(peer, sid, tx.clone(), r.clone(), h.clone(), l.clone())
            .expect("install under cap");
        (MeshStream::new(mux.clone(), peer, sid, generation, rx, r, h, l), tx)
    }

    /// Client / mesh modes drop the accept receiver. An Open flood must be
    /// refused (and its table entries freed) instead of blocking the read
    /// loop on a channel nobody drains.
    #[tokio::test]
    async fn opens_refused_when_not_accepting() {
        let (mux, accept_rx) = MeshMux::new(conn());
        drop(accept_rx);
        let peer: PubKey = [0x33; 32];
        // Far more than the 64-deep accept queue: the old awaiting send
        // would never return past the 65th.
        for sid in 0..200 {
            handle_open(&mux, peer, sid, OpenTarget::Egress);
        }
        for sid in 0..200 {
            assert!(mux.lookup_entry(&peer, sid).is_none(), "refused Open sid={sid} must not linger");
        }
    }

    /// An exit whose acceptor is backlogged refuses the overflow with a
    /// Reset rather than parking the read loop on the full queue.
    #[tokio::test]
    async fn opens_beyond_accept_backlog_are_refused_not_awaited() {
        let (mux, mut accept_rx) = MeshMux::new(conn());
        let peer: PubKey = [0x34; 32];
        for sid in 0..100 {
            handle_open(&mux, peer, sid, OpenTarget::Egress);
        }
        let mut queued = Vec::new();
        while let Ok(acc) = accept_rx.try_recv() {
            queued.push(acc);
        }
        assert_eq!(queued.len(), 64, "exactly the accept-queue depth is queued");
        assert!(mux.lookup_entry(&peer, 63).is_some(), "queued streams stay live");
        assert!(mux.lookup_entry(&peer, 64).is_none(), "overflow Opens are refused");
    }

    /// OpenAck into a stream whose event channel is full must neither block
    /// the read loop nor be lost.
    #[tokio::test]
    async fn open_ack_survives_full_event_channel_without_blocking() {
        let mux = test_mux();
        let peer: PubKey = [0x44; 32];
        let (mut stream, tx) = inbound_stream(&mux, peer, 7);
        for _ in 0..INBOUND_CHAN_DEPTH {
            tx.try_send(StreamEvent::WakeRead).unwrap();
        }
        // `signal` is synchronous now; a flood of these can't park demux.
        for _ in 0..1000 {
            signal(&mux, &peer, 7, StreamEvent::OpenAck(0x00));
        }
        let code = tokio::time::timeout(Duration::from_secs(2), stream.await_open_ack())
            .await
            .expect("await_open_ack must not hang")
            .expect("OpenAck delivered");
        assert_eq!(code, 0x00);
    }

    /// Same for Reset: latched through a full channel and surfaced on read.
    #[tokio::test]
    async fn reset_survives_full_event_channel() {
        use tokio::io::AsyncReadExt;
        let mux = test_mux();
        let peer: PubKey = [0x45; 32];
        let (mut stream, tx) = inbound_stream(&mux, peer, 8);
        for _ in 0..INBOUND_CHAN_DEPTH {
            tx.try_send(StreamEvent::WakeRead).unwrap();
        }
        let entry = mux.lookup_entry(&peer, 8).unwrap();
        assert!(entry.deliver(StreamEvent::Reset(0x05)), "consumer still alive");
        let mut buf = [0u8; 16];
        let err = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .expect("read must not hang")
            .expect_err("reset surfaces as an error");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionReset);
    }

    /// Lost-wakeup regression: poll_write on a closed window drains the
    /// event channel; if that consumed the event it would park on (here a
    /// Reset) it must re-check instead of returning Pending forever.
    #[tokio::test]
    async fn poll_write_rechecks_after_draining_events() {
        use std::task::Poll;
        use tokio::io::AsyncWrite;
        let mux = test_mux();
        let peer: PubKey = [0x46; 32];
        let (mut stream, _tx) = inbound_stream(&mux, peer, 9);
        let entry = mux.lookup_entry(&peer, 9).unwrap();
        // Peer advertised a zero window: poll_write can't allocate.
        entry.reliability.lock().unwrap().on_recv_ack(0, 0, Instant::now());
        // The event arrives before poll_write gets to its drain.
        entry.deliver(StreamEvent::Reset(0x01));
        // A SINGLE poll must resolve: once the drain has consumed the event
        // nothing will wake a parked writer again (a timeout wrapper would
        // mask that by re-polling when its timer fires).
        let mut stream = std::pin::Pin::new(&mut stream);
        let first = std::future::poll_fn(|cx| Poll::Ready(stream.as_mut().poll_write(cx, b"x"))).await;
        match first {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset),
            other => panic!("poll_write parked on a consumed wake: {other:?}"),
        }
    }
}
