// MeshStream — bidirectional byte stream backed by a single MeshMux
// stream id, with v0.2 ARQ on top of best-effort PacketConn datagrams.
//
// Read path: bytes arrive as Data frames into the mux's read loop, which
// pushes them through the per-stream Reliability state and signals us
// via `StreamEvent::WakeRead`. `poll_read` drains the Reliability's
// in-order rx_buf into the caller's slice.
//
// Write path: `poll_write` asks Reliability for sequence space (which
// honours the peer's advertised window), records the frame as in-flight,
// and dispatches a Data frame through the mux. If the window is closed,
// `poll_write` parks on the StreamEvent channel until the mux delivers a
// `WakeWrite` from an ACK.
//
// The retransmit timer lives in `MeshMux::retransmit_tick`, not here —
// idle streams still recover from loss because the mux walks them all
// every 50 ms.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::frame::{Frame, MAX_FRAME_OVERHEAD};
use crate::mux::MeshMux;
use crate::reliability::Reliability;
use crate::{PubKey, StreamId};

/// Bounded backlog of inbound events per stream. Wake notifications are
/// coalescable, so even a depth of 16 is plenty; we keep 256 for
/// headroom against bursty ACK floods.
pub const INBOUND_CHAN_DEPTH: usize = 256;

/// Default minimum effective payload per DATA frame.
const MIN_DATA_CHUNK: usize = 256;

#[derive(Debug, Clone, Copy)]
pub enum StreamEvent {
    /// rx_buf grew or EOF is now reachable — poll_read should retry.
    WakeRead,
    /// Peer ACKed something; write window may have opened.
    WakeWrite,
    /// Peer's Open reply (0x00 = success, anything else = SOCKS5 REP).
    OpenAck(u8),
    /// Peer sent Close (already integrated into Reliability; this is
    /// just a wake hint for callers waiting on `await_open_ack`).
    PeerClose,
    /// Peer aborted the stream (or our own retransmit budget ran out).
    Reset(u8),
}

/// SOCKS5-style reply codes used inside Reset / OpenAck frames so the
/// SOCKS5 daemon can mirror the wire-level "REP" field straight through.
pub mod reply {
    pub const SUCCESS:           u8 = 0x00;
    pub const GENERAL_FAILURE:   u8 = 0x01;
    pub const NET_UNREACHABLE:   u8 = 0x03;
    pub const HOST_UNREACHABLE:  u8 = 0x04;
    pub const CONN_REFUSED:      u8 = 0x05;
    pub const TTL_EXPIRED:       u8 = 0x06;
    pub const CMD_NOT_SUPPORTED: u8 = 0x07;
    pub const ATYP_NOT_SUPPORTED:u8 = 0x08;
}

type SendFut = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

pub struct MeshStream {
    mux: Arc<MeshMux>,
    peer: PubKey,
    sid: StreamId,
    rx: mpsc::Receiver<StreamEvent>,
    reliability: Arc<Mutex<Reliability>>,
    /// Outstanding Data-send future from poll_write. We deliberately
    /// hold exactly one — naively pipelining N futures here looked
    /// attractive (4-MB reliability window divided by ~64-KB chunks)
    /// but stalls the stream the moment the application stops writing,
    /// because nothing polls the queued futures until the next
    /// poll_write / poll_flush call. The single-fut design lets ARQ
    /// handle backpressure cleanly and, in practice, already saturates
    /// the link: real-WAN testing 2026-05-18 confirmed bifrost-SOCKS5
    /// matches raw TCP single-stream throughput on the same link
    /// (~47 Mbit/s on the UA↔NL Oracle hop, where iperf3 itself
    /// reports ~48 Mbit/s) — the per-stream ceiling is CUBIC + WAN
    /// loss, not us.
    write_fut: Option<SendFut>,
    /// Close-send future for poll_shutdown.
    close_fut: Option<SendFut>,
    /// True after the first Close frame was queued; further poll_shutdown
    /// calls just wait for the ACK (the mux retransmits as needed).
    close_registered: bool,
    /// One reply code from an OpenAck frame, consumed by `await_open_ack`.
    pending_ack: Option<u8>,
    /// True after poll_shutdown started (no more writes accepted).
    write_closed: bool,
    /// True once we deliver EOF to the application.
    read_eof: bool,
    /// Reset code received from peer; surfaces on the next read.
    pending_reset: Option<u8>,
    /// One drained-but-unforwarded byte buffer used to make AsyncRead's
    /// "copy into buf" cheap (avoids two-half-slice fiddling on every
    /// poll_read by pulling into a contiguous Vec once).
    scratch: VecDeque<u8>,
}

impl MeshStream {
    pub(crate) fn new(
        mux: Arc<MeshMux>,
        peer: PubKey,
        sid: StreamId,
        rx: mpsc::Receiver<StreamEvent>,
        reliability: Arc<Mutex<Reliability>>,
    ) -> Self {
        Self {
            mux,
            peer,
            sid,
            rx,
            reliability,
            write_fut: None,
            close_fut: None,
            close_registered: false,
            pending_ack: None,
            write_closed: false,
            read_eof: false,
            pending_reset: None,
            scratch: VecDeque::new(),
        }
    }

    pub fn peer(&self) -> &PubKey { &self.peer }
    pub fn stream_id(&self) -> StreamId { self.sid }

    fn chunk_size(&self) -> usize {
        let mtu = self.mux.conn().mtu() as usize;
        mtu.saturating_sub(MAX_FRAME_OVERHEAD).max(MIN_DATA_CHUNK)
    }

    /// Wait for the next OpenAck reply.
    pub async fn await_open_ack(&mut self) -> io::Result<u8> {
        if let Some(code) = self.pending_ack.take() {
            return Ok(code);
        }
        loop {
            match self.rx.recv().await {
                Some(StreamEvent::OpenAck(code)) => return Ok(code),
                Some(StreamEvent::Reset(code)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("stream reset (code 0x{code:02x}) before OpenAck"),
                    ));
                }
                Some(StreamEvent::PeerClose) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "peer closed before OpenAck",
                    ));
                }
                Some(StreamEvent::WakeRead) | Some(StreamEvent::WakeWrite) => continue,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "mux channel closed before OpenAck",
                    ));
                }
            }
        }
    }

    /// Server-side helper: send the OpenAck reply for this stream.
    pub fn send_open_ack(
        &self,
        code: u8,
    ) -> impl Future<Output = anyhow::Result<()>> + Send + 'static {
        let mux = self.mux.clone();
        let peer = self.peer;
        let sid = self.sid;
        async move { mux.send_frame(&peer, Frame::OpenAck { sid, code }).await }
    }

    pub fn reset(
        &mut self,
        code: u8,
    ) -> impl Future<Output = ()> + Send + 'static {
        self.write_closed = true;
        let mux = self.mux.clone();
        let peer = self.peer;
        let sid = self.sid;
        async move {
            let _ = mux.send_frame(&peer, Frame::Reset { sid, code }).await;
            mux.drop_stream(&peer, sid);
        }
    }
}

impl Drop for MeshStream {
    fn drop(&mut self) {
        // If the stream was abandoned WITHOUT a graceful poll_shutdown
        // (typical for happy-eyeballs racing losers — JoinSet::abort_all
        // tears the future down mid-await_open_ack), fire a Reset at
        // the peer so the exit-side TCP closes immediately instead of
        // lingering for the ARQ retransmit budget to exhaust (~30 s).
        //
        // Best-effort:
        //   * `write_closed == true` means poll_shutdown already sent
        //     Close (or this is a winner that completed normally);
        //     skip the Reset.
        //   * No tokio runtime in scope = drop happens in a non-async
        //     context (shouldn't happen in practice but Drop must be
        //     infallible). Skip silently.
        if !self.write_closed
            && let Ok(handle) = tokio::runtime::Handle::try_current() {
                let mux = self.mux.clone();
                let peer = self.peer;
                let sid = self.sid;
                handle.spawn(async move {
                    let _ = mux
                        .send_frame(&peer, Frame::Reset { sid, code: RESET_ABORTED })
                        .await;
                });
            }
        self.mux.drop_stream(&self.peer, self.sid);
    }
}

/// Reset code emitted by MeshStream::drop when the stream is
/// abandoned without poll_shutdown. SOCKS5 doesn't define this code;
/// 0x05 mirrors "Connection refused / aborted" sentinels.
pub const RESET_ABORTED: u8 = 0x05;

/// Pull ready events from the channel without blocking and apply their
/// side effects. Returns true if at least one event was consumed.
fn drain_events(
    rx: &mut mpsc::Receiver<StreamEvent>,
    pending_ack: &mut Option<u8>,
    pending_reset: &mut Option<u8>,
    cx: &mut Context<'_>,
) -> bool {
    let mut consumed = false;
    loop {
        match rx.poll_recv(cx) {
            Poll::Ready(Some(StreamEvent::WakeRead))
            | Poll::Ready(Some(StreamEvent::WakeWrite))
            | Poll::Ready(Some(StreamEvent::PeerClose)) => {
                consumed = true;
                continue;
            }
            Poll::Ready(Some(StreamEvent::OpenAck(code))) => {
                *pending_ack = Some(code);
                consumed = true;
                continue;
            }
            Poll::Ready(Some(StreamEvent::Reset(code))) => {
                *pending_reset = Some(code);
                consumed = true;
                continue;
            }
            Poll::Ready(None) | Poll::Pending => return consumed,
        }
    }
}

impl AsyncRead for MeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(code) = self.pending_reset.take() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    format!("peer reset (code 0x{code:02x})"),
                )));
            }
            // Step 1: hand over any cached scratch bytes first.
            if !self.scratch.is_empty() {
                let want = buf.remaining().min(self.scratch.len());
                let (front, back) = self.scratch.as_slices();
                let n_front = front.len().min(want);
                buf.put_slice(&front[..n_front]);
                let n_back = want - n_front;
                if n_back > 0 {
                    buf.put_slice(&back[..n_back]);
                }
                self.scratch.drain(..want);
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(())); // EOF: empty fill
            }
            // Step 2: pull from Reliability's rx_buf. We compute the
            // drain inside the lock and copy out the bytes, then push
            // into self.scratch only after dropping the guard — Rust's
            // borrow checker doesn't see that `self.reliability` and
            // `self.scratch` are disjoint fields through .lock().
            let want = buf.remaining();
            let drained_eof: (Option<Vec<u8>>, bool) = {
                let mut r = self.reliability.lock().expect("Reliability mutex poisoned");
                if r.rx_buf_len() == 0 {
                    (None, r.eof_reached())
                } else {
                    let mut tmp = vec![0u8; want.max(1)];
                    let n = r.rx_drain(&mut tmp);
                    tmp.truncate(n);
                    (Some(tmp), false)
                }
            };
            match drained_eof {
                (Some(tmp), _) => {
                    self.scratch.extend(tmp);
                    continue;
                }
                (None, true) => {
                    self.read_eof = true;
                    return Poll::Ready(Ok(()));
                }
                (None, false) => {}
            }
            // Step 3: nothing to read right now — wait for a wake.
            let Self { ref mut rx, ref mut pending_ack, ref mut pending_reset, .. } = *self;
            let consumed = drain_events(rx, pending_ack, pending_reset, cx);
            if !consumed {
                return Poll::Pending;
            }
            // Spin once more — Reliability or pending_reset may have updated.
        }
    }
}

impl AsyncWrite for MeshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "stream half-closed for writes",
            )));
        }
        if let Some(code) = self.pending_reset.take() {
            self.write_closed = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("peer reset (code 0x{code:02x})"),
            )));
        }
        // Finish any in-flight send before issuing a new one. We hold
        // exactly one outstanding Data send per stream — that bounds
        // memory and gives the mux retransmit task room to work.
        if let Some(mut fut) = self.write_fut.take() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.write_fut = Some(fut);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.write_closed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        e.to_string(),
                    )));
                }
                Poll::Ready(Ok(())) => {}
            }
        }
        // Pick a chunk that fits both the MTU and the peer's remaining window.
        let cap = self.chunk_size();
        let alloc = {
            let mut r = self.reliability.lock().expect("Reliability mutex poisoned");
            let win = r.write_window_available() as usize;
            let len = buf.len().min(cap).min(win);
            if len == 0 {
                None
            } else {
                let seq = r.allocate_seq(len as u32).expect("window check just passed");
                r.record_sent(seq, buf[..len].to_vec(), Instant::now());
                Some((seq, len))
            }
        };
        let (seq, chunk_len) = match alloc {
            Some(x) => x,
            None => {
                // Window closed — wait for an ACK to land.
                let Self { ref mut rx, ref mut pending_ack, ref mut pending_reset, .. } = *self;
                let _ = drain_events(rx, pending_ack, pending_reset, cx);
                return Poll::Pending;
            }
        };
        let data = buf[..chunk_len].to_vec();
        let mux = self.mux.clone();
        let peer = self.peer;
        let sid = self.sid;
        let fut: SendFut = Box::pin(async move {
            mux.send_frame(&peer, Frame::Data { sid, seq, data }).await
        });
        self.write_fut = Some(fut);
        // Try to make immediate progress on the send so callers see
        // back-pressure now rather than on the next poll. Either way
        // we've accepted `chunk_len` bytes into the reliability layer.
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(chunk_len)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(mut fut) = self.write_fut.take() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.write_fut = Some(fut);
                    Poll::Pending
                }
                Poll::Ready(Err(e)) => {
                    self.write_closed = true;
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())))
                }
                Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drain any in-flight Data send first so Close doesn't reorder
        // ahead of trailing application bytes.
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        // First call: register the Close in reliability (so the mux's
        // retransmit task will resend it if dropped) and kick off the
        // first transmission.
        if !self.close_registered && self.close_fut.is_none() {
            let close_seq = {
                let mut r = self.reliability.lock().expect("Reliability mutex poisoned");
                r.mark_write_finished();
                let seq = r.local_close_seq();
                r.record_close_sent(seq, Instant::now());
                seq
            };
            let mux = self.mux.clone();
            let peer = self.peer;
            let sid = self.sid;
            self.close_fut = Some(Box::pin(async move {
                mux.send_frame(&peer, Frame::Close { sid, seq: close_seq }).await
            }));
            self.close_registered = true;
        }
        // Drive the initial Close send to completion.
        if let Some(mut fut) = self.close_fut.take() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.close_fut = Some(fut);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.write_closed = true;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())));
                }
                Poll::Ready(Ok(())) => {}
            }
        }
        // Now wait for the ACK of our FIN. Mux retransmits Close every
        // RTO; we just park until either close_pending clears or peer
        // resets us (or retries exhaust → mux Resets).
        if let Some(code) = self.pending_reset.take() {
            self.write_closed = true;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("peer reset (code 0x{code:02x})"),
            )));
        }
        let still_pending = {
            let r = self.reliability.lock().expect("Reliability mutex poisoned");
            r.close_pending()
        };
        if !still_pending {
            self.write_closed = true;
            return Poll::Ready(Ok(()));
        }
        let Self { ref mut rx, ref mut pending_ack, ref mut pending_reset, .. } = *self;
        let _ = drain_events(rx, pending_ack, pending_reset, cx);
        Poll::Pending
    }
}
