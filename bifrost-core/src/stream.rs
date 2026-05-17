// MeshStream — bidirectional byte stream over a single norn-rs PacketConn
// stream id. Implements AsyncRead + AsyncWrite so it slots into the same
// `tokio::io::copy_bidirectional` plumbing as a real TcpStream.
//
// AsyncRead pulls StreamEvents from the per-stream channel installed by
// the mux. Data events fill an internal byte buffer; Close signals EOF;
// Reset surfaces as an Io error. OpenAck events buffer separately so the
// SOCKS5 client can `await_open_ack()` before pumping bytes.
//
// AsyncWrite chunks the input into MTU-sized DATA frames and dispatches
// each through MeshMux::send_frame. We hold one in-flight future at a
// time — that bounds memory use per stream and makes back-pressure flow
// naturally from PacketConn's own internal queues.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::frame::{Frame, MAX_FRAME_OVERHEAD};
use crate::mux::MeshMux;
use crate::{PubKey, StreamId};

/// Bounded backlog of inbound events per stream. Limits memory if the
/// reader stalls — the mux blocks on send, which propagates pressure
/// back to the underlying PacketConn read loop.
pub const INBOUND_CHAN_DEPTH: usize = 256;

/// Default minimum effective payload per DATA frame, used when the
/// PacketConn's reported MTU would underflow after subtracting framing
/// overhead. 256 bytes is well below any real-world MTU.
const MIN_DATA_CHUNK: usize = 256;

#[derive(Debug)]
pub enum StreamEvent {
    Data(Vec<u8>),
    Close,
    Reset(u8),
    OpenAck(u8),
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

type WriteFut = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

pub struct MeshStream {
    mux: Arc<MeshMux>,
    peer: PubKey,
    sid: StreamId,
    rx: mpsc::Receiver<StreamEvent>,
    /// Bytes ready to copy into the next poll_read buffer.
    read_buf: VecDeque<u8>,
    /// FIN seen — once the read_buf drains, poll_read returns 0 (EOF).
    read_closed: bool,
    /// One reply code from an OpenAck frame, consumed by `await_open_ack`.
    pending_ack: Option<u8>,
    /// Outstanding write future (frame in flight on PacketConn).
    write_fut: Option<WriteFut>,
    /// Mirror of write_fut for Close-on-shutdown.
    shutdown_fut: Option<WriteFut>,
    /// We've sent (or attempted to send) a CLOSE frame; further writes are errors.
    write_closed: bool,
}

impl MeshStream {
    pub(crate) fn new(
        mux: Arc<MeshMux>,
        peer: PubKey,
        sid: StreamId,
        rx: mpsc::Receiver<StreamEvent>,
    ) -> Self {
        Self {
            mux,
            peer,
            sid,
            rx,
            read_buf: VecDeque::new(),
            read_closed: false,
            pending_ack: None,
            write_fut: None,
            shutdown_fut: None,
            write_closed: false,
        }
    }

    pub fn peer(&self) -> &PubKey {
        &self.peer
    }

    pub fn stream_id(&self) -> StreamId {
        self.sid
    }

    /// Maximum DATA payload bytes per frame, computed from the
    /// PacketConn's MTU minus our framing overhead.
    fn chunk_size(&self) -> usize {
        let mtu = self.mux.conn().mtu() as usize;
        mtu.saturating_sub(MAX_FRAME_OVERHEAD).max(MIN_DATA_CHUNK)
    }

    /// Wait for the next OpenAck reply. Returns the reply code (0 = success).
    /// Errors if the stream closes or resets before the ack arrives.
    pub async fn await_open_ack(&mut self) -> io::Result<u8> {
        if let Some(code) = self.pending_ack.take() {
            return Ok(code);
        }
        loop {
            match self.rx.recv().await {
                Some(StreamEvent::OpenAck(code)) => return Ok(code),
                Some(StreamEvent::Data(d)) => self.read_buf.extend(d),
                Some(StreamEvent::Close) => {
                    self.read_closed = true;
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "stream closed before OpenAck",
                    ));
                }
                Some(StreamEvent::Reset(code)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("stream reset (code 0x{code:02x}) before OpenAck"),
                    ));
                }
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
    ///
    /// Returns an owned (`'static`) future so the caller doesn't have to
    /// hold `&MeshStream` across the await — that would force the
    /// stream to be `Sync`, which the inner write-future state can't be.
    pub fn send_open_ack(
        &self,
        code: u8,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send + 'static {
        let mux = self.mux.clone();
        let peer = self.peer;
        let sid = self.sid;
        async move { mux.send_frame(&peer, Frame::OpenAck { sid, code }).await }
    }

    /// Send a Reset frame and stop accepting writes. The caller should
    /// drop the stream shortly after. Same `'static` future shape as
    /// `send_open_ack` for the same Sync-avoidance reason.
    pub fn reset(
        &mut self,
        code: u8,
    ) -> impl std::future::Future<Output = ()> + Send + 'static {
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
        // Best-effort table cleanup. Sending a Close frame here would
        // require an async context that Drop doesn't provide; callers
        // that need clean half-close should call poll_shutdown.
        self.mux.drop_stream(&self.peer, self.sid);
    }
}

impl AsyncRead for MeshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            // Drain buffered bytes in contiguous slices — VecDeque exposes
            // its two halves so we can fill `buf` without per-byte copies.
            if !self.read_buf.is_empty() {
                let want = std::cmp::min(self.read_buf.len(), buf.remaining());
                let (front, back) = self.read_buf.as_slices();
                let from_front = front.len().min(want);
                buf.put_slice(&front[..from_front]);
                let remaining = want - from_front;
                if remaining > 0 {
                    buf.put_slice(&back[..remaining]);
                }
                self.read_buf.drain(..want);
                return Poll::Ready(Ok(()));
            }
            if self.read_closed {
                return Poll::Ready(Ok(())); // EOF — empty fill = 0 bytes
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(d))) => self.read_buf.extend(d),
                Poll::Ready(Some(StreamEvent::Close)) => self.read_closed = true,
                Poll::Ready(Some(StreamEvent::Reset(code))) => {
                    self.read_closed = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("peer reset (code 0x{code:02x})"),
                    )));
                }
                Poll::Ready(Some(StreamEvent::OpenAck(code))) => {
                    // OpenAck arriving on a stream the caller is reading
                    // means the caller skipped await_open_ack(). Cache it
                    // so a later await_open_ack() still works (unusual,
                    // but defensible).
                    self.pending_ack = Some(code);
                }
                Poll::Ready(None) => {
                    // Mux dropped — treat as EOF rather than error so
                    // copy_bidirectional finishes cleanly.
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
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
        // Finish any in-flight write before starting a new one.
        if self.write_fut.is_some() {
            let mut fut = self.write_fut.take().unwrap();
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.write_fut = Some(fut);
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => {
                    self.write_closed = true;
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())));
                }
                Poll::Ready(Ok(())) => { /* fall through to start a new write */ }
            }
        }
        let chunk = std::cmp::min(buf.len(), self.chunk_size());
        let data = buf[..chunk].to_vec();
        let mux = self.mux.clone();
        let peer = self.peer;
        let sid = self.sid;
        let fut: WriteFut = Box::pin(async move {
            mux.send_frame(&peer, Frame::Data { sid, data }).await
        });
        self.write_fut = Some(fut);
        // Tell tokio we accepted `chunk` bytes; the actual transmission
        // completes on the next poll_write / poll_flush. This is the
        // standard "store-and-forward" AsyncWrite pattern.
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // Flush in progress is fine — we accepted the bytes.
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(chunk)),
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
        // Flush in-flight DATA first so Close doesn't get reordered ahead.
        match self.as_mut().poll_flush(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if self.shutdown_fut.is_none() {
            let mux = self.mux.clone();
            let peer = self.peer;
            let sid = self.sid;
            self.shutdown_fut = Some(Box::pin(async move {
                mux.send_frame(&peer, Frame::Close { sid }).await
            }));
        }
        let mut fut = self.shutdown_fut.take().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Pending => {
                self.shutdown_fut = Some(fut);
                Poll::Pending
            }
            Poll::Ready(res) => {
                self.write_closed = true;
                Poll::Ready(res.map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e.to_string())))
            }
        }
    }
}
