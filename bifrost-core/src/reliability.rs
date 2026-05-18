// Per-stream reliability state — sliding-window ARQ over a best-effort
// MeshMux datagram channel.
//
// Design (v0.3+):
//   * Cumulative ACK after every Data frame (no delayed ACKs yet —
//     simpler debugging, predictable latency, costs ~5% extra frames).
//   * RTO estimated per RFC 6298 (Karn/Partridge SRTT/RTTVAR). Starts
//     at a 500 ms guess, gets replaced by the first non-ambiguous
//     sample; subsequent samples smooth via α=1/8 (SRTT) and β=1/4
//     (RTTVAR). The retransmit timer doubles RTO on timeout per
//     RFC 6298 §5.5; a clean ACK resets it to SRTT-based.
//   * Karn's rule: a frame that has been retransmitted at least once
//     produces no RTT sample (we can't tell which transmission the
//     ACK answers).
//   * Receive window = remaining rx_buf capacity (256 KiB default).
//     Sender's peer_window starts optimistically (matches
//     DEFAULT_RX_BUF_CAP) and is updated by every inbound ACK.
//   * Close and Reset are NOT carried by ARQ themselves. Close has a
//     parallel close-pending slot in the retransmit timer; Reset is
//     intentionally single-shot (it's the "abort" sentinel, retries
//     are pointless).

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Initial RTO before the first RTT sample lands (RFC 6298 §2.1).
pub const INITIAL_RTO: Duration = Duration::from_millis(500);
/// Lower bound on RTO. RFC 6298 says 1 s for the public internet;
/// mesh hops are much shorter so we allow 200 ms.
pub const MIN_RTO: Duration = Duration::from_millis(200);
/// Upper bound on RTO. Keeps a stuck stream from sleeping for minutes.
pub const MAX_RTO: Duration = Duration::from_secs(8);
pub const MAX_RETRIES: u8 = 16;
/// RFC 6298 SRTT weight: SRTT ← (1-α)·SRTT + α·R'
const ALPHA_NUM: u32 = 1;
const ALPHA_DEN: u32 = 8;
/// RFC 6298 RTTVAR weight: RTTVAR ← (1-β)·RTTVAR + β·|SRTT-R'|
const BETA_NUM: u32 = 1;
const BETA_DEN: u32 = 4;
/// RFC 6298 §2.1 "K = 4" — RTO ← SRTT + K·RTTVAR
const K: u32 = 4;
/// Default receive-side buffer cap. Bytes beyond this trigger zero-window
/// ACKs that pause the peer until the app drains us.
pub const DEFAULT_RX_BUF_CAP: u32 = 256 * 1024;
/// Initial assumption for the peer's receive window before any ACK arrives.
/// Matches DEFAULT_RX_BUF_CAP so the first burst can fill the peer's full
/// buffer instead of stalling on a conservative guess.
pub const INITIAL_PEER_WINDOW: u32 = DEFAULT_RX_BUF_CAP;
/// Largest amount the reorder buffer can hold before we start dropping
/// (and forcing the peer to retransmit). Mirrors rx_buf_cap.
pub const REORDER_BYTE_CAP: u32 = 256 * 1024;

#[derive(Debug)]
struct UnackedFrame {
    /// Sequence number of the FIRST byte in `data`.
    seq: u32,
    data: Vec<u8>,
    last_sent: Instant,
    retries: u8,
}

#[derive(Debug)]
struct UnackedClose {
    seq: u32,
    last_sent: Instant,
    retries: u8,
}

#[derive(Debug)]
pub struct RetransmitJob {
    pub seq: u32,
    pub data: Vec<u8>,
}

/// Result of a retransmit-window scan. Data jobs and the optional Close
/// job are surfaced separately so the mux sends the right frame type.
#[derive(Debug, Default)]
pub struct RetransmitDue {
    pub data_jobs: Vec<RetransmitJob>,
    pub close_job: Option<RetransmitJob>,
}

/// Outcome flag from `on_recv_data` — the caller (mux) uses it to decide
/// whether to send an Ack frame and whether the stream now has bytes
/// the consumer can read.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecvOutcome {
    pub send_ack: bool,
    pub rx_buf_grew: bool,
    /// True iff Close had been buffered and this Data drained enough of
    /// the gap that EOF is now reachable. The MeshStream uses this to
    /// flip read_closed.
    pub eof_ready: bool,
}

#[derive(Debug)]
pub struct Reliability {
    // ── Sender state ─────────────────────────────────────────────────────
    /// Sequence number to assign to the next byte queued for transmit.
    next_seq: u32,
    /// In-flight frames, ordered by seq. Front == oldest unacked.
    unacked: VecDeque<UnackedFrame>,
    /// Sum of `data.len()` over `unacked` — kept in sync to avoid an
    /// O(n) scan on every flow-control check.
    unacked_bytes: u32,
    /// Receiver's most recent advertised window. Sender must keep
    /// `unacked_bytes <= peer_window`.
    peer_window: u32,
    /// True once the sender has called close() — no more app writes
    /// will be accepted; remaining unacked must still drain.
    write_finished: bool,
    /// Seq the local FIN occupies (always = total bytes sent). Set when
    /// the upper layer decides to send Close; once peer ACKs > this
    /// value (cumulative ack treats Close as one virtual byte), Close
    /// has been received.
    local_close_seq: Option<u32>,
    /// Like `unacked`, but for the FIN itself. The mux's retransmit
    /// task re-sends the Close frame each RTO until the peer ACK passes
    /// `local_close_seq + 1`, ensuring EOF is delivered even if the
    /// first Close packet is dropped on the wire.
    close_pending: Option<UnackedClose>,

    // ── Receiver state ───────────────────────────────────────────────────
    /// Next in-order byte we expect.
    expected_seq: u32,
    /// Out-of-order frames waiting for the gap to close.
    reorder: BTreeMap<u32, Vec<u8>>,
    reorder_bytes: u32,
    /// Bytes ready for the application to read.
    rx_buf: VecDeque<u8>,
    rx_buf_cap: u32,
    /// Peer sent Close with this seq — deliver EOF once expected_seq >= it
    /// and rx_buf is drained.
    peer_close_seq: Option<u32>,
    eof_delivered: bool,

    // ── Timing (RFC 6298 RTT estimator) ──────────────────────────────────
    rto: Duration,
    /// Smoothed RTT. Unused until `have_rtt_sample` flips to true.
    srtt: Duration,
    /// RTT variation estimate. Set to RTT/2 by the first sample, then
    /// updated by β-weighted mean of |SRTT-R'|.
    rttvar: Duration,
    /// False until the first non-retransmitted frame has been ACKed.
    /// Karn's rule: retransmits never contribute a sample.
    have_rtt_sample: bool,
}

impl Default for Reliability {
    fn default() -> Self {
        Self::new(DEFAULT_RX_BUF_CAP)
    }
}

impl Reliability {
    pub fn new(rx_buf_cap: u32) -> Self {
        Self {
            next_seq: 0,
            unacked: VecDeque::new(),
            unacked_bytes: 0,
            peer_window: INITIAL_PEER_WINDOW,
            write_finished: false,
            local_close_seq: None,
            close_pending: None,
            expected_seq: 0,
            reorder: BTreeMap::new(),
            reorder_bytes: 0,
            rx_buf: VecDeque::new(),
            rx_buf_cap,
            peer_close_seq: None,
            eof_delivered: false,
            rto: INITIAL_RTO,
            srtt: Duration::ZERO,
            rttvar: Duration::ZERO,
            have_rtt_sample: false,
        }
    }

    /// RFC 6298 §2.2 / §2.3 RTT estimator. Called once per ACK that
    /// covers at least one frame whose `retries == 0` (Karn's rule).
    fn update_rtt(&mut self, sample: Duration) {
        if !self.have_rtt_sample {
            // §2.2: initial sample.
            self.srtt = sample;
            self.rttvar = sample / 2;
            self.have_rtt_sample = true;
        } else {
            // §2.3: weighted moving average for both SRTT and RTTVAR.
            // RTTVAR ← (1-β)·RTTVAR + β·|SRTT − R'|
            let diff = if self.srtt > sample {
                self.srtt - sample
            } else {
                sample - self.srtt
            };
            self.rttvar = weighted(self.rttvar, diff, BETA_NUM, BETA_DEN);
            // SRTT ← (1-α)·SRTT + α·R'
            self.srtt = weighted(self.srtt, sample, ALPHA_NUM, ALPHA_DEN);
        }
        // RTO ← SRTT + K·RTTVAR, clamped to [MIN_RTO, MAX_RTO].
        let raw = self.srtt + self.rttvar * K;
        self.rto = raw.clamp(MIN_RTO, MAX_RTO);
    }

    /// Inspect the current RTO. Mostly for tests / diagnostics.
    pub fn current_rto(&self) -> Duration {
        self.rto
    }

    /// Inspect the smoothed RTT estimate. Returns `None` until the
    /// first Karn-eligible ACK lands.
    pub fn srtt(&self) -> Option<Duration> {
        self.have_rtt_sample.then_some(self.srtt)
    }

    // ── SENDER ───────────────────────────────────────────────────────────

    /// Reserve `len` bytes of sequence space; returns the assigned seq
    /// or None if the peer's window doesn't have room. `len` must be
    /// > 0 and ≤ what `write_window_available()` reports.
    pub fn allocate_seq(&mut self, len: u32) -> Option<u32> {
        if self.write_finished {
            return None;
        }
        if self.unacked_bytes.saturating_add(len) > self.peer_window {
            return None;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(len);
        Some(seq)
    }

    /// Record a frame as in-flight. Caller has already done the actual
    /// send through the mux.
    pub fn record_sent(&mut self, seq: u32, data: Vec<u8>, now: Instant) {
        self.unacked_bytes = self.unacked_bytes.saturating_add(data.len() as u32);
        self.unacked.push_back(UnackedFrame { seq, data, last_sent: now, retries: 0 });
    }

    /// Process an incoming Ack. Drops cumulatively-ACKed frames. Updates
    /// the peer window. Clears close_pending if the peer has acknowledged
    /// past the local FIN. Folds a Karn-eligible RTT sample (frame with
    /// `retries == 0`) into the SRTT/RTTVAR estimator.
    pub fn on_recv_ack(&mut self, ack: u32, win: u32, now: Instant) {
        self.peer_window = win;
        let mut sampled_rtt: Option<Duration> = None;
        while let Some(front) = self.unacked.front() {
            let end = front.seq.wrapping_add(front.data.len() as u32);
            // No wrap handling: streams are short enough that 4 GB never
            // accumulates between an ACK roundtrip. Documented assumption.
            if end <= ack {
                // Karn: a frame that's been retransmitted at least once
                // is ambiguous — the ACK could answer any of the copies,
                // so its elapsed time is not a valid RTT. Sample only
                // virgins. First eligible frame per ACK wins (covers
                // the most-recent unambiguous round-trip).
                if front.retries == 0 && sampled_rtt.is_none() {
                    sampled_rtt = Some(now.duration_since(front.last_sent));
                }
                self.unacked_bytes = self.unacked_bytes.saturating_sub(front.data.len() as u32);
                self.unacked.pop_front();
            } else {
                break;
            }
        }
        if let Some(c) = self.close_pending.as_ref() {
            // Receiver acks `local_close_seq + 1` once Close has been
            // delivered — see ack_state() on the receiver side.
            if ack > c.seq {
                self.close_pending = None;
            }
        }
        if let Some(sample) = sampled_rtt {
            self.update_rtt(sample);
        }
    }

    /// Returns frames whose RTO has elapsed (both Data and Close).
    /// Doubles the RTO so the next loss in a row backs off. Returns
    /// Err(seq) if any frame has hit MAX_RETRIES — caller should reset
    /// the stream.
    pub fn retransmit_due(&mut self, now: Instant) -> Result<RetransmitDue, u32> {
        let mut due = RetransmitDue::default();
        for u in self.unacked.iter_mut() {
            if now.duration_since(u.last_sent) >= self.rto {
                if u.retries >= MAX_RETRIES {
                    return Err(u.seq);
                }
                u.retries = u.retries.saturating_add(1);
                u.last_sent = now;
                due.data_jobs
                    .push(RetransmitJob { seq: u.seq, data: u.data.clone() });
            }
        }
        if let Some(c) = self.close_pending.as_mut() {
            if now.duration_since(c.last_sent) >= self.rto {
                if c.retries >= MAX_RETRIES {
                    return Err(c.seq);
                }
                c.retries = c.retries.saturating_add(1);
                c.last_sent = now;
                due.close_job = Some(RetransmitJob { seq: c.seq, data: Vec::new() });
            }
        }
        if !due.data_jobs.is_empty() || due.close_job.is_some() {
            // RFC 6298 §5.5: double RTO on retransmit. This is
            // independent of the SRTT estimate; the retransmit timer
            // is conservative on purpose so spurious retransmits
            // don't cascade.
            self.rto = (self.rto * 2).clamp(MIN_RTO, MAX_RTO);
        }
        Ok(due)
    }

    /// Mark the local FIN as in-flight. Caller has just sent (or queued)
    /// a Close frame; this records the seq + timer so the mux's
    /// retransmit task can re-send the Close until acknowledged.
    pub fn record_close_sent(&mut self, seq: u32, now: Instant) {
        self.close_pending = Some(UnackedClose { seq, last_sent: now, retries: 0 });
        self.local_close_seq = Some(seq);
    }

    pub fn close_pending(&self) -> bool {
        self.close_pending.is_some()
    }

    pub fn write_window_available(&self) -> u32 {
        if self.write_finished {
            return 0;
        }
        self.peer_window.saturating_sub(self.unacked_bytes)
    }

    pub fn unacked_bytes(&self) -> u32 {
        self.unacked_bytes
    }

    pub fn unacked_empty(&self) -> bool {
        self.unacked.is_empty()
    }

    pub fn mark_write_finished(&mut self) {
        self.write_finished = true;
    }

    pub fn local_close_seq(&self) -> u32 {
        // The local FIN logically occupies the byte position equal to
        // total-bytes-sent (i.e. next_seq at the time Close is decided).
        self.next_seq
    }

    pub fn set_local_close_seq(&mut self, seq: u32) {
        self.local_close_seq = Some(seq);
    }

    pub fn local_close_acked(&self) -> bool {
        self.local_close_seq
            .map(|s| self.unacked.is_empty() && self.next_seq >= s)
            .unwrap_or(false)
    }

    // ── RECEIVER ─────────────────────────────────────────────────────────

    /// Ingest a Data frame. Returns an outcome flagging whether to send
    /// an ACK and whether the application now has fresh bytes / EOF to
    /// observe.
    pub fn on_recv_data(&mut self, seq: u32, data: Vec<u8>) -> RecvOutcome {
        let mut out = RecvOutcome::default();
        let len = data.len() as u32;
        if len == 0 {
            // Empty Data frames are pure keep-alives; ack and move on.
            out.send_ack = true;
            return out;
        }
        // Already-received bytes: ack so the peer stops retransmitting.
        if seq.wrapping_add(len) <= self.expected_seq {
            out.send_ack = true;
            return out;
        }
        if seq == self.expected_seq {
            // In-order — flush directly into rx_buf.
            if self.rx_buf.len() as u32 + len > self.rx_buf_cap {
                // Drop and let the peer retransmit when our window opens.
                out.send_ack = true; // zero-win ACK
                return out;
            }
            self.rx_buf.extend(data.iter().copied());
            self.expected_seq = self.expected_seq.wrapping_add(len);
            out.rx_buf_grew = true;
            // Drain any reorder entries the gap just closed for.
            while let Some((&next_seq, _)) = self.reorder.iter().next() {
                if next_seq == self.expected_seq {
                    let bytes = self.reorder.remove(&next_seq).unwrap();
                    if self.rx_buf.len() as u32 + bytes.len() as u32 > self.rx_buf_cap {
                        // Re-insert and stop; window forced us to spill.
                        self.reorder.insert(next_seq, bytes);
                        break;
                    }
                    self.reorder_bytes =
                        self.reorder_bytes.saturating_sub(bytes.len() as u32);
                    self.expected_seq =
                        self.expected_seq.wrapping_add(bytes.len() as u32);
                    self.rx_buf.extend(bytes.iter().copied());
                } else {
                    break;
                }
            }
            out.send_ack = true;
        } else if seq > self.expected_seq {
            // Out of order — buffer if cap permits.
            if self.reorder_bytes + len > REORDER_BYTE_CAP {
                // Drop; peer will retransmit. Still ACK to push the peer
                // toward filling our gap rather than piling more frames.
                out.send_ack = true;
                return out;
            }
            // De-dupe: if we already have this seq, keep the longer copy.
            let insert = match self.reorder.get(&seq) {
                Some(existing) if existing.len() >= data.len() => false,
                Some(existing) => {
                    self.reorder_bytes =
                        self.reorder_bytes.saturating_sub(existing.len() as u32);
                    true
                }
                None => true,
            };
            if insert {
                self.reorder_bytes = self.reorder_bytes.saturating_add(len);
                self.reorder.insert(seq, data);
            }
            out.send_ack = true;
        } else {
            // Partial overlap with already-received: rare under our chunking.
            // Easiest correct behaviour is to ACK and ignore.
            out.send_ack = true;
        }
        // Did this just close the gap to a buffered FIN?
        if let Some(c) = self.peer_close_seq {
            if self.expected_seq >= c && self.rx_buf.is_empty() && !self.eof_delivered {
                out.eof_ready = true;
            }
        }
        out
    }

    /// Ingest a Close frame carrying the peer's final seq.
    pub fn on_recv_close(&mut self, seq: u32) -> RecvOutcome {
        let mut out = RecvOutcome::default();
        self.peer_close_seq = Some(seq);
        out.send_ack = true;
        if self.expected_seq >= seq && self.rx_buf.is_empty() && !self.eof_delivered {
            out.eof_ready = true;
        }
        out
    }

    /// What the next outgoing ACK should advertise: cumulative ack +
    /// our remaining receive window. Once the peer's Close has been
    /// received in-order, the ack advances PAST close_seq (by one
    /// virtual FIN byte) so the peer learns the Close has landed and
    /// can stop retransmitting it.
    pub fn ack_state(&self) -> (u32, u32) {
        let win = self.rx_buf_cap.saturating_sub(self.rx_buf.len() as u32);
        let mut ack = self.expected_seq;
        if let Some(c) = self.peer_close_seq {
            if self.expected_seq >= c {
                ack = c.wrapping_add(1);
            }
        }
        (ack, win)
    }

    pub fn rx_drain(&mut self, dst: &mut [u8]) -> usize {
        let want = dst.len().min(self.rx_buf.len());
        for (i, b) in self.rx_buf.drain(..want).enumerate() {
            dst[i] = b;
        }
        want
    }

    pub fn rx_buf_len(&self) -> usize {
        self.rx_buf.len()
    }

    /// True iff peer Close was received AND all data ahead of it
    /// reached the consumer.
    pub fn eof_reached(&mut self) -> bool {
        if self.eof_delivered {
            return true;
        }
        if let Some(c) = self.peer_close_seq {
            if self.expected_seq >= c && self.rx_buf.is_empty() {
                self.eof_delivered = true;
                return true;
            }
        }
        false
    }
}

/// Compute (1 - num/den)·a + (num/den)·b in integer-nanosecond space
/// so we don't lose precision to f64 round-trips and we don't bring
/// in a float-math dep.
fn weighted(a: Duration, b: Duration, num: u32, den: u32) -> Duration {
    debug_assert!(num < den, "weighted: num/den must be < 1");
    let inv = den - num;
    let a_ns = a.as_nanos();
    let b_ns = b.as_nanos();
    let scaled = (a_ns * inv as u128 + b_ns * num as u128) / den as u128;
    // Saturate at u64::MAX nanoseconds (~585 years) — far past any
    // sane RTT, so the clamp is purely defensive.
    Duration::from_nanos(scaled.min(u64::MAX as u128) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes(s: &str) -> Vec<u8> { s.as_bytes().to_vec() }

    #[test]
    fn in_order_delivery() {
        let mut r = Reliability::default();
        let o1 = r.on_recv_data(0, bytes("hello"));
        assert!(o1.rx_buf_grew && o1.send_ack);
        let o2 = r.on_recv_data(5, bytes("world"));
        assert!(o2.rx_buf_grew && o2.send_ack);
        let mut dst = [0u8; 10];
        let n = r.rx_drain(&mut dst);
        assert_eq!(n, 10);
        assert_eq!(&dst, b"helloworld");
    }

    #[test]
    fn out_of_order_reordering() {
        let mut r = Reliability::default();
        // Receive 5..10 first.
        let o = r.on_recv_data(5, bytes("world"));
        assert!(!o.rx_buf_grew); // out-of-order, buffered
        assert!(o.send_ack);     // still ack to nudge peer
        // Now 0..5 fills the gap; reorder should drain.
        let o = r.on_recv_data(0, bytes("hello"));
        assert!(o.rx_buf_grew);
        let mut dst = [0u8; 10];
        assert_eq!(r.rx_drain(&mut dst), 10);
        assert_eq!(&dst, b"helloworld");
    }

    #[test]
    fn duplicate_data_acked_but_ignored() {
        let mut r = Reliability::default();
        let _ = r.on_recv_data(0, bytes("hello"));
        let o = r.on_recv_data(0, bytes("hello"));
        assert!(o.send_ack);
        assert!(!o.rx_buf_grew);
    }

    #[test]
    fn ack_drops_cumulative() {
        let mut r = Reliability::default();
        let now = Instant::now();
        let seq_a = r.allocate_seq(5).unwrap();
        r.record_sent(seq_a, bytes("hello"), now);
        let seq_b = r.allocate_seq(5).unwrap();
        r.record_sent(seq_b, bytes("world"), now);
        assert_eq!(r.unacked_bytes(), 10);
        r.on_recv_ack(5, INITIAL_PEER_WINDOW, now + Duration::from_millis(50));
        assert_eq!(r.unacked_bytes(), 5);
        r.on_recv_ack(10, INITIAL_PEER_WINDOW, now + Duration::from_millis(60));
        assert_eq!(r.unacked_bytes(), 0);
        assert!(r.unacked_empty());
    }

    #[test]
    fn retransmit_after_rto() {
        let mut r = Reliability::default();
        let now = Instant::now();
        let seq = r.allocate_seq(5).unwrap();
        r.record_sent(seq, bytes("hello"), now);
        let due = r.retransmit_due(now + INITIAL_RTO / 2).unwrap();
        assert!(due.data_jobs.is_empty() && due.close_job.is_none(), "RTO not yet elapsed");
        let due = r.retransmit_due(now + INITIAL_RTO + Duration::from_millis(50)).unwrap();
        assert_eq!(due.data_jobs.len(), 1);
        assert_eq!(due.data_jobs[0].seq, seq);
    }

    #[test]
    fn retransmit_eventually_gives_up() {
        let mut r = Reliability::default();
        let now = Instant::now();
        let seq = r.allocate_seq(1).unwrap();
        r.record_sent(seq, bytes("x"), now);
        let mut t = now;
        for _ in 0..MAX_RETRIES {
            t += Duration::from_secs(60); // way past RTO
            let _ = r.retransmit_due(t).unwrap();
        }
        t += Duration::from_secs(60);
        // The (MAX_RETRIES + 1)-th call should fail.
        assert!(r.retransmit_due(t).is_err());
    }

    #[test]
    fn window_blocks_allocate() {
        let mut r = Reliability::default();
        // Fill the peer window in one shot.
        let win = INITIAL_PEER_WINDOW;
        let seq = r.allocate_seq(win).unwrap();
        r.record_sent(seq, vec![0u8; win as usize], Instant::now());
        // Next byte exceeds the window → blocked.
        assert!(r.allocate_seq(1).is_none());
        // ACK opens the window again.
        r.on_recv_ack(win, INITIAL_PEER_WINDOW, Instant::now());
        assert!(r.allocate_seq(10_000).is_some());
    }

    #[test]
    fn close_retransmits_then_clears_on_ack() {
        let mut r = Reliability::default();
        let now = Instant::now();
        // Sender wrote 5 bytes, then closes.
        let seq = r.allocate_seq(5).unwrap();
        r.record_sent(seq, bytes("hello"), now);
        r.mark_write_finished();
        let close_seq = r.local_close_seq();
        assert_eq!(close_seq, 5);
        r.record_close_sent(close_seq, now);
        assert!(r.close_pending());

        // Before RTO: no close in retransmit_due.
        let due = r.retransmit_due(now + Duration::from_millis(100)).unwrap();
        assert!(due.close_job.is_none());

        // After RTO: close retransmits.
        let due = r
            .retransmit_due(now + INITIAL_RTO + Duration::from_millis(50))
            .unwrap();
        assert!(due.close_job.is_some());
        assert_eq!(due.close_job.unwrap().seq, close_seq);

        // ACK that covers only the data (ack=5) doesn't clear close.
        r.on_recv_ack(5, INITIAL_PEER_WINDOW, now);
        assert!(r.close_pending(), "ACK that doesn't pass close_seq+1 keeps close pending");

        // ACK past close_seq (ack=6) clears close_pending.
        r.on_recv_ack(6, INITIAL_PEER_WINDOW, now);
        assert!(!r.close_pending(), "ACK past close_seq+1 clears the FIN");
    }

    #[test]
    fn ack_state_advances_past_received_close() {
        let mut r = Reliability::default();
        let _ = r.on_recv_data(0, bytes("hello"));
        let _ = r.on_recv_close(5);
        // expected_seq has caught up to peer_close_seq → ack should be 6.
        let (ack, _win) = r.ack_state();
        assert_eq!(ack, 6, "ack must include the FIN byte once it's been received");
    }

    #[test]
    fn ack_state_no_advance_until_close_caught_up() {
        let mut r = Reliability::default();
        // Receive Close before all data → ack stays at expected_seq.
        let _ = r.on_recv_close(10);
        let _ = r.on_recv_data(0, bytes("hello"));
        let (ack, _) = r.ack_state();
        assert_eq!(ack, 5, "ack stays at expected_seq until Close gap closes");
    }

    #[test]
    fn rtt_first_sample_initializes_srtt() {
        let mut r = Reliability::default();
        assert!(r.srtt().is_none(), "no sample yet");
        let t0 = Instant::now();
        let seq = r.allocate_seq(4).unwrap();
        r.record_sent(seq, bytes("abcd"), t0);
        // 100 ms later the ACK lands.
        r.on_recv_ack(4, INITIAL_PEER_WINDOW, t0 + Duration::from_millis(100));
        let srtt = r.srtt().expect("first ACK must initialise SRTT");
        assert_eq!(srtt, Duration::from_millis(100), "SRTT == first sample");
        // RTO = SRTT + K·RTTVAR = 100ms + 4·50ms = 300ms, clamped >= MIN_RTO.
        assert_eq!(r.current_rto(), Duration::from_millis(300));
    }

    #[test]
    fn rtt_subsequent_samples_smooth() {
        let mut r = Reliability::default();
        let t0 = Instant::now();
        // First sample: 100 ms.
        let seq = r.allocate_seq(1).unwrap();
        r.record_sent(seq, bytes("a"), t0);
        r.on_recv_ack(1, INITIAL_PEER_WINDOW, t0 + Duration::from_millis(100));
        let srtt_1 = r.srtt().unwrap();
        // Second sample: 200 ms — SRTT moves a small fraction toward 200.
        let seq2 = r.allocate_seq(1).unwrap();
        let t1 = t0 + Duration::from_millis(200);
        r.record_sent(seq2, bytes("b"), t1);
        r.on_recv_ack(2, INITIAL_PEER_WINDOW, t1 + Duration::from_millis(200));
        let srtt_2 = r.srtt().unwrap();
        // (7/8)·100 + (1/8)·200 = 112.5 ms. Allow ±1 ms for ns/ms rounding.
        let expected = Duration::from_micros(112_500);
        let diff = if srtt_2 > expected { srtt_2 - expected } else { expected - srtt_2 };
        assert!(diff < Duration::from_millis(1),
                "SRTT after second sample ≈ 112.5 ms, got {srtt_2:?} (was {srtt_1:?})");
    }

    #[test]
    fn karn_skips_retransmitted_frames() {
        let mut r = Reliability::default();
        let t0 = Instant::now();
        let seq = r.allocate_seq(1).unwrap();
        r.record_sent(seq, bytes("x"), t0);
        // Pretend the retransmit timer fired: bump retries.
        let _ = r
            .retransmit_due(t0 + INITIAL_RTO + Duration::from_millis(50))
            .unwrap();
        // ACK lands now, but Karn forbids sampling the retransmitted frame.
        r.on_recv_ack(1, INITIAL_PEER_WINDOW, t0 + INITIAL_RTO + Duration::from_millis(60));
        assert!(r.srtt().is_none(),
                "Karn: retransmitted frame must not produce an RTT sample");
    }

    #[test]
    fn rto_clamped_between_min_and_max() {
        // Force a tiny SRTT by sampling 1 µs (way below MIN_RTO).
        let mut r = Reliability::default();
        let t0 = Instant::now();
        let seq = r.allocate_seq(1).unwrap();
        r.record_sent(seq, bytes("y"), t0);
        r.on_recv_ack(1, INITIAL_PEER_WINDOW, t0 + Duration::from_micros(1));
        assert!(r.current_rto() >= MIN_RTO, "RTO must clamp to MIN_RTO");
        // Doubling on retransmit shouldn't exceed MAX_RTO either.
        let seq2 = r.allocate_seq(1).unwrap();
        r.record_sent(seq2, bytes("z"), t0);
        let mut t = t0;
        // Six doublings starting from MIN_RTO=200ms hits 12.8s — above MAX_RTO=8s.
        for _ in 0..6 {
            t += Duration::from_secs(60); // ensure RTO elapsed
            let _ = r.retransmit_due(t).unwrap();
        }
        assert!(r.current_rto() <= MAX_RTO, "RTO must clamp to MAX_RTO");
    }

    #[test]
    fn weighted_average_handles_typical_inputs() {
        // (7/8)·100 + (1/8)·200 = 112.5
        let out = weighted(Duration::from_millis(100), Duration::from_millis(200), 1, 8);
        assert_eq!(out.as_micros(), 112_500);
        // (3/4)·40 + (1/4)·80 = 50
        let out = weighted(Duration::from_millis(40), Duration::from_millis(80), 1, 4);
        assert_eq!(out.as_millis(), 50);
    }

    #[test]
    fn close_then_drain_yields_eof() {
        let mut r = Reliability::default();
        // Peer wrote 5 bytes, then close at seq=5.
        let o = r.on_recv_close(5);
        assert!(!o.eof_ready); // gap still open
        let o = r.on_recv_data(0, bytes("hello"));
        assert!(o.rx_buf_grew);
        // Buffer has 5 bytes; eof_reached should be false until drained.
        assert!(!r.eof_reached());
        let mut dst = [0u8; 5];
        assert_eq!(r.rx_drain(&mut dst), 5);
        assert!(r.eof_reached());
    }
}
