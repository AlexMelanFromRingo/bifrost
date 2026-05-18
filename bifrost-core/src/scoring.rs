// Weighted exit picker for EgressPolicy::Auto.
//
// Replaces the round-robin ExitRotator with a live-scored pool. The
// design follows three principles:
//
//   1. SCORE = trust / (rtt_ms + penalty_ms + 1)
//
//      Trust comes from norn-rs's per-peer reputation (default 1.0,
//      floor 0.01 for sustained misbehaviour); RTT comes from the
//      same router's lag estimate. The +1 in the denominator keeps
//      a zero-RTT exit from monopolising the entire pool weight.
//
//   2. THUNDERING-HERD PROTECTION.
//      We never pick the maximum-scoring exit deterministically. The
//      top N candidates participate in a weighted-random draw so the
//      load spreads naturally across the best peers. If one peer's
//      RTT spikes the next refresh will redistribute. Without this
//      every client on the network would simultaneously gravitate to
//      the same low-RTT exit and DDoS it.
//
//   3. APP-LEVEL FEEDBACK.
//      A peer that reachably pings well but returns GENERAL_FAILURE
//      / HOST_UNREACHABLE on every CONNECT (broken process, blocked
//      upstream) needs to be deprioritised even when its routing-
//      layer trust is fine. `record_failure` injects a +1000 ms
//      penalty that decays after 120 s, dropping the offender's
//      weight roughly 6× without nuking it from the pool.

use norn_rs::PeerStats;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::PubKey;

/// Penalty added to a peer's effective RTT after a failed CONNECT.
/// Big enough to push the offender below the top N in most fleets
/// (~10ms RTT typical → 1000ms = 100× weight reduction), small enough
/// to recover after a brief outage rather than retire permanently.
pub const FAILURE_PENALTY: Duration = Duration::from_millis(1000);
/// How long a single failure-penalty entry lingers before expiring.
pub const PENALTY_TTL: Duration = Duration::from_secs(120);
/// How many top-weight exits participate in the weighted random draw.
pub const PICK_TOP_N: usize = 5;
/// Score fallback for a candidate the router doesn't have stats for
/// (newly-added pub_key, multi-hop peer): assume a mediocre 200 ms
/// RTT with default 0.5 trust so we still try it but rarely.
const UNKNOWN_TRUST: f32 = 0.5;
const UNKNOWN_RTT_MS: f64 = 200.0;

#[derive(Debug, Clone)]
pub struct ScoredExit {
    pub pub_key: PubKey,
    pub tag: Option<String>,
    pub weight: f64,
    /// Snapshot of the inputs that produced `weight` — useful for
    /// `/metrics` or diagnostic dumps.
    pub trust: f32,
    pub rtt_ms: f64,
    pub penalty_ms: f64,
    /// True if the candidate appeared in the latest PeerStats refresh.
    /// `false` either means the peer hasn't been dialed yet or it's a
    /// multi-hop neighbour the router doesn't track directly.
    pub stats_known: bool,
}

#[derive(Debug, Clone)]
struct Penalty {
    /// Total RTT inflation to apply.
    extra: Duration,
    /// When this penalty entry becomes a no-op.
    expires_at: Instant,
}

pub struct ScoredExitPool {
    /// Candidate list — guarded so mDNS discovery (or any other
    /// dynamic source) can add / remove peers at runtime without
    /// restarting the daemon. Kept in Mutex<Vec<_>> rather than a
    /// HashMap so the order is stable (e.g. for human-readable
    /// admin output before the snapshot has been refreshed).
    candidates: Mutex<Vec<(PubKey, Option<String>)>>,
    /// Per-peer RTT inflations from recent application-level failures.
    penalties: Mutex<HashMap<PubKey, Penalty>>,
    /// Most recent scoring snapshot, sorted descending by weight.
    /// Refreshed by a background tick reading PeerStats.
    snapshot: Mutex<Vec<ScoredExit>>,
}

impl ScoredExitPool {
    pub fn new(candidates: Vec<(PubKey, Option<String>)>) -> Self {
        // Seed snapshot with "stats unknown" entries so the first
        // pick() before any refresh() still returns something.
        let initial: Vec<ScoredExit> = candidates
            .iter()
            .map(|(pk, tag)| ScoredExit {
                pub_key: *pk,
                tag: tag.clone(),
                trust: UNKNOWN_TRUST,
                rtt_ms: UNKNOWN_RTT_MS,
                penalty_ms: 0.0,
                weight: UNKNOWN_TRUST as f64 / (UNKNOWN_RTT_MS + 1.0),
                stats_known: false,
            })
            .collect();
        Self {
            candidates: Mutex::new(candidates),
            penalties: Mutex::new(HashMap::new()),
            snapshot: Mutex::new(initial),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.candidates.lock().expect("candidates mutex poisoned").is_empty()
    }

    pub fn len(&self) -> usize {
        self.candidates.lock().expect("candidates mutex poisoned").len()
    }

    /// Add a peer to the rotation if it isn't already there. Returns
    /// true when the peer was new (so callers can log a "discovered"
    /// event without polling). Idempotent.
    pub fn add_candidate(&self, pub_key: PubKey, tag: Option<String>) -> bool {
        let mut c = self.candidates.lock().expect("candidates mutex poisoned");
        if c.iter().any(|(k, _)| *k == pub_key) {
            return false;
        }
        c.push((pub_key, tag.clone()));
        // Seed the snapshot with a fallback entry so the very next
        // pick() can see this peer without waiting for the next
        // refresh tick.
        let mut s = self.snapshot.lock().expect("snapshot mutex poisoned");
        s.push(ScoredExit {
            pub_key,
            tag,
            trust: UNKNOWN_TRUST,
            rtt_ms: UNKNOWN_RTT_MS,
            penalty_ms: 0.0,
            weight: UNKNOWN_TRUST as f64 / (UNKNOWN_RTT_MS + 1.0),
            stats_known: false,
        });
        // Re-sort so an immediate pick() doesn't fall through the
        // top-N because we appended at the end.
        s.sort_by(|a, b| b.weight.partial_cmp(&a.weight).unwrap_or(std::cmp::Ordering::Equal));
        true
    }

    /// Remove a peer from the rotation. Returns true if the peer was
    /// present. Also drops any active penalty entry for it.
    pub fn remove_candidate(&self, pub_key: &PubKey) -> bool {
        let mut c = self.candidates.lock().expect("candidates mutex poisoned");
        let before = c.len();
        c.retain(|(k, _)| k != pub_key);
        let removed = c.len() < before;
        drop(c);
        if removed {
            let mut p = self.penalties.lock().expect("penalties mutex poisoned");
            p.remove(pub_key);
            let mut s = self.snapshot.lock().expect("snapshot mutex poisoned");
            s.retain(|e| e.pub_key != *pub_key);
        }
        removed
    }

    /// Recompute the snapshot from a fresh PeerStats list. Drops any
    /// penalty entries whose TTL has expired so a once-flaky exit
    /// can rejoin the rotation.
    pub fn refresh(&self, stats: &[PeerStats]) {
        self.refresh_at(stats, Instant::now());
    }

    fn refresh_at(&self, stats: &[PeerStats], now: Instant) {
        // GC expired penalties before scoring so a recovering peer
        // shows up with its real weight on the very next pick.
        {
            let mut p = self.penalties.lock().expect("penalties mutex poisoned");
            p.retain(|_, pen| pen.expires_at > now);
        }
        let penalties = self.penalties.lock().expect("penalties mutex poisoned");
        // Snapshot the candidate list under its own lock so a parallel
        // mDNS add_candidate doesn't race us mid-scan.
        let candidates_snap: Vec<(PubKey, Option<String>)> = self
            .candidates
            .lock()
            .expect("candidates mutex poisoned")
            .clone();
        let mut snapshot = Vec::with_capacity(candidates_snap.len());
        for (pk, tag) in &candidates_snap {
            let (trust, rtt_ms, stats_known) = match stats.iter().find(|s| s.key == *pk) {
                Some(s) => (s.trust, s.lag.as_secs_f64() * 1000.0, true),
                None => (UNKNOWN_TRUST, UNKNOWN_RTT_MS, false),
            };
            let penalty_ms = penalties
                .get(pk)
                .map(|p| p.extra.as_secs_f64() * 1000.0)
                .unwrap_or(0.0);
            // +1 ms in the denominator avoids a divide-by-zero on a
            // 0 ms RTT measurement (rare but happens on loopback)
            // and caps the maximum useful weight ratio.
            let denom = (rtt_ms + penalty_ms + 1.0).max(1.0);
            let weight = trust as f64 / denom;
            snapshot.push(ScoredExit {
                pub_key: *pk,
                tag: tag.clone(),
                weight,
                trust,
                rtt_ms,
                penalty_ms,
                stats_known,
            });
        }
        snapshot.sort_by(|a, b| {
            b.weight
                .partial_cmp(&a.weight)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        *self.snapshot.lock().expect("snapshot mutex poisoned") = snapshot;
    }

    /// Weighted random draw across the top N entries of the current
    /// snapshot. Returns None only if there are no candidates at all.
    pub fn pick(&self) -> Option<(PubKey, Option<String>)> {
        self.pick_with(|| rand::random::<f64>())
    }

    /// Pick up to `n` DISTINCT candidates for parallel racing. Each
    /// pick is independent weighted-random (sampling with replacement
    /// per draw); we deduplicate the result so the same peer doesn't
    /// appear twice. If the pool has fewer than `n` candidates, returns
    /// what we have. Used by SOCKS5 happy-eyeballs to fan a CONNECT
    /// across the top of the pool concurrently.
    pub fn pick_n(&self, n: usize) -> Vec<(PubKey, Option<String>)> {
        if n == 0 { return Vec::new(); }
        let total = self.len();
        let cap = n.min(total);
        if cap == 0 { return Vec::new(); }
        let mut out: Vec<(PubKey, Option<String>)> = Vec::with_capacity(cap);
        let mut seen: std::collections::HashSet<PubKey> =
            std::collections::HashSet::with_capacity(cap);
        // Allow some extra attempts to converge despite duplicates in
        // weighted draws — bounded so a wildly skewed weight
        // distribution can't loop forever.
        let max_attempts = (cap * 4).max(8);
        for _ in 0..max_attempts {
            if out.len() >= cap { break; }
            if let Some((pk, tag)) = self.pick() {
                if seen.insert(pk) {
                    out.push((pk, tag));
                }
            } else {
                break;
            }
        }
        out
    }

    /// Deterministic variant for tests — caller injects the [0,1) draw.
    pub fn pick_with(&self, mut roll: impl FnMut() -> f64) -> Option<(PubKey, Option<String>)> {
        let snapshot = self.snapshot.lock().expect("snapshot mutex poisoned");
        if snapshot.is_empty() {
            return None;
        }
        let top: Vec<&ScoredExit> = snapshot.iter().take(PICK_TOP_N).collect();
        let total: f64 = top.iter().map(|s| s.weight).sum();
        if total <= 0.0 || !total.is_finite() {
            // Everyone is penalised to oblivion (or arithmetic broke);
            // fall back to a uniform draw so the network keeps
            // flowing instead of stalling on a dead pool.
            let i = (roll() * top.len() as f64).floor() as usize;
            let pick = &top[i.min(top.len() - 1)];
            return Some((pick.pub_key, pick.tag.clone()));
        }
        let mut r = roll() * total;
        for s in &top {
            r -= s.weight;
            if r <= 0.0 {
                return Some((s.pub_key, s.tag.clone()));
            }
        }
        // Floating-point rounding can leave a sliver — fall back to
        // the highest-weight pick.
        Some((top[0].pub_key, top[0].tag.clone()))
    }

    /// Record an application-level failure (OpenAck error, timeout,
    /// dial failure). Stacks with existing penalties: a peer that
    /// fails repeatedly accumulates inflation. The TTL also re-extends
    /// on each failure so a flaky run stays parked through the storm.
    pub fn record_failure(&self, key: &PubKey) {
        self.record_failure_at(key, Instant::now());
    }

    fn record_failure_at(&self, key: &PubKey, now: Instant) {
        let mut penalties = self.penalties.lock().expect("penalties mutex poisoned");
        let entry = penalties.entry(*key).or_insert(Penalty {
            extra: Duration::ZERO,
            expires_at: now + PENALTY_TTL,
        });
        entry.extra = entry.extra.saturating_add(FAILURE_PENALTY);
        entry.expires_at = now + PENALTY_TTL;
    }

    /// Read-only snapshot for diagnostics / `/metrics` rendering.
    pub fn snapshot(&self) -> Vec<ScoredExit> {
        self.snapshot.lock().expect("snapshot mutex poisoned").clone()
    }

    /// Snapshot of the current candidate list (pub_key + tag). Cloned
    /// so callers can't accidentally hold the candidates lock across
    /// awaits.
    pub fn candidates(&self) -> Vec<(PubKey, Option<String>)> {
        self.candidates.lock().expect("candidates mutex poisoned").clone()
    }

    /// Drop any active penalty for `key`. The next refresh recomputes
    /// the weight from raw trust/RTT without inflation. Idempotent.
    pub fn reset_penalty(&self, key: &PubKey) {
        let mut p = self.penalties.lock().expect("penalties mutex poisoned");
        p.remove(key);
    }

    /// Drop ALL active penalties — useful as a "give the fleet one
    /// more chance" knob after a known incident has been resolved.
    pub fn reset_all_penalties(&self) {
        let mut p = self.penalties.lock().expect("penalties mutex poisoned");
        p.clear();
    }
}

/// Spawn the background refresher loop. Wakes every `interval` and
/// pulls fresh PeerStats from the supplied PacketConn into the pool.
/// Returns immediately; the spawned task lives as long as the Arc
/// references hold.
pub fn spawn_refresher(
    pool: Arc<ScoredExitPool>,
    conn: Arc<norn_rs::PacketConn>,
    interval: Duration,
) {
    tokio::spawn(async move {
        // First tick fires `interval` from NOW instead of at t=0.
        // tokio::time::interval's default behaviour returns the first
        // tick immediately, which on a cold-started daemon means we
        // grab the norn-rs RouterState mutex while the underlying
        // session-init handshake is still wiring itself up — that
        // hand-shake then misses its window and the peer connection
        // stalls for a full retransmit cycle. interval_at offsets
        // the start so the daemon has time to settle.
        let start = tokio::time::Instant::now() + interval;
        let mut tick = tokio::time::interval_at(start, interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let stats = conn.get_peer_stats();
            pool.refresh(&stats);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(b: u8) -> PubKey {
        let mut k = [0u8; 32];
        k[0] = b;
        k
    }

    fn stat(b: u8, trust: f32, rtt_ms: u64) -> PeerStats {
        PeerStats {
            key: pk(b),
            lag: Duration::from_millis(rtt_ms),
            jitter: Duration::ZERO,
            loss_rate: 0.0,
            priority: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            uptime: Duration::ZERO,
            trust,
        }
    }

    #[test]
    fn refresh_orders_by_weight_descending() {
        let pool = ScoredExitPool::new(vec![
            (pk(1), Some("slow".into())),
            (pk(2), Some("fast-trusted".into())),
            (pk(3), Some("fast-flaky".into())),
        ]);
        pool.refresh(&[
            stat(1, 1.0, 200),  // weight ≈ 1/201 ≈ 0.005
            stat(2, 1.0,  20),  // weight ≈ 1/21  ≈ 0.048 — winner
            stat(3, 0.2,  20),  // weight ≈ 0.2/21 ≈ 0.010
        ]);
        let snap = pool.snapshot();
        assert_eq!(snap[0].tag.as_deref(), Some("fast-trusted"));
        assert_eq!(snap[1].tag.as_deref(), Some("fast-flaky"));
        assert_eq!(snap[2].tag.as_deref(), Some("slow"));
    }

    #[test]
    fn deterministic_pick_picks_top_when_roll_is_zero() {
        let pool = ScoredExitPool::new(vec![(pk(1), None), (pk(2), None)]);
        pool.refresh(&[stat(1, 1.0, 100), stat(2, 1.0, 10)]);
        // roll=0 → pick the highest-weight entry (peer 2)
        let (chosen, _) = pool.pick_with(|| 0.0).unwrap();
        assert_eq!(chosen, pk(2));
    }

    #[test]
    fn deterministic_pick_walks_to_secondary_with_high_roll() {
        let pool = ScoredExitPool::new(vec![(pk(1), None), (pk(2), None)]);
        pool.refresh(&[stat(1, 1.0, 10), stat(2, 1.0, 10)]);
        // Equal weights → roll=0.5 lands at the boundary; either pick
        // is acceptable. The roll=0.99 case should land on the second.
        let (chosen, _) = pool.pick_with(|| 0.99).unwrap();
        assert_eq!(chosen, pk(2));
    }

    #[test]
    fn failure_penalty_demotes_a_previously_good_peer() {
        let pool = ScoredExitPool::new(vec![(pk(1), None), (pk(2), None)]);
        let now = Instant::now();
        pool.refresh_at(&[stat(1, 1.0, 10), stat(2, 1.0, 100)], now);
        // Without penalty pk(1) is the top pick (10 ms vs 100 ms).
        let before = pool.snapshot();
        assert_eq!(before[0].pub_key, pk(1));
        // Penalise pk(1) → +1000 ms RTT → weight collapses.
        pool.record_failure_at(&pk(1), now);
        pool.refresh_at(&[stat(1, 1.0, 10), stat(2, 1.0, 100)], now);
        let after = pool.snapshot();
        assert_eq!(after[0].pub_key, pk(2),
                   "penalised peer must lose the top slot");
    }

    #[test]
    fn penalty_expires_after_ttl() {
        let pool = ScoredExitPool::new(vec![(pk(1), None)]);
        let now = Instant::now();
        pool.record_failure_at(&pk(1), now);
        pool.refresh_at(&[stat(1, 1.0, 10)], now);
        let immediately_after = pool.snapshot()[0].penalty_ms;
        assert!(immediately_after > 0.0);

        // Move past TTL — the refresh should GC the entry.
        pool.refresh_at(&[stat(1, 1.0, 10)], now + PENALTY_TTL + Duration::from_secs(1));
        let after_ttl = pool.snapshot()[0].penalty_ms;
        assert_eq!(after_ttl, 0.0, "penalty must clear after PENALTY_TTL");
    }

    #[test]
    fn unknown_peer_gets_fallback_weight() {
        let pool = ScoredExitPool::new(vec![(pk(99), Some("multi-hop".into()))]);
        // No stats supplied → fallback (UNKNOWN_TRUST / UNKNOWN_RTT).
        pool.refresh(&[]);
        let snap = pool.snapshot();
        assert!(!snap[0].stats_known);
        assert_eq!(snap[0].trust, UNKNOWN_TRUST);
        assert!(snap[0].weight > 0.0);
    }

    #[test]
    fn empty_pool_returns_none() {
        let pool = ScoredExitPool::new(vec![]);
        assert!(pool.pick().is_none());
    }

    #[test]
    fn reset_penalty_clears_a_single_entry() {
        let pool = ScoredExitPool::new(vec![(pk(1), None), (pk(2), None)]);
        let now = Instant::now();
        pool.record_failure_at(&pk(1), now);
        pool.record_failure_at(&pk(2), now);
        pool.refresh_at(&[stat(1, 1.0, 10), stat(2, 1.0, 10)], now);
        assert!(pool.snapshot().iter().all(|s| s.penalty_ms > 0.0));
        pool.reset_penalty(&pk(1));
        pool.refresh_at(&[stat(1, 1.0, 10), stat(2, 1.0, 10)], now);
        let snap = pool.snapshot();
        let one = snap.iter().find(|s| s.pub_key == pk(1)).unwrap();
        let two = snap.iter().find(|s| s.pub_key == pk(2)).unwrap();
        assert_eq!(one.penalty_ms, 0.0, "reset_penalty wipes the named entry");
        assert!(two.penalty_ms > 0.0, "untouched entry stays penalised");
    }

    #[test]
    fn add_candidate_is_idempotent_and_seeds_snapshot() {
        let pool = ScoredExitPool::new(vec![]);
        assert!(pool.is_empty());
        assert!(pool.add_candidate(pk(1), Some("first".into())));
        assert!(!pool.add_candidate(pk(1), Some("dup".into())), "second add is a no-op");
        assert_eq!(pool.len(), 1);
        // Snapshot already has an entry so pick() works without a refresh.
        let (chosen, _) = pool.pick().unwrap();
        assert_eq!(chosen, pk(1));
    }

    #[test]
    fn remove_candidate_clears_pool_and_penalty() {
        let pool = ScoredExitPool::new(vec![(pk(1), None)]);
        let now = Instant::now();
        pool.record_failure_at(&pk(1), now);
        assert!(pool.remove_candidate(&pk(1)));
        assert!(pool.is_empty());
        // Re-adding starts fresh — no leftover penalty.
        pool.add_candidate(pk(1), None);
        pool.refresh_at(&[stat(1, 1.0, 10)], now);
        assert_eq!(pool.snapshot()[0].penalty_ms, 0.0);
    }

    #[test]
    fn reset_all_penalties_clears_everything() {
        let pool = ScoredExitPool::new(vec![(pk(1), None), (pk(2), None)]);
        let now = Instant::now();
        pool.record_failure_at(&pk(1), now);
        pool.record_failure_at(&pk(2), now);
        pool.reset_all_penalties();
        pool.refresh_at(&[stat(1, 1.0, 10), stat(2, 1.0, 10)], now);
        assert!(pool.snapshot().iter().all(|s| s.penalty_ms == 0.0));
    }

    #[test]
    fn pick_n_returns_distinct_candidates() {
        let pool = ScoredExitPool::new(vec![
            (pk(1), None), (pk(2), None), (pk(3), None), (pk(4), None),
        ]);
        pool.refresh(&[
            stat(1, 1.0, 20), stat(2, 1.0, 20), stat(3, 1.0, 20), stat(4, 1.0, 20),
        ]);
        let three = pool.pick_n(3);
        assert_eq!(three.len(), 3, "must get 3 distinct candidates");
        let set: std::collections::HashSet<_> = three.iter().map(|(k, _)| *k).collect();
        assert_eq!(set.len(), 3, "picks must be unique");
    }

    #[test]
    fn pick_n_caps_at_pool_size() {
        let pool = ScoredExitPool::new(vec![(pk(1), None), (pk(2), None)]);
        pool.refresh(&[stat(1, 1.0, 20), stat(2, 1.0, 20)]);
        assert_eq!(pool.pick_n(5).len(), 2, "can't exceed pool size");
    }

    #[test]
    fn pick_n_zero_returns_empty() {
        let pool = ScoredExitPool::new(vec![(pk(1), None)]);
        assert!(pool.pick_n(0).is_empty());
    }

    #[test]
    fn weighted_draw_eventually_visits_all_top_n() {
        let pool = ScoredExitPool::new(vec![
            (pk(1), None),
            (pk(2), None),
            (pk(3), None),
        ]);
        pool.refresh(&[
            stat(1, 1.0, 50),
            stat(2, 1.0, 50),
            stat(3, 1.0, 50),
        ]);
        // Roll a deterministic spread of values; each peer should be
        // picked at least once across the spread.
        let mut seen = std::collections::HashSet::new();
        for i in 0..30 {
            let r = (i as f64) / 30.0;
            let (chosen, _) = pool.pick_with(|| r).unwrap();
            seen.insert(chosen);
        }
        assert_eq!(seen.len(), 3, "weighted draw must visit all equally-weighted peers");
    }
}
