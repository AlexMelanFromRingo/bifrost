// Prometheus text-exposition rendering for the ScoredExitPool.
//
// Lives in bifrost-core so both daemons (socks5d, vpnd) can re-export
// the same gauges without duplicating the formatter. The actual HTTP
// serving belongs to the binary — this module is data-in / text-out.
//
// Gauges per candidate exit (label `pub_key` is the full 64-hex pub
// key; `tag` is the operator-supplied nickname or empty):
//
//   bifrost_exit_weight{pub_key="…",tag="…"}     Trust / (RTT + Penalty + 1)
//   bifrost_exit_trust{pub_key="…",tag="…"}      raw trust score
//   bifrost_exit_rtt_ms{pub_key="…",tag="…"}     PeerStats.lag in ms
//   bifrost_exit_penalty_ms{pub_key="…",tag="…"} active failure penalty
//   bifrost_exit_stats_known{pub_key="…",tag="…"} 1 if router has live
//                                                  stats; 0 = fallback
//
// One summary gauge:
//
//   bifrost_exit_pool_size                       count of candidates
//
// Privacy: pub_keys are leaked in labels (same as norn-rs's per-peer
// metrics), so the endpoint should be on loopback or behind auth.

use crate::scoring::{ScoredExit, ScoredExitPool};

const HELP: &str = "\
# HELP bifrost_exit_pool_size Number of egress candidates in the local pool.
# TYPE bifrost_exit_pool_size gauge
# HELP bifrost_exit_weight Selection weight = trust / (rtt_ms + penalty_ms + 1).
# TYPE bifrost_exit_weight gauge
# HELP bifrost_exit_trust Trust score from norn-rs reputation [0.01, 4.0].
# TYPE bifrost_exit_trust gauge
# HELP bifrost_exit_rtt_ms Per-peer RTT estimate (lag) in milliseconds.
# TYPE bifrost_exit_rtt_ms gauge
# HELP bifrost_exit_penalty_ms Active failure penalty in milliseconds.
# TYPE bifrost_exit_penalty_ms gauge
# HELP bifrost_exit_stats_known 1 if live PeerStats backs this row; 0 = fallback values.
# TYPE bifrost_exit_stats_known gauge
";

/// Render the pool's current snapshot in Prometheus exposition format.
/// Cheap to call; copy of the snapshot once + linear formatting.
pub fn render_pool(pool: &ScoredExitPool) -> String {
    render_snapshot(&pool.snapshot())
}

/// Same but for a pre-fetched snapshot (handy in tests).
pub fn render_snapshot(snap: &[ScoredExit]) -> String {
    let mut out = String::with_capacity(HELP.len() + snap.len() * 200);
    out.push_str(HELP);
    out.push_str(&format!("bifrost_exit_pool_size {}\n", snap.len()));
    for e in snap {
        let pk = hex::encode(e.pub_key);
        let tag = escape_label(e.tag.as_deref().unwrap_or(""));
        let common = format!("{{pub_key=\"{pk}\",tag=\"{tag}\"}}");
        out.push_str(&format!("bifrost_exit_weight{common} {:.6}\n",     e.weight));
        out.push_str(&format!("bifrost_exit_trust{common} {:.4}\n",      e.trust));
        out.push_str(&format!("bifrost_exit_rtt_ms{common} {:.3}\n",     e.rtt_ms));
        out.push_str(&format!("bifrost_exit_penalty_ms{common} {:.0}\n", e.penalty_ms));
        out.push_str(&format!("bifrost_exit_stats_known{common} {}\n",
                              if e.stats_known { 1 } else { 0 }));
    }
    out
}

/// Prometheus label-value rules: escape `\`, `"`, and newlines.
fn escape_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PubKey;

    fn pk(b: u8) -> PubKey { let mut k = [0u8; 32]; k[0] = b; k }

    #[test]
    fn render_includes_help_and_pool_size() {
        let pool = ScoredExitPool::new(vec![(pk(1), Some("primary".into()))]);
        let out = render_pool(&pool);
        assert!(out.contains("# HELP bifrost_exit_pool_size"));
        assert!(out.contains("bifrost_exit_pool_size 1\n"));
        assert!(out.contains("bifrost_exit_weight{pub_key=\""));
        assert!(out.contains("tag=\"primary\""));
    }

    #[test]
    fn render_escapes_quotes_in_tag() {
        let out = render_snapshot(&[ScoredExit {
            pub_key: pk(2),
            tag: Some("evil\"tag".into()),
            weight: 0.5,
            trust: 1.0,
            rtt_ms: 10.0,
            penalty_ms: 0.0,
            stats_known: true,
        }]);
        assert!(out.contains("tag=\"evil\\\"tag\""),
                "double-quote in tag must be escaped");
    }

    #[test]
    fn render_empty_pool_yields_zero_size() {
        let pool = ScoredExitPool::new(vec![]);
        let out = render_pool(&pool);
        assert!(out.contains("bifrost_exit_pool_size 0\n"));
        // No per-row gauges.
        assert!(!out.contains("bifrost_exit_weight{"));
    }
}
