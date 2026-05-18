// Shared types for the bifrost admin RPC.
//
// Wire format: one newline-terminated JSON object per direction over
// a UNIX SOCK_STREAM. Request → Response, then the connection
// closes. No long-lived multiplexing — admin calls are interactive
// and rare, so the simplest possible framing wins.
//
// Both the daemon (server) and `bifrost-ctl` (client) depend on this
// module, so request/response shapes stay in sync without any
// version-skew dance.

use serde::{Deserialize, Serialize};

/// One admin request. `cmd` tags the variant; field names match what
/// `bifrost-ctl` exposes as subcommands so wire ↔ CLI mapping is 1:1.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum AdminRequest {
    /// High-level daemon summary (pub_key, mode, uptime, pool size).
    Status,
    /// Full ScoredExitPool snapshot, sorted descending by weight.
    Exits,
    /// PeerStats list from the underlying PacketConn.
    Peers,
    /// Manually inflate a peer's penalty (same effect as an
    /// application-level failure).
    Penalty { pub_key: String },
    /// Clear the penalty entry for one peer.
    ResetPenalty { pub_key: String },
    /// Clear ALL active penalties — "give the fleet one more chance".
    ResetAllPenalties,
}

/// Uniform envelope for every response. Either `data` holds the
/// success payload (variant-specific JSON object) or `error` holds a
/// human-readable explanation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl AdminResponse {
    pub fn ok<T: Serialize>(data: T) -> Self {
        Self {
            ok: true,
            data: Some(serde_json::to_value(data).expect("admin payload must serialise")),
            error: None,
        }
    }
    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, data: None, error: Some(msg.into()) }
    }
}

/// Payload for `Status`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// 64-hex ed25519 pub_key of this node.
    pub pub_key: String,
    /// Derived 0200::/7 IPv6 address (canonical text form).
    pub address: String,
    /// Daemon role: "client" / "exit" / "mesh".
    pub mode: String,
    /// Wall-clock seconds since `Daemon::start`.
    pub uptime_secs: u64,
    /// Live mesh peers (direct neighbours).
    pub peer_count: usize,
    /// ScoredExitPool entry count; 0 when not in Auto mode.
    pub exit_pool_size: usize,
    /// True iff EgressPolicy::Auto is active.
    pub auto_egress: bool,
    /// Daemon build version (CARGO_PKG_VERSION at compile time).
    pub version: String,
}

/// One row in the `Exits` payload. Mirrors `ScoredExit` but stringifies
/// the pub_key for JSON friendliness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitRow {
    pub pub_key: String,
    pub tag: Option<String>,
    pub weight: f64,
    pub trust: f32,
    pub rtt_ms: f64,
    pub penalty_ms: f64,
    pub stats_known: bool,
}

/// One row in the `Peers` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRow {
    pub pub_key: String,
    pub trust: f32,
    pub lag_ms: u64,
    pub loss_rate: f32,
    pub uptime_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_through_json() {
        for r in [
            AdminRequest::Status,
            AdminRequest::Exits,
            AdminRequest::Peers,
            AdminRequest::Penalty { pub_key: "ab".repeat(32) },
            AdminRequest::ResetPenalty { pub_key: "cd".repeat(32) },
            AdminRequest::ResetAllPenalties,
        ] {
            let j = serde_json::to_string(&r).unwrap();
            let back: AdminRequest = serde_json::from_str(&j).unwrap();
            assert_eq!(r, back, "request must round-trip");
        }
    }

    #[test]
    fn response_omits_empty_fields() {
        let ok = AdminResponse::ok(serde_json::json!({"x": 1}));
        let j = serde_json::to_string(&ok).unwrap();
        assert!(!j.contains("\"error\""), "ok response must omit error");

        let err = AdminResponse::err("nope");
        let j = serde_json::to_string(&err).unwrap();
        assert!(!j.contains("\"data\""), "err response must omit data");
        assert!(j.contains("\"error\":\"nope\""));
    }

    #[test]
    fn request_tag_uses_snake_case() {
        let j = serde_json::to_string(&AdminRequest::ResetAllPenalties).unwrap();
        assert!(j.contains("\"reset_all_penalties\""),
                "rename_all = snake_case must apply to the tag");
    }
}
