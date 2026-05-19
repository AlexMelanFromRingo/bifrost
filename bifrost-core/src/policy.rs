// Egress policy: which mesh peer carries this CONNECT?
//
// v0.1 is intentionally dumb: a TOML list of pub keys is loaded at
// startup and rotated round-robin. A future revision will pull live
// trust / latency from the PacketConn's PeerStats and prefer the lowest
// effective_cost exit. The interface here is shaped so callers don't
// need to know which algorithm picks next time.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::PubKey;

/// One row in the exit table — the pub key of a peer that has opted to
/// proxy traffic for clients. `tag` is opaque to the core and useful for
/// logging ("us-east-1", "tor", whatever the operator names it).
#[derive(Debug, Clone, Deserialize)]
pub struct ExitPeer {
    /// 64 hex chars = 32-byte ed25519 pub key.
    pub pub_key: String,
    #[serde(default)]
    pub tag: Option<String>,
}

impl ExitPeer {
    pub fn decoded_pub_key(&self) -> Result<PubKey> {
        let raw = hex::decode(self.pub_key.trim())
            .with_context(|| format!("decoding exit pub_key {:?}", self.pub_key))?;
        if raw.len() != 32 {
            anyhow::bail!("exit pub_key must be 32 bytes (64 hex), got {}", raw.len());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Routing policy for a SOCKS5 / VPN client.
///
/// * `Mesh`  — stay inside the 0200::/7 overlay, no egress.
/// * `Exit`  — round-robin across the listed peers.
/// * `Auto`  — same candidate list, but pick by Trust/(RTT+Penalty)
///   with weighted-random top-N selection. The picker consumes live
///   PeerStats refreshed from PacketConn and absorbs application-
///   level failures as temporary RTT penalties so a sick exit drains
///   gracefully.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum EgressPolicy {
    Mesh,
    Exit { exits: Vec<ExitPeer> },
    Auto { exits: Vec<ExitPeer> },
}

impl EgressPolicy {
    pub fn load_from_file(path: impl AsRef<Path>) -> Result<Self> {
        let body = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("reading egress policy from {:?}", path.as_ref()))?;
        Self::from_toml(&body)
    }

    pub fn from_toml(body: &str) -> Result<Self> {
        toml::from_str(body).context("parsing egress policy TOML")
    }

    /// Pre-decode all listed exits so caller doesn't have to re-parse
    /// hex on every CONNECT.
    pub fn exit_keys(&self) -> Result<Vec<(PubKey, Option<String>)>> {
        match self {
            Self::Mesh => Ok(Vec::new()),
            Self::Exit { exits } | Self::Auto { exits } => exits
                .iter()
                .map(|e| Ok((e.decoded_pub_key()?, e.tag.clone())))
                .collect(),
        }
    }

    /// True if this policy wants scored-and-weighted selection.
    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto { .. })
    }
}

/// Round-robin picker over a pre-decoded exit list. Threadsafe via
/// AtomicUsize so the SOCKS5 server can spin many concurrent CONNECTs
/// without coordinating locks.
pub struct ExitRotator {
    exits: Vec<(PubKey, Option<String>)>,
    cursor: AtomicUsize,
}

impl ExitRotator {
    pub fn new(exits: Vec<(PubKey, Option<String>)>) -> Self {
        Self { exits, cursor: AtomicUsize::new(0) }
    }

    pub fn is_empty(&self) -> bool {
        self.exits.is_empty()
    }

    pub fn pick(&self) -> Option<(PubKey, Option<String>)> {
        if self.exits.is_empty() {
            return None;
        }
        let i = self.cursor.fetch_add(1, Ordering::Relaxed) % self.exits.len();
        Some(self.exits[i].clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_peer_decodes_valid_hex() {
        let p = ExitPeer { pub_key: "00".repeat(32), tag: Some("x".into()) };
        assert_eq!(p.decoded_pub_key().unwrap(), [0u8; 32]);
    }

    #[test]
    fn exit_peer_rejects_short_hex() {
        let p = ExitPeer { pub_key: "abcd".into(), tag: None };
        assert!(p.decoded_pub_key().is_err());
    }

    #[test]
    fn egress_policy_mesh() {
        let pol: EgressPolicy = toml::from_str(r#"mode = "mesh""#).unwrap();
        matches!(pol, EgressPolicy::Mesh);
        assert!(pol.exit_keys().unwrap().is_empty());
    }

    #[test]
    fn egress_policy_exit_parses() {
        let body = r#"
            mode = "exit"
            exits = [
                { pub_key = "11111111111111111111111111111111111111111111111111111111111111aa", tag = "lab" },
            ]
        "#;
        let pol = EgressPolicy::from_toml(body).unwrap();
        let keys = pol.exit_keys().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].1, Some("lab".into()));
    }

    #[test]
    fn rotator_round_robins() {
        let r = ExitRotator::new(vec![
            ([1u8; 32], Some("a".into())),
            ([2u8; 32], Some("b".into())),
        ]);
        let a = r.pick().unwrap().0;
        let b = r.pick().unwrap().0;
        let a2 = r.pick().unwrap().0;
        assert_ne!(a, b);
        assert_eq!(a, a2);
    }

    #[test]
    fn rotator_empty_returns_none() {
        let r = ExitRotator::new(vec![]);
        assert!(r.pick().is_none());
    }
}
