//! Exit-side client admission for `Open(Egress)`.
//!
//! An ed25519 identity costs nothing to mint, and every admitted identity
//! gets a sticky (and, with persistence on, restart-surviving) address lease.
//! Without a gate, a few hundred throwaway keys exhaust the default /24 pool.
//! Two independent knobs, both checked before any lease is touched:
//!
//! * `allowed_clients` — explicit pubkey allowlist. Empty = open exit (a
//!   startup warning says so).
//! * `min_client_pow_bits` — per-identity admission cost, using the same
//!   key-difficulty measure as norn's transport-layer Sybil threshold
//!   ([`norn_rs::address::key_difficulty_bits`]: leading 1-bits of
//!   BLAKE2b-512(pub_key)). Each extra bit doubles the expected key-grinding
//!   work for an attacker; 0 disables the check.
//!
//! The data plane only forwards datagrams from peers that hold a lease, so
//! refusing the handshake (and dropping non-admitted persisted leases at
//! startup) is sufficient to keep a non-admitted key out entirely.

use anyhow::{Context, Result};
use bifrost_core::PubKey;
use std::collections::HashSet;

/// Why a peer was refused. Rendered into the exit's log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `allowed_clients` is non-empty and does not list this key.
    NotAllowlisted,
    /// The key's difficulty is below `min_client_pow_bits`.
    InsufficientPow { got: u32, need: u32 },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NotAllowlisted => write!(f, "not in [exit].allowed_clients"),
            Refusal::InsufficientPow { got, need } => {
                write!(f, "key difficulty {got} bits < min_client_pow_bits {need}")
            }
        }
    }
}

/// Immutable admission policy, built once from `[exit]` config.
#[derive(Debug, Clone, Default)]
pub struct ExitAdmission {
    /// `None` = open (any key passes this check).
    allowed: Option<HashSet<PubKey>>,
    min_pow_bits: u32,
}

impl ExitAdmission {
    /// Build from config strings. Each entry must be a 64-hex-char ed25519
    /// public key; an invalid entry fails startup rather than silently
    /// shrinking the allowlist.
    pub fn new(allowed_clients: &[String], min_pow_bits: u32) -> Result<Self> {
        let allowed = if allowed_clients.is_empty() {
            None
        } else {
            let mut set = HashSet::with_capacity(allowed_clients.len());
            for s in allowed_clients {
                set.insert(parse_pub_key(s).with_context(|| {
                    format!("[exit].allowed_clients entry {s:?}")
                })?);
            }
            Some(set)
        };
        Ok(Self { allowed, min_pow_bits })
    }

    /// True when no allowlist is configured (any key that meets the PoW
    /// bar is admitted). The daemon logs a warning at startup in that case.
    pub fn is_open(&self) -> bool {
        self.allowed.is_none()
    }

    pub fn min_pow_bits(&self) -> u32 {
        self.min_pow_bits
    }

    pub fn allowlist_len(&self) -> usize {
        self.allowed.as_ref().map_or(0, |s| s.len())
    }

    /// Admit or refuse `peer`. Cheap: one hash lookup + one BLAKE2b.
    pub fn check(&self, peer: &PubKey) -> std::result::Result<(), Refusal> {
        if let Some(set) = &self.allowed
            && !set.contains(peer)
        {
            return Err(Refusal::NotAllowlisted);
        }
        if self.min_pow_bits > 0 {
            let got = norn_rs::address::key_difficulty_bits(peer);
            if got < self.min_pow_bits {
                return Err(Refusal::InsufficientPow { got, need: self.min_pow_bits });
            }
        }
        Ok(())
    }
}

/// Parse a 64-hex-char ed25519 public key.
pub fn parse_pub_key(s: &str) -> Result<PubKey> {
    let s = s.trim();
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out)
        .with_context(|| format!("expected 64 hex chars (32-byte ed25519 key), got {} chars", s.len()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find a key whose difficulty is exactly `want` bits (cheap for small
    /// `want`: ~2^(want+1) hashes).
    fn key_with_bits(want: u32) -> PubKey {
        for i in 0u64.. {
            let mut k = [0u8; 32];
            k[..8].copy_from_slice(&i.to_le_bytes());
            if norn_rs::address::key_difficulty_bits(&k) == want {
                return k;
            }
        }
        unreachable!()
    }

    #[test]
    fn empty_allowlist_is_open() {
        let a = ExitAdmission::new(&[], 0).unwrap();
        assert!(a.is_open());
        assert!(a.check(&[0x11; 32]).is_ok());
    }

    #[test]
    fn allowlist_admits_listed_and_refuses_others() {
        let listed = [0xab; 32];
        let a = ExitAdmission::new(&[hex::encode(listed)], 0).unwrap();
        assert!(!a.is_open());
        assert_eq!(a.allowlist_len(), 1);
        assert!(a.check(&listed).is_ok());
        assert_eq!(a.check(&[0xcd; 32]), Err(Refusal::NotAllowlisted));
    }

    #[test]
    fn allowlist_rejects_malformed_entries_at_build() {
        assert!(ExitAdmission::new(&["abcd".into()], 0).is_err());
        assert!(ExitAdmission::new(&["zz".repeat(32)], 0).is_err());
    }

    #[test]
    fn pow_threshold_uses_norn_key_difficulty() {
        let weak = key_with_bits(0);
        let strong = key_with_bits(4);
        let a = ExitAdmission::new(&[], 3).unwrap();
        assert_eq!(
            a.check(&weak),
            Err(Refusal::InsufficientPow { got: 0, need: 3 })
        );
        assert!(a.check(&strong).is_ok());
        // Both knobs apply: allowlisted but too weak is still refused.
        let b = ExitAdmission::new(&[hex::encode(weak)], 3).unwrap();
        assert!(matches!(b.check(&weak), Err(Refusal::InsufficientPow { .. })));
    }
}
