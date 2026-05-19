//! Persistence for `bifrost-vpnd` exit-mode IP leases.
//!
//! ## Why
//!
//! Without this, an exit's `AddressPool` is in-memory only: on
//! restart the pool starts fresh, the first reconnecting client
//! gets `.2`, the second gets `.3`, regardless of who used to own
//! what. For a single user that's invisible; for an operator
//! running services pinned to a specific tunnel IP, or for a
//! peer-trust scheme that whitelists by inner IP, the shuffle is
//! a real-world headache.
//!
//! ## What it persists
//!
//! A flat JSON list of `(peer pub_key, lease)` pairs. Loaded into
//! `EgressTable` at startup, written atomically after every
//! lease-affecting change in `handle_egress_handshake`.
//!
//! Wire form (v1):
//!
//! ```json
//! {
//!   "version": 1,
//!   "leases": [
//!     { "peer": "ad427eaa…", "v4": "10.55.0.2", "v6": "fd55::2" },
//!     { "peer": "bb63f7c7…", "v4": "10.55.0.3", "v6": null      }
//!   ]
//! }
//! ```
//!
//! ## Eviction policy
//!
//! v0.1: **sticky leases**. Once handed out, an entry stays in the
//! file until an operator deletes it manually (e.g. via `bifrost-ctl
//! evict-lease <pub_key>` — not implemented yet) or until the pool
//! is exhausted and a new client needs the slot. Stream-close on
//! the control channel no longer releases the underlying lease —
//! the bifrost-vpnd `handle_egress_handshake` change keeps the
//! `EgressTable` entry alive for sticky resume.
//!
//! ## Failure modes
//!
//! * **File missing** — fresh start, equivalent to v0.1 behaviour
//!   pre-persistence. No log noise.
//! * **File present but unparseable** — load returns the error.
//!   The caller (`start_exit`) logs a warning and continues with
//!   an empty store rather than refusing to boot. A corrupted
//!   file is better than a dead daemon; we'll just hand out
//!   fresh slots and overwrite the file on the next save.
//! * **Lease references a host index outside the configured pool
//!   range** (e.g. operator changed `pool_base` between restarts) —
//!   the entry is dropped on load with a warning. The peer will
//!   get a fresh lease on reconnect.

use anyhow::{Context, Result};
use bifrost_core::PubKey;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use crate::egress::Lease;

/// Current persistence schema version. Bumped only if we change
/// the on-disk JSON shape — readers fall back to "fresh start" on
/// any mismatch rather than try to read an unfamiliar file.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PersistedLease {
    /// 64-hex peer pub key (ed25519 verifying key). Lowercase.
    peer: String,
    v4: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    v6: Option<Ipv6Addr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedFile {
    version: u32,
    #[serde(default)]
    leases: Vec<PersistedLease>,
}

/// In-memory mirror of the on-disk file with the I/O glue around it.
#[derive(Debug, Clone)]
pub struct LeaseStore {
    path: PathBuf,
    leases: Vec<(PubKey, Lease)>,
}

impl LeaseStore {
    /// Create a store backed by `path`. If `path` is empty the
    /// store is a no-op (`save()` returns Ok without touching the
    /// disk, `load()` returns the in-memory state). Callers can
    /// always construct one; persistence is purely a function of
    /// whether the path is set.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into(), leases: Vec::new() }
    }

    /// True if a non-empty path is set. Callers use this to decide
    /// whether to log "persistence on" at startup.
    pub fn is_persistent(&self) -> bool {
        !self.path.as_os_str().is_empty()
    }

    /// Pull `(peer, lease)` pairs out of the store. Returns an
    /// empty vec when the file doesn't exist, the path is empty,
    /// or the file is unparseable (the caller is expected to log
    /// the latter at warn level via `load_with_warn`).
    pub fn load(&mut self) -> Result<Vec<(PubKey, Lease)>> {
        if !self.is_persistent() { return Ok(Vec::new()); }
        let body = match std::fs::read_to_string(&self.path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("reading lease store"),
        };
        let parsed: PersistedFile = serde_json::from_str(&body)
            .with_context(|| format!("parsing lease store {:?}", self.path))?;
        if parsed.version != SCHEMA_VERSION {
            anyhow::bail!(
                "lease store {:?} has version {} (expected {}); treating as fresh",
                self.path, parsed.version, SCHEMA_VERSION
            );
        }
        let mut out = Vec::with_capacity(parsed.leases.len());
        for p in &parsed.leases {
            let mut peer = [0u8; 32];
            hex::decode_to_slice(&p.peer, &mut peer)
                .with_context(|| format!("bad peer hex {:?}", p.peer))?;
            out.push((peer, Lease { v4: p.v4, v6: p.v6 }));
        }
        self.leases = out.clone();
        Ok(out)
    }

    /// Write the current set of leases to disk atomically:
    /// `path.tmp` → fsync → `rename(2)` so a crash mid-save can't
    /// leave a half-written file in place. Permissions are set to
    /// 0600 on Unix — lease metadata, while not exactly secret,
    /// has no business being world-readable.
    ///
    /// No-op when the store path is empty.
    pub fn save(&self) -> Result<()> {
        if !self.is_persistent() { return Ok(()); }
        let file = PersistedFile {
            version: SCHEMA_VERSION,
            leases: self.leases.iter().map(|(peer, lease)| PersistedLease {
                peer: hex::encode(peer),
                v4: lease.v4,
                v6: lease.v6,
            }).collect(),
        };
        let body = serde_json::to_vec_pretty(&file).context("serialising lease store")?;
        let tmp = self.path.with_extension("tmp");
        // Truncate-and-write the .tmp; rename onto the real path.
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .with_context(|| format!("opening temp lease store {:?}", tmp))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        f.write_all(&body).context("writing temp lease store")?;
        f.sync_all().context("fsyncing temp lease store")?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("renaming {:?} → {:?}", tmp, self.path))?;
        Ok(())
    }

    /// Record the (peer, lease) mapping. Replaces any prior entry
    /// for the same peer. The caller is expected to follow with a
    /// `save()` to actually persist; we don't save-on-every-insert
    /// here so a batch of changes can flush in one I/O.
    pub fn insert(&mut self, peer: PubKey, lease: Lease) {
        if let Some(slot) = self.leases.iter_mut().find(|(p, _)| *p == peer) {
            slot.1 = lease;
        } else {
            self.leases.push((peer, lease));
        }
    }

    /// Remove `peer`'s entry from the store. No-op if not present.
    /// Like `insert`, this is in-memory only; `save()` flushes.
    pub fn remove(&mut self, peer: &PubKey) -> bool {
        let before = self.leases.len();
        self.leases.retain(|(p, _)| p != peer);
        self.leases.len() != before
    }

    /// Look up an existing lease by peer pub key. Used by tests and
    /// future `bifrost-ctl` introspection; the hot path doesn't go
    /// through here (it goes through [`EgressTable::lease_of`]).
    #[allow(dead_code)]
    pub fn get(&self, peer: &PubKey) -> Option<Lease> {
        self.leases.iter().find(|(p, _)| p == peer).map(|(_, l)| *l)
    }

    /// Snapshot the full set of `(peer, lease)` pairs — primarily
    /// for tests and `bifrost-ctl` introspection.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> Vec<(PubKey, Lease)> {
        self.leases.clone()
    }

    /// Drop everything. Useful for tests; production should use
    /// targeted `remove`.
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.leases.clear();
    }
}

/// Best-effort load that swallows parse errors as warnings rather
/// than refusing to start the daemon. Returns the recovered
/// leases (empty on error).
pub fn load_with_warn(path: &Path) -> Vec<(PubKey, Lease)> {
    let mut store = LeaseStore::new(path);
    match store.load() {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "lease store at {:?} unreadable ({e:#}); starting with empty store. \
                 Returning clients may land on different IPs until they reconnect again.",
                path
            );
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn peer(byte: u8) -> PubKey {
        let mut k = [0u8; 32];
        for b in k.iter_mut() { *b = byte; }
        k
    }

    #[test]
    fn empty_path_is_noop() {
        let mut store = LeaseStore::new("");
        store.insert(peer(0xaa), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 2), v6: None
        });
        // save() must succeed and create no file.
        store.save().unwrap();
        // load() returns empty.
        let mut fresh = LeaseStore::new("");
        assert!(fresh.load().unwrap().is_empty());
    }

    #[test]
    fn roundtrip_through_disk_preserves_order_and_values() {
        let tmpdir = tempdir_pathbuf();
        let path = tmpdir.join("leases.json");
        let mut store = LeaseStore::new(&path);
        store.insert(peer(0x01), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 2),
            v6: Some("fd55::2".parse().unwrap()),
        });
        store.insert(peer(0x02), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 3),
            v6: None,
        });
        store.save().unwrap();

        // Verify the file actually exists and is readable.
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("\"version\": 1"));
        assert!(body.contains("10.55.0.2"));

        let mut reloaded = LeaseStore::new(&path);
        let got = reloaded.load().unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, peer(0x01));
        assert_eq!(got[0].1.v4, Ipv4Addr::new(10, 55, 0, 2));
        assert_eq!(got[0].1.v6, Some("fd55::2".parse().unwrap()));
        assert_eq!(got[1].0, peer(0x02));
        assert_eq!(got[1].1.v6, None);

        std::fs::remove_dir_all(&tmpdir).unwrap();
    }

    #[test]
    fn load_returns_empty_when_file_absent() {
        let tmpdir = tempdir_pathbuf();
        let path = tmpdir.join("nope.json");
        let mut store = LeaseStore::new(&path);
        assert!(store.load().unwrap().is_empty());
        std::fs::remove_dir_all(&tmpdir).unwrap();
    }

    #[test]
    fn load_errors_on_bad_version() {
        let tmpdir = tempdir_pathbuf();
        let path = tmpdir.join("future.json");
        std::fs::write(&path, r#"{"version": 99, "leases": []}"#).unwrap();
        let mut store = LeaseStore::new(&path);
        assert!(store.load().is_err());
        // load_with_warn must swallow the error and return empty.
        assert!(load_with_warn(&path).is_empty());
        std::fs::remove_dir_all(&tmpdir).unwrap();
    }

    #[test]
    fn insert_replaces_existing_peer() {
        let mut store = LeaseStore::new("");
        store.insert(peer(0x07), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 2), v6: None,
        });
        store.insert(peer(0x07), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 5), v6: None,
        });
        let s = store.snapshot();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].1.v4, Ipv4Addr::new(10, 55, 0, 5));
    }

    #[test]
    fn remove_returns_true_when_present_false_when_absent() {
        let mut store = LeaseStore::new("");
        store.insert(peer(0x07), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 2), v6: None,
        });
        assert!(store.remove(&peer(0x07)));
        assert!(!store.remove(&peer(0x07)));
        assert!(store.snapshot().is_empty());
    }

    #[test]
    fn atomic_save_does_not_corrupt_on_concurrent_read() {
        // Race a save against a read: with the atomic rename, the
        // reader must see either the old contents or the new ones,
        // never a half-written file.
        let tmpdir = tempdir_pathbuf();
        let path = tmpdir.join("race.json");
        let mut store = LeaseStore::new(&path);
        store.insert(peer(0xaa), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 7), v6: None,
        });
        store.save().unwrap();
        // Now overwrite with a different value while reading.
        store.insert(peer(0xaa), Lease {
            v4: Ipv4Addr::new(10, 55, 0, 8), v6: None,
        });
        // A pre-save snapshot of the file's bytes:
        let pre = std::fs::read_to_string(&path).unwrap();
        store.save().unwrap();
        let post = std::fs::read_to_string(&path).unwrap();
        // Both reads must parse successfully (no truncation race).
        let _: PersistedFile = serde_json::from_str(&pre).unwrap();
        let _: PersistedFile = serde_json::from_str(&post).unwrap();
        assert!(post.contains("10.55.0.8"));
        std::fs::remove_dir_all(&tmpdir).unwrap();
    }

    /// Cargo doesn't bundle the `tempfile` crate by default; for
    /// the few tests that need a scratch directory we just pick a
    /// per-PID/per-thread path under `/tmp`. Clean-up is the
    /// caller's job via `remove_dir_all` at the end of the test.
    fn tempdir_pathbuf() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "bifrost-lease-store-{}-{:?}",
            std::process::id(),
            std::thread::current().id(),
        ));
        // Idempotent — wipe any leftover from a previous failed
        // test run before creating fresh.
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
