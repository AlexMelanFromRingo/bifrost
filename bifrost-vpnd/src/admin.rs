//! vpnd-specific admin RPC over UNIX socket.
//!
//! Mirrors [`bifrost_socks5d::admin`] on the protocol level — same
//! `AdminRequest` / `AdminResponse` envelope from
//! [`bifrost_core::admin_proto`] — but the dispatch wires up to the
//! egress table + lease store instead of the SOCKS5 exit pool.
//!
//! Endpoints implemented:
//!
//! * `Status` — pub_key, mode, uptime, lease count, persistence path.
//! * `Peers` — direct mesh peers from the underlying `PacketConn`.
//! * `Leases` — every sticky `(peer, IPv4, IPv6?)` mapping. On the
//!   client this is the single self-allocated lease.
//! * `EvictLease { pub_key }` — drop the peer from the table, free
//!   its address-pool slot, and remove it from the persistence file.
//!   Exit-only — client returns "not applicable".
//!
//! Other variants from the cross-daemon protocol (`Exits`,
//! `Penalty`, `ResetPenalty`, `ResetAllPenalties`, `Reload`) return
//! a structured "not supported on vpnd" error so cross-daemon
//! tooling can talk to either socket and either get an answer or
//! a clean rejection.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use bifrost_core::admin_proto::{
    AdminRequest, AdminResponse, EvictLeaseResponse, LeaseRow, LeasesResponse, PeerRow,
    StatusResponse,
};
use norn_rs::router::PacketConn;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use crate::egress::{Lease, SharedPool, SharedTable};
use crate::lease_store::LeaseStore;

/// Shared state the admin dispatch needs to read or mutate.
///
/// `pool` / `table` / `lease_store` are present only in exit mode;
/// `self_lease` is present only in client mode (and only after the
/// handshake succeeds).
#[derive(Clone)]
pub struct AdminState {
    pub conn: Arc<PacketConn>,
    pub mode: AdminMode,
    pub started_at: Instant,
    pub pool: Option<SharedPool>,
    pub table: Option<SharedTable>,
    pub lease_store: Option<Arc<Mutex<LeaseStore>>>,
    pub self_lease: Option<Lease>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminMode {
    Exit,
    Client,
}

impl AdminMode {
    fn as_str(self) -> &'static str {
        match self {
            AdminMode::Exit => "exit",
            AdminMode::Client => "client",
        }
    }
}

/// Bind the UNIX socket at `path` (0600) and dispatch incoming
/// requests in tokio tasks until the listener is dropped. Returns
/// immediately after spawning the accept loop; caller keeps the
/// state alive for the daemon lifetime.
pub fn spawn_listener(path: PathBuf, state: AdminState) -> Result<()> {
    if path.as_os_str().is_empty() {
        info!("vpnd admin socket disabled (empty path)");
        return Ok(());
    }
    // Remove any stale socket file from a prior crashed run; the
    // bind would fail with EADDRINUSE otherwise.
    let _ = std::fs::remove_file(&path);
    // Use a tight umask around the bind so the socket lands at 0600
    // (the default on Linux is 0777-umask). We restore the umask
    // immediately so we don't leak this restriction to other code
    // paths in the same process.
    #[cfg(unix)]
    let _g = {
        struct UmaskGuard(libc::mode_t);
        impl Drop for UmaskGuard {
            fn drop(&mut self) {
                // SAFETY: umask is process-global; restoring the
                // previous mask is the canonical pattern.
                unsafe { libc::umask(self.0); }
            }
        }
        // SAFETY: setting + reading the umask is process-global
        // but always defined.
        let prev = unsafe { libc::umask(0o077) };
        UmaskGuard(prev)
    };
    let listener = UnixListener::bind(&path)?;
    info!("vpnd admin socket at {path:?} (mode 0600)");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let s = state.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, &s).await {
                            debug!("vpnd admin: client handler: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    warn!("vpnd admin accept: {e}");
                    return;
                }
            }
        }
    });
    Ok(())
}

async fn handle_client(
    stream: tokio::net::UnixStream,
    state: &AdminState,
) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let req: AdminRequest = serde_json::from_str(line.trim())
        .map_err(|e| anyhow::anyhow!("malformed admin request: {e}"))?;
    let response = dispatch(req, state);
    let body = serde_json::to_string(&response)?;
    w.write_all(body.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.shutdown().await.ok();
    Ok(())
}

fn dispatch(req: AdminRequest, state: &AdminState) -> AdminResponse {
    match req {
        AdminRequest::Status => AdminResponse::ok(StatusResponse {
            pub_key: hex::encode(state.conn.pub_key),
            address: ipv6_string(&norn_rs::address::address_from_key(&state.conn.pub_key)),
            mode: state.mode.as_str().to_string(),
            uptime_secs: state.started_at.elapsed().as_secs(),
            peer_count: state.conn.get_peer_stats().len(),
            // Re-use `exit_pool_size` to surface the active lease
            // count on exit mode (matches what an operator usually
            // wants to see at a glance: "how many clients am I
            // serving right now?"). Client mode reports 0.
            exit_pool_size: state
                .table
                .as_ref()
                .map(|t| t.lock().unwrap().snapshot().len())
                .unwrap_or(0),
            auto_egress: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),

        AdminRequest::Peers => {
            let rows: Vec<PeerRow> = state
                .conn
                .get_peer_stats()
                .into_iter()
                .map(|s| PeerRow {
                    pub_key: hex::encode(s.key),
                    trust: s.trust,
                    lag_ms: s.lag.as_millis() as u64,
                    loss_rate: s.loss_rate,
                    uptime_secs: s.uptime.as_secs(),
                    rx_bytes: s.rx_bytes,
                    tx_bytes: s.tx_bytes,
                })
                .collect();
            AdminResponse::ok(rows)
        }

        AdminRequest::Leases => AdminResponse::ok(snapshot_leases(state)),

        AdminRequest::EvictLease { pub_key } => evict_lease(state, &pub_key),

        // The cross-daemon protocol carries variants that only make
        // sense for `bifrost-socks5d`; ack them politely instead of
        // panicking so tooling that hits either socket gets a clean
        // signal.
        AdminRequest::Exits => AdminResponse::ok(Vec::<bifrost_core::admin_proto::ExitRow>::new()),
        AdminRequest::Penalty { .. }
        | AdminRequest::ResetPenalty { .. }
        | AdminRequest::ResetAllPenalties => AdminResponse::err(
            "bifrost-vpnd has no ScoredExitPool — these commands are socks5d-only",
        ),
        AdminRequest::Reload => AdminResponse::err(
            "bifrost-vpnd does not support in-place reload yet; restart the daemon",
        ),
    }
}

fn snapshot_leases(state: &AdminState) -> LeasesResponse {
    let persistence_path = state
        .lease_store
        .as_ref()
        .and_then(|s| {
            let store = s.lock().unwrap();
            if store.is_persistent() {
                Some(store.path_display())
            } else {
                None
            }
        });

    // Exit: snapshot the full EgressTable; persisted-but-disconnected
    // entries are surfaced as `live=false` so an operator can tell
    // sticky reserves apart from active sessions.
    if let Some(table) = &state.table {
        let live_map: std::collections::HashMap<_, _> = table
            .lock()
            .unwrap()
            .snapshot()
            .into_iter()
            .collect();
        let persisted: Vec<(bifrost_core::PubKey, Lease)> = state
            .lease_store
            .as_ref()
            .map(|s| s.lock().unwrap().snapshot())
            .unwrap_or_default();
        let mut rows: Vec<LeaseRow> = persisted
            .iter()
            .map(|(p, l)| LeaseRow {
                pub_key: hex::encode(p),
                v4: l.v4.to_string(),
                v6: l.v6.map(|v| v.to_string()),
                live: live_map.contains_key(p),
            })
            .collect();
        // Surface in-memory-only rows too (rare but possible:
        // persistence disabled, or a lease added after the last
        // save). Avoid double-counting by skipping peers already
        // present in `persisted`.
        let seen: std::collections::HashSet<bifrost_core::PubKey> =
            persisted.iter().map(|(p, _)| *p).collect();
        for (p, l) in live_map {
            if !seen.contains(&p) {
                rows.push(LeaseRow {
                    pub_key: hex::encode(p),
                    v4: l.v4.to_string(),
                    v6: l.v6.map(|v| v.to_string()),
                    live: true,
                });
            }
        }
        return LeasesResponse {
            rows,
            persistence_path,
        };
    }

    // Client: just our own assigned lease, if any.
    let rows: Vec<LeaseRow> = state
        .self_lease
        .iter()
        .map(|l| LeaseRow {
            pub_key: hex::encode(state.conn.pub_key),
            v4: l.v4.to_string(),
            v6: l.v6.map(|v| v.to_string()),
            live: true,
        })
        .collect();
    LeasesResponse {
        rows,
        persistence_path,
    }
}

fn evict_lease(state: &AdminState, hex_key: &str) -> AdminResponse {
    if state.mode != AdminMode::Exit {
        return AdminResponse::err(
            "EvictLease only applies to exit mode; client mode owns at most its own self-lease",
        );
    }
    let peer = match decode_pub_key(hex_key) {
        Ok(k) => k,
        Err(e) => return AdminResponse::err(e),
    };
    let pool = state.pool.as_ref().expect("exit mode invariant: pool is set");
    let table = state.table.as_ref().expect("exit mode invariant: table is set");

    // Acquire-and-release in one critical section per Mutex so we
    // never hold two locks at once (the data plane locks pool and
    // table independently — overlapping them risks an ordering
    // deadlock with the handshake path).
    let removed = table.lock().unwrap().remove_peer(&peer);
    if let Some(lease) = removed {
        pool.lock().unwrap().release(lease);
        if let Some(store) = &state.lease_store {
            let mut s = store.lock().unwrap();
            s.remove(&peer);
            if let Err(e) = s.save() {
                warn!(
                    "evict-lease: persistence save failed for {}: {e:#} \
                     (in-memory state is correct; will retry on next change)",
                    &hex_key[..16.min(hex_key.len())]
                );
            }
        }
        info!(
            "evict-lease: freed {} (was held by peer {})",
            lease.v4,
            &hex_key[..16.min(hex_key.len())]
        );
        AdminResponse::ok(EvictLeaseResponse {
            pub_key: hex_key.to_string(),
            evicted: true,
            freed_v4: Some(lease.v4.to_string()),
            freed_v6: lease.v6.map(|v| v.to_string()),
        })
    } else {
        AdminResponse::ok(EvictLeaseResponse {
            pub_key: hex_key.to_string(),
            evicted: false,
            freed_v4: None,
            freed_v6: None,
        })
    }
}

fn decode_pub_key(hex_s: &str) -> std::result::Result<bifrost_core::PubKey, String> {
    if hex_s.len() != 64 {
        return Err(format!(
            "pub_key must be 64 hex chars (got {})",
            hex_s.len()
        ));
    }
    let bytes = hex::decode(hex_s).map_err(|e| format!("hex decode: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn ipv6_string(bytes: &[u8; 16]) -> String {
    let mut out = String::new();
    let mut first = true;
    for chunk in bytes.chunks(2) {
        if !first {
            out.push(':');
        }
        first = false;
        out.push_str(&format!("{:x}", u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn dummy_state(mode: AdminMode) -> AdminState {
        // Construct a minimal PacketConn for the conn field. We
        // never `start()` it — just need the pub_key surface.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let conn = Arc::new(PacketConn::new(sk));
        AdminState {
            conn,
            mode,
            started_at: Instant::now(),
            pool: None,
            table: None,
            lease_store: None,
            self_lease: None,
        }
    }

    #[test]
    fn decode_pub_key_rejects_short() {
        let err = decode_pub_key("dead").unwrap_err();
        assert!(err.contains("64 hex"));
    }

    #[test]
    fn decode_pub_key_rejects_non_hex() {
        let err = decode_pub_key(&"z".repeat(64)).unwrap_err();
        assert!(err.contains("hex decode"));
    }

    #[test]
    fn decode_pub_key_accepts_64_hex() {
        let key = decode_pub_key(&"ab".repeat(32)).unwrap();
        assert_eq!(key, [0xab; 32]);
    }

    #[tokio::test]
    async fn evict_rejects_client_mode() {
        let state = dummy_state(AdminMode::Client);
        let resp = evict_lease(&state, &"00".repeat(32));
        assert!(!resp.ok, "client mode must refuse evict-lease");
        assert!(resp.error.unwrap().contains("client mode"));
    }

    #[tokio::test]
    async fn evict_returns_false_when_peer_absent() {
        let state = AdminState {
            pool: Some(Arc::new(Mutex::new(
                crate::egress::AddressPool::new(
                    Ipv4Addr::new(10, 55, 0, 0),
                    24,
                    None,
                    64,
                )
                .unwrap(),
            ))),
            table: Some(Arc::new(Mutex::new(crate::egress::EgressTable::default()))),
            ..dummy_state(AdminMode::Exit)
        };
        let resp = evict_lease(&state, &"ff".repeat(32));
        assert!(resp.ok);
        let payload: EvictLeaseResponse =
            serde_json::from_value(resp.data.unwrap()).unwrap();
        assert!(!payload.evicted);
        assert!(payload.freed_v4.is_none());
    }

    #[tokio::test]
    async fn evict_drops_peer_and_releases_pool_slot() {
        let pool = Arc::new(Mutex::new(
            crate::egress::AddressPool::new(
                Ipv4Addr::new(10, 55, 0, 0),
                24,
                None,
                64,
            )
            .unwrap(),
        ));
        let table = Arc::new(Mutex::new(crate::egress::EgressTable::default()));
        let peer = [0x42u8; 32];
        let lease = pool.lock().unwrap().allocate().unwrap();
        table.lock().unwrap().insert(peer, lease);

        let state = AdminState {
            pool: Some(pool.clone()),
            table: Some(table.clone()),
            ..dummy_state(AdminMode::Exit)
        };
        let resp = evict_lease(&state, &hex::encode(peer));
        assert!(resp.ok);
        let payload: EvictLeaseResponse =
            serde_json::from_value(resp.data.unwrap()).unwrap();
        assert!(payload.evicted);
        assert_eq!(payload.freed_v4.as_deref(), Some("10.55.0.2"));
        // Pool slot must be reusable on the next allocate.
        let next = pool.lock().unwrap().allocate().unwrap();
        assert_eq!(next.v4, Ipv4Addr::new(10, 55, 0, 2));
        // Table no longer knows about this peer.
        assert!(table.lock().unwrap().lease_of(&peer).is_none());
    }

    #[tokio::test]
    async fn snapshot_leases_marks_disconnected_persisted_as_not_live() {
        let lease_store = Arc::new(Mutex::new(LeaseStore::new("")));
        let peer_live = [0x01u8; 32];
        let peer_persisted_only = [0x02u8; 32];
        let lease_a = Lease { v4: Ipv4Addr::new(10, 55, 0, 2), v6: None };
        let lease_b = Lease { v4: Ipv4Addr::new(10, 55, 0, 3), v6: None };
        lease_store.lock().unwrap().insert(peer_live, lease_a);
        lease_store.lock().unwrap().insert(peer_persisted_only, lease_b);

        let table = Arc::new(Mutex::new(crate::egress::EgressTable::default()));
        table.lock().unwrap().insert(peer_live, lease_a);

        let state = AdminState {
            table: Some(table),
            lease_store: Some(lease_store),
            ..dummy_state(AdminMode::Exit)
        };
        let resp = snapshot_leases(&state);
        assert_eq!(resp.rows.len(), 2);
        let live_row = resp.rows.iter().find(|r| r.pub_key == hex::encode(peer_live)).unwrap();
        let persisted_row = resp
            .rows
            .iter()
            .find(|r| r.pub_key == hex::encode(peer_persisted_only))
            .unwrap();
        assert!(live_row.live);
        assert!(!persisted_row.live);
    }
}
