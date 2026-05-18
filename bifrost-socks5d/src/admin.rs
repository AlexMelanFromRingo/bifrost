// Admin UNIX socket server for bifrost-socks5d.
//
// Listens on a configurable path (default /tmp/bifrost-socks5d-ctl.sock),
// reads ONE newline-terminated JSON request per connection, dispatches
// into the live daemon state, writes ONE JSON response back, closes.
//
// The socket is chmod 0600 on creation — the file lives in /tmp by
// default and we don't want other users on the host poking at the
// daemon's selection state.

use anyhow::{Context, Result};
use bifrost_core::admin_proto::{
    AdminRequest, AdminResponse, ExitRow, PeerRow, ReloadResponse, StatusResponse,
};
use bifrost_core::scoring::ScoredExitPool;
use bifrost_core::PubKey;
use norn_rs::PacketConn;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use crate::config::{DaemonConfig, Mode};

/// Reloadable per-CONNECT knobs that handle_socks5 reads on each
/// accept. Atomics so the admin Reload command can rewrite without
/// any lock and without restarting the daemon.
pub struct RaceConfig {
    race_exits: AtomicUsize,
    race_timeout_ms: AtomicU64,
}

impl RaceConfig {
    pub fn new(race_exits: usize, race_timeout_ms: u64) -> Self {
        Self {
            race_exits: AtomicUsize::new(race_exits),
            race_timeout_ms: AtomicU64::new(race_timeout_ms),
        }
    }
    pub fn race_exits(&self) -> usize {
        self.race_exits.load(Ordering::Relaxed)
    }
    pub fn race_timeout(&self) -> Duration {
        Duration::from_millis(self.race_timeout_ms.load(Ordering::Relaxed))
    }
    pub fn store(&self, exits: usize, timeout_ms: u64) {
        self.race_exits.store(exits, Ordering::Relaxed);
        self.race_timeout_ms.store(timeout_ms, Ordering::Relaxed);
    }
}

pub struct AdminState {
    pub conn: Arc<PacketConn>,
    pub pool: Option<Arc<ScoredExitPool>>,
    pub mode: Mode,
    pub started_at: Instant,
    /// Path to the daemon's config file, captured at startup so
    /// `Reload` can re-read it without restart.
    pub config_path: PathBuf,
    /// Atomics behind the per-CONNECT race knobs. Reload swings
    /// these in place.
    pub race_cfg: Arc<RaceConfig>,
}

/// Tag bifrost uses on every mDNS-discovered candidate. Reload
/// preserves these (the source of truth is the live mesh, not the
/// config file).
const MDNS_TAG: &str = "mDNS";

pub async fn listen(path: &str, state: Arc<AdminState>) -> Result<()> {
    // Idempotent restart: a stale socket from a previous run blocks
    // bind() with EADDRINUSE. Remove unconditionally — only the
    // owner has access (chmod 0600 below).
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding admin socket {path}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 on admin socket {path}"))?;
    info!("bifrost admin socket at {path} (mode 0600)");

    loop {
        let (stream, _addr) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                warn!("admin accept: {e}");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, state).await {
                debug!("admin: client conn ended: {e}");
            }
        });
    }
}

async fn handle_conn(stream: tokio::net::UnixStream, state: Arc<AdminState>) -> Result<()> {
    let (r, mut w) = stream.into_split();
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    // One-request-per-connection — cap input at a sensible size so a
    // misbehaving client can't slurp memory by sending an infinite
    // pre-newline payload.
    let mut bounded = (&mut reader).take(64 * 1024);
    bounded.read_line(&mut line).await.context("read admin request")?;
    let response = match serde_json::from_str::<AdminRequest>(line.trim()) {
        Ok(req) => dispatch(req, &state),
        Err(e) => AdminResponse::err(format!("bad request: {e}")),
    };
    let body = serde_json::to_string(&response).context("serialise admin response")?;
    w.write_all(body.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.shutdown().await.ok();
    Ok(())
}

fn dispatch(req: AdminRequest, state: &AdminState) -> AdminResponse {
    match req {
        AdminRequest::Status => AdminResponse::ok(StatusResponse {
            pub_key: hex::encode(state.conn.pub_key),
            address: ipv6_string(&address_from_key(&state.conn.pub_key)),
            mode: match state.mode { Mode::Client => "client", Mode::Exit => "exit" }.into(),
            uptime_secs: state.started_at.elapsed().as_secs(),
            peer_count: state.conn.get_peer_stats().len(),
            exit_pool_size: state.pool.as_ref().map(|p| p.snapshot().len()).unwrap_or(0),
            auto_egress: state.pool.is_some(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),

        AdminRequest::Exits => {
            // Force a fresh refresh so a recently-recorded penalty or
            // a peer that just connected shows up immediately, not
            // on the next 10 s background tick. Cheap: linear in the
            // candidate count.
            if let Some(pool) = &state.pool {
                pool.refresh(&state.conn.get_peer_stats());
            }
            let rows: Vec<ExitRow> = state
                .pool
                .as_ref()
                .map(|p| {
                    p.snapshot()
                        .into_iter()
                        .map(|s| ExitRow {
                            pub_key: hex::encode(s.pub_key),
                            tag: s.tag,
                            weight: s.weight,
                            trust: s.trust,
                            rtt_ms: s.rtt_ms,
                            penalty_ms: s.penalty_ms,
                            stats_known: s.stats_known,
                        })
                        .collect()
                })
                .unwrap_or_default();
            AdminResponse::ok(rows)
        }

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

        AdminRequest::Penalty { pub_key } => match (decode_pub_key(&pub_key), &state.pool) {
            (Ok(k), Some(pool)) => {
                pool.record_failure(&k);
                AdminResponse::ok(serde_json::json!({
                    "penalised": pub_key,
                    "note": "next 120 s",
                }))
            }
            (Err(e), _) => AdminResponse::err(e),
            (_, None) => AdminResponse::err("no ScoredExitPool — egress mode must be 'auto'"),
        },

        AdminRequest::ResetPenalty { pub_key } => match (decode_pub_key(&pub_key), &state.pool) {
            (Ok(k), Some(pool)) => {
                pool.reset_penalty(&k);
                AdminResponse::ok(serde_json::json!({"reset": pub_key}))
            }
            (Err(e), _) => AdminResponse::err(e),
            (_, None) => AdminResponse::err("no ScoredExitPool — egress mode must be 'auto'"),
        },

        AdminRequest::ResetAllPenalties => match &state.pool {
            Some(pool) => {
                pool.reset_all_penalties();
                AdminResponse::ok(serde_json::json!({"reset": "all"}))
            }
            None => AdminResponse::err("no ScoredExitPool — egress mode must be 'auto'"),
        },

        AdminRequest::Reload => reload(state),
    }
}

fn reload(state: &AdminState) -> AdminResponse {
    let new_cfg = match DaemonConfig::load(&state.config_path) {
        Ok(c) => c,
        Err(e) => return AdminResponse::err(format!("reload: re-read {:?}: {e}", state.config_path)),
    };
    // Mode swaps require recreating the picker + spawning/killing
    // refresh+discovery tasks — out of scope for in-place reload.
    if new_cfg.mode != state.mode {
        return AdminResponse::err(format!(
            "reload: mode change ({:?} -> {:?}) requires a restart",
            state.mode, new_cfg.mode
        ));
    }

    let mut response = ReloadResponse::default();

    // Apply [bifrost] race tuning unconditionally — it's a runtime
    // knob and a hot-swap is the entire point of the command.
    let new_race_exits = new_cfg.bifrost.race_exits;
    let new_race_timeout_ms = new_cfg.bifrost.race_timeout_ms;
    let old_race_exits = state.race_cfg.race_exits();
    let old_race_timeout_ms = state.race_cfg.race_timeout().as_millis() as u64;
    if new_race_exits != old_race_exits || new_race_timeout_ms != old_race_timeout_ms {
        state.race_cfg.store(new_race_exits, new_race_timeout_ms);
        response.race_exits = Some(new_race_exits);
        response.race_timeout_ms = Some(new_race_timeout_ms);
        info!(
            "reload: race tuning {} → {} exits, {} → {} ms timeout",
            old_race_exits, new_race_exits, old_race_timeout_ms, new_race_timeout_ms
        );
    }

    // Apply egress.exits delta into the ScoredExitPool (Auto mode only).
    // Round-robin Exit mode has no pool to mutate — config edits there
    // need a full restart, surfaced to the operator.
    if let Some(pool) = &state.pool {
        let new_exits: Vec<(PubKey, Option<String>)> = match new_cfg
            .egress
            .as_ref()
            .and_then(|p| p.exit_keys().ok())
        {
            Some(v) => v,
            None => {
                return AdminResponse::ok(response);
            }
        };
        let new_pks: std::collections::HashSet<PubKey> =
            new_exits.iter().map(|(k, _)| *k).collect();
        let current: Vec<(PubKey, Option<String>)> = pool.candidates();
        let current_pks: std::collections::HashSet<PubKey> =
            current.iter().map(|(k, _)| *k).collect();

        // Add newcomers.
        for (pk, tag) in &new_exits {
            if !current_pks.contains(pk) {
                pool.add_candidate(*pk, tag.clone());
                response.exits_added.push(hex::encode(pk));
                info!("reload: + exit {}", hex::encode(&pk[..8]));
            }
        }

        // Drop removals — but PRESERVE mDNS-discovered entries even if
        // the config doesn't list them. The point of mDNS discovery is
        // that the live mesh, not the config, is the source of truth
        // for those peers.
        for (pk, tag) in &current {
            if !new_pks.contains(pk) {
                if tag.as_deref() == Some(MDNS_TAG) {
                    response.exits_skipped_mdns += 1;
                    continue;
                }
                pool.remove_candidate(pk);
                response.exits_removed.push(hex::encode(pk));
                info!("reload: − exit {}", hex::encode(&pk[..8]));
            }
        }

        // Force a refresh so the freshly-added / removed entries show
        // up in the next bifrost-ctl exits call without waiting for
        // the 10 s tick.
        pool.refresh(&state.conn.get_peer_stats());
    } else if new_cfg.egress.as_ref().is_some_and(|p| {
        p.exit_keys()
            .ok()
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    }) {
        // Static-rotator + non-empty [egress].exits means the operator
        // changed the static list — but ExitRotator isn't mutable.
        // Tell them to restart for that change.
        warn!(
            "reload: [egress].exits change ignored — rotator (mode=exit) \
             is immutable; restart the daemon to pick up changes"
        );
    }

    AdminResponse::ok(response)
}

fn decode_pub_key(hex_str: &str) -> std::result::Result<PubKey, String> {
    let raw = hex::decode(hex_str.trim()).map_err(|e| format!("hex decode: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("pub_key must be 32 bytes (64 hex chars), got {}", raw.len()));
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Ok(k)
}

// ── small helpers (avoid pulling norn-rs::address publicly) ────────────────

fn address_from_key(pk: &PubKey) -> [u8; 16] {
    // Re-derive via norn-rs's own helper so we don't drift.
    norn_rs::address::address_from_key(pk)
}

fn ipv6_string(bytes: &[u8; 16]) -> String {
    use std::net::Ipv6Addr;
    let mut groups = [0u16; 8];
    for (i, chunk) in bytes.chunks(2).enumerate() {
        groups[i] = u16::from_be_bytes([chunk[0], chunk[1]]);
    }
    Ipv6Addr::new(
        groups[0], groups[1], groups[2], groups[3],
        groups[4], groups[5], groups[6], groups[7],
    )
    .to_string()
}

// AsyncRead extension is in `tokio::io` — bring AsyncReadExt for `.take`.
use tokio::io::AsyncReadExt;
