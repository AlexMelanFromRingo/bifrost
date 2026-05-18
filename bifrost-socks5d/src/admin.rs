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
    AdminRequest, AdminResponse, ExitRow, PeerRow, StatusResponse,
};
use bifrost_core::scoring::ScoredExitPool;
use bifrost_core::PubKey;
use norn_rs::PacketConn;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tracing::{debug, info, warn};

use crate::config::Mode;

pub struct AdminState {
    pub conn: Arc<PacketConn>,
    pub pool: Option<Arc<ScoredExitPool>>,
    pub mode: Mode,
    pub started_at: Instant,
}

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
    }
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
