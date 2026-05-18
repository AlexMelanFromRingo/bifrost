// bifrost-socks5d — bridge SOCKS5 over a norn-rs overlay mesh.
//
// `client` mode: listens on 127.0.0.1:1080, accepts SOCKS5 v5
// CONNECTs, routes each to an exit peer via a MeshStream, and pipes
// bytes both ways with tokio::io::copy_bidirectional.
//
// `exit` mode: accepts MeshStream Opens from any peer, dials the real
// target with tokio::net::TcpStream, and bridges the two. Reply codes
// flow back as OpenAck frames so the client can mirror them on its
// SOCKS5 socket.

mod admin;
mod config;
mod metrics;
mod socks5;

use admin::AdminState;
use anyhow::{Context, Result};
use bifrost_core::{
    discovery,
    frame::OpenTarget,
    mux::{AcceptedStream, MeshMux},
    policy::{EgressPolicy, ExitRotator},
    scoring::{spawn_refresher, ScoredExitPool},
    stream::reply,
};
use clap::{Parser, Subcommand};
use config::{DaemonConfig, Mode};
use norn_rs::node::Node;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "bifrost-socks5d", version, about = "SOCKS5 over norn-rs mesh")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a starter config to stdout. Two flavours: --exit prints the
    /// exit-side template, omitting it prints the client-side template.
    Genconfig {
        #[arg(long)]
        exit: bool,
    },
    /// Run the daemon. Reads the TOML config (must be chmod 600).
    Run {
        #[arg(short, long)]
        config: std::path::PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Genconfig { exit } => {
            print!("{}", if exit { DaemonConfig::sample_exit() } else { DaemonConfig::sample_client() });
            Ok(())
        }
        Cmd::Run { config } => run(config).await,
    }
}

async fn run(config_path: std::path::PathBuf) -> Result<()> {
    let cfg = DaemonConfig::load(&config_path)?;
    init_logging(&cfg.node.log_level);

    let started_at = Instant::now();
    info!("starting bifrost-socks5d in {:?} mode", cfg.mode);
    let node = Node::new(cfg.node.clone()).await.context("starting norn node")?;
    node.start().await.context("starting norn subsystems")?;
    let conn = node.conn.clone();
    info!("norn node up; our pub_key={}", hex::encode(conn.pub_key));

    let (mux, accept_rx) = MeshMux::new(conn);

    match cfg.mode {
        Mode::Client => run_client(cfg, mux, started_at).await,
        Mode::Exit => run_exit(cfg, mux, accept_rx, started_at).await,
    }
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

// ── CLIENT ────────────────────────────────────────────────────────────────

/// Either selection strategy: round-robin (`Exit`) or trust/RTT-weighted
/// random (`Auto`). Both expose the same `pick()` API for handle_socks5;
/// only Auto knows how to absorb failure feedback.
enum ExitPicker {
    Rotator(Arc<ExitRotator>),
    Scored(Arc<ScoredExitPool>),
}

impl ExitPicker {
    fn pick(&self) -> Option<(bifrost_core::PubKey, Option<String>)> {
        match self {
            Self::Rotator(r) => r.pick(),
            Self::Scored(s) => s.pick(),
        }
    }

    fn record_failure(&self, key: &bifrost_core::PubKey) {
        if let Self::Scored(s) = self {
            s.record_failure(key);
        }
    }
}

async fn run_client(cfg: DaemonConfig, mux: Arc<MeshMux>, started_at: Instant) -> Result<()> {
    let policy = cfg
        .egress
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("client mode requires [egress]"))?;
    let exits = policy.exit_keys().context("decoding egress.exits")?;
    if exits.is_empty() && !matches!(policy, EgressPolicy::Mesh) {
        warn!("egress mode is exit/auto but no exits configured — every CONNECT will fail");
    }
    let picker = if policy.is_auto() {
        let pool = Arc::new(ScoredExitPool::new(exits));
        // Refresh once now so the snapshot is warm before the first
        // CONNECT lands; the background tick keeps it fresh after.
        pool.refresh(&mux.conn().get_peer_stats());
        spawn_refresher(pool.clone(), mux.conn().clone(), Duration::from_secs(10));
        info!("egress.auto: weighted-random pool of {} candidates", pool.snapshot().len());
        // The bifrost-specific Prometheus endpoint only makes sense
        // when there's a ScoredExitPool to expose; skip it for
        // round-robin Exit mode.
        if !cfg.bifrost.metrics_addr.is_empty() {
            let addr = cfg.bifrost.metrics_addr.clone();
            let pool_for_metrics = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics::listen(&addr, pool_for_metrics).await {
                    warn!("bifrost metrics endpoint: {e}");
                }
            });
        }
        if cfg.bifrost.mdns_discovery {
            match discovery::browse_exits(pool.clone(), mux.conn().pub_key) {
                Ok(daemon) => {
                    info!("mDNS exit discovery active ({})", discovery::SERVICE_TYPE);
                    // Stash the handle in a Box<dyn Any + Send + Sync>
                    // so it lives for the daemon's lifetime; dropping
                    // it would unregister the browser.
                    Box::leak(Box::new(daemon));
                }
                Err(e) => warn!("mDNS exit discovery failed to start: {e}"),
            }
        }
        ExitPicker::Scored(pool)
    } else {
        if !cfg.bifrost.metrics_addr.is_empty() {
            warn!(
                "bifrost.metrics_addr set but egress mode is not 'auto' — skipping endpoint \
                 (the gauges are pool-specific and only have meaning with weighted selection)"
            );
        }
        ExitPicker::Rotator(Arc::new(ExitRotator::new(exits)))
    };
    let picker = Arc::new(picker);

    // Spin up the bifrost admin socket if configured. Works in both
    // Auto (with pool) and Exit (rotator only — penalty/exits ops will
    // return a "no pool" error but status/peers still work).
    spawn_admin_if_configured(
        &cfg,
        AdminState {
            conn: mux.conn().clone(),
            pool: match picker.as_ref() {
                ExitPicker::Scored(p) => Some(p.clone()),
                ExitPicker::Rotator(_) => None,
            },
            mode: Mode::Client,
            started_at,
        },
    );

    let listener = TcpListener::bind(&cfg.socks5_listen)
        .await
        .with_context(|| format!("binding SOCKS5 listener {:?}", cfg.socks5_listen))?;
    info!("SOCKS5 listener up at {}", cfg.socks5_listen);

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                error!("accept error: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        let mux = mux.clone();
        let picker = picker.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(sock, mux, picker).await {
                tracing::debug!("socks5 from {peer}: {e}");
            }
        });
    }
}

async fn handle_socks5(
    mut sock: TcpStream,
    mux: Arc<MeshMux>,
    picker: Arc<ExitPicker>,
) -> Result<()> {
    socks5::negotiate_methods(&mut sock).await?;
    let target = match socks5::read_request(&mut sock).await {
        Ok(t) => t,
        Err(e) => return Err(e),
    };
    let Some((exit_peer, tag)) = picker.pick() else {
        let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
        anyhow::bail!("no exit peers configured");
    };
    info!(
        "CONNECT {} → exit {}{}",
        target.display(),
        hex::encode(&exit_peer[..8]),
        tag.as_deref().map(|t| format!(" [{t}]")).unwrap_or_default()
    );
    let mut mesh = match mux.open(exit_peer, target.clone()).await {
        Ok(s) => s,
        Err(e) => {
            warn!("open(exit={}): {e}", hex::encode(&exit_peer[..8]));
            // Auto mode absorbs the failure as a temporary penalty so
            // the next CONNECT skips this peer. Rotator mode just
            // moves on; round-robin will visit it again next pass.
            picker.record_failure(&exit_peer);
            let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };
    let ack = match mesh.await_open_ack().await {
        Ok(code) => code,
        Err(e) => {
            picker.record_failure(&exit_peer);
            let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
            return Err(e.into());
        }
    };
    socks5::write_reply(&mut sock, ack).await?;
    if ack != socks5::REP_SUCCESS {
        // Exit replied but couldn't dial the target — also a penalty
        // signal, since a healthy exit on a working upstream would
        // succeed. (HOST_UNREACHABLE / CONN_REFUSED for the target
        // host are correctly attributed to the EXIT's view of that
        // host, not the exit itself failing — but at the SOCKS5 layer
        // that's the actionable signal we have.)
        picker.record_failure(&exit_peer);
        return Ok(());
    }
    match tokio::io::copy_bidirectional(&mut sock, &mut mesh).await {
        Ok((up, down)) => tracing::debug!("CONNECT {} done up={up} down={down}", target.display()),
        Err(e) => tracing::debug!("CONNECT {} pipe err: {e}", target.display()),
    }
    Ok(())
}

// ── EXIT ─────────────────────────────────────────────────────────────────

async fn run_exit(
    cfg: DaemonConfig,
    mux: Arc<MeshMux>,
    mut accept_rx: tokio::sync::mpsc::Receiver<AcceptedStream>,
    started_at: Instant,
) -> Result<()> {
    info!("exit mode: waiting for SOCKS5 CONNECTs over the mesh");
    spawn_admin_if_configured(
        &cfg,
        AdminState {
            conn: mux.conn().clone(),
            pool: None,
            mode: Mode::Exit,
            started_at,
        },
    );
    if cfg.bifrost.mdns_discovery {
        let port = cfg.node.tcp_listen_port().unwrap_or(9001);
        match discovery::advertise_exit(mux.conn().pub_key, port) {
            Ok(daemon) => {
                info!("mDNS exit advertisement live on port {port}");
                Box::leak(Box::new(daemon));
            }
            Err(e) => warn!("mDNS advertise failed: {e}"),
        }
    }
    while let Some(acc) = accept_rx.recv().await {
        tokio::spawn(handle_exit_stream(acc));
    }
    warn!("accept channel closed — mux read loop ended");
    Ok(())
}

fn spawn_admin_if_configured(cfg: &DaemonConfig, state: AdminState) {
    if cfg.bifrost.admin_socket.is_empty() {
        return;
    }
    let path = cfg.bifrost.admin_socket.clone();
    let state = Arc::new(state);
    tokio::spawn(async move {
        if let Err(e) = admin::listen(&path, state).await {
            warn!("bifrost admin socket: {e}");
        }
    });
}

async fn handle_exit_stream(acc: AcceptedStream) {
    let target = acc.target.clone();
    let mut mesh = acc.stream;
    info!(
        "exit: incoming from {} → {}",
        hex::encode(&acc.from[..8]),
        target.display()
    );
    // bifrost-socks5d only handles SOCKS5 CONNECT targets; egress
    // tunnels belong to bifrost-vpnd. Reject cleanly so the client
    // (which may be SOCKS5 only) doesn't hang waiting for an answer.
    if matches!(target, OpenTarget::Egress) {
        warn!("exit: refusing Egress target — this daemon is SOCKS5-only");
        let _ = mesh.send_open_ack(reply::CMD_NOT_SUPPORTED).await;
        return;
    }
    let target_str = open_target_to_connect_str(&target);
    let tcp = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect(&target_str)).await;
    let mut tcp = match tcp {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("exit: dial {target_str} failed: {e}");
            let _ = mesh.send_open_ack(map_dial_err(&e)).await;
            return;
        }
        Err(_) => {
            warn!("exit: dial {target_str} timed out");
            let _ = mesh.send_open_ack(reply::HOST_UNREACHABLE).await;
            return;
        }
    };
    if let Err(e) = mesh.send_open_ack(reply::SUCCESS).await {
        warn!("exit: write OpenAck failed: {e}");
        return;
    }
    match tokio::io::copy_bidirectional(&mut tcp, &mut mesh).await {
        Ok((up, down)) => tracing::debug!("exit: {} done up={up} down={down}", target.display()),
        Err(e) => tracing::debug!("exit: {} pipe err: {e}", target.display()),
    }
}

fn open_target_to_connect_str(t: &OpenTarget) -> String {
    match t {
        OpenTarget::V4(ip, port) => format!("{ip}:{port}"),
        OpenTarget::V6(ip, port) => format!("[{ip}]:{port}"),
        OpenTarget::Domain(host, port) => format!("{host}:{port}"),
        // Egress is rejected at the call site before we reach here,
        // but keep the arm so the compiler can prove exhaustiveness.
        OpenTarget::Egress => String::from("<egress>"),
    }
}

fn map_dial_err(e: &std::io::Error) -> u8 {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => reply::CONN_REFUSED,
        TimedOut => reply::TTL_EXPIRED,
        NotFound | AddrNotAvailable => reply::HOST_UNREACHABLE,
        _ => reply::GENERAL_FAILURE,
    }
}
