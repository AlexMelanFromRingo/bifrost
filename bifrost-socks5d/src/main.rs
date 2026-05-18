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

use admin::{AdminState, RaceConfig};
use anyhow::{Context, Result};
use bifrost_core::{
    discovery,
    frame::OpenTarget,
    mux::{AcceptedStream, MeshMux},
    policy::{EgressPolicy, ExitRotator},
    scoring::{spawn_refresher, ScoredExitPool},
    stream::reply,
    MeshStream, PubKey,
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
        Mode::Client => run_client(cfg, config_path, mux, started_at).await,
        Mode::Exit => run_exit(cfg, config_path, mux, accept_rx, started_at).await,
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
    fn pick(&self) -> Option<(PubKey, Option<String>)> {
        match self {
            Self::Rotator(r) => r.pick(),
            Self::Scored(s) => s.pick(),
        }
    }

    /// Up to `n` distinct candidates for happy-eyeballs racing. The
    /// Scored variant draws weighted-random without replacement; the
    /// Rotator variant just walks N times (round-robin already gives
    /// us distinctness modulo pool size).
    fn pick_n(&self, n: usize) -> Vec<(PubKey, Option<String>)> {
        match self {
            Self::Scored(s) => s.pick_n(n),
            Self::Rotator(r) => {
                let mut out = Vec::with_capacity(n);
                let mut seen = std::collections::HashSet::new();
                for _ in 0..(n * 2) {
                    if out.len() >= n { break; }
                    if let Some((pk, tag)) = r.pick() {
                        if seen.insert(pk) {
                            out.push((pk, tag));
                        }
                    } else { break; }
                }
                out
            }
        }
    }

    fn record_failure(&self, key: &PubKey) {
        if let Self::Scored(s) = self {
            s.record_failure(key);
        }
    }
}

async fn run_client(
    cfg: DaemonConfig,
    config_path: std::path::PathBuf,
    mux: Arc<MeshMux>,
    started_at: Instant,
) -> Result<()> {
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

    // RaceConfig is shared between the accept loop (reader) and the
    // admin Reload handler (writer). Atomics so neither side blocks.
    let race_cfg = Arc::new(RaceConfig::new(
        cfg.bifrost.race_exits,
        cfg.bifrost.race_timeout_ms,
    ));

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
            config_path: config_path.clone(),
            race_cfg: race_cfg.clone(),
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
        // Read knobs at accept time so a Reload between accepts is
        // picked up by every subsequent CONNECT without restart.
        let race_exits = race_cfg.race_exits();
        let race_timeout = race_cfg.race_timeout();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(sock, mux, picker, race_exits, race_timeout).await {
                tracing::debug!("socks5 from {peer}: {e}");
            }
        });
    }
}

async fn handle_socks5(
    mut sock: TcpStream,
    mux: Arc<MeshMux>,
    picker: Arc<ExitPicker>,
    race_exits: usize,
    race_timeout: Duration,
) -> Result<()> {
    socks5::negotiate_methods(&mut sock).await?;
    let target = match socks5::read_request(&mut sock).await {
        Ok(t) => t,
        Err(e) => return Err(e),
    };
    let candidates = picker.pick_n(race_exits.max(1));
    if candidates.is_empty() {
        let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
        anyhow::bail!("no exit peers configured");
    }
    let race_now = candidates.len() > 1;
    info!(
        "CONNECT {} → {} candidate(s) [{}]",
        target.display(),
        candidates.len(),
        candidates
            .iter()
            .map(|(pk, tag)| format!(
                "{}{}",
                hex::encode(&pk[..8]),
                tag.as_deref().map(|t| format!("({t})")).unwrap_or_default(),
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    let outcome = if race_now {
        race_connect(&mux, target.clone(), candidates.clone(), race_timeout, &picker).await
    } else {
        single_connect(&mux, target.clone(), candidates[0].clone(), &picker).await
    };
    match outcome {
        ConnectOutcome::Success { mut stream, pk, tag } => {
            if race_now {
                info!("CONNECT {} won by {}{}",
                    target.display(),
                    hex::encode(&pk[..8]),
                    tag.as_deref().map(|t| format!(" [{t}]")).unwrap_or_default());
            }
            socks5::write_reply(&mut sock, socks5::REP_SUCCESS).await?;
            match tokio::io::copy_bidirectional(&mut sock, &mut stream).await {
                Ok((up, down)) => tracing::debug!(
                    "CONNECT {} done up={up} down={down}", target.display()),
                Err(e) => tracing::debug!("CONNECT {} pipe err: {e}", target.display()),
            }
            Ok(())
        }
        ConnectOutcome::AllRefused { last_code } => {
            socks5::write_reply(&mut sock, last_code).await?;
            Ok(())
        }
        ConnectOutcome::AllFailed { errors } => {
            warn!(
                "CONNECT {} failed across {} candidate(s): {}",
                target.display(),
                errors.len(),
                errors
                    .iter()
                    .map(|(pk, e)| format!("{}={e}", hex::encode(&pk[..8])))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
            anyhow::bail!("all candidates failed");
        }
    }
}

/// Outcome of (single or raced) CONNECT setup against the mesh.
enum ConnectOutcome {
    /// At least one exit returned OpenAck(SUCCESS); use this stream.
    Success { stream: MeshStream, pk: PubKey, tag: Option<String> },
    /// Every exit replied OpenAck with a non-success reply code (host
    /// unreachable / connection refused, etc.). We pass the last code
    /// back so the SOCKS5 client gets a meaningful REP.
    AllRefused { last_code: u8 },
    /// Every exit failed to OPEN or returned an unrelated error.
    AllFailed { errors: Vec<(PubKey, String)> },
}

async fn single_connect(
    mux: &Arc<MeshMux>,
    target: OpenTarget,
    candidate: (PubKey, Option<String>),
    picker: &Arc<ExitPicker>,
) -> ConnectOutcome {
    let (pk, tag) = candidate;
    let mut stream = match mux.open(pk, target).await {
        Ok(s) => s,
        Err(e) => {
            picker.record_failure(&pk);
            return ConnectOutcome::AllFailed { errors: vec![(pk, e.to_string())] };
        }
    };
    // Cap the wait so a totally-deaf exit doesn't hang the SOCKS5
    // request forever; 15 s matches the racing path's default.
    match tokio::time::timeout(Duration::from_secs(15), stream.await_open_ack()).await {
        Ok(Ok(code)) if code == socks5::REP_SUCCESS => {
            tracing::debug!("single_connect: OpenAck SUCCESS from {}", hex::encode(&pk[..8]));
            ConnectOutcome::Success { stream, pk, tag }
        }
        Ok(Ok(code)) => {
            picker.record_failure(&pk);
            ConnectOutcome::AllRefused { last_code: code }
        }
        Ok(Err(e)) => {
            picker.record_failure(&pk);
            ConnectOutcome::AllFailed { errors: vec![(pk, e.to_string())] }
        }
        Err(_) => {
            tracing::debug!("single_connect: OpenAck timeout from {}", hex::encode(&pk[..8]));
            picker.record_failure(&pk);
            ConnectOutcome::AllFailed { errors: vec![(pk, "OpenAck timeout (15 s)".into())] }
        }
    }
}

/// Happy Eyeballs for exits. Spawn one task per candidate to open a
/// MeshStream + await OpenAck. As soon as one returns SUCCESS, abort
/// the others and return the winning stream.
///
/// Caveat (documented in README): aborted losers' streams are
/// dropped without sending Reset to the peer — the mux's retransmit
/// budget on each exit-side stream will exhaust after ~30 s and the
/// exit will tear down its TCP itself. For interactive CONNECT
/// traffic this is a tolerable resource lag.
async fn race_connect(
    mux: &Arc<MeshMux>,
    target: OpenTarget,
    candidates: Vec<(PubKey, Option<String>)>,
    race_timeout: Duration,
    picker: &Arc<ExitPicker>,
) -> ConnectOutcome {
    use tokio::task::JoinSet;

    let mut set: JoinSet<RacerOutcome> = JoinSet::new();
    for (pk, tag) in candidates {
        let mux = mux.clone();
        let target = target.clone();
        set.spawn(async move {
            let mut stream = match mux.open(pk, target).await {
                Ok(s) => s,
                Err(e) => return RacerOutcome::OpenFailed { pk, err: e.to_string() },
            };
            match stream.await_open_ack().await {
                Ok(code) if code == socks5::REP_SUCCESS => {
                    RacerOutcome::Success { stream, pk, tag }
                }
                Ok(code) => RacerOutcome::AckRejected { pk, code },
                Err(e) => RacerOutcome::AckFailed { pk, err: e.to_string() },
            }
        });
    }

    let mut errors: Vec<(PubKey, String)> = Vec::new();
    let mut last_refused: Option<u8> = None;
    let deadline = tokio::time::Instant::now() + race_timeout;

    loop {
        let next = tokio::time::timeout_at(deadline, set.join_next()).await;
        let joined = match next {
            Ok(Some(j)) => j,
            // None = JoinSet empty: every racer reported back.
            Ok(None) => break,
            // Err = deadline elapsed: bail with whatever we have.
            Err(_) => {
                set.abort_all();
                break;
            }
        };
        match joined {
            Ok(RacerOutcome::Success { stream, pk, tag }) => {
                // We've got a winner — abort everyone else so their
                // exit-side dials don't burn target-network resources.
                set.abort_all();
                return ConnectOutcome::Success { stream, pk, tag };
            }
            Ok(RacerOutcome::AckRejected { pk, code }) => {
                picker.record_failure(&pk);
                last_refused = Some(code);
                errors.push((pk, format!("OpenAck(0x{code:02x})")));
            }
            Ok(RacerOutcome::OpenFailed { pk, err })
            | Ok(RacerOutcome::AckFailed { pk, err }) => {
                picker.record_failure(&pk);
                errors.push((pk, err));
            }
            Err(_join) => {} // task cancelled or panicked — ignore.
        }
    }

    if let Some(code) = last_refused {
        ConnectOutcome::AllRefused { last_code: code }
    } else {
        ConnectOutcome::AllFailed { errors }
    }
}

/// What one racer task reports back to the orchestrator.
enum RacerOutcome {
    Success { stream: MeshStream, pk: PubKey, tag: Option<String> },
    /// OpenAck arrived with a non-success reply code (e.g. exit
    /// could reach us but couldn't dial the target).
    AckRejected { pk: PubKey, code: u8 },
    /// mux.open returned an error (no session, no route, etc.).
    OpenFailed { pk: PubKey, err: String },
    /// OpenAck never arrived (stream closed / reset / channel dead).
    AckFailed { pk: PubKey, err: String },
}

// ── EXIT ─────────────────────────────────────────────────────────────────

async fn run_exit(
    cfg: DaemonConfig,
    config_path: std::path::PathBuf,
    mux: Arc<MeshMux>,
    mut accept_rx: tokio::sync::mpsc::Receiver<AcceptedStream>,
    started_at: Instant,
) -> Result<()> {
    info!("exit mode: waiting for SOCKS5 CONNECTs over the mesh");
    // Exit mode has no per-CONNECT race knobs to manage, but RaceConfig
    // is still wired so a future Reload at least produces consistent
    // "no-op" responses (and so AdminState carries the same shape in
    // both modes).
    let race_cfg = Arc::new(RaceConfig::new(
        cfg.bifrost.race_exits,
        cfg.bifrost.race_timeout_ms,
    ));
    spawn_admin_if_configured(
        &cfg,
        AdminState {
            conn: mux.conn().clone(),
            pool: None,
            mode: Mode::Exit,
            started_at,
            config_path: config_path.clone(),
            race_cfg,
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
