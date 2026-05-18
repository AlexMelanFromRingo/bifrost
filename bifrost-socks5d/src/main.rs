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

mod config;
mod socks5;

use anyhow::{Context, Result};
use bifrost_core::{
    frame::OpenTarget,
    mux::{AcceptedStream, MeshMux},
    policy::{EgressPolicy, ExitRotator},
    stream::reply,
};
use clap::{Parser, Subcommand};
use config::{DaemonConfig, Mode};
use norn_rs::node::Node;
use std::sync::Arc;
use std::time::Duration;
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

    info!("starting bifrost-socks5d in {:?} mode", cfg.mode);
    let node = Node::new(cfg.node.clone()).await.context("starting norn node")?;
    node.start().await.context("starting norn subsystems")?;
    let conn = node.conn.clone();
    info!("norn node up; our pub_key={}", hex::encode(conn.pub_key));

    let (mux, accept_rx) = MeshMux::new(conn);

    match cfg.mode {
        Mode::Client => run_client(cfg, mux).await,
        Mode::Exit => run_exit(mux, accept_rx).await,
    }
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

// ── CLIENT ────────────────────────────────────────────────────────────────

async fn run_client(cfg: DaemonConfig, mux: Arc<MeshMux>) -> Result<()> {
    let policy = cfg
        .egress
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("client mode requires [egress]"))?;
    let exits = policy.exit_keys().context("decoding egress.exits")?;
    if exits.is_empty() && !matches!(policy, EgressPolicy::Mesh) {
        warn!("egress mode is exit/auto but no exits configured — every CONNECT will fail");
    }
    let rotator = Arc::new(ExitRotator::new(exits));
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
        let rotator = rotator.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_socks5(sock, mux, rotator).await {
                tracing::debug!("socks5 from {peer}: {e}");
            }
        });
    }
}

async fn handle_socks5(
    mut sock: TcpStream,
    mux: Arc<MeshMux>,
    rotator: Arc<ExitRotator>,
) -> Result<()> {
    socks5::negotiate_methods(&mut sock).await?;
    let target = match socks5::read_request(&mut sock).await {
        Ok(t) => t,
        Err(e) => {
            // read_request has already written a reply for protocol-level
            // errors; just close.
            return Err(e);
        }
    };
    let Some((exit_peer, tag)) = rotator.pick() else {
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
            let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
            return Err(e);
        }
    };
    let ack = match mesh.await_open_ack().await {
        Ok(code) => code,
        Err(e) => {
            let _ = socks5::write_reply(&mut sock, socks5::REP_GENERAL_FAILURE).await;
            return Err(e.into());
        }
    };
    socks5::write_reply(&mut sock, ack).await?;
    if ack != socks5::REP_SUCCESS {
        return Ok(()); // exit said the CONNECT failed; we relayed the code.
    }
    // Pipe both directions until either side closes.
    match tokio::io::copy_bidirectional(&mut sock, &mut mesh).await {
        Ok((up, down)) => tracing::debug!("CONNECT {} done up={up} down={down}", target.display()),
        Err(e) => tracing::debug!("CONNECT {} pipe err: {e}", target.display()),
    }
    Ok(())
}

// ── EXIT ─────────────────────────────────────────────────────────────────

async fn run_exit(
    _mux: Arc<MeshMux>,
    mut accept_rx: tokio::sync::mpsc::Receiver<AcceptedStream>,
) -> Result<()> {
    info!("exit mode: waiting for SOCKS5 CONNECTs over the mesh");
    while let Some(acc) = accept_rx.recv().await {
        tokio::spawn(handle_exit_stream(acc));
    }
    warn!("accept channel closed — mux read loop ended");
    Ok(())
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
