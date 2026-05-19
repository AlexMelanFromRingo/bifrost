// bifrost-vpnd — TUN-based VPN over a norn-rs mesh.
//
// Modes (see config.rs):
//   mesh    — v0.1 behaviour, mesh-internal 0200::/7 routing only.
//   exit    — runs an egress TUN + iptables MASQUERADE, accepts
//             Egress streams from mesh peers, forwards IP packets
//             out a real interface and pipes responses back.
//   client  — opens a single Egress stream to a configured exit,
//             brings up its own TUN with the allocated address, and
//             routes either the configured subnet or the full default
//             route through that TUN.

mod config;
mod egress;
mod lease_store;
mod tun_offload;

use anyhow::{Context, Result};
use bifrost_core::mux::MeshMux;
use bifrost_core::policy::EgressPolicy;
use clap::{Parser, Subcommand};
use config::{Mode, VpnConfig};
use norn_rs::node::Node;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "bifrost-vpnd", version, about = "TUN-based VPN over a norn-rs mesh")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a starter config to stdout.
    ///
    /// Default flavour is mesh; pass --exit / --client for the
    /// egress-NAT variants.
    Genconfig {
        #[arg(long, conflicts_with = "client")]
        exit: bool,
        #[arg(long, conflicts_with = "exit")]
        client: bool,
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
        Cmd::Genconfig { exit, client } => {
            let mode = if exit {
                Mode::Exit
            } else if client {
                Mode::Client
            } else {
                Mode::Mesh
            };
            print!("{}", VpnConfig::sample(mode));
            Ok(())
        }
        Cmd::Run { config } => run(config).await,
    }
}

async fn run(config_path: std::path::PathBuf) -> Result<()> {
    let mut cfg = VpnConfig::load(&config_path)?;
    init_logging(&cfg.node.log_level);

    // Exit/client modes manage their own egress TUN. Leaving the
    // norn-rs mesh TUN enabled here would spawn a second reader of
    // PacketConn::read_from that races our MeshMux — Open frames get
    // mis-routed into the TUN as raw IP packets. Force the mesh TUN
    // off so the mux owns the receive path.
    if matches!(cfg.mode, Mode::Exit | Mode::Client) && cfg.node.tun_name.is_some() {
        warn!(
            "{:?} mode: disabling node.tun_name={:?} (mesh TUN would steal frames from MeshMux)",
            cfg.mode,
            cfg.node.tun_name.as_deref().unwrap_or("")
        );
        cfg.node.tun_name = None;
    }

    info!(
        "starting bifrost-vpnd mode={:?} tun={:?} egress={}",
        cfg.mode,
        cfg.node.tun_name.as_deref().unwrap_or("<none>"),
        cfg.egress.as_ref().map(describe_egress).unwrap_or_else(|| "mesh".into()),
    );

    let node = Node::new(cfg.node.clone()).await.context("starting norn node")?;
    node.start().await.context("starting norn subsystems")?;
    let conn = node.conn.clone();
    info!("norn node up; our pub_key={}", hex::encode(conn.pub_key));

    let (mux, accept_rx) = MeshMux::new(conn);

    match cfg.mode {
        Mode::Mesh => {
            info!("mesh mode: norn-rs TUN active, no egress");
            futures_park().await;
            Ok(())
        }
        Mode::Exit => run_exit(mux, accept_rx, &cfg).await,
        Mode::Client => run_client(mux, &cfg).await,
    }
}

async fn run_exit(
    mux: Arc<MeshMux>,
    accept_rx: tokio::sync::mpsc::Receiver<bifrost_core::mux::AcceptedStream>,
    cfg: &VpnConfig,
) -> Result<()> {
    egress::start_exit(
        mux,
        accept_rx,
        cfg.exit.tun_name.clone(),
        cfg.exit.pool_base,
        cfg.exit.pool_prefix,
        cfg.exit.v6_pool_base,
        cfg.exit.v6_pool_prefix,
        cfg.exit.egress_iface.clone(),
        cfg.exit.lease_persistence_path.clone(),
    )
    .await
}

async fn run_client(mux: Arc<MeshMux>, cfg: &VpnConfig) -> Result<()> {
    let exits = cfg
        .egress
        .as_ref()
        .expect("validated: client mode has egress")
        .exit_keys()?;
    let (exit_peer, tag) = exits.first().cloned().expect("validated: ≥1 exit configured");
    info!(
        "client mode: tunnel via exit {}{}",
        hex::encode(&exit_peer[..8]),
        tag.as_deref().map(|t| format!(" [{t}]")).unwrap_or_default()
    );
    egress::start_client(
        mux,
        exit_peer,
        cfg.client.tun_name.clone(),
        cfg.client.install_default_route,
    )
    .await?;
    futures_park().await;
    Ok(())
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn describe_egress(p: &EgressPolicy) -> String {
    match p {
        EgressPolicy::Mesh => "mesh".into(),
        EgressPolicy::Auto { exits } => format!("auto (n={}, weighted by trust/RTT)", exits.len()),
        EgressPolicy::Exit { exits } => format!("exit (n={})", exits.len()),
    }
}

/// Block on Ctrl-C so the spawned background tasks keep running.
async fn futures_park() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("ctrl_c handler error: {e} — falling back to sleep loop");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }
    info!("ctrl-c received, exiting");
}
