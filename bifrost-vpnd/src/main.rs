// bifrost-vpnd — TUN-based VPN over a norn-rs mesh.
//
// v0.1 is intentionally thin: it spins up a norn Node with TUN enabled
// and lets norn-rs's existing tun.rs do the routing inside the 0200::/7
// address space. The interesting work — exit-mode NAT, default-route
// hijacking, IPv4-via-mesh — is reserved for the next milestone. We
// keep the binary anyway because: (a) it has a separate config schema
// and lifecycle from the SOCKS5 daemon, and (b) callers shouldn't have
// to know that v0.1 is mostly a wrapper.

mod config;

use anyhow::{Context, Result};
use bifrost_core::mux::MeshMux;
use clap::{Parser, Subcommand};
use config::VpnConfig;
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
    Genconfig,
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
        Cmd::Genconfig => {
            print!("{}", VpnConfig::sample());
            Ok(())
        }
        Cmd::Run { config } => run(config).await,
    }
}

async fn run(config_path: std::path::PathBuf) -> Result<()> {
    let cfg = VpnConfig::load(&config_path)?;
    init_logging(&cfg.node.log_level);

    if cfg.exit_enabled {
        warn!(
            "exit_enabled=true is reserved — v0.1 does NOT NAT outbound traffic. \
             Only 0200::/7 mesh traffic flows."
        );
    }

    info!(
        "starting bifrost-vpnd (tun={:?}, egress={:?})",
        cfg.node.tun_name.as_deref().unwrap_or("<none>"),
        cfg.egress.as_ref().map(describe_egress).unwrap_or_else(|| "mesh".into()),
    );

    let node = Node::new(cfg.node.clone()).await.context("starting norn node")?;
    node.start().await.context("starting norn subsystems")?;
    let conn = node.conn.clone();
    info!("norn node up; our pub_key={}", hex::encode(conn.pub_key));

    // We still spin up a MeshMux even when we don't accept any streams.
    // It's the hook future bifrost-vpnd milestones will use to talk to
    // the exit-side NAT helper without restarting the daemon.
    let (_mux, _accept_rx): (Arc<MeshMux>, _) = MeshMux::new(conn);

    // Block forever — Node::start spawned all its tasks in the background.
    futures_park().await;
    Ok(())
}

fn init_logging(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn describe_egress(p: &bifrost_core::policy::EgressPolicy) -> String {
    match p {
        bifrost_core::policy::EgressPolicy::Mesh => "mesh".into(),
        bifrost_core::policy::EgressPolicy::Auto => "auto (reserved)".into(),
        bifrost_core::policy::EgressPolicy::Exit { exits } => {
            format!("exit (n={}, reserved — not routed in v0.1)", exits.len())
        }
    }
}

/// Block on Ctrl-C so the spawned tasks keep running. tokio::signal
/// brings in fewer transitive deps than a raw `loop { sleep }`.
async fn futures_park() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("ctrl_c handler error: {e} — falling back to sleep loop");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
        }
    }
    info!("ctrl-c received, exiting");
}
