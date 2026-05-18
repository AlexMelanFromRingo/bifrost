// bifrost-ctl — admin CLI for a running bifrost-socks5d / bifrost-vpnd.
//
// Connects to the daemon's UNIX admin socket (defined under [bifrost]
// admin_socket in the daemon config), sends one JSON request, prints
// the response. Defaults to a human-readable table; --json dumps the
// raw response for scripts.

use anyhow::{anyhow, Context, Result};
use bifrost_core::admin_proto::{
    AdminRequest, AdminResponse, ExitRow, PeerRow, ReloadResponse, StatusResponse,
};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::{timeout, Duration};

#[derive(Parser)]
#[command(
    name = "bifrost-ctl",
    version,
    about = "Admin CLI for a running bifrost daemon."
)]
struct Cli {
    /// Path to the daemon's admin socket.
    #[arg(short, long, default_value = "/tmp/bifrost-socks5d-ctl.sock", env = "BIFROST_CTL_SOCKET")]
    socket: PathBuf,

    /// Print raw JSON instead of formatted output.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// High-level daemon summary (pub_key, mode, uptime, pool size).
    Status,
    /// Live ScoredExitPool snapshot, sorted by weight.
    Exits,
    /// Direct mesh peers (norn-rs PeerStats).
    Peers,
    /// Push a +1s/120s penalty onto an exit (same effect as a failed
    /// CONNECT). pub_key is 64 hex chars.
    Penalty { pub_key: String },
    /// Clear penalty for one exit.
    ResetPenalty { pub_key: String },
    /// Clear ALL active penalties.
    ResetAllPenalties,
    /// Re-read the daemon's config file from disk and hot-apply
    /// reloadable fields (egress.exits diff with mDNS preservation,
    /// race_exits, race_timeout_ms). Mode swaps and listen-address
    /// changes still need a full restart.
    Reload,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let req = match &cli.cmd {
        Cmd::Status => AdminRequest::Status,
        Cmd::Exits => AdminRequest::Exits,
        Cmd::Peers => AdminRequest::Peers,
        Cmd::Penalty { pub_key } => AdminRequest::Penalty { pub_key: pub_key.clone() },
        Cmd::ResetPenalty { pub_key } => AdminRequest::ResetPenalty { pub_key: pub_key.clone() },
        Cmd::ResetAllPenalties => AdminRequest::ResetAllPenalties,
        Cmd::Reload => AdminRequest::Reload,
    };

    let response = run_rpc(&cli.socket, &req).await?;

    if cli.json || !response.ok {
        println!("{}", serde_json::to_string_pretty(&response)?);
        if !response.ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Human-readable rendering depends on the command we sent — JSON
    // responses are untyped on this side, so we re-deserialise into
    // the concrete payload shapes from bifrost_core::admin_proto.
    let data = response
        .data
        .ok_or_else(|| anyhow!("ok=true response missing `data` field"))?;
    match cli.cmd {
        Cmd::Status => render_status(serde_json::from_value(data)?),
        Cmd::Exits => render_exits(serde_json::from_value(data)?),
        Cmd::Peers => render_peers(serde_json::from_value(data)?),
        Cmd::Reload => render_reload(serde_json::from_value(data)?),
        Cmd::Penalty { .. } | Cmd::ResetPenalty { .. } | Cmd::ResetAllPenalties => {
            // These return small status objects; pretty-print as JSON.
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
    }
    Ok(())
}

async fn run_rpc(socket: &PathBuf, req: &AdminRequest) -> Result<AdminResponse> {
    let stream = timeout(Duration::from_secs(3), UnixStream::connect(socket))
        .await
        .context("connect timeout (3 s) — is the daemon running?")?
        .with_context(|| format!("connecting to admin socket {socket:?}"))?;
    let (r, mut w) = stream.into_split();
    let body = serde_json::to_string(req)?;
    w.write_all(body.as_bytes()).await?;
    w.write_all(b"\n").await?;
    w.shutdown().await.ok();

    let mut reader = BufReader::new(r);
    let mut line = String::new();
    timeout(Duration::from_secs(5), reader.read_line(&mut line))
        .await
        .context("response timeout (5 s)")?
        .context("reading admin response")?;
    Ok(serde_json::from_str(line.trim()).context("parse admin response")?)
}

// ── renderers ────────────────────────────────────────────────────────────

fn render_status(s: StatusResponse) {
    println!("pub_key:       {}", s.pub_key);
    println!("address:       {}", s.address);
    println!("mode:          {}", s.mode);
    println!("version:       {}", s.version);
    println!("uptime:        {}", fmt_uptime(s.uptime_secs));
    println!("mesh peers:    {}", s.peer_count);
    println!("exit pool:     {} (auto={})", s.exit_pool_size, s.auto_egress);
}

fn render_exits(rows: Vec<ExitRow>) {
    if rows.is_empty() {
        println!("(no exits — daemon is not in Auto mode, or the pool is empty)");
        return;
    }
    println!(
        "{:<20} {:>10} {:>7} {:>10} {:>10} {:>6}  TAG",
        "PUB_KEY(8)", "WEIGHT", "TRUST", "RTT_MS", "PENALTY", "STATS"
    );
    for r in rows {
        let pk_short = &r.pub_key[..16];
        println!(
            "{:<20} {:>10.6} {:>7.3} {:>10.2} {:>10.0} {:>6}  {}",
            pk_short,
            r.weight,
            r.trust,
            r.rtt_ms,
            r.penalty_ms,
            if r.stats_known { "live" } else { "fall" },
            r.tag.as_deref().unwrap_or("-"),
        );
    }
}

fn render_peers(rows: Vec<PeerRow>) {
    if rows.is_empty() {
        println!("(no connected mesh peers)");
        return;
    }
    println!(
        "{:<20} {:>7} {:>8} {:>7} {:>12} {:>12} {:>12}",
        "PUB_KEY(8)", "TRUST", "LAG_MS", "LOSS", "UPTIME", "RX_BYTES", "TX_BYTES"
    );
    for p in rows {
        println!(
            "{:<20} {:>7.3} {:>8} {:>6.2}% {:>12} {:>12} {:>12}",
            &p.pub_key[..16],
            p.trust,
            p.lag_ms,
            p.loss_rate * 100.0,
            fmt_uptime(p.uptime_secs),
            p.rx_bytes,
            p.tx_bytes,
        );
    }
}

fn render_reload(r: ReloadResponse) {
    if r.exits_added.is_empty()
        && r.exits_removed.is_empty()
        && r.exits_skipped_mdns == 0
        && r.race_exits.is_none()
        && r.race_timeout_ms.is_none()
    {
        println!("reload: no-op (config matches running state)");
        return;
    }
    if let Some(n) = r.race_exits {
        println!("race_exits      → {}", n);
    }
    if let Some(t) = r.race_timeout_ms {
        println!("race_timeout_ms → {}", t);
    }
    if !r.exits_added.is_empty() {
        println!("+ {} added exit(s):", r.exits_added.len());
        for pk in &r.exits_added {
            println!("    {}", &pk[..16]);
        }
    }
    if !r.exits_removed.is_empty() {
        println!("- {} removed exit(s):", r.exits_removed.len());
        for pk in &r.exits_removed {
            println!("    {}", &pk[..16]);
        }
    }
    if r.exits_skipped_mdns > 0 {
        println!("ignored {} mDNS-discovered candidate(s) (preserved)", r.exits_skipped_mdns);
    }
}

fn fmt_uptime(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}
