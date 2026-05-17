// bifrost-socks5d on-disk config.
//
// One TOML file holds both the embedded norn-rs NodeConfig and the
// SOCKS5-specific knobs. Splitting into two files would force users to
// keep separate private-key permissions, separate paths, etc — one
// chmod 600 is enough this way.

use anyhow::{Context, Result};
use bifrost_core::policy::EgressPolicy;
use norn_rs::config::NodeConfig;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct DaemonConfig {
    /// "client" or "exit".
    pub mode: Mode,

    /// SOCKS5 listen address (client mode only). Defaults to loopback.
    #[serde(default = "default_socks5_listen")]
    pub socks5_listen: String,

    /// Embedded norn-rs node config.
    pub node: NodeConfig,

    /// Required when mode = "client". Ignored in exit mode.
    #[serde(default)]
    pub egress: Option<EgressPolicy>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Client,
    Exit,
}

fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}

impl DaemonConfig {
    pub fn load(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(path)
                .with_context(|| format!("stat'ing config {:?}", path))?
                .mode()
                & 0o777;
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "refusing to load {path:?} with mode {mode:o}: it contains the private key. \
                     Run: chmod 600 {path:?}"
                );
            }
        }
        let body = std::fs::read_to_string(path)
            .with_context(|| format!("reading {:?}", path))?;
        let cfg: DaemonConfig = toml::from_str(&body).context("parsing bifrost-socks5d TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        if self.mode == Mode::Client && self.egress.is_none() {
            anyhow::bail!(
                "mode=\"client\" requires an [egress] section (mode=mesh|exit|auto)"
            );
        }
        Ok(())
    }

    pub fn sample_client() -> String {
        let node_toml = NodeConfig::generate_toml();
        // Strip the comment header from generate_toml so we can wrap it
        // cleanly under a [node] section.
        let body: String = node_toml
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| format!("  {l}\n"))
            .collect();
        format!(
            r#"# bifrost-socks5d — client mode (local SOCKS5 → norn-mesh → exit)
mode = "client"
socks5_listen = "127.0.0.1:1080"

[node]
{body}
[egress]
mode = "exit"
exits = [
  # Replace with the exit peer's 32-byte ed25519 pub key (hex).
  # The exit must also be reachable as a [node].peers entry above,
  # or via mDNS / multicast discovery on the LAN.
  # {{ pub_key = "0000...0000", tag = "primary" }},
]
"#,
        )
    }

    pub fn sample_exit() -> String {
        let node_toml = NodeConfig::generate_toml();
        let body: String = node_toml
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| format!("  {l}\n"))
            .collect();
        format!(
            r#"# bifrost-socks5d — exit mode (dials real TCP on behalf of clients)
mode = "exit"

[node]
{body}"#,
        )
    }
}
