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

    /// Optional bifrost-specific endpoints. Distinct from
    /// `[node].metrics_addr` (which is norn-rs's own /metrics) and
    /// from `[node].admin_socket` (norn-rs admin). Empty = disabled.
    #[serde(default)]
    pub bifrost: BifrostEndpoints,

    /// Exit-side destination policy (SSRF defence). Ignored in client mode.
    #[serde(default)]
    pub exit: ExitSettings,
}

/// `[exit]` — destination filter knobs, named after `bifrost-vpnd`'s
/// `[exit]` section so one mental model covers both daemons.
#[derive(Debug, Deserialize)]
pub struct ExitSettings {
    /// SSRF defence: refuse CONNECTs whose target resolves to the exit's own
    /// internal/private ranges. Loopback, link-local (incl. 169.254.169.254
    /// cloud metadata), multicast, broadcast and unspecified are ALWAYS
    /// refused. With this enabled (the default) RFC1918 (10/8, 172.16/12,
    /// 192.168/16), CGNAT 100.64/10 and IPv6 ULA fc00::/7 are refused too.
    /// Set false for an exit that is *meant* to reach a private LAN (then
    /// scope it with `dst_allow`).
    #[serde(default = "default_true")]
    pub block_private_dst: bool,
    /// CIDRs to ALLOW even when `block_private_dst` would deny them. Does not
    /// override the always-blocked set.
    #[serde(default)]
    pub dst_allow: Vec<String>,
    /// Extra CIDRs to DENY on top of the defaults. `dst_allow` takes
    /// precedence over `dst_deny`.
    #[serde(default)]
    pub dst_deny: Vec<String>,
}

impl Default for ExitSettings {
    fn default() -> Self {
        Self { block_private_dst: true, dst_allow: Vec::new(), dst_deny: Vec::new() }
    }
}

#[derive(Debug, Deserialize)]
pub struct BifrostEndpoints {
    /// `host:port` for the bifrost-specific Prometheus exporter.
    /// Exposes ScoredExitPool gauges. Loopback strongly recommended.
    #[serde(default)]
    pub metrics_addr: String,
    /// UNIX socket path for `bifrost-ctl`. Empty = disabled.
    #[serde(default)]
    pub admin_socket: String,
    /// Toggle mDNS exit discovery (Auto mode only). Default: enabled — but
    /// mDNS is unauthenticated, so a discovered exit is only used if its
    /// pub key is in `trusted_exits` (or `mdns_trust_any = true`). With
    /// neither set the browser isn't started at all.
    #[serde(default = "default_true")]
    pub mdns_discovery: bool,
    /// Hex ed25519 pub keys of exits that may be picked up via mDNS. An
    /// exit sees every CONNECT target routed through it, so only list
    /// exits you trust. Statically configured `[egress].exits` don't need
    /// to be repeated here.
    #[serde(default)]
    pub trusted_exits: Vec<String>,
    /// Accept ANY mDNS-advertised exit key (any LAN host can then become
    /// an exit candidate and observe your traffic). Default false.
    #[serde(default)]
    pub mdns_trust_any: bool,
    /// Cap on mDNS-discovered exits tracked at once.
    #[serde(default = "default_mdns_max_exits")]
    pub mdns_max_exits: usize,
    /// Happy-eyeballs racing: race the SOCKS5 Open frame across N
    /// top-weighted exits and use the first that returns OpenAck
    /// success. 1 disables racing (fall back to single pick).
    /// Defaults to 3 — anti-blocking + redundancy without flooding.
    #[serde(default = "default_race_exits")]
    pub race_exits: usize,
    /// Per-CONNECT race timeout. After this, every racer is aborted
    /// and the SOCKS5 client gets a general-failure reply.
    #[serde(default = "default_race_timeout_ms")]
    pub race_timeout_ms: u64,
}

fn default_race_exits() -> usize { 3 }
fn default_mdns_max_exits() -> usize { bifrost_core::discovery::DEFAULT_MAX_DISCOVERED }
fn default_race_timeout_ms() -> u64 { 15_000 }

fn default_true() -> bool { true }

impl BifrostEndpoints {
    /// Build the mDNS discovery trust policy (fails on a malformed key).
    pub fn discovery_trust(&self) -> Result<bifrost_core::discovery::DiscoveryTrust> {
        let mut trusted = std::collections::HashSet::new();
        for s in &self.trusted_exits {
            let mut k = [0u8; 32];
            hex::decode_to_slice(s.trim(), &mut k)
                .with_context(|| format!("[bifrost].trusted_exits entry {s:?}: expected 64 hex chars"))?;
            trusted.insert(k);
        }
        Ok(bifrost_core::discovery::DiscoveryTrust {
            trusted,
            trust_any: self.mdns_trust_any,
            max_discovered: self.mdns_max_exits,
        })
    }
}

impl Default for BifrostEndpoints {
    fn default() -> Self {
        Self {
            metrics_addr: String::new(),
            admin_socket: String::new(),
            mdns_discovery: true,
            trusted_exits: Vec::new(),
            mdns_trust_any: false,
            mdns_max_exits: default_mdns_max_exits(),
            race_exits: default_race_exits(),
            race_timeout_ms: default_race_timeout_ms(),
        }
    }
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
        self.bifrost.discovery_trust()?;
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

[bifrost]
# Loopback-only Prometheus endpoint with ScoredExitPool gauges.
# Comment out to disable.
metrics_addr  = "127.0.0.1:9099"
# UNIX socket for `bifrost-ctl` — runtime status / penalty CLI.
admin_socket  = "/run/bifrost/socks5d.sock"
# mDNS exit discovery (egress mode = "auto" only). mDNS is unauthenticated:
# a discovered exit is used only if its pub key is listed here. Every exit
# sees the CONNECT targets routed through it.
# trusted_exits  = ["<EXIT-PUBKEY-HEX>"]
# mdns_trust_any = false   # true = accept ANY LAN host as an exit (unsafe)
# mdns_max_exits = 16
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

[exit]
# SSRF defence: loopback / link-local (incl. 169.254.169.254) / multicast are
# always refused; private ranges (RFC1918, CGNAT, ULA) too unless false.
block_private_dst = true
# dst_allow = ["192.168.10.0/24"]
# dst_deny  = ["203.0.113.0/24"]

[node]
{body}"#,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_filter_defaults_to_blocking_private() {
        let cfg: DaemonConfig = toml::from_str(&DaemonConfig::sample_exit())
            .expect("sample exit config parses");
        assert!(cfg.exit.block_private_dst);
        // Omitting [exit] entirely must also default to the safe setting.
        let bare = "mode = \"exit\"\n[node]\nprivate_key = \"00\"\n";
        if let Ok(cfg) = toml::from_str::<DaemonConfig>(bare) {
            assert!(cfg.exit.block_private_dst, "missing [exit] must not open the exit up");
        }
        assert!(ExitSettings::default().block_private_dst);
    }

    /// mDNS trust defaults closed: no trusted keys, no trust-any → the
    /// browser admits nothing; malformed trusted keys fail config load.
    #[test]
    fn mdns_discovery_trust_defaults_closed() {
        let t = BifrostEndpoints::default().discovery_trust().unwrap();
        assert!(!t.trust_any);
        assert!(t.trusted.is_empty());
        assert!(!t.admits_anything());
        let cfg: DaemonConfig = toml::from_str(&DaemonConfig::sample_client())
            .expect("sample client config parses");
        assert!(!cfg.bifrost.mdns_trust_any);
        assert!(!cfg.bifrost.discovery_trust().unwrap().admits_anything());

        let b = BifrostEndpoints { trusted_exits: vec!["ab".repeat(32)], ..Default::default() };
        let t = b.discovery_trust().unwrap();
        assert!(t.trusted.contains(&[0xab; 32]) && t.admits_anything());
        let bad = BifrostEndpoints { trusted_exits: vec!["xyz".into()], ..Default::default() };
        assert!(bad.discovery_trust().is_err());
    }
}
