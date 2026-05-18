// bifrost-vpnd config — supports three runtime modes:
//
//   mesh    — TUN-only, traffic stays inside the 0200::/7 overlay.
//             (This is what v0.1 shipped.)
//   exit    — bring up an egress TUN + iptables MASQUERADE, accept
//             Egress streams from any mesh peer, NAT them out to
//             the public interface.
//   client  — open a single Egress stream to the configured exit
//             peer, bring up the kernel TUN with the allocated IP,
//             pipe IP packets bidirectionally.

use anyhow::{Context, Result};
use bifrost_core::policy::EgressPolicy;
use norn_rs::config::NodeConfig;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct VpnConfig {
    /// Routing policy. Required when mode = exit/client; ignored for mesh.
    #[serde(default)]
    pub egress: Option<EgressPolicy>,

    /// Daemon role. Defaults to mesh for backwards compatibility with v0.1.
    #[serde(default)]
    pub mode: Mode,

    /// Exit-mode tuning (ignored unless mode = "exit").
    #[serde(default)]
    pub exit: ExitSettings,

    /// Client-mode tuning (ignored unless mode = "client").
    #[serde(default)]
    pub client: ClientSettings,

    /// Embedded norn-rs node config. `tun_name` MUST be set for mesh
    /// mode; for exit/client mode it's allowed to be unset (the
    /// egress TUN is the only one we touch).
    pub node: NodeConfig,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Mesh,
    Exit,
    Client,
}

#[derive(Debug, Deserialize)]
pub struct ExitSettings {
    /// TUN device name for the egress side. Must not collide with
    /// node.tun_name in mesh mode (different role, different device).
    #[serde(default = "default_egress_tun")]
    pub tun_name: String,
    /// First address of the /prefix subnet handed out to clients.
    /// Defaults to 10.55.0.0/24. The .1 of this subnet becomes the
    /// gateway IP the exit assigns to its own TUN end.
    #[serde(default = "default_pool_base")]
    pub pool_base: Ipv4Addr,
    #[serde(default = "default_pool_prefix")]
    pub pool_prefix: u8,
    /// Optional ULA IPv6 prefix to hand out alongside IPv4. The host
    /// portion is paired with the v4 lease (host index 2 in /24 → 2 in
    /// /64), so each client gets one matching pair. None = v4-only.
    #[serde(default)]
    pub v6_pool_base: Option<Ipv6Addr>,
    #[serde(default = "default_v6_pool_prefix")]
    pub v6_pool_prefix: u8,
    /// Real network interface to MASQUERADE through. Typically `eth0`
    /// in containers; on bare metal something like `wlan0`/`enp4s0`.
    #[serde(default = "default_egress_iface")]
    pub egress_iface: String,
}

impl Default for ExitSettings {
    fn default() -> Self {
        Self {
            tun_name: default_egress_tun(),
            pool_base: default_pool_base(),
            pool_prefix: default_pool_prefix(),
            v6_pool_base: None,
            v6_pool_prefix: default_v6_pool_prefix(),
            egress_iface: default_egress_iface(),
        }
    }
}

fn default_egress_tun() -> String { "bifrost-eg0".to_string() }
fn default_pool_base() -> Ipv4Addr { Ipv4Addr::new(10, 55, 0, 0) }
fn default_pool_prefix() -> u8 { 24 }
fn default_v6_pool_prefix() -> u8 { 64 }
fn default_egress_iface() -> String { "eth0".to_string() }

#[derive(Debug, Deserialize)]
pub struct ClientSettings {
    /// TUN device name on the client side. Convention: distinct from
    /// the mesh TUN so the two can coexist on one host.
    #[serde(default = "default_egress_tun")]
    pub tun_name: String,
    /// If true, the client kernel's default route is replaced to send
    /// all outbound traffic through this TUN. Off by default — that's
    /// a system-wide change and the operator should opt in.
    #[serde(default)]
    pub install_default_route: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            tun_name: default_egress_tun(),
            install_default_route: false,
        }
    }
}

impl VpnConfig {
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
        let cfg: VpnConfig = toml::from_str(&body).context("parsing bifrost-vpnd TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        match self.mode {
            Mode::Mesh => {
                if self.node.tun_name.is_none() {
                    anyhow::bail!(
                        "mode=\"mesh\": node.tun_name must be set — the mesh \
                         daemon's whole job is to manage that TUN"
                    );
                }
            }
            Mode::Client => {
                if self.egress.is_none() {
                    anyhow::bail!(
                        "mode=\"client\" requires an [egress] section with mode=\"exit\" \
                         + the exit's pub_key in `exits`"
                    );
                }
                let exits = self.egress.as_ref().unwrap().exit_keys()?;
                if exits.is_empty() {
                    anyhow::bail!(
                        "mode=\"client\": at least one exit pub_key required in [egress].exits"
                    );
                }
            }
            Mode::Exit => {
                if !(16..=30).contains(&self.exit.pool_prefix) {
                    anyhow::bail!(
                        "mode=\"exit\": pool_prefix /{} must be in [16, 30]",
                        self.exit.pool_prefix
                    );
                }
                if self.exit.v6_pool_base.is_some()
                    && !(64..=126).contains(&self.exit.v6_pool_prefix)
                {
                    anyhow::bail!(
                        "mode=\"exit\": v6_pool_prefix /{} must be in [64, 126]",
                        self.exit.v6_pool_prefix
                    );
                }
            }
        }
        Ok(())
    }

    pub fn sample(mode: Mode) -> String {
        let body: String = NodeConfig::generate_toml()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| format!("  {l}\n"))
            .collect();
        match mode {
            Mode::Mesh => format!(
                r#"# bifrost-vpnd — mesh mode (v0.1 behaviour: 0200::/7 only).
mode = "mesh"

[egress]
mode = "mesh"

[node]
{body}"#
            ),
            Mode::Exit => format!(
                r#"# bifrost-vpnd — exit mode (NAT'd egress for mesh clients).
# Requires CAP_NET_ADMIN: the daemon creates a TUN, sets MASQUERADE
# on egress_iface, and toggles ip_forward.
mode = "exit"

[exit]
tun_name     = "bifrost-eg0"
pool_base    = "10.55.0.0"
pool_prefix  = 24
# Uncomment to enable dual-stack (IPv6 NAT66). The host portion is
# paired with the IPv4 lease so each client gets matched addresses.
# v6_pool_base   = "fd55:0:0:1::"
# v6_pool_prefix = 64
egress_iface = "eth0"

[node]
{body}"#
            ),
            Mode::Client => format!(
                r#"# bifrost-vpnd — client mode (tunnel local IP traffic through
# a chosen exit peer).
mode = "client"

[client]
tun_name              = "bifrost-eg0"
# Hijack the system default route. Off by default; turn on once you
# trust the exit operator to see every byte of outbound traffic.
install_default_route = false

[egress]
mode = "exit"
exits = [
  # Replace with the exit peer's 32-byte ed25519 pub key (hex).
  # {{ pub_key = "0000...0000", tag = "primary" }},
]

[node]
{body}"#
            ),
        }
    }
}
