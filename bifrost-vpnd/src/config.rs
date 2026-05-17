// bifrost-vpnd config — TUN-side daemon.
//
// Same layout idea as bifrost-socks5d: one TOML, [node] for norn-rs,
// plus VPN-specific knobs. Mesh-only is the v0.1 default: traffic
// stays within 0200::/7. Exit-mode is reserved for the next milestone
// (needs kernel NAT + a userspace policy router).

use anyhow::{Context, Result};
use bifrost_core::policy::EgressPolicy;
use norn_rs::config::NodeConfig;
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct VpnConfig {
    /// Routing policy. `mesh` ⇒ only forward inside 0200::/7. `exit`
    /// would NAT outbound packets through a chosen peer (not yet wired).
    #[serde(default)]
    pub egress: Option<EgressPolicy>,

    /// If true, this node advertises itself as exit-capable. Reserved —
    /// the exit-side NAT path is not implemented in v0.1.
    #[serde(default)]
    pub exit_enabled: bool,

    /// Embedded norn-rs node config — tun_name **must** be set here.
    pub node: NodeConfig,
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
        if self.node.tun_name.is_none() {
            anyhow::bail!(
                "node.tun_name must be set — bifrost-vpnd exists to manage the TUN device"
            );
        }
        Ok(())
    }

    pub fn sample() -> String {
        let body: String = NodeConfig::generate_toml()
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| format!("  {l}\n"))
            .collect();
        format!(
            r#"# bifrost-vpnd — TUN-based mesh VPN.
# Brings up the norn interface, routes 0200::/7 through the mesh.

# Reserved for the next milestone. v0.1 only supports mesh-only egress.
exit_enabled = false

[egress]
mode = "mesh"

[node]
{body}"#
        )
    }
}
