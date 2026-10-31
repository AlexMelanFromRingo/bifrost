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
    /// Where to persist the `peer → lease` mapping so clients
    /// reconnecting after an exit restart land back on the same
    /// IPv4/IPv6 lease. Empty (the default) keeps the v0.1
    /// behaviour: every restart re-allocates fresh slots and
    /// returning clients may shuffle addresses.
    ///
    /// On atomic write we use a `<path>.tmp + rename(2)` dance so
    /// a power-cut mid-save leaves the prior file intact rather
    /// than truncating it to garbage. The file is written `0600`
    /// (it's lease metadata, not secrets — but it's not for
    /// public inspection either).
    #[serde(default)]
    pub lease_persistence_path: String,

    /// UNIX socket for the vpnd admin RPC (Status / Peers / Leases
    /// / EvictLease). `bifrost-ctl --socket <this>` talks to it.
    /// Empty disables the admin server entirely. Defaults to
    /// `/run/bifrost/vpnd-exit.sock`; a missing parent directory is
    /// created 0700 and the socket is chmod'ed 0600.
    #[serde(default = "default_admin_socket_exit")]
    pub admin_socket: String,

    /// Client allowlist: hex ed25519 pub keys allowed to open an egress
    /// session (and so receive a lease). Empty (the default) = open exit —
    /// any mesh key is admitted, subject to `min_client_pow_bits`, and the
    /// daemon logs a warning at startup.
    #[serde(default)]
    pub allowed_clients: Vec<String>,

    /// Per-identity admission cost: minimum norn key difficulty (leading
    /// 1-bits of BLAKE2b-512(pub_key), the same measure as norn's
    /// transport-layer Sybil threshold) a client key must have to get a
    /// lease. Each bit doubles the key-grinding cost of a throwaway
    /// identity. 0 (the default) disables the check.
    #[serde(default)]
    pub min_client_pow_bits: u32,

    /// SSRF defence: block client packets destined to the exit's own
    /// internal/private ranges before the kernel routes them out. Loopback,
    /// link-local (incl. 169.254.169.254 cloud metadata), multicast,
    /// broadcast and unspecified are ALWAYS blocked. With this enabled (the
    /// default) RFC1918 (10/8, 172.16/12, 192.168/16), CGNAT 100.64/10 and
    /// IPv6 ULA fc00::/7 are blocked too. Set false for a split-tunnel exit
    /// that is *meant* to reach a private LAN (then scope it with `dst_allow`).
    #[serde(default = "default_true")]
    pub block_private_dst: bool,

    /// CIDRs to ALLOW even when `block_private_dst` would deny them, e.g.
    /// `["192.168.10.0/24"]` for one reachable corporate subnet. Does not
    /// override the always-blocked set.
    #[serde(default)]
    pub dst_allow: Vec<String>,

    /// Extra CIDRs to DENY on top of the defaults (e.g. block a specific
    /// public range). `dst_allow` takes precedence over `dst_deny`.
    #[serde(default)]
    pub dst_deny: Vec<String>,
}

fn default_true() -> bool { true }

impl Default for ExitSettings {
    fn default() -> Self {
        Self {
            tun_name: default_egress_tun(),
            pool_base: default_pool_base(),
            pool_prefix: default_pool_prefix(),
            v6_pool_base: None,
            v6_pool_prefix: default_v6_pool_prefix(),
            egress_iface: default_egress_iface(),
            lease_persistence_path: String::new(),
            admin_socket: default_admin_socket_exit(),
            allowed_clients: Vec::new(),
            min_client_pow_bits: 0,
            block_private_dst: true,
            dst_allow: Vec::new(),
            dst_deny: Vec::new(),
        }
    }
}

fn default_egress_tun() -> String { "bifrost-eg0".to_string() }
fn default_pool_base() -> Ipv4Addr { Ipv4Addr::new(10, 55, 0, 0) }
fn default_pool_prefix() -> u8 { 24 }
fn default_v6_pool_prefix() -> u8 { 64 }
fn default_egress_iface() -> String { "eth0".to_string() }
// Under /run (root-owned, not world-writable) rather than a predictable
// /tmp path another local user could pre-create or squat.
fn default_admin_socket_exit() -> String { "/run/bifrost/vpnd-exit.sock".to_string() }
fn default_admin_socket_client() -> String { "/run/bifrost/vpnd-client.sock".to_string() }

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
    /// UNIX socket for the vpnd admin RPC on the client side. Mirrors
    /// `exit.admin_socket` — `bifrost-ctl` can hit either end. Empty
    /// disables the admin server.
    #[serde(default = "default_admin_socket_client")]
    pub admin_socket: String,
    /// Extra CIDRs the exit may place this client's lease subnet in. By
    /// default the client only accepts a lease whose subnet (and gateway,
    /// which must sit in the same subnet) lies inside RFC1918
    /// (10/8, 172.16/12, 192.168/16), CGNAT 100.64/10, or — for IPv6 — ULA
    /// fc00::/7, so a malicious exit can't install routes that hijack
    /// public address space on a split-tunnel client. List a CIDR here only
    /// for an exit you trust to hand out addresses from it.
    #[serde(default)]
    pub allowed_lease_cidrs: Vec<String>,
}

impl ExitSettings {
    /// Build the `Open(Egress)` admission policy (allowlist + PoW bar).
    pub fn admission(&self) -> Result<crate::admission::ExitAdmission> {
        crate::admission::ExitAdmission::new(&self.allowed_clients, self.min_client_pow_bits)
    }
}

impl ClientSettings {
    /// Parse `allowed_lease_cidrs` (fails on a malformed CIDR).
    pub fn lease_policy(&self) -> Result<crate::egress::LeasePolicy> {
        crate::egress::LeasePolicy::new(&self.allowed_lease_cidrs)
    }
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            tun_name: default_egress_tun(),
            install_default_route: false,
            admin_socket: default_admin_socket_client(),
            allowed_lease_cidrs: Vec::new(),
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
                self.client.lease_policy()?;
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
                // key_difficulty_bits counts leading 1-bits of a 512-bit hash;
                // anything near this bound is unreachable in practice and would
                // just lock every client out.
                if self.exit.min_client_pow_bits > 64 {
                    anyhow::bail!(
                        "mode=\"exit\": min_client_pow_bits {} is unreasonably high (max 64)",
                        self.exit.min_client_pow_bits
                    );
                }
                self.exit.admission()?;
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
# Persist (peer → IP) so a returning client lands on the same lease
# after the exit restarts. Empty disables persistence.
# lease_persistence_path = "/var/lib/bifrost/leases.json"
# Client admission. Every admitted key gets a sticky lease, and keys are
# free to mint — list the clients you serve (hex pub keys). Empty = open
# exit (logged as a warning at startup).
allowed_clients = [
  # "0000...0000",
]
# Per-identity admission cost: minimum norn key difficulty (leading 1-bits
# of BLAKE2b(pub_key)) a client key needs. 0 disables.
min_client_pow_bits = 0
# bifrost-ctl admin socket (Status / Peers / Leases / EvictLease).
admin_socket = "/run/bifrost/vpnd-exit.sock"

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
# bifrost-ctl admin socket on the client side.
admin_socket          = "/run/bifrost/vpnd-client.sock"
# The exit's lease subnet must lie in RFC1918 / CGNAT 100.64/10 / ULA
# fc00::/7 (with the gateway inside it). Add CIDRs here only to trust this
# exit with other address space.
# allowed_lease_cidrs = []

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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(body: &str) -> Result<VpnConfig> {
        let cfg: VpnConfig = toml::from_str(body)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn with_node(top: &str) -> String {
        format!("{top}\n[node]\nprivate_key = \"{}\"\n", "00".repeat(32))
    }

    #[test]
    fn exit_defaults_are_open_but_admin_socket_is_private() {
        let cfg = parse(&with_node("mode = \"exit\"")).unwrap();
        assert!(cfg.exit.allowed_clients.is_empty());
        assert_eq!(cfg.exit.min_client_pow_bits, 0);
        assert!(cfg.exit.admission().unwrap().is_open());
        assert_eq!(cfg.exit.admin_socket, "/run/bifrost/vpnd-exit.sock");
        assert_eq!(ClientSettings::default().admin_socket, "/run/bifrost/vpnd-client.sock");
    }

    #[test]
    fn genconfig_samples_parse() {
        let exit: VpnConfig = toml::from_str(&VpnConfig::sample(Mode::Exit)).unwrap();
        assert_eq!(exit.exit.admin_socket, "/run/bifrost/vpnd-exit.sock");
        assert!(exit.exit.allowed_clients.is_empty());
        let client: VpnConfig = toml::from_str(&VpnConfig::sample(Mode::Client)).unwrap();
        assert!(client.client.allowed_lease_cidrs.is_empty());
    }

    #[test]
    fn exit_admission_knobs_are_validated() {
        let ok = with_node(&format!(
            "mode = \"exit\"\n[exit]\nallowed_clients = [\"{}\"]\nmin_client_pow_bits = 8",
            "ab".repeat(32)
        ));
        let cfg = parse(&ok).unwrap();
        assert!(!cfg.exit.admission().unwrap().is_open());
        let bad_key = with_node("mode = \"exit\"\n[exit]\nallowed_clients = [\"nope\"]");
        assert!(parse(&bad_key).is_err());
        let bad_pow = with_node("mode = \"exit\"\n[exit]\nmin_client_pow_bits = 200");
        assert!(parse(&bad_pow).is_err());
    }

    #[test]
    fn client_allowed_lease_cidrs_are_validated() {
        let exits = format!(
            "[egress]\nmode = \"exit\"\nexits = [{{ pub_key = \"{}\" }}]",
            "cd".repeat(32)
        );
        let ok = with_node(&format!(
            "mode = \"client\"\n[client]\nallowed_lease_cidrs = [\"198.18.0.0/15\"]\n{exits}"
        ));
        parse(&ok).unwrap();
        let bad = with_node(&format!(
            "mode = \"client\"\n[client]\nallowed_lease_cidrs = [\"198.18.0.0\"]\n{exits}"
        ));
        assert!(parse(&bad).is_err());
    }
}
