//! Egress destination filtering — SSRF defence for the exit.
//!
//! Shared by both exit flavours:
//!
//!   * `bifrost-vpnd` writes client IP packets to its egress TUN and the
//!     kernel routes them out (MASQUERADE) — every packet's destination is
//!     checked via [`DstFilter::dst_of`] + [`DstFilter::allows`].
//!   * `bifrost-socks5d` dials `TcpStream::connect` on behalf of clients — it
//!     resolves the CONNECT target first and checks *every* resolved address,
//!     then connects only to a vetted `SocketAddr` (no second resolution, so
//!     DNS rebinding can't swap in a blocked address between check and dial).
//!
//! Without a destination filter a malicious client could aim at the exit's own
//! loopback, its private LAN (RFC1918 / CGNAT), or the cloud metadata endpoint
//! (IPv4 169.254.169.254, IPv6 `fd00:ec2::254`) and use the exit as an SSRF
//! pivot into the operator's infrastructure.
//!
//! [`DstFilter`] classifies each destination:
//!
//!   * **Always blocked** (never sensible to egress, not overridable):
//!     loopback, link-local (incl. IPv4 cloud metadata 169.254.0.0/16),
//!     multicast, broadcast, "this network" 0.0.0.0/8, the IPv6 transition
//!     prefixes that hide an IPv4 behind a v6 address (6to4 2002::/16, NAT64
//!     64:ff9b::/96 and the local-use 64:ff9b:1::/48), and the exit host's
//!     **own interface addresses** (public / LAN / TUN — see
//!     [`DstFilter::refresh_local_addrs`]), so a client can't reach a service
//!     bound on the exit via its public IP.
//!   * IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`) and
//!     IPv4-translated (`::ffff:0:a.b.c.d`) IPv6 are judged by the embedded
//!     IPv4 (see [`normalize`]).
//!   * **Blocked when `block_private`** (the default): RFC1918
//!     (10/8, 172.16/12, 192.168/16), CGNAT 100.64.0.0/10, IPv6 ULA fc00::/7
//!     (which covers the AWS IPv6 metadata `fd00:ec2::254`).
//!   * `allow` CIDRs punch holes in the private block (split-tunnel to a known
//!     LAN). `deny` CIDRs add extra blocks. Precedence (first match wins):
//!     **always-blocked → allow → deny → block_private → allow (public)**.
//!
//! The hot-path check ([`DstFilter::allows`]) is allocation-free: a handful of
//! range comparisons plus a scan of the (usually empty) allow/deny lists.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A parsed CIDR block, pre-masked so matching is a single bitwise-AND compare.
/// Public so other policy checks (e.g. vpnd's client-side lease validation)
/// share one parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl Cidr {
    /// Parse `addr/prefix` (v4 or v6). Host bits are masked off.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let (addr, prefix) = s
            .split_once('/')
            .with_context(|| format!("CIDR {s:?} missing '/<prefix>'"))?;
        let prefix: u32 = prefix
            .trim()
            .parse()
            .with_context(|| format!("CIDR {s:?} has a non-numeric prefix"))?;
        if let Ok(v4) = addr.trim().parse::<Ipv4Addr>() {
            if prefix > 32 {
                bail!("CIDR {s:?} IPv4 prefix must be 0..=32");
            }
            let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            Ok(Cidr::V4 { net: u32::from(v4) & mask, mask })
        } else if let Ok(v6) = addr.trim().parse::<Ipv6Addr>() {
            if prefix > 128 {
                bail!("CIDR {s:?} IPv6 prefix must be 0..=128");
            }
            let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            Ok(Cidr::V6 { net: u128::from(v6) & mask, mask })
        } else {
            bail!("CIDR {s:?} has an unparseable address")
        }
    }

    /// True if `ip` lies inside this block (family mismatch never matches).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { net, mask }, IpAddr::V4(a)) => (u32::from(a) & mask) == *net,
            (Cidr::V6 { net, mask }, IpAddr::V6(a)) => (u128::from(a) & mask) == *net,
            _ => false, // address family mismatch never matches
        }
    }

    /// True if the whole aligned block `other` lies inside this one. For two
    /// CIDRs that holds iff both of `other`'s endpoints are contained.
    pub fn contains_cidr(&self, other: &Cidr) -> bool {
        match *other {
            Cidr::V4 { net, mask } => {
                self.contains(IpAddr::V4(Ipv4Addr::from(net)))
                    && self.contains(IpAddr::V4(Ipv4Addr::from(net | !mask)))
            }
            Cidr::V6 { net, mask } => {
                self.contains(IpAddr::V6(Ipv6Addr::from(net)))
                    && self.contains(IpAddr::V6(Ipv6Addr::from(net | !mask)))
            }
        }
    }

    /// True if the two blocks share any address. Aligned CIDRs either nest or
    /// are disjoint, so this is "one contains the other" (family mismatch
    /// never overlaps).
    pub fn overlaps(&self, other: &Cidr) -> bool {
        self.contains_cidr(other) || other.contains_cidr(self)
    }
}

/// The exit host's own interface addresses, shared between a [`DstFilter`]
/// (and its clones) and whatever refreshes it. Stored normalised.
pub type LocalAddrs = Arc<RwLock<HashSet<IpAddr>>>;

/// How often the exits re-enumerate their interface addresses (DHCP renewals,
/// hot-plugged NICs, a late-assigned public IP).
pub const LOCAL_ADDR_REFRESH: Duration = Duration::from_secs(60);

/// Egress destination policy. Cheap to clone-by-`Arc`; the CIDR policy is
/// immutable after build, only the shared local-address set is refreshed.
/// Clones share that set.
#[derive(Debug, Clone)]
pub struct DstFilter {
    block_private: bool,
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
    local: LocalAddrs,
}

impl DstFilter {
    /// Build from operator config. CIDR parse errors are surfaced at startup
    /// (fail-fast) rather than silently dropping traffic later.
    pub fn new(block_private: bool, allow: &[String], deny: &[String]) -> Result<Self> {
        let allow = allow
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>>>()
            .context("parsing exit dst_allow CIDRs")?;
        let deny = deny
            .iter()
            .map(|s| Cidr::parse(s))
            .collect::<Result<Vec<_>>>()
            .context("parsing exit dst_deny CIDRs")?;
        Ok(Self { block_private, allow, deny, local: LocalAddrs::default() })
    }

    /// Seed the always-blocked local-address set (the exit's own IPs). The
    /// daemons use [`refresh_local_addrs`](Self::refresh_local_addrs); this is
    /// the injectable form for tests and non-`getifaddrs` platforms.
    pub fn with_local_addrs(self, addrs: impl IntoIterator<Item = IpAddr>) -> Self {
        self.set_local_addrs(addrs);
        self
    }

    /// Replace the local-address set (visible to every clone of this filter).
    pub fn set_local_addrs(&self, addrs: impl IntoIterator<Item = IpAddr>) {
        let fresh: HashSet<IpAddr> = addrs.into_iter().map(normalize).collect();
        *self.local.write().unwrap_or_else(|e| e.into_inner()) = fresh;
    }

    /// Handle on the shared local-address set.
    pub fn local_addrs(&self) -> LocalAddrs {
        self.local.clone()
    }

    /// Re-enumerate this host's interface addresses ([`local_interface_addrs`])
    /// into the always-blocked set. Returns how many were found. On error the
    /// previous set is kept.
    pub fn refresh_local_addrs(&self) -> std::io::Result<usize> {
        let addrs = local_interface_addrs()?;
        let n = addrs.len();
        self.set_local_addrs(addrs);
        Ok(n)
    }

    /// Refresh the local-address set every `every` in a background task
    /// (call [`refresh_local_addrs`](Self::refresh_local_addrs) once first so
    /// startup fails fast). A failed refresh keeps the last good set.
    pub fn spawn_local_addr_refresh(&self, every: Duration) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tick.tick().await; // first tick is immediate; the caller just refreshed
            loop {
                tick.tick().await;
                match this.refresh_local_addrs() {
                    Ok(n) => tracing::trace!("dst filter: {n} local address(es) blocked"),
                    Err(e) => tracing::warn!(
                        "dst filter: re-enumerating local addresses failed: {e} (keeping last set)"
                    ),
                }
            }
        })
    }

    /// True if a packet / connection destined to `ip` may be forwarded out the
    /// egress. IPv4-embedding IPv6 forms are judged by the embedded IPv4 (see
    /// [`normalize`]) — a dialer handed `[::ffff:127.0.0.1]` reaches v4
    /// loopback.
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        if Self::always_blocked(ip) || self.is_local(ip) {
            return false;
        }
        if self.allow.iter().any(|c| c.contains(ip)) {
            return true;
        }
        if self.deny.iter().any(|c| c.contains(ip)) {
            return false;
        }
        if self.block_private && Self::is_private(ip) {
            return false;
        }
        true
    }

    /// Extract the destination address from a raw IP packet (first nibble is
    /// the version). Returns `None` for truncated or unknown-version packets so
    /// the caller can fail closed (drop) rather than forward something it can't
    /// classify.
    pub fn dst_of(pkt: &[u8]) -> Option<IpAddr> {
        match pkt.first()? >> 4 {
            4 if pkt.len() >= 20 => {
                Some(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]).into())
            }
            6 if pkt.len() >= 40 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&pkt[24..40]);
                Some(normalize(IpAddr::V6(Ipv6Addr::from(o))))
            }
            _ => None,
        }
    }

    /// One of the exit host's own addresses. A poisoned lock is read through
    /// (the set is replaced wholesale, so it is never half-written).
    fn is_local(&self, ip: IpAddr) -> bool {
        self.local.read().unwrap_or_else(|e| e.into_inner()).contains(&ip)
    }

    /// Never sensible to egress, regardless of policy. `ip` is already
    /// [`normalize`]d, so v4-mapped / -compatible / -translated v6 arrive here
    /// as V4; the transition prefixes left in V6 are blocked outright.
    fn always_blocked(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                a.is_loopback()        // 127.0.0.0/8
                    || a.is_link_local()  // 169.254.0.0/16 (incl. cloud metadata)
                    || a.is_multicast()   // 224.0.0.0/4
                    || a.is_broadcast()   // 255.255.255.255
                    || a.octets()[0] == 0 // 0.0.0.0/8 "this network" (RFC 791/1122)
            }
            IpAddr::V6(a) => {
                a.is_loopback()        // ::1
                    || a.is_multicast()   // ff00::/8
                    || a.is_unspecified() // ::
                    || is_v6_link_local(a) // fe80::/10
                    || is_v6_6to4(a)      // 2002::/16 — embeds v4 (tunnel range)
                    || is_v6_nat64(a)     // 64:ff9b::/96 — embeds v4 (translation)
                    || is_v6_nat64_local(a) // 64:ff9b:1::/48 — local-use NAT64
                    || is_v6_teredo(a)    // 2001::/32 — Teredo, embeds v4
            }
        }
    }

    /// Internal / private ranges, blocked only when `block_private`.
    fn is_private(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => a.is_private() || is_v4_cgnat(a),
            IpAddr::V6(a) => is_v6_ula(a),
        }
    }
}

/// Normalise the IPv6 forms that carry an IPv4 in their low 32 bits to that
/// IPv4 so the v4 always-blocked / private rules apply. Otherwise a client
/// could reach 127.0.0.1 / 169.254.169.254 / 10.0.0.0/8 via a v6 destination
/// the v6-only checks would miss (SSRF):
///
///   * IPv4-mapped `::ffff:0:0/96` (RFC 4291) — what a dual-stack socket dials.
///   * IPv4-compatible `::/96` (RFC 4291, deprecated) — `::` and `::1` are
///     left as v6 (unspecified / loopback, both always blocked anyway).
///   * IPv4-translated `::ffff:0:0:0/96` (RFC 2765 SIIT).
///
/// 6to4 and NAT64 also embed an IPv4 but are blocked outright in
/// `always_blocked` instead (the exit runs neither, and the local-use NAT64
/// /48's embedding offset is deployment-specific, RFC 8215).
pub fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match embedded_v4(v6) {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// The IPv4 inside an IPv4-mapped / -compatible / -translated IPv6 address.
fn embedded_v4(a: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = a.to_ipv4_mapped() {
        return Some(v4);
    }
    let o = a.octets();
    let low = Ipv4Addr::new(o[12], o[13], o[14], o[15]);
    let compatible = o[..12].iter().all(|&b| b == 0);
    let translated = o[..8].iter().all(|&b| b == 0) && o[8..12] == [0xff, 0xff, 0, 0];
    // `::` / `::1` stay v6 (still blocked) so their Display / v6 rules are kept.
    if (compatible && u32::from(low) > 1) || translated {
        Some(low)
    } else {
        None
    }
}

/// This host's interface addresses (every family, every interface, up or
/// not), for the always-blocked local set. `getifaddrs(3)` on unix; other
/// platforms return an empty list — use [`DstFilter::with_local_addrs`] there.
#[cfg(unix)]
pub fn local_interface_addrs() -> std::io::Result<Vec<IpAddr>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs fills `head` with a list we free below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` walks the getifaddrs list, valid until freeifaddrs;
        // `ifa_addr` (nullable) points at a sockaddr of the family it names.
        unsafe {
            let sa = (*cur).ifa_addr;
            if !sa.is_null() {
                match i32::from((*sa).sa_family) {
                    libc::AF_INET => {
                        let sin = &*(sa as *const libc::sockaddr_in);
                        out.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr))));
                    }
                    libc::AF_INET6 => {
                        let sin6 = &*(sa as *const libc::sockaddr_in6);
                        out.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed once.
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

#[cfg(not(unix))]
pub fn local_interface_addrs() -> std::io::Result<Vec<IpAddr>> {
    Ok(Vec::new())
}

/// 100.64.0.0/10 — RFC 6598 carrier-grade NAT space.
fn is_v4_cgnat(a: Ipv4Addr) -> bool {
    let o = a.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

/// fc00::/7 — RFC 4193 unique local addresses (covers fd00:ec2::254).
fn is_v6_ula(a: Ipv6Addr) -> bool {
    (a.octets()[0] & 0xfe) == 0xfc
}

/// fe80::/10 — IPv6 link-local (the stable std method is still unstable).
fn is_v6_link_local(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0xfe && (o[1] & 0xc0) == 0x80
}

/// 2002::/16 — 6to4 (RFC 3056, deprecated by RFC 7526). Embeds an IPv4 address;
/// block outright so it can't smuggle a private/loopback v4 past the v6 checks
/// (a normal exit doesn't run 6to4).
fn is_v6_6to4(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0x20 && o[1] == 0x02
}

/// 2001::/32 — Teredo (RFC 4380). Embeds the server and (obfuscated) client
/// IPv4; only reachable if the exit runs a Teredo client, but blocked
/// outright like the other v4-embedding tunnel ranges.
fn is_v6_teredo(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[..4] == [0x20, 0x01, 0x00, 0x00]
}

/// 64:ff9b::/96 — the well-known NAT64 prefix (RFC 6052). Embeds an IPv4 in the
/// low 32 bits; block so it can't reach a private/loopback v4 via translation.
fn is_v6_nat64(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[0] == 0x00 && o[1] == 0x64 && o[2] == 0xff && o[3] == 0x9b
        && o[4..12].iter().all(|&b| b == 0)
}

/// 64:ff9b:1::/48 — the local-use NAT64 prefix (RFC 8215). It may be used with
/// any RFC 6052 prefix length (/48../96), so where the IPv4 sits is a
/// per-deployment choice; rather than guess one embedding (and miss the
/// others) block the whole /48.
fn is_v6_nat64_local(a: Ipv6Addr) -> bool {
    let o = a.octets();
    o[..6] == [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse::<Ipv4Addr>().unwrap().into()
    }
    fn v6(s: &str) -> IpAddr {
        s.parse::<Ipv6Addr>().unwrap().into()
    }
    fn default_filter() -> DstFilter {
        DstFilter::new(true, &[], &[]).unwrap()
    }

    #[test]
    fn always_blocks_loopback_linklocal_multicast_broadcast_unspecified() {
        let f = default_filter();
        for s in ["127.0.0.1", "169.254.169.254", "224.0.0.1", "255.255.255.255", "0.0.0.0"] {
            assert!(!f.allows(v4(s)), "{s} must always be blocked");
        }
        for s in ["::1", "ff02::1", "::", "fe80::1"] {
            assert!(!f.allows(v6(s)), "{s} must always be blocked");
        }
    }

    #[test]
    fn metadata_endpoints_blocked() {
        let f = default_filter();
        // IPv4 cloud metadata (link-local, always blocked).
        assert!(!f.allows(v4("169.254.169.254")));
        // AWS IPv6 metadata (ULA, blocked by block_private).
        assert!(!f.allows(v6("fd00:ec2::254")));
    }

    #[test]
    fn private_ranges_blocked_by_default() {
        let f = default_filter();
        for s in ["10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
                  "192.168.0.1", "192.168.255.255", "100.64.0.1", "100.127.255.255"] {
            assert!(!f.allows(v4(s)), "{s} (private) must be blocked by default");
        }
        for s in ["fc00::1", "fd12:3456::1", "fdff:ffff::1"] {
            assert!(!f.allows(v6(s)), "{s} (ULA) must be blocked by default");
        }
    }

    #[test]
    fn public_addresses_allowed() {
        let f = default_filter();
        for s in ["8.8.8.8", "1.1.1.1",
                  "172.15.255.255", "172.32.0.1",   // just outside 172.16/12
                  "100.63.255.255", "100.128.0.0",  // just outside CGNAT
                  "11.0.0.1", "192.167.255.255", "192.169.0.0"] {
            assert!(f.allows(v4(s)), "{s} (public) must be allowed");
        }
        for s in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(f.allows(v6(s)), "{s} (public) must be allowed");
        }
    }

    #[test]
    fn block_private_false_allows_private() {
        let f = DstFilter::new(false, &[], &[]).unwrap();
        assert!(f.allows(v4("10.0.0.1")), "split-tunnel mode permits RFC1918");
        assert!(f.allows(v6("fd00::1")), "split-tunnel mode permits ULA");
        // ...but the always-blocked set still holds.
        assert!(!f.allows(v4("127.0.0.1")));
        assert!(!f.allows(v4("169.254.169.254")));
    }

    #[test]
    fn allow_list_overrides_private_block() {
        let f = DstFilter::new(true, &["192.168.10.0/24".into()], &[]).unwrap();
        assert!(f.allows(v4("192.168.10.5")), "allowlisted subnet is reachable");
        assert!(!f.allows(v4("192.168.11.5")), "neighbouring subnet still blocked");
    }

    #[test]
    fn allow_does_not_override_always_blocked() {
        // Even an over-broad allowlist cannot re-enable loopback / metadata.
        let f = DstFilter::new(true, &["0.0.0.0/0".into()], &[]).unwrap();
        assert!(!f.allows(v4("127.0.0.1")));
        assert!(!f.allows(v4("169.254.169.254")));
        assert!(f.allows(v4("8.8.8.8")), "but public still flows");
    }

    #[test]
    fn deny_blocks_extra_public_range() {
        let f = DstFilter::new(false, &[], &["203.0.113.0/24".into()]).unwrap();
        assert!(!f.allows(v4("203.0.113.5")), "denylisted public range blocked");
        assert!(f.allows(v4("8.8.8.8")));
    }

    #[test]
    fn allow_beats_deny() {
        let f = DstFilter::new(false, &["203.0.113.5/32".into()], &["203.0.113.0/24".into()]).unwrap();
        assert!(f.allows(v4("203.0.113.5")), "explicit allow wins over deny");
        assert!(!f.allows(v4("203.0.113.6")), "rest of denied range stays blocked");
    }

    #[test]
    fn cidr_parse_rejects_garbage() {
        assert!(Cidr::parse("garbage").is_err());
        assert!(Cidr::parse("10.0.0.0").is_err(), "missing prefix");
        assert!(Cidr::parse("10.0.0.0/33").is_err(), "v4 prefix > 32");
        assert!(Cidr::parse("::/129").is_err(), "v6 prefix > 128");
        assert!(Cidr::parse("10.0.0.0/x").is_err(), "non-numeric prefix");
        assert!(DstFilter::new(true, &["nope".into()], &[]).is_err(), "build fails on bad allow");
    }

    #[test]
    fn cidr_prefix_zero_matches_all_same_family() {
        let f = DstFilter::new(false, &[], &["0.0.0.0/0".into()]).unwrap();
        assert!(!f.allows(v4("8.8.8.8")), "/0 deny blocks all v4");
        assert!(f.allows(v6("2606:4700::1111")), "v4 /0 doesn't touch v6");
    }

    #[test]
    fn dst_of_parses_v4_v6_and_rejects_junk() {
        // Minimal IPv4 header: dst at bytes 16..20.
        let mut p4 = vec![0u8; 20];
        p4[0] = 0x45; // version 4, IHL 5
        p4[16..20].copy_from_slice(&[8, 8, 8, 8]);
        assert_eq!(DstFilter::dst_of(&p4), Some(v4("8.8.8.8")));

        // Minimal IPv6 header: dst at bytes 24..40.
        let mut p6 = vec![0u8; 40];
        p6[0] = 0x60; // version 6
        p6[24..40].copy_from_slice(&Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1).octets());
        assert_eq!(DstFilter::dst_of(&p6), Some(v6("2606:4700::1")));

        assert_eq!(DstFilter::dst_of(&[]), None, "empty → None");
        assert_eq!(DstFilter::dst_of(&[0x45; 10]), None, "truncated v4 → None");
        assert_eq!(DstFilter::dst_of(&[0x60; 20]), None, "truncated v6 → None");
        assert_eq!(DstFilter::dst_of(&[0x00; 40]), None, "unknown version → None");
    }

    #[test]
    fn ssrf_ipv4_mapped_ipv6_normalized_then_blocked() {
        let f = default_filter();
        // Build an IPv6 packet whose dst is ::ffff:<v4>.
        let mapped_pkt = |v4: Ipv4Addr| -> Vec<u8> {
            let mut p = vec![0u8; 40];
            p[0] = 0x60; // version 6
            p[24..40].copy_from_slice(&v4.to_ipv6_mapped().octets());
            p
        };
        for s in ["127.0.0.1", "169.254.169.254", "10.0.0.1", "192.168.1.1"] {
            let v4: Ipv4Addr = s.parse().unwrap();
            let dst = DstFilter::dst_of(&mapped_pkt(v4)).expect("mapped v6 dst parses");
            assert_eq!(dst, IpAddr::V4(v4), "::ffff:{s} must normalise to embedded v4");
            assert!(!f.allows(dst), "mapped {s} must be blocked via v4 rules (SSRF)");
        }
        // A mapped PUBLIC v4 still flows.
        let pub_dst = DstFilter::dst_of(&mapped_pkt("8.8.8.8".parse().unwrap())).unwrap();
        assert!(f.allows(pub_dst), "mapped public v4 still allowed");
    }

    #[test]
    fn ssrf_ipv4_mapped_address_blocked_without_packet_parse() {
        // socks5d checks resolved SocketAddrs directly (no dst_of): a CONNECT
        // to [::ffff:127.0.0.1] must still hit the v4 rules.
        let f = default_filter();
        for s in ["::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1"] {
            assert!(!f.allows(v6(s)), "{s} must be blocked via its embedded v4");
        }
        assert!(f.allows(v6("::ffff:8.8.8.8")), "mapped public v4 still allowed");
        // An allowlist written in v4 applies to the mapped form too.
        let f = DstFilter::new(true, &["192.168.10.0/24".into()], &[]).unwrap();
        assert!(f.allows(v6("::ffff:192.168.10.5")));
    }

    #[test]
    fn ssrf_teredo_blocked_but_neighbouring_2001_space_allowed() {
        let f = DstFilter::new(true, &[], &[]).unwrap();
        assert!(!f.allows("2001:0:4136:e378:8000:63bf:3fff:fdd2".parse().unwrap()), "Teredo");
        assert!(f.allows("2001:4860:4860::8888".parse().unwrap()), "regular 2001:4860::/32 stays reachable");
    }

    #[test]
    fn ssrf_6to4_and_nat64_ranges_blocked() {
        let f = default_filter();
        // 6to4 (2002::/16) embedding loopback, and the NAT64 well-known prefix
        // embedding loopback / RFC1918 — both must be blocked.
        assert!(!f.allows(v6("2002:7f00:0001::")), "6to4 range must be blocked");
        assert!(!f.allows(v6("64:ff9b::7f00:1")), "NAT64 embedding 127.0.0.1 must be blocked");
        assert!(!f.allows(v6("64:ff9b::a00:1")), "NAT64 embedding 10.0.0.1 must be blocked");
        // A normal public v6 in a neighbouring range is unaffected.
        assert!(f.allows(v6("2001:4860:4860::8888")), "public v6 still allowed");
    }

    /// Regression (SSRF via transition prefixes): only 64:ff9b::/96 was
    /// caught, so the local-use NAT64 /48 and IPv4-compatible / -translated
    /// v6 smuggled loopback / RFC1918 / metadata past the v6-only checks.
    #[test]
    fn ssrf_local_use_nat64_and_v4_compatible_blocked() {
        let f = default_filter();
        // 64:ff9b:1::/48 — blocked whatever the embedding offset.
        for s in ["64:ff9b:1::7f00:1", "64:ff9b:1::a9fe:a9fe", "64:ff9b:1:7f00:1::",
                  "64:ff9b:1:ffff::808:808"] {
            assert!(!f.allows(v6(s)), "local-use NAT64 {s} must be blocked");
        }
        // IPv4-compatible ::a.b.c.d and IPv4-translated ::ffff:0:a.b.c.d are
        // judged by the embedded v4.
        for s in ["::127.0.0.1", "::169.254.169.254", "::10.0.0.1", "::192.168.1.1",
                  "::ffff:0:127.0.0.1", "::ffff:0:10.0.0.1"] {
            assert!(!f.allows(v6(s)), "{s} must be blocked via its embedded v4");
        }
        assert_eq!(normalize(v6("::10.0.0.1")), v4("10.0.0.1"));
        assert!(f.allows(v6("::8.8.8.8")), "compatible public v4 follows v4 rules");
        assert!(f.allows(v6("::ffff:0:8.8.8.8")), "translated public v4 follows v4 rules");
        // An allowlist written in v4 applies to the compatible form too, and
        // `::` / `::1` keep their v6 meaning (still blocked).
        let allow = DstFilter::new(true, &["192.168.10.0/24".into()], &[]).unwrap();
        assert!(allow.allows(v6("::192.168.10.5")));
        assert_eq!(normalize(v6("::1")), v6("::1"));
        assert!(!f.allows(v6("::1")) && !f.allows(v6("::")));
        // Just outside 64:ff9b:1::/48 is ordinary (public) v6.
        assert!(f.allows(v6("64:ff9b:2::808:808")));
    }

    #[test]
    fn this_network_0_0_0_0_slash_8_blocked() {
        let f = DstFilter::new(false, &["0.0.0.0/0".into()], &[]).unwrap();
        for s in ["0.0.0.0", "0.0.0.1", "0.1.2.3", "0.255.255.255"] {
            assert!(!f.allows(v4(s)), "{s} (0.0.0.0/8) must always be blocked");
        }
        assert!(!f.allows(v6("::ffff:0.1.2.3")), "mapped 0/8 blocked too");
        assert!(f.allows(v4("1.0.0.1")), "1.0.0.0/8 is outside");
    }

    /// Regression (exit reachable via its own IPs): the exit's public / LAN
    /// addresses weren't blocked, so a client could hit services bound on the
    /// exit host itself. They're always blocked, even past `allow`.
    #[test]
    fn exit_own_addresses_always_blocked() {
        let f = DstFilter::new(false, &["0.0.0.0/0".into(), "::/0".into()], &[])
            .unwrap()
            .with_local_addrs([v4("203.0.113.7"), v4("192.168.1.20"), v6("2001:db8::7")]);
        assert!(!f.allows(v4("203.0.113.7")), "exit's public v4");
        assert!(!f.allows(v4("192.168.1.20")), "exit's LAN v4 (even with block_private off)");
        assert!(!f.allows(v6("2001:db8::7")), "exit's public v6");
        assert!(!f.allows(v6("::ffff:203.0.113.7")), "mapped form of a local v4");
        assert!(f.allows(v4("203.0.113.8")), "neighbouring public host still reachable");

        // Clones share the set: a refresh after a DHCP change is seen by all.
        let clone = f.clone();
        f.set_local_addrs([v4("203.0.113.8")]);
        assert!(clone.allows(v4("203.0.113.7")), "old address released");
        assert!(!clone.allows(v4("203.0.113.8")), "new address blocked via the shared set");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refresh_local_addrs_enumerates_this_host() {
        let f = DstFilter::new(false, &[], &[]).unwrap();
        let n = f.refresh_local_addrs().expect("getifaddrs");
        assert!(n >= 1, "at least loopback is enumerated");
        let set = f.local_addrs();
        assert!(set.read().unwrap().contains(&v4("127.0.0.1")), "lo's 127.0.0.1 is found");
    }
}
