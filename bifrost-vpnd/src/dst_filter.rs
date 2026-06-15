//! Egress destination filtering — SSRF defence for the exit.
//!
//! A bifrost exit writes client IP packets to its egress TUN and the kernel
//! routes them out (MASQUERADE). Without a destination filter a malicious
//! client could address packets at the exit's own loopback, its private LAN
//! (RFC1918 / CGNAT), or the cloud metadata endpoint (IPv4 169.254.169.254,
//! IPv6 `fd00:ec2::254`) and use the exit as an SSRF pivot into the operator's
//! infrastructure.
//!
//! [`DstFilter`] classifies each forwarded packet's destination:
//!
//!   * **Always blocked** (never sensible to egress, not overridable):
//!     loopback, link-local (incl. IPv4 cloud metadata 169.254.0.0/16),
//!     multicast, broadcast, unspecified.
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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A parsed CIDR block, pre-masked so matching is a single bitwise-AND compare.
#[derive(Debug, Clone, Copy)]
enum Cidr {
    V4 { net: u32, mask: u32 },
    V6 { net: u128, mask: u128 },
}

impl Cidr {
    fn parse(s: &str) -> Result<Self> {
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

    fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { net, mask }, IpAddr::V4(a)) => (u32::from(a) & mask) == *net,
            (Cidr::V6 { net, mask }, IpAddr::V6(a)) => (u128::from(a) & mask) == *net,
            _ => false, // address family mismatch never matches
        }
    }
}

/// Egress destination policy. Cheap to clone-by-`Arc`; immutable after build.
#[derive(Debug, Clone)]
pub struct DstFilter {
    block_private: bool,
    allow: Vec<Cidr>,
    deny: Vec<Cidr>,
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
        Ok(Self { block_private, allow, deny })
    }

    /// True if a packet destined to `ip` may be forwarded out the egress.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if Self::always_blocked(ip) {
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
                Some(Ipv6Addr::from(o).into())
            }
            _ => None,
        }
    }

    /// Never sensible to egress, regardless of policy.
    fn always_blocked(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => {
                a.is_loopback()        // 127.0.0.0/8
                    || a.is_link_local()  // 169.254.0.0/16 (incl. cloud metadata)
                    || a.is_multicast()   // 224.0.0.0/4
                    || a.is_broadcast()   // 255.255.255.255
                    || a.is_unspecified() // 0.0.0.0
            }
            IpAddr::V6(a) => {
                a.is_loopback()        // ::1
                    || a.is_multicast()   // ff00::/8
                    || a.is_unspecified() // ::
                    || is_v6_link_local(a) // fe80::/10
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
}
