// mDNS exit-discovery for bifrost.
//
// Exit daemons advertise the `_bifrost-exit._norn._tcp.local` service
// type with their ed25519 pub_key in a `pk=<64hex>` TXT record. Auto-
// mode clients browse the same service type and feed every discovered
// pub_key into their ScoredExitPool. ServiceRemoved evictions drop
// the candidate so a peer going dark stops being picked.
//
// Sibling to norn-rs's own `_norn._tcp.local` discovery (which finds
// transport-layer peers). They share the mdns-sd backend but advertise
// distinct service types so a client that doesn't speak bifrost won't
// try to make a SOCKS5 stream to a generic norn peer.
//
// TRUST: an mDNS advertisement is unauthenticated — any LAN host can
// announce any pub_key. An exit sees every CONNECT target routed through
// it (and with happy-eyeballs racing, up to `race_exits` exits see each
// one), so a discovered key only becomes a candidate if it is listed in
// the client's `trusted_exits` (or the operator opted into
// `mdns_trust_any`). Discovered candidates are capped so a flood of
// advertisements can't grow the pool without bound. Statically configured
// exits are never evicted by mDNS events.

use crate::scoring::ScoredExitPool;
use crate::PubKey;
use anyhow::{Context, Result};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Bifrost-specific mDNS service type. Standard DNS-SD shape
/// (`_<service>._tcp.local.`), distinct from norn-rs's `_norn._tcp`
/// so a generic norn browser doesn't accidentally pick a bifrost
/// exit up as a plain mesh peer.
pub const SERVICE_TYPE: &str = "_bifrost-exit._tcp.local.";

/// TXT record key carrying the pub_key as 64 hex chars.
pub const PUBKEY_TXT_KEY: &str = "pk";

/// Spawn the exit-side mDNS advertiser. Holds the returned daemon for
/// as long as the advertisement should be live — drop it to unregister.
pub fn advertise_exit(our_pub_key: PubKey, tcp_port: u16) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("creating mDNS daemon (advertise)")?;
    let pk_hex = hex::encode(our_pub_key);
    let instance_name = format!("bifrost-{}", &pk_hex[..8]);
    let mut props = HashMap::new();
    props.insert(PUBKEY_TXT_KEY.to_string(), pk_hex.clone());
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name,
        &format!("{}.local.", instance_name),
        "",
        tcp_port,
        Some(props),
    )
    .context("building bifrost-exit ServiceInfo")?
    .enable_addr_auto();
    daemon.register(info).context("registering bifrost-exit mDNS service")?;
    info!("mDNS: advertising exit service {}.{}", instance_name, SERVICE_TYPE);
    Ok(daemon)
}

/// Default cap on simultaneously tracked mDNS-discovered exits.
pub const DEFAULT_MAX_DISCOVERED: usize = 16;

/// Which discovered exits the browser may add to the pool.
#[derive(Debug, Clone)]
pub struct DiscoveryTrust {
    /// Pub keys that may be added when seen via mDNS.
    pub trusted: HashSet<PubKey>,
    /// Accept ANY advertised key (explicit opt-in; LAN-trusting).
    pub trust_any: bool,
    /// Maximum number of mDNS-added candidates tracked at once.
    pub max_discovered: usize,
}

impl Default for DiscoveryTrust {
    fn default() -> Self {
        Self { trusted: HashSet::new(), trust_any: false, max_discovered: DEFAULT_MAX_DISCOVERED }
    }
}

impl DiscoveryTrust {
    /// True if this policy can ever admit a discovered exit (otherwise
    /// running the browser is pointless).
    pub fn admits_anything(&self) -> bool {
        self.max_discovered > 0 && (self.trust_any || !self.trusted.is_empty())
    }

    fn permits(&self, pk: &PubKey) -> bool {
        self.trust_any || self.trusted.contains(pk)
    }
}

/// Browser-side bookkeeping: which fullnames map to which discovered key,
/// and which keys mDNS itself added to the pool (only those may be evicted
/// by mDNS — a statically configured exit must survive a `ServiceRemoved`).
#[derive(Default)]
struct BrowseState {
    by_fullname: HashMap<String, PubKey>,
    added_by_mdns: HashSet<PubKey>,
}

/// Spawn the client-side mDNS browser. Returns the daemon handle (keep
/// it alive — dropping it stops the browser). The browser thread feeds
/// discovered exits into `pool`; we filter out our own pub_key so a
/// node running both an exit AND a client mode doesn't loop on itself.
pub fn browse_exits(
    pool: Arc<ScoredExitPool>,
    our_pub_key: PubKey,
    trust: DiscoveryTrust,
) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("creating mDNS daemon (browse)")?;
    let receiver = daemon.browse(SERVICE_TYPE).context("browsing bifrost-exit service")?;
    info!(
        "mDNS: browsing {} for exit candidates ({}, max {})",
        SERVICE_TYPE,
        if trust.trust_any {
            "trusting ANY advertised key".to_string()
        } else {
            format!("{} trusted key(s)", trust.trusted.len())
        },
        trust.max_discovered
    );

    let state = Arc::new(Mutex::new(BrowseState::default()));

    tokio::spawn(async move {
        while let Ok(event) = receiver.recv_async().await {
            handle_event(event, &pool, &state, &our_pub_key, &trust);
        }
        warn!("mDNS browse channel closed");
    });
    Ok(daemon)
}

fn handle_event(
    event: ServiceEvent,
    pool: &ScoredExitPool,
    state: &Mutex<BrowseState>,
    our_pub_key: &PubKey,
    trust: &DiscoveryTrust,
) {
    match event {
        ServiceEvent::ServiceResolved(resolved) => {
            let Some(pk) = extract_pub_key_from_resolved(&resolved) else {
                debug!(
                    "mDNS: {} resolved without a usable {} TXT, ignoring",
                    resolved.fullname, PUBKEY_TXT_KEY
                );
                return;
            };
            on_resolved(pk, &resolved.fullname, pool, state, our_pub_key, trust);
        }
        ServiceEvent::ServiceRemoved(_service_type, fullname) => {
            on_removed(&fullname, pool, state);
        }
        _ => {}
    }
}

/// A service resolved with pub key `pk`. Returns true if `pk` was added to
/// the pool as a new candidate.
fn on_resolved(
    pk: PubKey,
    fullname: &str,
    pool: &ScoredExitPool,
    state: &Mutex<BrowseState>,
    our_pub_key: &PubKey,
    trust: &DiscoveryTrust,
) -> bool {
    if pk == *our_pub_key {
        return false;
    }
    if !trust.permits(&pk) {
        debug!(
            "mDNS: ignoring untrusted exit {} via {} (not in trusted_exits)",
            hex::encode(&pk[..8]),
            fullname
        );
        return false;
    }
    let mut st = state.lock().expect("mDNS browse state poisoned");
    if st.added_by_mdns.contains(&pk) {
        // Same key under another (or the same) instance name: remember the
        // alias so the key is only evicted once all its names are gone.
        // Bounded: aliases only for keys we track, capped per tracked key.
        if !st.by_fullname.contains_key(fullname)
            && st.by_fullname.len() < trust.max_discovered.saturating_mul(4)
        {
            st.by_fullname.insert(fullname.to_string(), pk);
        }
        return false;
    }
    if st.added_by_mdns.len() >= trust.max_discovered {
        debug!(
            "mDNS: discovered-exit cap ({}) reached, ignoring {}",
            trust.max_discovered,
            hex::encode(&pk[..8])
        );
        return false;
    }
    // add_candidate is false for a key already in the pool (a statically
    // configured exit): leave it alone and do NOT track it, so a later
    // ServiceRemoved can't evict a configured exit.
    if !pool.add_candidate(pk, Some("mDNS".to_string())) {
        return false;
    }
    st.added_by_mdns.insert(pk);
    st.by_fullname.insert(fullname.to_string(), pk);
    info!("mDNS: discovered trusted exit {} via {}", hex::encode(&pk[..8]), fullname);
    true
}

/// A service went away. Evicts its key only if mDNS added it and no other
/// tracked instance name still advertises it. Returns true on eviction.
fn on_removed(fullname: &str, pool: &ScoredExitPool, state: &Mutex<BrowseState>) -> bool {
    let mut st = state.lock().expect("mDNS browse state poisoned");
    let Some(pk) = st.by_fullname.remove(fullname) else { return false };
    if st.by_fullname.values().any(|k| *k == pk) || !st.added_by_mdns.remove(&pk) {
        return false;
    }
    drop(st);
    pool.remove_candidate(&pk);
    info!("mDNS: evicted exit {} ({} gone)", hex::encode(&pk[..8]), fullname);
    true
}

fn extract_pub_key_from_resolved(svc: &ResolvedService) -> Option<PubKey> {
    let val = svc.txt_properties.get_property_val_str(PUBKEY_TXT_KEY)?;
    decode_hex_pub_key(val)
}

/// Unit-test friendly: the test fixture uses ServiceInfo (which we
/// build directly), production handles ResolvedService (which arrives
/// from the mdns-sd browser).
#[cfg(test)]
fn extract_pub_key(info: &ServiceInfo) -> Option<PubKey> {
    let val = info.get_property_val_str(PUBKEY_TXT_KEY)?;
    decode_hex_pub_key(val)
}

fn decode_hex_pub_key(hex_str: &str) -> Option<PubKey> {
    let raw = hex::decode(hex_str).ok()?;
    if raw.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Some(k)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_pub_key_decodes_valid_hex() {
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            "test-instance",
            "test-instance.local.",
            "",
            9001,
            Some([(PUBKEY_TXT_KEY.to_string(), "ab".repeat(32))].into_iter().collect()),
        )
        .unwrap();
        let pk = extract_pub_key(&info).unwrap();
        assert_eq!(pk, [0xab; 32]);
    }

    #[test]
    fn extract_pub_key_rejects_wrong_length() {
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            "short",
            "short.local.",
            "",
            9001,
            Some([(PUBKEY_TXT_KEY.to_string(), "ab".to_string())].into_iter().collect()),
        )
        .unwrap();
        assert!(extract_pub_key(&info).is_none());
    }

    fn trust(keys: &[PubKey], any: bool, max: usize) -> DiscoveryTrust {
        DiscoveryTrust { trusted: keys.iter().copied().collect(), trust_any: any, max_discovered: max }
    }

    /// Regression: any LAN host advertising any key became an Auto-mode exit
    /// candidate (and, with race_exits, saw CONNECT targets). Untrusted keys
    /// are now ignored by default.
    #[test]
    fn untrusted_mdns_exit_is_ignored_by_default() {
        let pool = ScoredExitPool::new(vec![]);
        let st = Mutex::new(BrowseState::default());
        let me = [0u8; 32];
        let t = DiscoveryTrust::default();
        assert!(!t.admits_anything(), "default policy admits nothing");
        assert!(!on_resolved([0x66; 32], "evil._bifrost-exit", &pool, &st, &me, &t));
        assert!(pool.is_empty());

        let t = trust(&[[0x11; 32]], false, 16);
        assert!(!on_resolved([0x66; 32], "evil", &pool, &st, &me, &t));
        assert!(on_resolved([0x11; 32], "good", &pool, &st, &me, &t));
        assert_eq!(pool.len(), 1);
        // Own key never added even if trusted / trust_any.
        let t = trust(&[], true, 16);
        assert!(!on_resolved(me, "self", &pool, &st, &me, &t));
    }

    /// mDNS-discovered candidates are capped (unbounded growth before).
    #[test]
    fn discovered_candidates_are_capped() {
        let pool = ScoredExitPool::new(vec![]);
        let st = Mutex::new(BrowseState::default());
        let t = trust(&[], true, 3);
        for i in 1..=50u8 {
            on_resolved([i; 32], &format!("svc-{i}"), &pool, &st, &[0u8; 32], &t);
        }
        assert_eq!(pool.len(), 3);
        // Aliases for tracked keys are bounded too.
        for i in 0..1000 {
            on_resolved([1; 32], &format!("alias-{i}"), &pool, &st, &[0u8; 32], &t);
        }
        assert!(st.lock().unwrap().by_fullname.len() <= 12);
        // Freeing a slot lets a new one in.
        assert!(on_removed("svc-2", &pool, &st));
        assert!(on_resolved([9; 32], "svc-9", &pool, &st, &[0u8; 32], &t));
        assert_eq!(pool.len(), 3);
    }

    /// A statically configured exit that is also advertised via mDNS must
    /// not be evicted when the advertisement disappears.
    #[test]
    fn mdns_removal_never_evicts_static_exit() {
        let static_pk = [0x22; 32];
        let pool = ScoredExitPool::new(vec![(static_pk, Some("primary".into()))]);
        let st = Mutex::new(BrowseState::default());
        let t = trust(&[static_pk], false, 16);
        assert!(!on_resolved(static_pk, "static", &pool, &st, &[0u8; 32], &t));
        assert!(!on_removed("static", &pool, &st));
        assert_eq!(pool.len(), 1, "configured exit survives ServiceRemoved");
    }

    /// A key advertised under two instance names stays until both are gone.
    #[test]
    fn mdns_key_with_two_names_evicted_after_last() {
        let pool = ScoredExitPool::new(vec![]);
        let st = Mutex::new(BrowseState::default());
        let t = trust(&[[5; 32]], false, 16);
        assert!(on_resolved([5; 32], "a", &pool, &st, &[0u8; 32], &t));
        assert!(!on_resolved([5; 32], "b", &pool, &st, &[0u8; 32], &t));
        assert!(!on_removed("a", &pool, &st));
        assert_eq!(pool.len(), 1);
        assert!(on_removed("b", &pool, &st));
        assert!(pool.is_empty());
    }

    #[test]
    fn extract_pub_key_returns_none_without_txt() {
        let info = ServiceInfo::new(
            SERVICE_TYPE,
            "no-txt",
            "no-txt.local.",
            "",
            9001,
            None::<HashMap<String, String>>,
        )
        .unwrap();
        assert!(extract_pub_key(&info).is_none());
    }
}
