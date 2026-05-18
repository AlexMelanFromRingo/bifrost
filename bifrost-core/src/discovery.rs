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

use crate::scoring::ScoredExitPool;
use crate::PubKey;
use anyhow::{Context, Result};
use mdns_sd::{ResolvedService, ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
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

/// Spawn the client-side mDNS browser. Returns the daemon handle (keep
/// it alive — dropping it stops the browser). The browser thread feeds
/// discovered exits into `pool`; we filter out our own pub_key so a
/// node running both an exit AND a client mode doesn't loop on itself.
pub fn browse_exits(
    pool: Arc<ScoredExitPool>,
    our_pub_key: PubKey,
) -> Result<ServiceDaemon> {
    let daemon = ServiceDaemon::new().context("creating mDNS daemon (browse)")?;
    let receiver = daemon.browse(SERVICE_TYPE).context("browsing bifrost-exit service")?;
    info!("mDNS: browsing {} for exit candidates", SERVICE_TYPE);

    // fullname → pub_key map so ServiceRemoved events can find the
    // right peer to evict (the Removed event doesn't carry TXT).
    let evict_map: Arc<Mutex<HashMap<String, PubKey>>> = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(async move {
        while let Ok(event) = receiver.recv_async().await {
            handle_event(event, &pool, &evict_map, &our_pub_key);
        }
        warn!("mDNS browse channel closed");
    });
    Ok(daemon)
}

fn handle_event(
    event: ServiceEvent,
    pool: &Arc<ScoredExitPool>,
    evict_map: &Arc<Mutex<HashMap<String, PubKey>>>,
    our_pub_key: &PubKey,
) {
    match event {
        ServiceEvent::ServiceResolved(resolved) => {
            let pk = match extract_pub_key_from_resolved(&resolved) {
                Some(k) => k,
                None => {
                    debug!(
                        "mDNS: {} resolved without a usable {} TXT, ignoring",
                        resolved.fullname, PUBKEY_TXT_KEY
                    );
                    return;
                }
            };
            if pk == *our_pub_key {
                return;
            }
            let added = pool.add_candidate(pk, Some("mDNS".to_string()));
            if added {
                info!(
                    "mDNS: discovered exit {} via {}",
                    hex::encode(&pk[..8]),
                    resolved.fullname
                );
            }
            evict_map
                .lock()
                .expect("evict_map mutex poisoned")
                .insert(resolved.fullname.clone(), pk);
        }
        ServiceEvent::ServiceRemoved(_service_type, fullname) => {
            let evicted = evict_map
                .lock()
                .expect("evict_map mutex poisoned")
                .remove(&fullname);
            if let Some(pk) = evicted {
                pool.remove_candidate(&pk);
                info!(
                    "mDNS: evicted exit {} ({} gone)",
                    hex::encode(&pk[..8]),
                    fullname
                );
            }
        }
        _ => {}
    }
}

fn extract_pub_key_from_resolved(svc: &ResolvedService) -> Option<PubKey> {
    let val = svc.txt_properties.get_property_val_str(PUBKEY_TXT_KEY)?;
    decode_hex_pub_key(val)
}

/// Unit-test friendly: the test fixture uses ServiceInfo (which we
/// build directly), production handles ResolvedService (which arrives
/// from the mdns-sd browser).
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
