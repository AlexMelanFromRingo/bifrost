//! Library surface for `bifrost-vpnd`.
//!
//! The crate is primarily a `[[bin]]` (the daemon binary in
//! `src/main.rs`), but several modules are reused by
//! `bifrost-ffi` for the mobile shim. Exposing them via a `[lib]`
//! target avoids duplicating ~150 LOC of subtle batching /
//! coalescing logic across crates.
//!
//! Public surface:
//!
//! * [`egress`] — `client_handshake` + `run_client_pump` (the data
//!   plane primitives), plus the TUN-backed `start_client` /
//!   `start_exit` entry points used by the daemon.
//! * [`lease_store`] — JSON-backed persistent IP lease store.
//! * [`tun_offload`] — `virtio_net_hdr` encode/decode + the
//!   `TUNSETOFFLOAD` ioctl wrapper.
//! * [`tun_dev`] — `OffloadTun`, the hand-rolled async TUN device
//!   that replaces `tun2` for exit/client paths. Linux-only.
//! * [`config`] — `VpnConfig` (TOML schema). Re-exported so
//!   external tools can validate / generate configs without
//!   depending on the daemon binary.

pub mod config;
pub mod egress;
pub mod lease_store;
#[cfg(all(feature = "tun", target_os = "linux"))]
pub mod tun_dev;
pub mod tun_offload;
