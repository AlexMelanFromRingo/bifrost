//! Egress destination filtering — SSRF defence for the exit.
//!
//! The implementation lives in [`bifrost_core::dst_filter`] so both exits
//! (`bifrost-vpnd`'s packet egress and `bifrost-socks5d`'s TCP dialer) share
//! one policy. Re-exported here so existing `bifrost_vpnd::dst_filter` paths
//! keep working.

pub use bifrost_core::dst_filter::*;
