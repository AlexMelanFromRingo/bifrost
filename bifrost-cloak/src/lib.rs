//! bifrost-cloak — opt-in anti-DPI transport for the Bifrost mesh VPN.
//!
//! Provides the `wss://` mesh transport: a real TLS 1.3 session carrying
//! a real WebSocket, so a DPI box on the path sees an ordinary HTTPS
//! connection. The norn-rs mesh protocol (NRN1 handshake + frames) rides
//! unchanged *inside* the WebSocket.
//!
//! This crate is deliberately separate from the lightweight `norn-rs`
//! core. All the TLS / HTTP / WebSocket machinery and its heavier
//! dependencies live here; a consuming binary pulls `bifrost-cloak` in
//! only behind its own `anti-dpi` feature, so a default build never
//! compiles or links any of it. norn-rs stays a clean mesh library and
//! exposes exactly one seam — `transport::serve_authenticated_link` —
//! that this crate hands an established byte pipe to.
//!
//! See `docs/ANTI-DPI.md` for the threat model and design.

mod tls;
pub mod wss;

pub use wss::{dial, listen, parse_wss_uri, spawn_wss};
