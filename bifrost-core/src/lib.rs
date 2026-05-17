// bifrost-core — reliable stream multiplexer over a norn-rs PacketConn.
//
// The mesh PacketConn is a best-effort datagram channel addressed by ed25519
// pub key. To carry SOCKS5 / VPN streams across it we layer:
//
//   * frame.rs   — wire format: OPEN / DATA / CLOSE / RESET / OPEN_ACK.
//   * mux.rs     — demultiplexer: one PacketConn read loop fans inbound
//                  frames into per-(peer, stream_id) channels, and routes
//                  accepted OPENs to an accept queue.
//   * stream.rs  — `MeshStream`: implements AsyncRead + AsyncWrite. Writes
//                  fragment into MTU-sized DATA frames; reads pull from the
//                  stream's per-stream channel.
//   * policy.rs  — exit-peer selection: parse pub keys, pick one for a
//                  CONNECT, drop unreachable peers from the rotation.
//
// v0.1 makes one explicit reliability assumption: the exit peer is a
// direct neighbour of the client, so the underlying TCP session inside
// norn-rs delivers our datagrams in order without loss. Multi-hop paths
// will need an ARQ layer; that's earmarked but not implemented yet.

pub mod frame;
pub mod mux;
pub mod policy;
pub mod reliability;
pub mod stream;

pub use frame::{Frame, FrameKind, OpenTarget, MAX_FRAME_OVERHEAD};
pub use mux::{accept_streams, MeshMux};
pub use policy::{EgressPolicy, ExitPeer};
pub use stream::MeshStream;

/// 32-byte ed25519 public key — addresses everything inside the mesh.
pub type PubKey = [u8; 32];

/// Locally-allocated stream identifier. Unique per (local_node, remote_node) pair.
pub type StreamId = u32;
