# bifrost roadmap

Items 1-6 are ordered by **expected throughput uplift on a
non-WAN-limited link** (datacenter / metro / 1 Gbit symmetric). On
the real-WAN testbed (UA↔Oracle NL, ~50 Mbit/s aggregate cap)
several of these don't move the needle — the WAN is the
bottleneck, not bifrost. They're prerequisites for fast LANs and
inter-region cloud bonding where the WAN headroom is real.

Items 7-9 were added after an external review — they are about
*reach and resilience* (censorship resistance, onboarding, scale)
rather than raw speed.

**Status: all nine items have landed.** #4 — the hands-on CPU
profile — is "done as far as this hardware allows": `perf` has no
PMU on the WSL2 testbed, so it was done with the benchmark suite
instead, and that already found and fixed the one real hot spot.

## 1. `sendmmsg` batching in `norn-rs::transport` ✅ done in 0.7.0

The `norn-rs::router::handle_conn` writer task drains up to 32
sibling frames with `try_recv()` after the blocking `recv().await`,
concatenates them into one `[varint_len][payload]…` buffer, and
ships the whole thing with one `write_all` — `sendmmsg(2)`-equivalent
(`norn-rs::packet::write_frames_batched`). `PacketConn::write_to_batch`
exposes the same amortisation at the application API.

Expected uplift on a Gbit+ link: 5-20%; nil on the 50 Mbit/s WAN,
which confirmed the change is safe.

## 2. Multi-core crypto worker pool ✅ done in 0.8.0

`PacketConn::enable_crypto_pool(n)` spins up `n` `crypto_worker`
tasks, each owning a bounded mpsc queue. `write_to` hashes the
destination key to a worker and hands it the pad + ChaCha20-Poly1305
+ envelope + dispatch work; on a multi-thread runtime the workers
run on separate cores. Hashing by destination keeps every packet for
one peer on one worker — per-peer wire order is preserved and a
peer's session mutex is never contended across workers. A saturated
queue falls back to inline encryption: pure offload, never a drop.

Opt-in via `NodeConfig.crypto_workers` (default 0 = inline). The
prerequisite — per-peer session sharding (`RwLock<SessionManager>`
over per-peer `Arc<Mutex<SessionInfo>>`) — landed alongside it and
removed the single-big-lock contention this item was written to fix.

## 3. TUN GSO/GRO (`IFF_VNET_HDR` + `TUNSETOFFLOAD`) ✅ done

`bifrost-vpnd/src/tun_dev.rs` replaces the `tun2` dependency with a
hand-rolled `AsyncFd<OwnedFd>` that opens `/dev/net/tun` with
`IFF_TUN | IFF_NO_PI | IFF_VNET_HDR`.

* `OffloadTun::DEFAULT_OFFLOAD` enables `TUN_F_CSUM | TSO4 | TSO6 |
  USO4`; `try_enable_tun_offload` has a USO-aware retry for kernels
  < 6.0.
* The kernel `virtio_net_hdr` is 10 bytes; `AsyncRead`/`AsyncWrite`
  pass the `[virtio_net_hdr | ip]` slab through verbatim.
* GSO super-segments are not re-segmented in userspace — the whole
  `[vhdr | payload]` slab (up to ~64 KiB, hence `MAX_RELAYED_PACKET`
  = 60 KiB) rides one `Frame::Datagram` and the receiving exit's
  kernel does the segmentation.
* `EgressHello` v3 carries a `capabilities` bitfield
  (`EGRESS_CAP_VNET_HDR`) so the framing is used only when both ends
  agree; a mixed-version mesh degrades to plain-IP framing.

## 4. Hands-on CPU profile of the bottleneck ✅ done (best-effort)

`perf record` is non-functional on the WSL2 testbed — the kernel
exposes no PMU, so a sampled flamegraph yields zero samples. The
profile was instead done with the criterion benchmark suite
(`norn-rs/benches/bench.rs`), which surfaced one clear hot spot:

```
session/encrypt_64B     55.7 µs
session/encrypt_1024B   55.8 µs   <- flat, independent of payload size
session/encrypt_16384B  67.8 µs
```

A ~55 µs *fixed* cost per encrypt — `SessionInfo::encrypt`/`decrypt`
ran a full X25519 Diffie-Hellman scalar multiplication on every
packet, even though the keypair only changes on rotation, so the
result was identical between rotations and recomputed for nothing.

Fixed (`norn-rs` 0.9.0) with a self-validating `dh_shared` cache —
it tags the memoised secret with the public-key fingerprints it was
derived from and recomputes on any rotation, so it cannot desync:

```
session/encrypt_64B     55.7 µs -> 2.08 µs   (~27x)
session/encrypt_1024B   55.8 µs -> 2.79 µs   (~20x)
session/encrypt_16384B  67.8 µs -> 14.3 µs   (~4.7x; now AEAD-bound)
```

Per-packet crypto is now dominated by the actual AEAD, lifting the
single-core crypto ceiling from ~200 Mbit/s to multi-Gbit — exactly
the headroom #2's worker pool needs. A genuine sampled
`perf`/flamegraph pass on a metro box with a working PMU is still
worth doing, but the one obvious software bottleneck is closed.

## 5. Mobile clients (Android NDK, iOS) ✅ FFI shim + Android app

`bifrost-ffi/` produces a `cdylib` (Android `jniLibs`) and a
`staticlib` (iOS xcframework). The C surface is pinned in
`include/bifrost_ffi.h`; `bifrost-vpnd::egress` exposes
`client_handshake` + `run_client_pump<R,W>` so the FFI drives the
same coalescing data plane desktop clients use.

The Android client is now a full, buildable app — `bifrost-android/`:

* `bifrost-ffi/src/android.rs` — a JNI bridge (android-gated, `jni`
  crate) exporting `Java_org_norn_bifrost_NativeBridge_*`.
* A dependency-light Kotlin `VpnService` app (no AndroidX, no layout
  XML, no CMake): `BifrostVpnService` builds the TUN and runs the
  native pump on a worker thread; `MainActivity` is a one-screen
  test harness.
* `cargo ndk` cross-builds `libbifrost_ffi.so` for `arm64-v8a` +
  `x86_64`; `./gradlew assembleDebug` produces an installable
  debug-signed APK. See `bifrost-android/README.md`.

To compile this crate for `*-linux-android`, `bifrost-vpnd`'s `libc`
dependency was widened from `cfg(target_os = "linux")` to
`cfg(unix)` (admin.rs uses `libc::umask` unconditionally).

iOS packaging (xcframework, `NEPacketTunnelProvider` glue) is the
remaining mobile follow-up; `BUILD-MOBILE.md` has the recipes.

## 6. Persistent crash-recovery for `bifrost-vpnd` leases ✅ done

`lease_store.rs` keeps `(peer_pubkey → lease)` in a JSON file that
round-trips through `<path>.tmp + fsync + rename(2)`. On startup
`start_exit` reserves each leased host index and reinstates
`EgressTable::lease_of`, so a returning client resumes its IPv4/IPv6
pair across reconnects *and* exit restarts. `bifrost-ctl leases` /
`evict-lease` manage them over the admin socket.

## 7. Transport obfuscation / DPI resistance ✅ first increment in 0.9.0

`norn-rs::obfs` — an opt-in, pre-shared-key stream obfuscator. With
`NodeConfig.obfuscation_psk` set, every TCP link is wrapped in a
BLAKE2b keystream so the whole connection — NRN1 handshake included
— is uniform random bytes on the wire: no static signature for a DPI
box to match.

* A 16-byte per-direction nonce is exchanged in clear; the
  per-connection key is `BLAKE2b(psk ‖ nonce)`; the keystream is
  `BLAKE2b(conn_key ‖ counter)` with a 64-bit counter (never
  exhausts).
* `CipherReader`/`CipherWriter` are byte-count preserving, so the
  keystream cannot desync; `ObfsReader`/`ObfsWriter` keep
  `handle_conn` monomorphic over plain vs obfuscated links.

This defeats signature-based blocking. It is **not** obfs4: packet
sizes and timing are unchanged (traffic analysis still works), the
16-byte cleartext opener is a weak signal, and QUIC links are out of
scope. **Next increment:** length/timing padding toward a target
distribution; optionally a pluggable-transport-style outer tunnel
for the hardest networks. This problem is adversarial and never
truly "done" — the goal is raising the cost of a *trivial* block.

## 8. Out-of-band key exchange UX ✅ first increment in 0.9.0

`norn-rs::keyshare` gives two lossless, reversible channels for a
node's 64-hex public key:

* `to_mnemonic`/`from_mnemonic` — the key as a 24-word BIP39 English
  phrase; the BIP39 checksum makes a mistyped phrase fail loudly.
* `qr_terminal` — the key (or any short string) as a scannable
  Unicode-block QR.

`nornctl share` prints the running node's identity as pub_key +
address + mnemonic + QR; `nornctl resolve <words…>` decodes a phrase
back. **Next increments** (still open): short-lived rendezvous
tokens via an introducer node, and an opt-in name→key directory.

## 9. Control-plane scaling past ~20k nodes ✅ adaptive cadence in 0.9.0

`do_maintenance` used to re-flood `send_announces` (×K trees) +
`broadcast_coord` to every peer every 1 Hz tick regardless of
change. Now it digests the topology each tick (per-tree root /
root_seq / parent, own depth, onion ephemeral pub, peer count);
while the digest is unchanged the broadcast interval backs off
linearly 1→8 ticks, and any change snaps it back to every tick. The
8-tick ceiling stays well under `ANNOUNCE_EXPIRY` (30 s).
`norn_control_broadcasts_total` / `norn_control_suppressed_total` in
`/metrics` quantify the saving.

Measured on the 100-node docker cluster: 2575 control broadcasts
suppressed cluster-wide over a deliberately churny 120 s run
(convergence + mid-run chaos) — ~22 %; in a steady neighbourhood the
suppression approaches 7/8. Cluster CPU was 19.9 % mean total (vs a
~24.5 % pre-#9 post-patch baseline), memory flat at 285 MiB.

**Next increments** (still open): adaptive `ReputationReport`
cadence, gossip suppression/aggregation once a neighbourhood agrees,
and pushing the docker harness past 300 nodes to find the real knee.

## What's *not* on the roadmap

* **Anonymity from the exit node.** Like any VPN — unlike Tor — a
  `bifrost-vpnd` exit sees the client's destination IPs (and
  plaintext, if the client isn't using TLS). The mesh hides the
  client's *location* and hides traffic from the *path*, but the
  exit operator is trusted by construction. For internet egress the
  answer is "run your own exit", not a protocol change.
* **Switching the mesh transport from TCP to UDP/QUIC by default.**
  QUIC measures the same throughput as TCP on real WAN; it's wired
  for `quic://` URIs as an opt-in (UDP traversal, 0-RTT resume) but
  isn't the default because it speeds nothing up.
* **Inline lz4/zstd compression on the wire.** Encrypted bytes are
  high-entropy; compression buys 0–2 % and costs a per-packet CPU
  tax that hurts more than it helps.
