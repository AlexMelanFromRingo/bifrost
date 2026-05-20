# bifrost roadmap

Items 1-6 are ordered by **expected throughput uplift on a
non-WAN-limited link** (datacenter / metro / 1 Gbit symmetric). On
the real-WAN testbed (UA↔Oracle NL, ~50 Mbit/s aggregate cap)
several of these don't move the needle — the WAN is the
bottleneck, not bifrost. They're prerequisites for fast LANs and
inter-region cloud bonding where the WAN headroom is real.

Five of those six have landed; only #4 is still open, and it is
blocked on hardware rather than on work. Items 7-9 were added
after an external review — they are about *reach and resilience*
(censorship resistance, onboarding, scale) rather than raw speed.

## 1. `sendmmsg` batching in `norn-rs::transport` ✅ done in 0.7.0

Status: **landed** in `norn-rs::router::handle_conn` writer task
and `norn-rs::packet::write_frames_batched`.

The writer task drains up to 32 sibling frames from its mpsc
channel with `try_recv()` after the blocking `recv().await`,
concatenates them into one `[varint_len][payload]…` buffer, and
ships the whole thing with one `write_all`. Functionally
equivalent to `sendmmsg(2)`: one syscall, one mio waker
round-trip per *batch* of frames instead of per frame. Three
unit tests pin the wire format (`write_frames_batched_*` in
`src/packet.rs`).

`PacketConn::write_to_batch(payloads, dst)` exposes the same
pattern at the application API: encrypt + envelope N payloads to
the same peer under one round of session-manager lock
acquisitions. Currently unused — wired in when an upper-layer
caller wants the amortisation (vpnd's coalesce path already
batches at a higher level, so doesn't need it).

Expected uplift on a Gbit+ link: 5-20%. On the 50 Mbit/s WAN the
writer was nowhere near syscall-bound, so the iter-11 bench was
unchanged — which confirms the change is safe.

## 2. Multi-core crypto worker pool ✅ done in 0.8.0

Status: **landed** in `norn-rs::router`.

`PacketConn::write_to` used to encrypt inline on the caller's
task. ChaCha20-Poly1305 runs ~2 GB/s on modern x86, so at
50 Mbit/s the crypto is ~0.3% of one core — invisible. At
10 Gbit/s it would be ~60% of a core and gate throughput.

Two pieces landed:

* **Per-peer session sharding** — the prerequisite. The session
  manager used to be one `Mutex<SessionManager>` whose lock every
  encrypt/decrypt contended. It is now an `RwLock<SessionManager>`
  over a map of per-peer `SessionHandle = Arc<Mutex<SessionInfo>>`:
  the hot path takes the read lock only long enough to *clone the
  handle*, then encrypts under that peer's own mutex. Encrypts to
  different peers no longer serialise. This alone removed the lock
  contention item #2 was originally written to fix.

* **The worker pool.** `PacketConn::enable_crypto_pool(n)` spins up
  `n` `crypto_worker` tasks, each owning one bounded mpsc queue.
  `write_to` hashes the destination key to a worker and hands it
  the pad + AEAD + envelope + route-and-dispatch work; on a
  multi-thread runtime the workers run on separate cores. Hashing
  by destination keeps every packet for one peer on one worker, so
  per-peer wire order is preserved and a peer's session mutex is
  never touched by two workers at once. A saturated queue falls
  back to inline encryption — the pool is a pure offload, never a
  packet drop.

Opt-in via `NodeConfig.crypto_workers` (default 0 = inline). A
sensible value is the physical core count. `Node::new` wires the
config field straight to `enable_crypto_pool`, so a `bifrost-vpnd`
operator turns it on from the `[node]` section of the TOML.

Verified for **correctness** by `crypto_worker_pool_preserves_order`
in `norn-rs/tests/integration.rs` (200 ordered messages through a
3-worker pool, asserted in submission order). The throughput uplift
can't be *measured* on the WSL2 / 50 Mbit testbed where crypto is a
rounding error — it's there for the ≥ 500 Mbit/s links where it
isn't. Measuring it is part of #4.

## 3. TUN GSO/GRO (`IFF_VNET_HDR` + `TUNSETOFFLOAD`) ✅ done

Status: **fully live in the data plane.** `bifrost-vpnd/src/tun_dev.rs`
replaces the `tun2` dependency with a hand-rolled `AsyncFd<OwnedFd>`
that opens `/dev/net/tun` with `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR`.
`tun2` is no longer in `bifrost-vpnd`'s dependency tree (the
mesh-only mode in norn-rs still uses it).

What's wired in:

* `OffloadTun::DEFAULT_OFFLOAD` enables `TUN_F_CSUM | TSO4 | TSO6 |
  USO4`. `try_enable_tun_offload` has a USO-aware retry: on kernels
  older than 6.0 that reject `USO4` it falls back to TSO-only
  rather than failing the ioctl. The startup log line shows what
  actually stuck.
* The kernel `virtio_net_hdr` is **10 bytes** (the basic layout).
  An early build assumed the 12-byte v1 layout and dropped every
  packet on the real-WAN test — trace logging showed the IPv4
  header starting at offset 10. The constant is now
  `VIRTIO_NET_HDR_LEN = 10`.
* `AsyncRead` / `AsyncWrite` pass the `[virtio_net_hdr | ip]` slab
  through **verbatim** — nothing stripped on read, nothing
  synthesised on write. The vhdr travels end-to-end across the
  mesh.
* GSO super-segments are **not** re-segmented in userspace. The
  whole `[vhdr | payload]` slab (up to ~64 KiB) rides one
  `Frame::Datagram`; `MAX_RELAYED_PACKET` was raised 16 KiB →
  60 KiB to fit it. The receiving exit writes the slab to its TUN
  verbatim and *its* kernel does the segmentation — the userspace
  re-segmenter the original plan called for turned out to be
  unnecessary.
* `EgressHello` was bumped v2 → v3: it now carries a
  `capabilities: u16` bitfield (`EGRESS_CAP_VNET_HDR`), so the
  vhdr-carrying wire format is used only when both ends advertise
  support. A mixed-version mesh degrades cleanly to plain-IP
  framing.
* MTU is set inline via `SIOCSIFMTU`.

Caveat: on WSL2 the kernel exposes a smaller offload-flag set than
mainline; the best-effort `TUNSETOFFLOAD` + USO retry cover this
transparently, so the WSL build still gets VNET_HDR framing without
hard-failing.

## 4. Hands-on CPU profile of the current bottleneck — **open**

The one backlog item that genuinely can't be closed on the current
testbed. Generic syscall / crypto / scheduling theory only goes so
far: a `perf record + flamegraph` of `bifrost-vpnd` under sustained
load (iperf3 across the TUN) on a quiet metro link would say
exactly where the next 10% of throughput goes — and would let #2's
worker pool finally be *measured* instead of just reasoned about.
On the WSL2 / 50 Mbit testbed the WAN ceiling masks all of it.

To run on a fresh metro box:

```bash
sudo apt install linux-tools-common linux-tools-$(uname -r) flamegraph
sudo perf record -F 199 -g -p $(pidof bifrost-vpnd) -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > vpnd-cpu.svg
```

Read the SVG with browser zoom — wide horizontal stacks are where
time goes.

## 5. Mobile clients (Android NDK, iOS) ✅ FFI shim landed

`bifrost-ffi/` is a workspace member producing both a `cdylib`
(`libbifrost_ffi.so` for Android jniLibs) and a `staticlib`
(`libbifrost_ffi.a` for an iOS xcframework). The C surface is
pinned in `bifrost-ffi/include/bifrost_ffi.h`:

* `bifrost_ffi_abi_version()` — gate against
  `BIFROST_FFI_ABI_VERSION` from the header at app launch.
* `bifrost_client_start(tun_fd, node_config_json, exit_pub_key_hex, out_handle)`
  — adopts a host-provided TUN fd (`dup(2)` + `CLOEXEC`), spins up
  a tokio multi-thread runtime, brings up the norn-rs Node,
  handshakes with the exit, and runs the same coalescing data
  plane desktop clients use.
* `bifrost_client_stop(handle)` — shuts the runtime down in the
  background; null-safe.
* `bifrost_last_error()` — thread-local string for the most recent
  failure.

To reuse the data plane without cloning the subtle coalescing
logic, `bifrost-vpnd::egress` exposes two public primitives —
`client_handshake(...)` and `run_client_pump<R, W>(...)` — and
`start_client` is a thin wrapper that adds `OffloadTun` opening +
`configure_client_kernel` around them. `bifrost-ffi` calls the
primitives directly with the host fd wrapped as a `HostTun`
(plain `AsyncFd<OwnedFd>`, no virtio framing — `VpnService` /
`NEPacketTunnelProvider`'s contract is per-packet IP).

`BUILD-MOBILE.md` has the cross-compile recipes for
`aarch64-linux-android`, `armv7-linux-androideabi`,
`aarch64-apple-ios`, `aarch64-apple-ios-sim`, plus Kotlin/Swift
glue and `xcframework` packaging. The actual Android Gradle /
Xcode app build is deliberately out of scope here — the shim is
the contract, the app is downstream.

Intentionally skipped (tracked in BUILD-MOBILE.md): virtio-net
framing on the host fd (bypassing `VpnService.Builder` disables
the system VPN status UI — not worth the throughput), and
platform log sinks (`tracing-android` / `tracing-oslog` are
unmaintained; hosts capture stderr instead).

## 6. Persistent crash-recovery for `bifrost-vpnd` leases ✅ done

`bifrost-vpnd/src/lease_store.rs` keeps `(peer_pubkey → lease)` in
a JSON v1 file that round-trips through `<path>.tmp + fsync +
rename(2)` so a power-cut mid-save can never truncate the prior
file (`save()` also `create_dir_all`s the parent so a fresh path
works first time). Enable it by setting
`exit.lease_persistence_path` in the TOML; empty (the default)
preserves v0.1 behaviour.

On startup `egress::start_exit` reads the file, calls
`AddressPool::reserve` for each host index so fresh allocations
never collide with sticky leases, and reinstates
`EgressTable::lease_of` so the first handshake from a returning
client resumes its previous IPv4/IPv6 pair without touching the
wire. Disconnect no longer releases the lease — sticky by default
— so a flapping client keeps its address across reconnects *and*
across exit restarts.

Eviction is no longer manual: `bifrost-ctl leases` lists the
sticky leases an exit holds and `bifrost-ctl evict-lease <pubkey>`
drops one, both over the vpnd admin socket (`admin.rs`,
`AdminRequest::Leases` / `EvictLease`). Auto-expiry by last-seen
is still a possible follow-up but isn't needed for the v0.1 use
case.

## 7. Transport obfuscation / DPI resistance

bifrost and norn-rs encrypt payloads but make no attempt to hide
*that the protocol is in use*. The mesh handshake and frame
framing have a fixed, recognisable shape, so a provider running
deep packet inspection can fingerprint it and block the TCP/UDP
flows between nodes. That's acceptable under the current threat
model (a passive observer who must not be able to *read* traffic)
but it rules bifrost out as a censorship-circumvention tool.

Scope of the work:

* A pluggable obfuscation layer *below* the mesh framing — length
  and inter-packet-timing padding toward a target distribution, or
  polymorphic framing that doesn't present a static signature.
* Optionally a pluggable-transport-style outer tunnel (TLS/HTTPS
  mimicry, or a shadowsocks-style wrapper) for the hardest
  networks.

Honest assessment: this is a large, adversarial, never-"done"
problem — DPI vendors adapt. It must be opt-in (it costs bandwidth
and latency) and should be scoped to "raise the cost of a trivial
block", **not** "defeat a nation-state firewall". Quinn's QUIC
transport (already wired for `quic://` URIs) is a partial help —
UDP/443 with a TLS-shaped handshake blends in better than raw TCP
— but it is not obfuscation.

## 8. Out-of-band key exchange UX

Two nodes that aren't on the same LAN (where mDNS discovers them
with no config) currently exchange identity by a human
copy-pasting a 64-hex-char ed25519 key. That's a hard wall for
non-technical users and a roadblock to anything past hobbyist
adoption.

Candidate improvements, smallest first:

* Render a key as a QR code and/or a BIP39-style word mnemonic so
  it can be transferred by phone camera or read aloud.
* A short-lived rendezvous token (a few words) that resolves to a
  full key via an introducer node.
* Optionally a name → key directory for nodes that *opt in* to
  being publicly addressable.

Each step trades a sliver of the "no central authority" property
for usability, so all of them stay opt-in — a paranoid operator
can keep copy-pasting hex.

## 9. Control-plane scaling past ~20k nodes

`norn-rs` keeps per-node state tiny (~2.5 MiB) by holding only
neighbours instead of a full routing table — but the control
plane still gossips: `ANNOUNCE` for the K=3 spanning trees,
cuckoo-filter generation rollovers, and `ReputationReport`. That
fixed-rate background chatter is negligible on the 30/100/300-node
docker clusters we test, but it grows with node count and would
start to crowd slow links somewhere in the low tens of thousands
of nodes. The network does not scale to global-internet size as-is.

Scope:

* Measure real per-node control overhead vs. cluster size — the
  docker harness can be pushed well past 300 to find the knee.
* Make announce / reputation cadence adaptive: back off in a
  stable neighbourhood, spend the budget where the topology is
  churning.
* Gossip suppression / aggregation so a report isn't re-flooded
  once a neighbourhood already agrees on it.

This is a "good problem to have" — it only bites at a scale the
network hasn't reached — so it sits last.

## What's *not* on the roadmap

* **Anonymity from the exit node.** Like any VPN — and unlike Tor
  — a `bifrost-vpnd` exit sees the client's destination IPs (and
  the plaintext, if the client isn't using TLS itself). The mesh
  hides the client's *location* from the destination and hides
  traffic from the *path*, but the exit operator is trusted by
  construction. Onion routing inside norn-rs mitigates this for
  mesh-internal traffic; for internet egress the answer is "run
  your own exit", not a protocol change.
* **Switching from TCP to UDP/QUIC as the primary mesh transport.**
  QUIC was measured on the same link (iter 7-8) and gives the same
  throughput as TCP — the WAN cap is identical regardless of
  transport. Quinn's QUIC *is* wired in `norn-rs` for `quic://`
  URIs, so operators with NAT-friendly preferences (UDP traversal,
  0-RTT resume) can opt into it; it just isn't the default because
  it doesn't speed anything up on real WAN.
* **Inline lz4/zstd compression on the wire.** Encrypted bytes are
  high-entropy by construction, so compression buys 0–2% on
  realistic traffic and adds a per-packet CPU tax that hurts far
  more than it helps.
