# bifrost roadmap

Ordered by **expected throughput uplift on a non-WAN-limited link**
(e.g. datacenter / metro / 1 Gbit symmetric). On the current
real-WAN testbed (UA↔Oracle NL, ~50 Mbit/s aggregate cap),
several of these don't move the needle — the WAN is the
bottleneck, not bifrost. They're prerequisites for fast LANs and
inter-region cloud bonding where the WAN headroom is real.

## 1. `sendmmsg` batching in `norn-rs::transport` ✅ done in 0.7.0

Status: **landed** in `norn-rs::router::handle_conn` writer task
and `norn-rs::packet::write_frames_batched`.

The writer task now drains up to 32 sibling frames from its mpsc
channel with `try_recv()` after the blocking `recv().await`,
concatenates them into one `[varint_len][payload]…` buffer, and
ships the whole thing with one `write_all`. Functionally
equivalent to `sendmmsg(2)`: one syscall, one mio waker
round-trip per *batch* of frames instead of per frame. Three
new unit tests pin the wire format (`write_frames_batched_*`
in `src/packet.rs`).

`PacketConn::write_to_batch(payloads, dst)` exposes the same
pattern at the application API: encrypt + envelope N payloads
to the same peer under one round of session-manager mutex
acquisitions. Currently unused — wired in when an upper-layer
caller wants the amortisation (vpnd's coalesce path already
batches at a higher level, so doesn't need it).

Expected uplift on a Gbit+ link: 5-20%. On our 50 Mbit/s WAN
the writer was nowhere near syscall-bound, so no change in
the iter 11 bench (good — it confirms the change is safe).

## 2. Multi-core crypto worker pool

`norn-rs::router::PacketConn::write_to` currently encrypts inline
on the caller's task. ChaCha20-Poly1305 hits ~2 GB/s on modern
x86, so at 50 Mbit/s = 6 MB/s the crypto is 0.3% of one core —
not a bottleneck. **But at 10 Gbit/s = 1.25 GB/s, crypto would
occupy ~60% of one core**, gating throughput.

Plan: a per-PacketConn worker pool. Senders enqueue
`(payload, dst)` into a SPMC queue; N workers (one per physical
core, `num_cpus::get_physical()`) pull, encrypt, and forward to
the existing per-peer writer task. Pool is opt-in via
`NodeConfig.crypto_workers: u8` so single-core boxes don't pay
the queueing overhead.

Tricky bits: keep the per-session ChaCha20 state lock-friendly
(today it's behind one big `Mutex`; per-session would need
sharded locks or a `parking_lot::RwLock` per session entry).
Also: ordering on the receive side has to handle out-of-order
arrival from N workers (the per-peer ARQ already handles that
for streams, but `Frame::Datagram` doesn't, so VPN packets
might arrive out of order — usually fine, IP handles reorder).

Expected uplift: enables 10+ Gbit/s scenarios. No measurable
effect below ~500 Mbit/s.

## 3. TUN GSO/GRO (`IFF_VNET_HDR` + `TUNSETOFFLOAD`) ⏳ foundation landed

Status: **foundation in `bifrost-vpnd::tun_offload`**, not yet
wired into the live data plane.

What's there today:

* `VirtioNetHdr` type with `encode` / `decode` / `split`
  round-trip helpers and 7 unit tests pinning the wire layout
  against the kernel `include/uapi/linux/virtio_net.h` constants
  (`GSO_TCPV4`, `GSO_UDP`, `GSO_TCPV6`, `ECN_FLAG`, etc.).
* `try_enable_tun_offload(fd, flags)` — safe wrapper around the
  `TUNSETOFFLOAD` ioctl. Linux-only; stubs to
  `io::ErrorKind::Unsupported` elsewhere.
* `offload_flag::*` constants (`CSUM`, `TSO4`, `TSO6`, `USO4`,
  `USO6`) so callers don't have to look them up in
  `if_tun.h`.

What's not there yet:

* `bifrost-vpnd::egress` still opens the TUN device through
  `tun2`, which doesn't expose `IFF_VNET_HDR`. Even if we call
  `try_enable_tun_offload` on the resulting fd, the kernel
  refuses offload flags without `IFF_VNET_HDR`, so the read /
  write path stays at one-packet-per-syscall.
* Wiring needs either (a) replacing `tun2` with a hand-rolled
  `AsyncFd<File>` over the TUN, or (b) a fork / PR to `tun2`
  exposing the flag. Both are concrete follow-ups; the wire
  parser is already done and tested.

Expected uplift after wiring: VPN closes the gap with SOCKS5
throughput at multi-Gbit/s rates. WSL2 may not support
`IFF_VNET_HDR` — kernel-side virtio TUN offload is patchy in WSL,
so this is a "test on a native Linux host first" change.

## 4. Hands-on CPU profile of the current bottleneck

Generic syscall / crypto / scheduling theory only goes so far. A
`perf record + flamegraph` of `bifrost-vpnd` under sustained
load (e.g. iperf3 across the TUN) on a Linux box would say
exactly where the next 10% of throughput goes. Today on WSL2
the WAN ceiling masks this; on a quiet metro link the actual
software bottleneck would surface.

To run on a fresh metro box:

```bash
sudo apt install linux-tools-common linux-tools-$(uname -r) flamegraph
sudo perf record -F 199 -g -p $(pidof bifrost-vpnd) -- sleep 30
sudo perf script | stackcollapse-perf.pl | flamegraph.pl > vpnd-cpu.svg
```

Read the SVG with browser zoom — wide horizontal stacks are
where time goes.

## 5. Mobile clients (Android NDK, iOS)

Cross-compile bifrost-socks5d for `aarch64-linux-android` and
`aarch64-apple-ios`. Each platform has its own TUN integration
(`VpnService` on Android, `NEPacketTunnelProvider` on iOS), so
this needs a thin shim FFI layer wrapping `MeshMux` +
`bifrost-vpnd::egress::start_client`. Not a perf concern, just
a packaging one. Tracking issue:
<https://github.com/AlexMelanFromRingo/bifrost/issues> (not
filed yet).

## 6. Persistent crash-recovery for `bifrost-vpnd` leases ✅ done

`bifrost-vpnd/src/lease_store.rs` keeps `(peer_pubkey → lease)`
in a JSON v1 file that round-trips through `<path>.tmp +
fsync + rename(2)` so a power-cut mid-save can never truncate
the prior file. Enable it by setting `exit.lease_persistence_path`
in the TOML; empty (the default) preserves v0.1 behaviour.

On startup `egress::start_exit` reads the file, calls
`AddressPool::reserve` for each host index so fresh
allocations never collide with sticky leases, and reinstates
`EgressTable::lease_of` so the very first handshake from a
returning client resumes its previous IPv4/IPv6 pair without
touching the wire. Disconnect no longer releases the lease —
sticky-by-default — so a flapping TCP client gets the same
address across reconnects within a single exit lifetime *and*
across exit restarts.

Eviction is manual today (delete the file or future
`bifrost-ctl evict-lease`); auto-expiry by last-seen would be
a small follow-up but isn't needed for the v0.1 use case.

## What's *not* on the roadmap

* Switching from TCP to UDP/QUIC as the primary mesh transport.
  We measured QUIC on the same link (iter 7-8) and it gives the
  same throughput as TCP — the WAN cap is the same regardless
  of transport. Quinn's QUIC IS already wired in `norn-rs` for
  `quic://` URIs, so operators with NAT-friendly preferences
  (UDP traversal, 0-RTT resume) can opt into it; we don't make
  it the default because it doesn't speed anything up on real
  WAN.
* Inline lz4/zstd compression on the wire. Encrypted bytes are
  high-entropy by construction, so compression buys 0–2% on
  realistic traffic and adds a per-packet CPU tax that hurts
  far more than it helps.
