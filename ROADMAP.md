# bifrost roadmap

Ordered by **expected throughput uplift on a non-WAN-limited link**
(e.g. datacenter / metro / 1 Gbit symmetric). On the current
real-WAN testbed (UA↔Oracle NL, ~50 Mbit/s aggregate cap),
several of these don't move the needle — the WAN is the
bottleneck, not bifrost. They're prerequisites for fast LANs and
inter-region cloud bonding where the WAN headroom is real.

## 1. `sendmmsg` batching in `norn-rs::transport`

Today every encrypted Traffic frame is one `tcp.write_all(buf)`
syscall on the writer task. At 50 Mbit/s and 64 KB frames that's
~100 syscalls/s — fine. At 1 Gbit/s with 1400-byte vpnd packets
that becomes ~90 k syscalls/s, and per-syscall overhead starts to
show up in `perf`.

Linux's `sendmmsg(2)` accepts an array of buffers and submits
them in one syscall. The writer task could drain its mpsc channel
until empty or up to a budget, then issue one `sendmmsg`. tokio
exposes `tokio::net::UdpSocket::send_mmsg` for UDP; for the TCP
path we'd use raw `libc::sendmmsg` via `AsRawFd`.

Expected uplift: 5-20% on Gbit links, near-zero on our 50 Mbit/s
WAN.

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

## 3. TUN GSO/GRO (`IFF_VNET_HDR` + `TUNSETOFFLOAD`)

Today vpnd reads one IP packet per `tun.read()` syscall. With
`IFF_VNET_HDR`, the kernel can hand us multiple packets in one
read as a "super-packet" prefixed by a `virtio_net_hdr`, and we
can write super-packets back the same way. This is the same
mechanism WireGuard uses on Linux to hit 1+ Gbit/s on a single
core.

Requires patching the `tun2` crate (or replacing it with raw
`AsyncFd<File>` on the TUN fd plus our own ioctl wrappers) to
expose the flag. Then `bifrost-vpnd::egress` would issue
`recvmsg` with `MSG_TRUNC` and parse the virtio header to find
the per-segment lengths.

Expected uplift on a real Linux host: VPN closes the gap with
SOCKS5 throughput at multi-Gbit/s rates. WSL2 may not support
this — kernel-side virtio TUN offload is patchy in WSL.

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

## 6. Persistent crash-recovery for `bifrost-vpnd` leases

Today an exit's address pool is in-memory only; restart hands
out the same `.2 .3 .4 ...` slots and a returning client
might land on a different IP. Persisting `lease_by_peer` to
disk (via `bifrost-ctl reload`'s mechanism) would keep
client-side state stable across exit reboots.

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
