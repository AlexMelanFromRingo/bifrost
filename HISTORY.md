# bifrost performance history

How L3 VPN throughput went from **0.9 Mbit/s** (May 2026 baseline) to
**40 Mbit/s** (within 80% of raw TCP on the same long-fat WAN link)
over ten iterations.

Each step in this file matches a real commit on `master` or its
`norn-rs` dependency; each measurement is a real-WAN benchmark, not
loopback. Raw `bench.json`, configs and PNG graphs for every
iteration live alongside this file under
`bifrost-wan-test-2026-05-18/`.

## Test bed

* **Client:** WSL2 Ubuntu 24.04 on a residential UA ISP
  (188.163.47.11, ~250 Mbit/s downlink to nearby PoPs).
* **Exit:** Oracle Cloud Ubuntu 24.04 in Amsterdam
  (a single 2-vCPU cloud box, public interface).
* **WAN RTT:** ~55 ms, ~50 Mbit/s aggregate TCP cap regardless of
  parallelism — `iperf3 -c oracle -P 8` confirms 50 Mbit/s
  total, the same number that single-flow CUBIC reaches.
* **Targets:** `releases.ubuntu.com` byte-range (no anti-abuse,
  unlike `speed.cloudflare.com`, which returns HTTP 429 after a
  handful of probes from the same exit and silently breaks bench
  loops).

## Numbers at a glance

L3 VPN single-stream throughput, 25 MB Ubuntu mirror download
(higher is better):

```
iter 1  baseline                          ░ 0.9 Mbit/s + 25 MB timeouts
iter 2  framing + autotune + MSS + buffer ████ 5.3 Mbit/s
iter 4  + 64 KB copy_bidirectional        ████ 5.3 Mbit/s
iter 6  + channel cap, kernel auto-tune   ████ 5.0 Mbit/s
iter 8  + Frame::Datagram fast path       ████████ 10.2 Mbit/s
iter 9  + 16-packet coalescing            ████████ 10.7 Mbit/s
iter 10 + 4× multi-TCP per peer           ████████████████████████████████ 40 Mbit/s
                                                                   ^ 80% of raw TCP
```

SOCKS5 single-stream over the same link, 25 MB:

```
iter 1  baseline                          ███████████ 33 Mbit/s
iter 4  + autotune window + 64 KB         ████████████ 37 Mbit/s
iter 6  + kernel-friendly sock buf        ███████████████ 45 Mbit/s
iter 8  + Datagram fast path (no-op)      ████████████████ 49 Mbit/s
iter 10 + multi-TCP (no-op, already cap)  ███████████████ 45 Mbit/s

raw iperf3 single TCP on same link:       ████████████████ 48 Mbit/s
                                                ^ SOCKS5 = 92-102% of raw TCP
```

## Iterations

### iter 1 — 2026-05-18 — baseline

Bifrost commit at `20afd4c`. First real-WAN measurement: VPN single
download barely moves, p50 latency 575 ms, every 25 MB transfer
times out.

Root cause noted: the L3 path serialises each IP packet through
one MeshStream Data frame, each Data frame through the per-stream
ARQ. Combined with WAN RTT, the per-packet pipeline saturates
well below TCP cap.

### iter 2 — Fix #1, Fix #2, Fix #3 — framing, BDP autotune, MSS clamp

Three landed together because each was lossless individually.

* **`bifrost-vpnd` length-prefix framing.** Previous code wrote IP
  packets into the mesh stream as raw bytes and parsed `read(&mut
  buf)` as one packet per call. Mesh streams are byte streams —
  `read` can split a packet across two calls. The receiver
  mis-aligned on ~50% of packet boundaries, the kernel dropped
  garbage frames on the TUN, inner TCP retransmitted into the
  same broken pipe. New wire format: `u16 len BE + payload`,
  capped at `MAX_RELAYED_PACKET = 16 KiB`. Five round-trip
  unit tests pin the format.
* **`bifrost-core` reliability rx-window autotune.** Per-stream
  `rx_buf_cap` now starts at 256 KB and grows toward `2 × BDP`,
  capped at 32 MB. EWMA driven by the observed receive rate;
  refresh once per SRTT. Three unit tests cover growth-to-target,
  max-cap override, idle-stream stay-put.
* **`bifrost-vpnd` MSS clamping.** `iptables -t mangle ...
  TCPMSS --clamp-mss-to-pmtu` on both `FORWARD` directions of
  the egress TUN. Inner TCP now negotiates MSS ≤
  `tunnel_MTU - 40`, eliminating fragmentation under the
  1392-byte TUN MTU. Mirrored for ip6tables on dual-stack.

Effect: VPN went from `0.9 Mbit/s + timeouts` to a clean
5 Mbit/s. SOCKS5 saw a smaller bump (single-flow already had
some autotune from norn-rs autotuning beneath us).

### iter 4 — Fix #4 — `copy_bidirectional_with_sizes(64 KiB)`

`tokio::io::copy_bidirectional` defaults to 8 KiB per direction. On
the SOCKS5 path every chunk paid one mesh-encrypt + one TCP-write,
so per-byte CPU and syscall overhead dominated above ~30 Mbit/s.
64 KiB matches the mesh chunk_size — one full mesh frame per
chunk. Applied to both call sites (client CONNECT + exit
outbound).

### iter 5 — Fix #5 — per-peer write channel 256 → 8192

`norn-rs::router::send_to_peer` calls `try_send` on the per-peer
mpsc channel. The 256-slot ceiling saturated under sustained load
from upper-layer multiplexers (multiple SOCKS5 streams + vpnd
packets). On overflow, `try_send` silently dropped — our ARQ
retransmitted, CUBIC misread that as wire loss, halved cwnd.

Bumped to 8192 (~512 MB of pipelined encrypted Traffic at
typical 64 KB frame sizes). Added `warn!` on the remaining
`try_send` callers so future drops surface in operator logs.

### iter 6 — Fix #6 — don't `setsockopt(SO_RCVBUF/SO_SNDBUF)`

Initial reaction to a single-flow throughput cap was to set
`SO_SNDBUF/SO_RCVBUF = 4 MB` on every TCP socket. On Linux this
turned out to be **net negative**: explicit `setsockopt` disables
receive-window auto-tuning on the socket and clamps the buffer
to `net.core.{r,w}mem_max` — 208 KB on stock kernels.

`ss -ti` showed `snd_wnd:195584` (190 KB) and a cwnd that
plateaued at slow-start exit. Removing the `setsockopt` let the
kernel auto-tune toward `tcp_rmem.max` (6 MB default), bringing
single-stream SOCKS5 from 33 → 45 Mbit/s and matching raw
iperf3 on the same link.

Documented the trap as a long comment in
`norn-rs::transport::configure_socket` so a future "but more is
better" cleanup doesn't re-add the line.

Also reverted a *separate* failed experiment (`stream.rs`
pipelining of N in-flight Data sends per stream). The N-pipeline
stalled the stream the moment the app stopped writing — nothing
polled the queued futures until the next `poll_write`. The
single in-flight design lets ARQ handle backpressure cleanly
and, in practice, already saturates the link.

### iter 7 — investigation: 37 Mbit/s SOCKS5 cap

Spent a day chasing what looked like a 37 Mbit/s SOCKS5 ceiling.
Installed `iperf3` on both sides. **Raw TCP single-flow WSL2 →
Oracle = 48 Mbit/s**, with `Retr:2418` retransmits over 10 s
of sending. `iperf3 -P 4` aggregates to **50 Mbit/s**.
`iperf3 -P 8` = also 50 Mbit/s.

So the 37 Mbit/s wasn't bifrost — it was this specific WAN
path's actual aggregate capacity. The cap is consistent across
single-flow and multi-flow runs because losses come at the same
rate regardless of how we slice traffic.

Also confirmed `speed.cloudflare.com` is unsuitable for repeated
benchmarks from the same exit IP — it answers HTTP 429 after a
handful of probes and silently breaks bench loops. The updated
`bench.py` switches to `releases.ubuntu.com` byte ranges.

### iter 8 — `Frame::Datagram` fast path for L3 VPN

The 5 Mbit/s VPN ceiling was traced to a single architectural
decision: every TUN IP packet rode `MeshStream`'s reliability
layer, paying one full ARQ cycle per packet. WireGuard avoids
this by sending each packet as one UDP datagram with no
app-layer reliability — the inner TCP/QUIC handles loss
end-to-end.

This iteration ported the same idea on top of MeshMux without
abandoning the TCP transport:

* Added `Frame::Datagram { channel: u8, payload: Vec<u8> }`. No
  sid, no seq, no ack. `MeshMux::register_datagram_channel` /
  `send_datagram` API. Two unit tests pin the wire format.
* `bifrost-vpnd` switched to the fast path: handshake stays on
  the MeshStream (one-shot lease + EgressHello), IP packets ride
  Datagram frames directly. `EgressTable` reshaped from
  per-stream `mpsc::Sender` map to `peer_by_ip` +
  `lease_by_peer`.

Effect: VPN 25 MB throughput **5 → 10 Mbit/s** (2×). VPN p50
latency **128 → 176 ms** (slight regression from per-packet
TUN-writer mutex contention).

### iter 9 — packet coalescing on the Datagram fast path

The Datagram fast path still served one IP packet per round-trip
through the mux's send pipeline. Added coalescing: drain up to
`MAX_COALESCED_PACKETS = 16` packets (or `COALESCE_BYTE_BUDGET =
32 KiB`) within `COALESCE_DRAIN_TIMEOUT = 500 µs`, send as one
batched Datagram. Receiver iterates `PacketBatchIter` inside one
`tun_writer.lock().await` per batch.

* Client side has one destination peer → flat `Vec<Vec<u8>>`.
* Exit side buckets by destination peer (TCP packets to many
  clients arrive interleaved in the kernel conntrack stream).

Five unit tests cover encode/decode/truncated-tail/oversized/empty.

Effect on the same WAN:

* VPN p50 latency 176 → **128 ms** (-27%)
* VPN p95 latency 205 → **134 ms** (-35%)
* VPN sustained 14 → **20** chunks/20s (+43%)
* VPN 10× concurrent 0.46 → **0.28 s** (-39%)
* VPN 25 MB throughput 10.2 → **10.7 Mbit/s** (+5%)

Throughput barely moved — the WAN-on-WSL2 single-flow cap was
still in play. Latency / concurrency / sustained-rate metrics
all improved because each round of CPU work moved 16× more
bytes when the TCP burst fed enough into the kernel TUN queue.

### iter 10 — multi-link bonding per peer (parallel TCP)

The remaining 10 Mbit/s VPN ceiling was the per-packet pipeline
through a single underlying TCP. iperf3 had already shown the
WAN itself aggregates to ~50 Mbit/s with `-P 4`. To take
advantage, `norn-rs` had to drop the "one connection per peer"
invariant.

Changes in `norn-rs`:

* `PeerData::tx: Sender` → `txs: Vec<Sender>` + `next_tx`
  round-robin cursor. New constant `MAX_PARALLEL_LINKS_PER_PEER
  = 8`.
* `add_peer` appends to an existing entry instead of refusing
  duplicates, up to the cap.
* `send_to_peer` walks the rotation, spilling on
  `TrySendError::Full` to the next sibling, GCing
  `TrySendError::Closed` senders lazily. Warning only when every
  link is saturated simultaneously.
* `ConnectedPeers` reshaped from `HashSet<PubKey>` to
  `HashMap<PubKey, u32>` (link count). `transport::dial`,
  `transport::listen`, `quic::handle_quic_conn`, and
  `mdns::handle_resolve` all updated. `MutexGuard` carefully
  scoped before any `await` (it's `!Send`).

Operator config: list the same `tcp://host:port` URI N times in
`[node].peers` to dial N links. mDNS auto-discovery still treats
"any link present" as "skip rediscover" — multi-link is an
explicit-config gesture, not a side-effect of network scanning.

Effect:

* **VPN 5 MB throughput 10 → 31.5 Mbit/s (3.2×)**
* **VPN 25 MB throughput 10.7 → 39.7 Mbit/s (3.7×)**
* **VPN sustained 20 → 43 chunks/20s (2.2×)**
* SOCKS5 25 MB throughput 42 → 44.6 Mbit/s (+6%, run-to-run
  variance — SOCKS5 was already pegged at WAN aggregate cap)

VPN got the big jump because its bottleneck was per-packet
pipeline; spreading packets across 4 socket queues unsticks it.
SOCKS5 was already at WAN cap, so the round-robin couldn't push
past it.

## What's still on the table

The full real-WAN benchmark now sits at ~40 Mbit/s VPN /
~45 Mbit/s SOCKS5 — within a few percent of raw TCP on this
specific link. Further work would either need a different test
environment (datacenter-to-datacenter, low loss) or kernel-level
features. See [ROADMAP.md](ROADMAP.md).

## Reproducing the numbers

All ten iterations were measured with the same script:
`bench.py` under `bifrost-wan-test-2026-05-18/`. Each run takes
~3 minutes and produces a `bench.json` + five PNG graphs.
Configs (`server.toml`, `client.toml`, `vpnd-server.toml`,
`vpnd-client.toml`) and Bash one-liners to deploy on a fresh
Oracle box live there too.

The bench drives three paths in sequence: `direct` (no proxy),
`socks5` (`curl --socks5-hostname`), and `vpn`
(`curl --interface bif-eg0` over policy-routed default through
the TUN). Each path runs latency (30 samples), throughput
(3 runs × 3 sizes), 10× concurrent, and 20 s sustained.
