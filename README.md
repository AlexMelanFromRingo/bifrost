# bifrost

**SOCKS5 proxy + TUN-based VPN over a [norn-rs](https://github.com/AlexMelanFromRingo/norn-rs)
overlay mesh.** Every byte of application traffic rides an end-to-end encrypted
mesh stream between mutually-authenticated peers, with sliding-window ARQ so
the same stream survives multi-hop relays and packet loss.

> 🇷🇺 [Русская версия](README.ru.md)

---

## TL;DR

```text
                                ┌────────────────────────────────┐
                                │  bifrost-vpnd  exit mode       │
┌────────────────────┐          │  ┌───────────┐   ┌──────────┐  │
│  bifrost-vpnd      │          │  │ MeshMux   │──▶│ TUN+NAT  │──▶ Internet
│   client mode      │   norn   │  │ + ARQ     │   │ MASQUER. │  │
│ ┌────┐ ┌────────┐  ├─────────▶│  └───────────┘   └──────────┘  │
│ │ TUN│─│MeshMux │  │  mesh    └────────────────────────────────┘
│ └────┘ └────────┘  │
└────────────────────┘
```

* **`bifrost-socks5d`** — SOCKS5 v5 proxy that tunnels every CONNECT through a
  mesh peer. Two modes (`client`, `exit`) in one binary.
* **`bifrost-vpnd`** — TUN-based VPN. Three modes (`mesh`, `exit`, `client`):
  exit nodes assign IPv4 leases out of a private subnet and MASQUERADE
  outbound traffic; client nodes get one address each and tunnel all (or
  selected) packets through a chosen exit.

Both share **`bifrost-core`** — frame codec, MeshMux demultiplexer, MeshStream
(AsyncRead + AsyncWrite over a best-effort mesh datagram), and the sliding-
window ARQ that lifts the underlying datagram channel into a reliable byte
stream.

---

## Status

| Component                  | State    | Tested with                          |
|----------------------------|----------|--------------------------------------|
| Frame codec v2             | ✅ done  | 7 roundtrip + reject tests           |
| Reliability layer (ARQ)    | ✅ done  | 13 unit tests, multi-hop docker e2e  |
| `bifrost-socks5d` client   | ✅ done  | local + docker e2e (1 MB, sha256)    |
| `bifrost-socks5d` exit     | ✅ done  | docker e2e w/ NetEm 30 ms / 1 % loss |
| `bifrost-vpnd` mesh        | ✅ v0.1  | norn-rs `tun-support`                |
| `bifrost-vpnd` exit (NAT)  | ✅ done  | docker e2e w/ NetEm; SHA-256 match   |
| `bifrost-vpnd` client      | ✅ done  | docker e2e                           |
| IPv6 egress (NAT66)        | ✅ done  | 4 unit tests; dual-stack EgressHello |
| Karn/Partridge SRTT/RTTVAR | ✅ done  | RFC 6298; 5 unit tests               |
| Trust-weighted exit pick   | ✅ done  | `EgressPolicy::Auto`; 8 unit tests   |
| Mobile build (Android/iOS) | ⏸ later | x86_64 + aarch64 Linux only          |
| Multi-exit per stream      | ⏸ later | selective forwarding                 |
| Native exit discovery      | ⏸ later | Auto reads from a config list today  |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│ Application                                                         │
│  (curl, browser, ssh, etc.)                                         │
├─────────────────────────────────────────────────────────────────────┤
│ kernel TCP / SOCKS5 socket / TUN device                             │
├─────────────────────────────────────────────────────────────────────┤
│ bifrost-socks5d  │  bifrost-vpnd                                    │
│  (SOCKS5 server) │   (TUN reader + writer + egress NAT)             │
├─────────────────────────────────────────────────────────────────────┤
│ bifrost-core                                                        │
│  MeshStream  (AsyncRead + AsyncWrite, MTU-chunked Data frames)      │
│  reliability (per-stream seq + cumulative ACK + retransmit tick)    │
│  MeshMux     (one read loop demuxes (peer, stream_id) → channel)    │
├─────────────────────────────────────────────────────────────────────┤
│ norn-rs PacketConn                                                  │
│  best-effort datagram channel addressed by 32-byte ed25519 pub key  │
│  hop-by-hop ChaCha20-Poly1305 sessions, K=3 spanning-tree routing   │
└─────────────────────────────────────────────────────────────────────┘
```

`bifrost-core` is intentionally thin: it doesn't know about SOCKS5 or VPN, it
just turns a lossy mesh datagram into a reliable byte stream. The two daemons
sit on top.

---

## Build

```sh
# Requires Rust 1.85+ (norn-rs needs 1.88 for rcgen, the test image pins 1.90).
git clone https://github.com/AlexMelanFromRingo/bifrost
cd bifrost
cargo build --release --workspace
```

Binaries land in `target/release/bifrost-socks5d` and `target/release/bifrost-vpnd`.
The VPN daemon needs the `tun` feature (on by default):

```sh
cargo build --release -p bifrost-vpnd --features tun
```

The crate path-depends on `../norn-rs`, so clone them as siblings:

```text
~/code/
├── norn-rs/      # https://github.com/AlexMelanFromRingo/norn-rs
└── bifrost/      # this repo
```

---

## Quick start: SOCKS5 lab

Two nodes on one machine — exit and client.

```sh
# 1. Generate the exit config (private key, listen address, etc.)
./target/release/bifrost-socks5d genconfig --exit > exit.toml
chmod 600 exit.toml

# 2. Tweak exit.toml: listen, admin_socket, tun_name (optional).
# Then start the exit:
RUST_LOG=info ./target/release/bifrost-socks5d run -c exit.toml
```

The exit's log prints its pub key (`our pub_key=…`). Copy it.

```sh
# 3. Generate the client config and wire in the exit's pub key.
./target/release/bifrost-socks5d genconfig > client.toml
chmod 600 client.toml

# Edit client.toml:
#   socks5_listen = "127.0.0.1:1080"
#   [node] peers = ["tcp://<exit-host>:9001"]
#   [egress]
#   mode = "exit"
#   exits = [
#     { pub_key = "<exit-pub-key-hex>", tag = "primary" },
#   ]

RUST_LOG=info ./target/release/bifrost-socks5d run -c client.toml
```

Test it:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

The CONNECT is encrypted end-to-end across the mesh; the exit's outbound IP
appears at the target.

---

## Quick start: VPN lab

Three nodes — exit (does NAT), client (gets a lease), and whatever real
service you want to reach. **CAP_NET_ADMIN is required on both daemons** to
create TUN devices and rewrite iptables; on bare metal run as root or grant
the binary the capability:

```sh
sudo setcap cap_net_admin+ep ./target/release/bifrost-vpnd
```

```sh
# ── exit side ──
./target/release/bifrost-vpnd genconfig --exit > exit.toml
chmod 600 exit.toml
# Defaults: pool 10.55.0.0/24, egress_iface eth0, tun bifrost-eg0.
# Edit if your egress interface isn't eth0.
RUST_LOG=info ./target/release/bifrost-vpnd run -c exit.toml
# Copy "our pub_key=..." from the log.

# ── client side ──
./target/release/bifrost-vpnd genconfig --client > client.toml
chmod 600 client.toml
# Edit client.toml:
#   [node] peers = ["tcp://<exit-host>:9001"]
#   [egress] mode = "exit"
#            exits = [{ pub_key = "<exit-pub-key-hex>", tag = "main" }]
#   [client] install_default_route = true   # hijack default route
RUST_LOG=info ./target/release/bifrost-vpnd run -c client.toml
```

The client gets an IPv4 lease (default `10.55.0.2`+) and a default route
pointing at the exit's TUN. Every IPv4 packet to a destination outside the
egress subnet is wrapped in a mesh frame, sent to the exit, written to the
exit's TUN, NAT'd by the kernel, and dropped on the wire from the exit's
public interface. Responses retrace the path automatically (Linux conntrack
handles the reverse NAT; bifrost handles the reverse mesh routing via the
allocated address).

---

## Configuration reference

All configs are TOML and **must be `chmod 600`** — they hold the node's
ed25519 private key. The daemons refuse to load anything more permissive.

Common `[node]` fields (shared with `norn-rs`):

| Field                    | Meaning                                                |
|--------------------------|--------------------------------------------------------|
| `private_key`            | 64 hex chars = 32-byte ed25519 secret. Generate fresh. |
| `listen`                 | List of `tcp://addr:port` URIs to accept peers on.     |
| `peers`                  | List of `tcp://addr:port` URIs to dial at startup.     |
| `tun_name`               | mesh-only TUN name (e.g. `"norn0"`); auto-disabled by `bifrost-vpnd` exit/client modes. |
| `admin_socket`           | UNIX socket path for `nornctl`-style admin commands.   |
| `multicast_enabled`      | UDP multicast peer discovery on LAN.                   |
| `mdns_enabled`           | mDNS / DNS-SD peer discovery (`_norn._tcp.local`).     |
| `metrics_addr`           | `host:port` for the Prometheus `/metrics` endpoint.    |
| `min_peer_difficulty_bits` | Sybil-resistance threshold. 0 = off.                 |

`bifrost-socks5d`-specific:

```toml
mode = "client"                    # or "exit"
socks5_listen = "127.0.0.1:1080"   # client mode only

[egress]
mode = "exit"                      # "exit" round-robin, "auto" weighted,
                                   # or "mesh" (no egress, 0200::/7 only)
exits = [
  { pub_key = "abcd...32 bytes hex", tag = "primary" },
  { pub_key = "ef01...32 bytes hex", tag = "backup" },
]
```

**`auto`** uses `Weight = Trust / (RTT_ms + Penalty_ms + 1)` to pick
an exit. Trust + RTT come from norn-rs's live PeerStats (refreshed
every 10 s). A failed CONNECT injects a +1 s penalty on that exit
for 2 minutes so flaky peers self-deprioritise. Selection isn't
deterministic: a weighted-random draw over the top 5 spreads load
to prevent every client herding onto the same low-RTT exit at once.

`bifrost-vpnd`-specific (exit mode):

```toml
mode = "exit"

[exit]
tun_name       = "bifrost-eg0"
pool_base      = "10.55.0.0"
pool_prefix    = 24                # /24 = 253 leases (gateway + broadcast reserved)
egress_iface   = "eth0"            # interface that gets MASQUERADE'd
# Optional dual-stack: each client gets paired v4 + v6 leases. Host
# index 2 in /24 maps to host index 2 in /64, so the same client has
# matching addresses on both stacks. Omit v6_pool_base for v4-only.
# v6_pool_base   = "fd55:0:0:1::"
# v6_pool_prefix = 64
```

`bifrost-vpnd`-specific (client mode):

```toml
mode = "client"

[client]
tun_name              = "bifrost-eg0"
install_default_route = true        # off by default; opt-in
```

See `examples/*.toml` for ready-to-edit templates.

---

## Docker testbeds

Two end-to-end harnesses live under `tests/docker/`:

```sh
# SOCKS5 e2e: 3 services (exit + client + httpd target), NetEm 30 ms±5 ms /
# 1 % loss applied per-container, 1 MiB download with SHA-256 cross-check.
bash tests/docker/run.sh

# VPN e2e: same 3-service topology, exit runs the egress TUN + MASQUERADE,
# client gets an IPv4 lease, curl runs INSIDE the client container and the
# script asserts that target sees the EXIT's eth0 IP (NAT proven).
bash tests/docker/run-vpn.sh
```

Both scripts handle the two-phase startup (bring the exit up first, scrape
its pub key, then start client/target with the env wired in) and tear the
cluster down on exit. Set `BIFROST_KEEP=1` to leave the cluster running for
inspection:

```sh
BIFROST_KEEP=1 bash tests/docker/run-vpn.sh
docker logs bifrost-vpn-client
docker exec bifrost-vpn-client ip route
# When done:
cd tests/docker && BIFROST_EXIT_PUBKEY=00 docker compose -f docker-compose.vpn.yml down -v
```

Latest measurements (debug-cluster, ARM/x86_64 mix):

| Probe                                  | Time   | Throughput |
|----------------------------------------|--------|------------|
| 1 MiB SOCKS5, no NetEm (loopback)      | 0.17 s | ~24 MB/s   |
| 1 MiB SOCKS5, NetEm 30 ms±5 ms / 1 %   | 3.0 s  | ~340 KB/s  |
| 256 KiB VPN, NetEm 30 ms±5 ms / 1 %    | ~1 s   | ~250 KB/s  |

---

## Wire protocol (v2)

```
┌───────┬───────┬──────────────┬────────────────────────────────┐
│  ver  │ kind  │  stream_id   │     body (variable)            │
│  1 B  │  1 B  │ 4 B big-end. │                                │
└───────┴───────┴──────────────┴────────────────────────────────┘
```

| Kind | Hex  | Body                                                                |
|------|------|---------------------------------------------------------------------|
| Open | 0x01 | ATYP (0x01 v4 / 0x03 domain / 0x04 v6 / 0xfe egress) + addr + port  |
| Data | 0x02 | `seq` (4 B) + payload                                                |
| Close| 0x03 | `seq` (4 B) — position of the FIN byte                              |
| Reset| 0x04 | 1-byte code                                                          |
| OpenAck | 0x05 | 1-byte reply code (mirrors SOCKS5 REP)                           |
| Ack  | 0x06 | `ack` (4 B) + `win` (4 B) — cumulative ACK + advertised window      |

The reliability layer treats Data and Close as a single sequence space
(Close occupies one virtual byte) so a peer ACK strictly past `local_close_seq`
proves the FIN was delivered. Lost Closes are retransmitted with the same
RTO-doubling back-off as Data — no silent half-open streams.

---

## Security model

What this protocol protects:

* **End-to-end confidentiality + integrity** between the two endpoints of a
  mesh stream. Every byte rides ChaCha20-Poly1305 sessions in norn-rs; relays
  on the path see only ciphertext-with-routing-tag, never plaintext.
* **Peer authentication**: every mesh hop is an authenticated handshake bound
  to the peer's ed25519 pub key. Forged peers are detected at session setup,
  not after data has leaked.
* **Replay & reorder resistance** at the mesh layer (norn-rs sessions carry
  sequence numbers) and at the bifrost layer (per-stream seq + cumulative
  ACK rejects duplicates and reassembles in order).

What this protocol does **not** protect:

* **Traffic analysis**. Frame sizes are MTU-padded inside norn-rs but the
  shape of an HTTP request is still visible on the local wire. Use Tor for
  anonymity-grade protection.
* **Malicious exits**. An exit operator sees decrypted application traffic
  on the way out (it's a SOCKS5 / NAT'd packet, not a black box). Choose
  exits you trust; use TLS end-to-end (HTTPS) so even a hostile exit only
  sees ciphertext.
* **DoS resistance under flood**. Bifrost inherits norn-rs's per-IP
  handshake throttle but doesn't add its own. A flooded exit will drop
  CONNECTs gracefully but won't black-hole the attacker.

---

## Roadmap

* Multi-exit per stream (selective forwarding)
* Native exit discovery — Auto reads from a config list today; the
  next step is a `_bifrost-exit._norn` mDNS service that exit
  daemons advertise so clients pick them up automatically.
* Android NDK / iOS cross-builds for mobile clients
* `bifrost-ctl` admin CLI on the UNIX admin socket
* Prometheus exporter for the ScoredExitPool snapshot
  (weight, trust, RTT, penalty per candidate)

---

## License

MIT. See [LICENSE](LICENSE).
