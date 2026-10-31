# Changelog

All notable changes to bifrost are documented here.

## v0.2.2 — 2026-10-31

- **Evicted lease quarantine.** Operator `EvictLease` returned the address
  to the pool before the conntrack flush ran, so a new client could be
  handed it (and the old owner's flows) in between. The slot now goes back
  to the pool only after the flush completes.

## v0.2.1 — 2026-10-31

Fixes from an automated security review of v0.2.0. No wire changes; one new
config key (`[exit] reclaim_min_idle_secs`, vpnd).

### Security
- **Exit destination filter — IPv6 transition prefixes (SSRF):** only the
  well-known NAT64 prefix `64:ff9b::/96` was caught. The local-use NAT64
  prefix `64:ff9b:1::/48` (RFC 8215; its IPv4 embedding offset is
  deployment-specific) is now blocked outright, and IPv4-compatible
  `::a.b.c.d` / IPv4-translated `::ffff:0:a.b.c.d` are judged by their
  embedded IPv4 like IPv4-mapped already was. The whole "this network"
  `0.0.0.0/8` is always blocked (was only `0.0.0.0`). Shared by both exits.
- **Exit destination filter — the exit's own addresses:** a client could
  reach services bound on the exit host via its public / LAN IPs. Both exits
  (`bifrost-socks5d`, `bifrost-vpnd`) now enumerate their interface addresses
  (`getifaddrs`) at startup — failing fast if they can't — and every 60 s
  after, and always block them (not overridable by `dst_allow`). vpnd also
  re-enumerates right after configuring the egress TUN. New injectable API:
  `DstFilter::with_local_addrs` / `set_local_addrs` / `refresh_local_addrs` /
  `spawn_local_addr_refresh` (clones share the set).
- **vpnd client route install:** the lease route was installed with `ip route
  replace`, silently overwriting e.g. the client's own LAN or docker route
  when an exit handed out an overlapping (private) subnet. The client now
  refuses a lease subnet overlapping any existing route or interface address
  not on its TUN (default routes ignored; checked via `ip -j`, fails closed),
  and uses `ip route add` — EEXIST is accepted only when every route for that
  exact subnet is already on the bifrost TUN.
- **vpnd lease reclamation reuse:** a reclaimed address went straight to the
  next client, which inherited the previous owner's conntrack / NAT state and
  in-flight replies. A full pool now only reclaims leases idle for at least
  `[exit] reclaim_min_idle_secs` (default 600; otherwise the newcomer is
  refused), and flushes the old address's conntrack entries on reclaim
  (`conntrack -D -s/-d`, best-effort; skipped at debug level if the tool is
  missing).
- Teredo `2001::/32` (embeds an IPv4) is now blocked like 6to4 / NAT64.
- Operator `EvictLease` flushes the evicted lease's conntrack state too.
- Dependencies updated (`cargo update`): quinn-proto, rustls, rustls-webpki,
  tokio and others carrying RUSTSEC advisories; norn-rs 0.13.1.

## v0.2.0 — 2026-10-31

Two hardening passes, built on **norn-rs v0.13.0** (a flag-day wire change in
the mesh layer: bifrost 0.2 nodes only talk to norn 0.13 meshes). bifrost's
own frames are unchanged. Config additions are backward compatible (new keys
default to the previous behaviour, except where a default was itself the
problem — noted below); the lease-store JSON gains an optional `last_active`
field (old files still load).

### Ops
- Example configs and `bifrost-ctl` default to admin sockets under
  `/run/bifrost/` (created `0700` when missing) instead of `/tmp`.
- vpnd keeps running without its admin socket if it can't bind it (warning).
- "Libraries worth studying" note (Reticulum, rust-libp2p, iroh) in README /
  ROADMAP.

### Security
- **socks5d exit (SSRF / open proxy):** the exit now resolves each CONNECT
  target and vets *every* resolved address against the shared destination
  filter (now in `bifrost_core::dst_filter`) before dialing a vetted
  `SocketAddr` — no second resolution, so DNS rebinding can't swap one in.
  Loopback / link-local / cloud metadata / multicast are always refused,
  RFC1918 / CGNAT / ULA by default (`[exit] block_private_dst`, `dst_allow`,
  `dst_deny`, mirroring vpnd).
- **vpnd exit admission (lease-pool Sybil):** any ed25519 key that sent
  `Open(Egress)` got a sticky, persisted lease, so ~253 throwaway identities
  exhausted the default /24 for good. New `[exit] allowed_clients` (hex
  pubkeys; empty = open, with a startup warning) and `min_client_pow_bits`
  (norn's `key_difficulty_bits` measure). Refused peers get `NOT_ALLOWED`;
  persisted leases of no-longer-admitted keys are dropped at startup.
- **vpnd lease reclamation:** a full pool now reclaims the least-recently-
  active lease that has no live egress session and whose peer isn't
  connected (never a live one; all live → refuse). Per-lease last activity is
  persisted so the order survives restarts. Previously `allocate()` just
  returned `None` despite the docs claiming reclamation.
- **vpnd client route hijack:** `EgressHello::validate` now requires the
  gateway to sit inside the lease subnet (not equal to the lease, neither on
  the network/broadcast address) and that subnet to lie in RFC1918 /
  CGNAT 100.64/10 / ULA fc00::/7, unless `[client] allowed_lease_cidrs`
  explicitly covers it. A malicious exit could otherwise make a split-tunnel
  client `ip route replace` an arbitrary public /16 into the tunnel. Client
  routes are derived from the leased address, not the exit-chosen gateway.
- **socks5d mDNS exit trust:** in Auto mode any LAN host advertising any key
  became an exit candidate (and, with `race_exits = 3`, saw CONNECT targets).
  Discovered exits are now used only if listed in `[bifrost] trusted_exits`
  or with the explicit `mdns_trust_any = true` opt-in (default false — the
  browser isn't started otherwise); discovered candidates are capped
  (`mdns_max_exits`, default 16); an mDNS `ServiceRemoved` can no longer evict
  a statically configured exit.
- **vpnd admin socket:** default moved from predictable `/tmp/bifrost-vpnd-*.sock`
  to `/run/bifrost/vpnd-{exit,client}.sock`; a missing directory is created
  `0700` and the socket chmod'ed `0600` instead of flipping the process-global
  umask in a multithreaded runtime; request lines are capped at 64 KiB (as in
  socks5d). Failure to bind is now a warning, not a fatal startup error.

### Correctness / DoS
- **mux freeze:** inbound `Open`s are queued with `try_send` and refused with
  a `Reset` when the acceptor is backlogged or absent (client / mesh modes now
  drop the receiver) — 65 Opens from any peer used to wedge the read loop for
  every stream. OpenAck / Reset are latched per stream so a full event channel
  can't block demux or lose them; a reconnecting peer reusing a live sid
  retires the orphaned stream instead of colliding forever.
- **lost wakeups:** `poll_write` on a closed window re-checks a Reset/close it
  drained from the event channel instead of returning `Pending` forever.
- **zero-window persist:** a sender stalled on a peer-advertised zero window
  now sends persist probes (empty Data frames) so a lost window update can't
  stall the stream permanently.
- **datagram stall:** `send_datagram` is a single non-waiting attempt; one
  offline client could previously park the exit's shared TUN-reader for up to
  60 s and stall downlink for everyone.
- **vhdr EINVAL:** client-supplied `virtio_net_hdr`s the kernel would reject
  are dropped per packet (`slot_vhdr_is_sane`) instead of surfacing as errors
  on the shared TUN writer; TUN write errors are per-packet and never end the
  pump.
- **unbounded `read_to_end`:** the egress control stream is drained through a
  fixed buffer (`drain_to_eof`) — a peer could stream unbounded data into exit
  / client memory.
- **lease race:** lookup-or-allocate is one atomic step
  (`lease_lookup_or_allocate`); two concurrent `Open(Egress)` from one peer
  used to both allocate and leak a slot.
- **lease rollback race:** a failed handshake's rollback could free a lease a
  concurrent handshake from the same peer was still using. Leases now carry a
  live-session refcount and a generation; rollback drops only its own
  reference and frees the slot only if it allocated it and nobody joined
  (stale sessions are no-ops). A cancelled handshake task releases its
  reference via `Drop`.

## v0.1.1 — hardening

First tagged release. A full adversarial study of the data plane (notes in the
parent repo's `REVIEW-FINDINGS.md`) found the codebase well-hardened — bifrost-core
has no crypto of its own (it rides norn-rs's audited sessions), parsing is
defensively bounded, and the prior fixes (egress vhdr-only DoS, vhdr GSO panic,
4 GiB reliability wrap) held up. Seven additional findings, all LOW–MED and either
edge-cases or within the documented non-goals (DoS-resistance / traffic-analysis /
malicious-exit), are fixed here. No wire-format or API change.

### Security / correctness
- **reliability:** the reorder buffer now drains by exact sequence key
  (`remove(&expected_seq)`) instead of `BTreeMap::iter().next()` + `==`, which
  returned the wrong entry once the 32-bit byte-sequence space wrapped (~4 GiB
  into a stream) — a contiguous frame could stall until retransmit. Sibling of the
  earlier wrap fixes.
- **dst_filter (SSRF):** IPv4-mapped IPv6 destinations (`::ffff:a.b.c.d`) are now
  normalised to the embedded IPv4 so the v4 always-blocked / private rules apply,
  and the 6to4 (`2002::/16`) and NAT64 (`64:ff9b::/96`) embed ranges are blocked —
  closing a path that could reach `127.0.0.1` / `169.254.169.254` / RFC1918 via an
  IPv6 destination the v6-only checks missed.
- **egress:** the client now validates the exit-supplied `EgressHello` (lease
  prefix ranges, non-degenerate addresses, plausible MTU) before configuring its
  kernel TUN / routes — an untrusted exit can no longer feed an out-of-range prefix
  into the CIDR shift math or a zero MTU.

### DoS hardening (within the documented "drop gracefully" posture)
- **mux:** a per-peer concurrent-stream cap (1024) refuses excess `Open` frames
  with a `Reset` instead of growing the stream table unbounded; fire-and-forget
  control-frame sends (ACK / Reset) are now bounded by a semaphore (dropped when
  exhausted — cumulative ACKs self-heal). Data retransmits are unaffected.
- **vhdr:** GSO desegmentation caps the produced segment count (128); a hostile
  `gso_size = 1` can no longer explode one slot into thousands of packets.
- **reliability:** local unacked (send) buffering is capped at 32 MiB independent
  of the peer-advertised window (which is attacker-controlled via ACKs).

All crates: `cargo test --workspace` green, `clippy --workspace` clean.
