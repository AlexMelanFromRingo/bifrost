# Changelog

All notable changes to bifrost are documented here.

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
