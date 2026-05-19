//! Linux TUN GSO/GRO offload — foundation pieces for kernel-side
//! packet segmentation aggregation.
//!
//! ## What this is for
//!
//! Without offload, every IP packet that crosses the TUN device
//! costs one `read(2)` / `write(2)` syscall. At gigabit line
//! rates with 1500-byte MTU that's ~85k syscalls/s per direction,
//! which is where `perf` ends up dominated by kernel-mode work
//! (`__libc_write` + `mio::Waker::wake` were 30% of bifrost-socks5d's
//! user-mode samples even at our 50 Mbit/s ceiling — see
//! `bifrost-wan-test-2026-05-18/perf-findings-iter11.md`).
//!
//! Linux's TUN device supports two related offload mechanisms:
//!
//! * **`IFF_VNET_HDR`** — every read/write is prefixed by a
//!   12-byte `virtio_net_hdr_v1` struct that describes the
//!   payload (raw packet, TCP segmentation, UDP checksum
//!   offload, etc.). With this enabled, the kernel can hand us
//!   multiple back-to-back segments of a single TCP flow in one
//!   `read()` and we can write them back the same way.
//!
//! * **`TUNSETOFFLOAD` ioctl** — turns specific offload features
//!   on (`TUN_F_CSUM`, `TUN_F_TSO4`, `TUN_F_TSO6`, `TUN_F_USO4`,
//!   `TUN_F_USO6`). The kernel then trusts the userspace to
//!   produce already-checksummed / pre-segmented frames in the
//!   formats described by the `virtio_net_hdr` flags.
//!
//! ## Why this module is a *foundation*, not a finished feature
//!
//! `bifrost-vpnd` currently opens the TUN device through the
//! `tun2` crate, which does **not** expose `IFF_VNET_HDR`. Wiring
//! offload into the live data plane therefore needs either
//! (a) a patched `tun2` that round-trips the virtio header or
//! (b) replacing `tun2` with a hand-rolled `AsyncFd<File>` that
//! does the ioctl-and-prefix dance ourselves. Both are out of
//! scope for the current commit.
//!
//! This module *does*:
//! * Encode / decode `virtio_net_hdr_v1` — the wire format the
//!   future implementation will speak, with unit tests.
//! * Expose `try_enable_tun_offload(fd, flags)` — a safe wrapper
//!   around the raw `TUNSETOFFLOAD` ioctl, with a stub fallback
//!   on non-Linux.
//! * Document the integration path in the comments below.
//!
//! Until the data-plane switch happens, calling
//! `try_enable_tun_offload` on a `tun2`-owned fd will *not* break
//! anything (the kernel will just refuse the offload flags) — but
//! it also won't speed up reads or writes.
//!
//! ## Future integration sketch
//!
//! ```text
//!   open(/dev/net/tun, O_RDWR)
//!   ioctl(fd, TUNSETIFF, &ifr { name = "bif-eg0", flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR })
//!   ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6)
//!   fd.set_nonblocking(true)
//!   AsyncFd::new(fd)
//!
//!   on read:
//!     let buf = recv up to 64 KiB
//!     let (hdr, payload) = VirtioNetHdr::decode_prefixed(&buf)
//!     if hdr.flags & GSO_TYPE != 0:
//!         // single super-segment representing N TCP segments
//!         feed all of `payload` to the upper-layer mesh fast path
//!         (encrypt + frame + send) — N kernel segments, one
//!         userspace round trip
//!     else:
//!         single-packet path (today's behaviour)
//!
//!   on write:
//!     prepend VirtioNetHdr::raw_no_offload() to each outgoing
//!     IP packet; the kernel will checksum + fragment as needed.
//! ```

#![allow(dead_code)] // foundation module; wired into the data plane in a later iteration

use std::io;
use std::os::fd::AsRawFd;

/// Default kernel TUN virtio_net_hdr size: 10 bytes.
///
/// Layout (matches `struct virtio_net_hdr` in `<linux/virtio_net.h>`):
///
/// ```text
///   u8  flags                  1 byte
///   u8  gso_type               1 byte
///   u16 hdr_len                2 bytes
///   u16 gso_size               2 bytes
///   u16 csum_start             2 bytes
///   u16 csum_offset            2 bytes
///                          ───────────
///                              10 bytes
/// ```
///
/// The kernel can be asked to use a 12-byte layout (with a trailing
/// `u16 num_buffers` field, matching `virtio_net_hdr_mrg_rxbuf`)
/// via `TUNSETVNETHDRSZ`, but the default — and what we need to
/// match for unmodified `IFF_VNET_HDR` reads/writes — is 10.
///
/// History note: earlier revisions of this constant were set to
/// 12, which caused us to strip two extra bytes from the head of
/// every TUN read. The wire packet then looked like a malformed
/// IP header to the receiving exit (IHL nibble shifted into the
/// version slot), so the kernel silently dropped it — see
/// the bench session on 2026-05-19.
pub const VIRTIO_NET_HDR_LEN: usize = 10;

/// `virtio_net_hdr_v1` layout (Linux `include/uapi/linux/virtio_net.h`).
///
/// All fields are little-endian on the wire. `gso_type` is the
/// most-set field in practice; the rest stay zero unless the
/// kernel is asking us to fix up a checksum or hand back a
/// pre-segmented TCP/UDP super-packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    /// Bitfield: 0 means "no needs-checksum", 1 means kernel
    /// expects userspace to compute the checksum at
    /// `csum_offset` into the packet.
    pub flags: u8,
    /// One of `GSO_NONE` / `GSO_TCPV4` / `GSO_UDP` / etc.
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

/// `virtio_net_hdr.gso_type` constants. Mirror the kernel
/// `VIRTIO_NET_HDR_GSO_*` values.
pub mod gso_type {
    pub const NONE:     u8 = 0;
    pub const TCPV4:    u8 = 1;
    pub const UDP:      u8 = 3;
    pub const TCPV6:    u8 = 4;
    pub const UDP_L4:   u8 = 5; // newer kernels
    pub const ECN_FLAG: u8 = 0x80;
}

/// `TUNSETOFFLOAD` flag bits. Mirror the kernel `TUN_F_*` values.
pub mod offload_flag {
    pub const CSUM:  u32 = 0x01;
    pub const TSO4:  u32 = 0x02;
    pub const TSO6:  u32 = 0x04;
    pub const TSO_ECN: u32 = 0x08;
    pub const UFO:   u32 = 0x10; // legacy UDP fragmentation
    pub const USO4:  u32 = 0x20;
    pub const USO6:  u32 = 0x40;
}

impl VirtioNetHdr {
    /// A header for a plain, fully-formed IP packet: no offload
    /// hints, no checksum delegation, no GSO. The kernel passes
    /// these through unchanged. Use this when you've just emitted
    /// a normal IP packet and only want the virtio framing for
    /// `IFF_VNET_HDR` byte-stream compatibility.
    pub fn raw_no_offload() -> Self {
        Self::default()
    }

    /// Serialise to the 12-byte wire form. Little-endian fields
    /// per `virtio_net.h`.
    pub fn encode(&self) -> [u8; VIRTIO_NET_HDR_LEN] {
        let mut out = [0u8; VIRTIO_NET_HDR_LEN];
        out[0] = self.flags;
        out[1] = self.gso_type;
        out[2..4].copy_from_slice(&self.hdr_len.to_le_bytes());
        out[4..6].copy_from_slice(&self.gso_size.to_le_bytes());
        out[6..8].copy_from_slice(&self.csum_start.to_le_bytes());
        out[8..10].copy_from_slice(&self.csum_offset.to_le_bytes());
        // out[10..12] are `num_buffers` (only relevant with
        // TUN_F_NUM_BUFFERS); leave zero.
        out
    }

    /// Decode the 12-byte prefix of an `IFF_VNET_HDR`-framed read.
    /// Returns `None` if `buf` is shorter than the header.
    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < VIRTIO_NET_HDR_LEN { return None; }
        Some(Self {
            flags:       buf[0],
            gso_type:    buf[1],
            hdr_len:     u16::from_le_bytes([buf[2], buf[3]]),
            gso_size:    u16::from_le_bytes([buf[4], buf[5]]),
            csum_start:  u16::from_le_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_le_bytes([buf[8], buf[9]]),
        })
    }

    /// Split a `[virtio_net_hdr][packet bytes]` buffer into the
    /// header + a borrow of the payload. Returns `None` if the
    /// buffer is shorter than the header.
    pub fn split(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < VIRTIO_NET_HDR_LEN { return None; }
        Self::decode(buf).map(|h| (h, &buf[VIRTIO_NET_HDR_LEN..]))
    }
}

/// Try to enable kernel-side TUN offload on `fd`. The flags are
/// the bitwise-OR of `offload_flag::*` constants.
///
/// On non-Linux targets this is a no-op that returns
/// `Err(Unsupported)` so callers can fall back to the plain
/// per-packet path gracefully.
#[cfg(target_os = "linux")]
pub fn try_enable_tun_offload<F: AsRawFd>(fd: &F, flags: u32) -> io::Result<()> {
    // `TUNSETOFFLOAD` lives at request number 0x400454d0 on every
    // Linux arch we care about (it's `_IOW('T', 208, unsigned int)`).
    // We hard-code it rather than depending on `libc` constants
    // because libc 0.2 doesn't expose `TUNSETOFFLOAD` yet on
    // every supported platform.
    const TUNSETOFFLOAD: libc::c_ulong = 0x400454d0;
    // SAFETY: `fd.as_raw_fd()` is a valid Linux file descriptor
    // (caller owns the resource), `flags` is a primitive value,
    // and `TUNSETOFFLOAD` only reads the flags and reports back —
    // it doesn't mutate userspace memory.
    let rc = unsafe {
        libc::ioctl(fd.as_raw_fd(), TUNSETOFFLOAD, flags as libc::c_ulong)
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn try_enable_tun_offload<F: AsRawFd>(_fd: &F, _flags: u32) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TUN offload is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn virtio_net_hdr_raw_no_offload_encodes_to_zero() {
        let hdr = VirtioNetHdr::raw_no_offload();
        assert_eq!(hdr.encode(), [0u8; VIRTIO_NET_HDR_LEN]);
    }

    #[test]
    fn virtio_net_hdr_roundtrip_typical_tso4_segment() {
        // The kernel hands us a TCPv4 super-segment with a 40-byte
        // header (Ethernet stripped, IP + TCP only) and 1448-byte
        // segments; we should round-trip this verbatim.
        let h = VirtioNetHdr {
            flags: 0x01, // CSUM
            gso_type: gso_type::TCPV4,
            hdr_len: 40,
            gso_size: 1448,
            csum_start: 20,
            csum_offset: 16,
        };
        let encoded = h.encode();
        let decoded = VirtioNetHdr::decode(&encoded).unwrap();
        assert_eq!(h, decoded);
    }

    #[test]
    fn virtio_net_hdr_decode_short_buffer_is_none() {
        assert!(VirtioNetHdr::decode(&[]).is_none());
        assert!(VirtioNetHdr::decode(&[0u8; 5]).is_none());
        // exactly one byte short of the 10-byte basic layout
        assert!(VirtioNetHdr::decode(&[0u8; 9]).is_none());
    }

    #[test]
    fn virtio_net_hdr_split_finds_payload_start() {
        // Build [hdr][packet] and verify split returns both parts.
        let hdr = VirtioNetHdr {
            flags: 0,
            gso_type: gso_type::NONE,
            hdr_len: 20,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        };
        let pkt: Vec<u8> = (0..1400u16).map(|i| i as u8).collect();
        let mut buf = hdr.encode().to_vec();
        buf.extend_from_slice(&pkt);
        let (got_hdr, got_pkt) = VirtioNetHdr::split(&buf).unwrap();
        assert_eq!(got_hdr, hdr);
        assert_eq!(got_pkt, &pkt[..]);
    }

    #[test]
    fn virtio_net_hdr_split_rejects_undersize() {
        // 5 bytes — clearly too short for the 12-byte header.
        assert!(VirtioNetHdr::split(&[0u8; 5]).is_none());
    }

    #[test]
    fn gso_type_constants_match_kernel() {
        // Sanity check against `linux/virtio_net.h`. If these
        // change in a future kernel, the constants need updating
        // — wire-format compat with old hosts.
        assert_eq!(gso_type::NONE,     0);
        assert_eq!(gso_type::TCPV4,    1);
        assert_eq!(gso_type::UDP,      3);
        assert_eq!(gso_type::TCPV6,    4);
        assert_eq!(gso_type::ECN_FLAG, 0x80);
    }

    #[test]
    fn offload_flag_constants_match_kernel() {
        // Sanity check against `if_tun.h`. Same compat concern.
        assert_eq!(offload_flag::CSUM, 0x01);
        assert_eq!(offload_flag::TSO4, 0x02);
        assert_eq!(offload_flag::TSO6, 0x04);
        assert_eq!(offload_flag::USO4, 0x20);
    }
}
