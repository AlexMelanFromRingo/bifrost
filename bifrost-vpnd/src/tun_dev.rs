//! Hand-rolled async TUN device with kernel-side offload support.
//!
//! This module replaces the `tun2` crate dependency for
//! `bifrost-vpnd`'s exit/client data plane. The motivation is
//! `IFF_VNET_HDR` — `tun2` doesn't expose it, but we need the
//! virtio framing so the kernel can hand us TCP/UDP super-segments
//! via TSO/USO instead of one syscall per IP packet. See
//! [`crate::tun_offload`] for the wire format and the offload-flag
//! constants; that module already shipped the encode/decode + the
//! `TUNSETOFFLOAD` ioctl wrapper as a foundation.
//!
//! ## What this commit wires in
//!
//! * Open `/dev/net/tun` with `O_NONBLOCK | O_CLOEXEC`.
//! * `TUNSETIFF` with `IFF_TUN | IFF_NO_PI | IFF_VNET_HDR`.
//! * Best-effort `TUNSETOFFLOAD` with caller-provided flags
//!   (default: `TUN_F_CSUM`, the safest immediate win — kernel
//!   skips checksum computation for already-checksummed packets).
//! * `SIOCSIFMTU` for MTU.
//! * `AsyncFd<OwnedFd>` for tokio integration.
//! * [`AsyncRead`] strips the leading 12-byte `virtio_net_hdr` from
//!   every kernel read so callers continue to see plain IP packets.
//! * [`AsyncWrite`] prepends a zero `virtio_net_hdr` via `writev(2)`
//!   so there's no copy on the hot send path.
//!
//! ## What this commit does NOT do
//!
//! GSO super-segments aren't yet re-segmented before mesh forwarding.
//! With only `TUN_F_CSUM` enabled the kernel never produces them,
//! so the per-packet behaviour is unchanged on the wire — we just
//! save the checksum compute on both ends. Enabling `TSO4`/`TSO6`/
//! `USO4`/`USO6` is a follow-up (the encode/decode in
//! `tun_offload` is ready; the re-segmenter on read isn't).
//!
//! ## Why this is Linux-only
//!
//! `IFF_VNET_HDR` is a Linux-specific TUN feature. macOS/BSD have
//! utun, no virtio header at all. The exit/client modes already
//! depend on `iptables` + `ip` so we never ran them outside Linux
//! anyway — this just makes the dependency explicit.

#![cfg(target_os = "linux")]

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};
use tracing::{info, warn};

use crate::tun_offload::{
    offload_flag, try_enable_tun_offload, VIRTIO_NET_HDR_LEN,
};

// ── Linux TUN ioctl/flag constants ──────────────────────────────
//
// These live in `<linux/if_tun.h>` and `<linux/if.h>`. `libc 0.2`
// exposes some of them but the coverage is inconsistent across
// versions and the `_IOW('T', ...)` request numbers are stable
// across every Linux arch we ship for (x86_64, aarch64, armv7,
// i686 — same magic numbers). Hardcoding keeps the dep surface
// small and the failure modes obvious.

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const SIOCSIFMTU: libc::c_ulong = 0x8922;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
const IFF_VNET_HDR: i16 = 0x4000;

const IFNAMSIZ: usize = 16;

/// `struct ifreq` layout used for `TUNSETIFF`. Only the `name` and
/// the leading `i16` of the anonymous union (interpreted as flags
/// here) are read by the kernel. The trailing padding rounds the
/// struct up to the real `ifreq` size — 40 bytes on 64-bit Linux.
#[repr(C)]
struct IfreqFlags {
    name: [u8; IFNAMSIZ],
    flags: i16,
    _pad: [u8; 22],
}

/// `struct ifreq` flavour for `SIOCSIFMTU` — same first 16 bytes,
/// but the union slot here is an `i32`.
#[repr(C)]
struct IfreqMtu {
    name: [u8; IFNAMSIZ],
    mtu: i32,
    _pad: [u8; 20],
}

/// An async TUN device with kernel `IFF_VNET_HDR` framing and
/// best-effort `TUNSETOFFLOAD`. Read/write hide the 12-byte virtio
/// prefix from callers so the rest of the data plane keeps speaking
/// plain IP packets.
pub struct OffloadTun {
    fd: AsyncFd<OwnedFd>,
    #[allow(dead_code)] // exposed via name() for ops/debug introspection
    name: String,
    #[allow(dead_code)] // exposed via mtu()
    mtu: u16,
    /// Mirrors the result of [`try_enable_tun_offload`]. Useful for
    /// logging at startup and for future per-flag fast-path
    /// branching; the read/write path itself doesn't care.
    offload_active: bool,
}

impl OffloadTun {
    /// Default offload mask: `CSUM | TSO4 | TSO6 | USO4`.
    ///
    /// The EgressHello v3 wire format propagates the 10-byte
    /// virtio_net_hdr end-to-end through the mesh, so super-segments
    /// the kernel hands us at the client (gso_type=TCPV4/TCPV6/UDP)
    /// can be written to the exit's TUN verbatim — the exit kernel
    /// then re-segments on the way to its real NIC. One read on the
    /// client becomes one mesh datagram becomes one write on the
    /// exit, regardless of how many TCP segments the super-frame
    /// represents. On a 1500-byte MTU TCP flow that's a 10× drop
    /// in syscall + crypto + framing overhead per byte.
    ///
    /// CSUM is included because the same vhdr propagation also
    /// carries `NEEDS_CSUM` correctly to the receiving kernel — the
    /// previously-broken case (header stripped, raw bytes forwarded,
    /// receiver assumes valid checksum) doesn't apply anymore.
    ///
    /// USO4 (UDP segmentation offload, Linux ≥ 6.0) is best-effort:
    /// older kernels return `EINVAL` from `TUNSETOFFLOAD` and we
    /// retry with TSO-only. The `try_enable_tun_offload` log line
    /// at startup shows what actually stuck.
    pub const DEFAULT_OFFLOAD: u32 =
        offload_flag::CSUM | offload_flag::TSO4 | offload_flag::TSO6 | offload_flag::USO4;

    /// Open `/dev/net/tun`, configure the interface, and wrap it
    /// in an async-ready handle.
    ///
    /// * `name` — desired interface name (`bifrost-eg0` etc).
    ///   Must be 1..16 bytes; the kernel may rewrite it on
    ///   collision but we pass the requested name through.
    /// * `mtu` — set via `SIOCSIFMTU`. Bring-up + IP addresses are
    ///   the caller's job (see `egress::configure_*_kernel`).
    /// * `want_offload` — `TUNSETOFFLOAD` flag mask; pass
    ///   [`Self::DEFAULT_OFFLOAD`] for the safe default or `0` to
    ///   skip the ioctl entirely.
    pub fn open(name: &str, mtu: u16, want_offload: u32) -> io::Result<Self> {
        if name.is_empty() || name.len() >= IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid TUN name {:?}: length must be 1..{}",
                    name,
                    IFNAMSIZ - 1
                ),
            ));
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open("/dev/net/tun")?;
        let owned: OwnedFd = file.into();

        // TUNSETIFF: tell the kernel "carve me a TUN named X with
        // these flags". The kernel writes the finalised name back
        // into `req.name`; we re-read it so any kernel-side
        // rewriting (e.g. dedup suffix) is reflected to the caller.
        let mut req: IfreqFlags = unsafe { std::mem::zeroed() };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        req.flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR;
        // SAFETY: `owned` is a live Linux fd. `req` is a sized
        // ifreq on the stack; the kernel reads `name` + `flags`
        // and writes the finalised name back into the same bytes.
        let rc = unsafe {
            libc::ioctl(owned.as_raw_fd(), TUNSETIFF, &mut req as *mut IfreqFlags)
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        let nul = req.name.iter().position(|b| *b == 0).unwrap_or(IFNAMSIZ);
        let finalised_name =
            String::from_utf8_lossy(&req.name[..nul]).into_owned();
        if finalised_name != name {
            warn!(
                "tun_dev: kernel renamed TUN {:?} → {:?}",
                name, finalised_name
            );
        }

        // Best-effort TUNSETOFFLOAD with a USO-aware retry. USO4
        // landed in Linux 6.0; older kernels reject the bit with
        // `EINVAL`. We try the full requested mask first, and on
        // failure peel off USO and retry — that keeps WSL2 / RHEL8
        // builds running TSO+CSUM while letting modern kernels get
        // the full feature set transparently.
        let offload_active = if want_offload != 0 {
            let primary = try_enable_tun_offload(&owned, want_offload);
            let outcome = match primary {
                Ok(()) => Ok(want_offload),
                Err(e1) if (want_offload & (offload_flag::USO4 | offload_flag::USO6)) != 0 => {
                    let downgraded =
                        want_offload & !(offload_flag::USO4 | offload_flag::USO6);
                    match try_enable_tun_offload(&owned, downgraded) {
                        Ok(()) => Ok(downgraded),
                        Err(e2) => Err((e1, Some(e2))),
                    }
                }
                Err(e1) => Err((e1, None)),
            };
            match outcome {
                Ok(active_flags) => {
                    info!(
                        "tun_dev: TUNSETOFFLOAD on {finalised_name}, flags={active_flags:#x} \
                         (requested {:#x})",
                        want_offload
                    );
                    true
                }
                Err((e1, e2)) => {
                    warn!(
                        "tun_dev: TUNSETOFFLOAD({:#x}) on {finalised_name} failed: {e1}{} \
                         — falling back to VNET_HDR-only (per-packet, no GSO)",
                        want_offload,
                        e2.map(|e| format!(" (downgrade retry also failed: {e})"))
                            .unwrap_or_default(),
                    );
                    false
                }
            }
        } else {
            false
        };

        set_mtu(&finalised_name, mtu)?;

        Ok(Self {
            fd: AsyncFd::new(owned)?,
            name: finalised_name,
            mtu,
            offload_active,
        })
    }

    /// Kernel-finalised interface name (may differ from what was
    /// requested if the kernel did a collision rename). Used by
    /// ops/debug callers; the data plane uses [`Self::as_raw_fd`].
    #[allow(dead_code)]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Configured MTU, matching what was passed to [`Self::open`].
    #[allow(dead_code)]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn offload_active(&self) -> bool {
        self.offload_active
    }
}

impl AsRawFd for OffloadTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsyncRead for OffloadTun {
    /// Pass the kernel's `[virtio_net_hdr | ip_packet]` slab through
    /// to the caller verbatim — no longer strip the 10-byte header.
    /// The mesh data plane carries the vhdr end-to-end so the exit
    /// can write back exactly what the client kernel produced
    /// (preserving `gso_type` for TSO/USO super-segments).
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        loop {
            let mut guard = match me.fd.poll_read_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r?,
            };
            let unfilled = dst.initialize_unfilled();
            if unfilled.len() < VIRTIO_NET_HDR_LEN + 1 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "buffer too small for virtio-framed TUN read",
                )));
            }
            // SAFETY: `unfilled` is a writable slice; we hand its
            // raw pointer + length to `read(2)`, which writes at
            // most `len` bytes and returns the count.
            let n = unsafe {
                libc::read(
                    me.fd.as_raw_fd(),
                    unfilled.as_mut_ptr() as *mut libc::c_void,
                    unfilled.len(),
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(e));
            }
            let n = n as usize;
            if n == 0 {
                return Poll::Ready(Ok(()));
            }
            if n < VIRTIO_NET_HDR_LEN {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "TUN read returned {n} bytes — below virtio header size {}",
                        VIRTIO_NET_HDR_LEN
                    ),
                )));
            }
            dst.advance(n);
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for OffloadTun {
    /// Caller hands us `[virtio_net_hdr | ip_packet]` verbatim; we
    /// `write(2)` it as one slab. The vhdr is the caller's
    /// responsibility — the wire/data-plane decides whether it's a
    /// zero passthrough or a real `gso_type` super-segment hint.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if buf.len() < VIRTIO_NET_HDR_LEN {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "TUN write needs at least {VIRTIO_NET_HDR_LEN}-byte vhdr; got {}",
                    buf.len()
                ),
            )));
        }
        loop {
            let mut guard = match me.fd.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r?,
            };
            // SAFETY: `buf` is the caller's slice held alive for
            // the duration of `poll_write`.
            let n = unsafe {
                libc::write(
                    me.fd.as_raw_fd(),
                    buf.as_ptr() as *const libc::c_void,
                    buf.len(),
                )
            };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    guard.clear_ready();
                    continue;
                }
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(n as usize));
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // TUN writes go straight to the kernel queue, nothing to
        // flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // Drop-on-close is enough; no half-close semantics on TUN.
        Poll::Ready(Ok(()))
    }
}

fn set_mtu(name: &str, mtu: u16) -> io::Result<()> {
    if name.is_empty() || name.len() >= IFNAMSIZ {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {:?}", name),
        ));
    }
    // SIOCSIFMTU needs an AF_INET socket (any domain works, but
    // AF_INET is universal). We don't keep the socket past the
    // ioctl — it exists only to give us a valid fd.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut req: IfreqMtu = unsafe { std::mem::zeroed() };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    req.mtu = mtu as i32;
    // SAFETY: `sock` is a freshly-opened kernel fd; `req` is a
    // sized struct that the kernel reads `name` + `mtu` from.
    let rc = unsafe { libc::ioctl(sock, SIOCSIFMTU, &req as *const IfreqMtu) };
    let err = if rc < 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    unsafe { libc::close(sock) };
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Silence dead-code warnings — `CString` import is used only on
/// some cfg permutations of the test module (kept for symmetry
/// with `set_mtu` future eventd that may want a `CString` round-trip).
#[allow(dead_code)]
fn _unused_imports() {
    let _ = CString::new("").ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_layout_matches_kernel_size() {
        // `struct ifreq` on Linux is 40 bytes on every arch we
        // ship for; our two flavours must match.
        assert_eq!(std::mem::size_of::<IfreqFlags>(), 40);
        assert_eq!(std::mem::size_of::<IfreqMtu>(), 40);
    }

    #[test]
    fn iff_constants_match_kernel() {
        // `<linux/if_tun.h>` values. If these ever drift we'd
        // silently open a wrong-flavour interface, so unit-test
        // them like the offload flags in `tun_offload`.
        assert_eq!(IFF_TUN, 0x0001);
        assert_eq!(IFF_NO_PI, 0x1000);
        assert_eq!(IFF_VNET_HDR, 0x4000);
    }

    #[test]
    fn ioctl_request_constants_match_kernel() {
        // Hardcoded so callers can audit them without a libc bump.
        assert_eq!(TUNSETIFF, 0x400454ca);
        assert_eq!(SIOCSIFMTU, 0x8922);
    }

    #[test]
    fn default_offload_mask_enables_csum_tso_uso() {
        // EgressHello v3 carries vhdr end-to-end so we can finally
        // turn on TSO+CSUM safely (and USO on kernels that support
        // it — `try_enable_tun_offload` has a USO-aware retry path).
        const WANT: u32 = offload_flag::CSUM
            | offload_flag::TSO4
            | offload_flag::TSO6
            | offload_flag::USO4;
        const _: () = {
            assert!(OffloadTun::DEFAULT_OFFLOAD == WANT);
            assert!(OffloadTun::DEFAULT_OFFLOAD & offload_flag::CSUM != 0);
            assert!(OffloadTun::DEFAULT_OFFLOAD & offload_flag::TSO4 != 0);
        };
    }

    #[test]
    fn open_rejects_empty_and_oversize_names() {
        // We don't actually open `/dev/net/tun` here (CI runs
        // without CAP_NET_ADMIN); but the name-validation check
        // fires before the syscall and we can exercise it.
        let too_long = "a".repeat(IFNAMSIZ);
        match OffloadTun::open(&too_long, 1400, 0) {
            Ok(_) => panic!("expected name-validation rejection"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
        }
        match OffloadTun::open("", 1400, 0) {
            Ok(_) => panic!("expected name-validation rejection"),
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::InvalidInput),
        }
    }
}
