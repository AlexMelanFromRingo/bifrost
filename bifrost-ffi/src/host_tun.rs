//! Async wrapper around a host-provided TUN file descriptor.
//!
//! The host fd from `VpnService.Builder.establish()` (Android) or
//! `NEPacketTunnelProvider` (iOS) is **plain TUN**: each `read()`
//! returns one bare IP packet, each `write()` takes one.
//!
//! The bifrost mesh data plane, however, speaks the
//! `[10-byte virtio_net_hdr | IP packet]` wire format end-to-end (the
//! exit's kernel TUN is `IFF_VNET_HDR`, and `run_client_pump` /
//! `extract_routable` assume every slot carries that header). A plain
//! mobile fd would desync that framing — the exit would read the IP
//! source 10 bytes into the packet and drop everything as "spoofed".
//!
//! So `HostTun` bridges the two: on **read** it prepends a 10-byte
//! all-zero `virtio_net_hdr` (`gso_type = NONE` — a plain packet) to
//! whatever the host fd hands up; on **write** it strips the leading
//! 10-byte header before handing the IP packet to the host fd. To the
//! mesh side it looks exactly like `bifrost-vpnd`'s `OffloadTun`; to
//! the OS it stays plain.
//!
//! (For this to be lossless the exit must not emit GSO super-segments
//! toward a plain client — disable TSO/GSO on the exit's TUN.)

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

/// Length of the leading `virtio_net_hdr` on every mesh wire slot.
const VHDR: usize = bifrost_vpnd::tun_offload::VIRTIO_NET_HDR_LEN;

/// One-IP-packet-at-a-time async TUN wrapper that presents the
/// `[vhdr | ip]` framing the mesh data plane expects.
pub struct HostTun {
    fd: AsyncFd<OwnedFd>,
}

impl HostTun {
    /// Take ownership of a (host-provided, already duplicated) fd and
    /// register it with the tokio reactor. The fd is switched to
    /// non-blocking if it isn't already.
    pub fn from_owned_fd(raw: RawFd) -> io::Result<Self> {
        // Probe + flip O_NONBLOCK *before* adopting, so a failure here
        // doesn't hand a half-owned fd to `OwnedFd`'s Drop.
        set_nonblocking(raw)?;
        // SAFETY: `set_nonblocking` succeeded, so `raw` is a live,
        // caller-owned fd; `OwnedFd` now owns it.
        let owned = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            fd: AsyncFd::new(owned)?,
        })
    }
}

impl AsRawFd for HostTun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsyncRead for HostTun {
    /// Read one plain IP packet from the host fd and present it to the
    /// mesh side as `[10-byte zero vhdr | ip]`.
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
            if unfilled.len() <= VHDR {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "HostTun: read buffer too small for vhdr framing",
                )));
            }
            // Read the bare IP packet into the slice *after* the vhdr.
            // SAFETY: `unfilled[VHDR..]` is a writable slice we own for
            // this call.
            let n = unsafe {
                libc::read(
                    me.fd.as_raw_fd(),
                    unfilled[VHDR..].as_mut_ptr() as *mut libc::c_void,
                    unfilled.len() - VHDR,
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
            if n == 0 {
                // Genuine EOF — propagate as a 0-byte read, do NOT
                // synthesise a bogus 10-byte all-zero "packet".
                return Poll::Ready(Ok(()));
            }
            // Prepend the all-zero virtio_net_hdr (gso_type = NONE).
            unfilled[..VHDR].fill(0);
            dst.advance(VHDR + n as usize);
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for HostTun {
    /// Strip the leading `[vhdr]` and write the bare IP packet to the
    /// host fd. Reports the whole `[vhdr | ip]` slot as consumed.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // A slot with no IP payload after the vhdr — nothing to send,
        // but tell the caller the slot was consumed.
        if buf.len() <= VHDR {
            return Poll::Ready(Ok(buf.len()));
        }
        let ip = &buf[VHDR..];
        loop {
            let mut guard = match me.fd.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r?,
            };
            // SAFETY: `ip` is a borrowed slice held alive for the call.
            let n = unsafe {
                libc::write(
                    me.fd.as_raw_fd(),
                    ip.as_ptr() as *const libc::c_void,
                    ip.len(),
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
            // TUN writes are packet-atomic; the IP packet went out, so
            // the full `[vhdr | ip]` slot is logically consumed.
            return Poll::Ready(Ok(buf.len()));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid kernel fd held by the caller.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK != 0 {
        return Ok(());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Round-trip a `[vhdr | ip]` slot through a `socketpair` pair.
    /// The write side strips the 10-byte header, the read side
    /// re-synthesises an all-zero one — so the IP payload survives and
    /// the header comes back zeroed.
    #[tokio::test]
    async fn vhdr_framing_round_trips_the_ip_payload() {
        let mut fds = [0; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        let mut a = HostTun::from_owned_fd(fds[0]).unwrap();
        let mut b = HostTun::from_owned_fd(fds[1]).unwrap();

        // A wire slot: 10 (here non-zero) vhdr bytes + an "IP packet".
        let ip = b"\x45\x00 a fake ip packet payload";
        let mut slot = vec![0xEE_u8; VHDR];
        slot.extend_from_slice(ip);
        a.write_all(&slot).await.unwrap();

        let mut buf = vec![0u8; 256];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(n, VHDR + ip.len(), "read slot length");
        assert_eq!(&buf[..VHDR], &[0u8; VHDR], "vhdr re-synthesised as zeros");
        assert_eq!(&buf[VHDR..n], ip, "IP payload round-trips intact");
    }

    #[tokio::test]
    async fn nonblock_is_set_automatically() {
        let mut fds = [0; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        let tun = HostTun::from_owned_fd(fds[0]).unwrap();
        let flags = unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFL, 0) };
        assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
        unsafe { libc::close(fds[1]) };
        drop(tun);
    }

    #[test]
    fn rejects_closed_fd() {
        let mut fds = [0; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        unsafe { libc::close(fds[0]) };
        assert!(HostTun::from_owned_fd(fds[0]).is_err(), "closed fd must error");
        unsafe { libc::close(fds[1]) };
    }
}
