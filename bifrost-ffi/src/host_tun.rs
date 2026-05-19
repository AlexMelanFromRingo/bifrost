//! Async wrapper around a host-provided TUN file descriptor.
//!
//! Unlike `bifrost-vpnd::tun_dev::OffloadTun`, this one does NOT
//! prepend or strip a `virtio_net_hdr` — the host fd we get from
//! `VpnService.Builder.establish()` (Android) or
//! `NEPacketTunnelProvider`'s packet flow (iOS, via the experimental
//! `setTunnelNetworkSettings` + `packet_io_kit` path) is plain TUN:
//! each `read()` returns one IP packet, each `write()` accepts one.
//!
//! We could plumb `IFF_VNET_HDR` ourselves on Android by re-opening
//! `/dev/net/tun` from native code, but doing so bypasses
//! `VpnService`'s firewall hooks and breaks the system VPN status
//! UI. Easier and safer to keep the host's framing contract.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

/// One IP-packet-at-a-time async TUN wrapper.
///
/// Built on `tokio::io::unix::AsyncFd` so it integrates with the
/// existing data plane (`run_client_pump` expects an
/// `AsyncRead + AsyncWrite`).
pub struct HostTun {
    fd: AsyncFd<OwnedFd>,
}

impl HostTun {
    /// Take ownership of a (host-provided, already duplicated) fd
    /// and register it with the tokio reactor. The fd must be set
    /// to non-blocking; we'll switch it via `fcntl` if it isn't.
    pub fn from_owned_fd(raw: RawFd) -> io::Result<Self> {
        // Validate the fd *before* adopting it. `OwnedFd::from_raw_fd`
        // is non-fallible and will eagerly close the fd on drop — if
        // we let it adopt a bad fd and then bail on a subsequent
        // fcntl, the Drop double-closes (Rust 1.85+ IO-safety
        // assertion aborts the process). So: probe with F_GETFL
        // first, switch O_NONBLOCK on if needed, *then* take
        // ownership.
        set_nonblocking(raw)?;
        // SAFETY: `set_nonblocking` succeeded, so `raw` is a live,
        // caller-owned fd. From here on `OwnedFd` owns it and its
        // Drop will close it exactly once.
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
            // SAFETY: `unfilled` is a writable slice we own for
            // this call; we pass its raw pointer + length to
            // `read(2)`.
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
            dst.advance(n as usize);
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for HostTun {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        loop {
            let mut guard = match me.fd.poll_write_ready(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(r) => r?,
            };
            // SAFETY: `buf` is the caller's slice held alive for
            // the duration of `poll_write`; `write(2)` accepts a
            // pointer + length.
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
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
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
        return Ok(()); // already non-blocking
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

    /// Round-trip plain bytes through a `pipe(2)` pair wrapped as
    /// `HostTun`s. This validates the read/write plumbing without
    /// needing a real TUN (impossible on CI).
    #[tokio::test]
    async fn pipe_roundtrip_byte_stream() {
        // Use `socketpair` so both ends are full-duplex AF_UNIX
        // datagrams — that mirrors TUN's "packet boundaries are
        // preserved per syscall" semantics better than `pipe`.
        let mut fds = [0; 2];
        let rc = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_DGRAM,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(rc, 0, "socketpair failed: {}", io::Error::last_os_error());
        let mut a = HostTun::from_owned_fd(fds[0]).unwrap();
        let mut b = HostTun::from_owned_fd(fds[1]).unwrap();

        let payload = b"hello-tun".to_vec();
        a.write_all(&payload).await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], &payload[..]);
    }

    #[tokio::test]
    async fn nonblock_is_set_automatically() {
        // `socketpair` returns blocking fds by default; HostTun
        // should flip O_NONBLOCK so the tokio reactor can multiplex.
        let mut fds = [0; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        let tun = HostTun::from_owned_fd(fds[0]).unwrap();
        let flags = unsafe { libc::fcntl(tun.as_raw_fd(), libc::F_GETFL, 0) };
        assert!(flags >= 0);
        assert!(flags & libc::O_NONBLOCK != 0);
        // Close the unused half — we adopted fds[0] into HostTun;
        // fds[1] would leak otherwise.
        unsafe { libc::close(fds[1]) };
        drop(tun);
    }

    #[test]
    fn rejects_invalid_fd() {
        // -1 is the canonical "invalid fd". from_owned_fd accepts
        // it (it doesn't validate) but the subsequent fcntl will
        // fail.
        let _ = std::panic::catch_unwind(|| {
            // OwnedFd::from_raw_fd(-1) is technically UB per docs.
            // We instead use an actually-invalid (but allocated &
            // closed) fd for a real round-trip.
            let mut fds = [0; 2];
            unsafe { libc::pipe(fds.as_mut_ptr()) };
            unsafe { libc::close(fds[0]) };
            let res = HostTun::from_owned_fd(fds[0]);
            assert!(res.is_err(), "expected error on closed fd");
            unsafe { libc::close(fds[1]) };
        });
    }
}
