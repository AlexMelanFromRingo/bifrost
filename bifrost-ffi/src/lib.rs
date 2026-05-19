//! C ABI shim driving `bifrost-vpnd`'s client data plane from
//! mobile hosts (Android `VpnService`, iOS `NEPacketTunnelProvider`).
//!
//! ## Why a separate crate
//!
//! `bifrost-vpnd` is a long-running CLI daemon: it owns its config
//! file, opens its own kernel TUN, and configures iptables/ip(8).
//! On mobile that's all done by the host OS — the app gets a
//! pre-opened TUN file descriptor and we just push IP packets
//! through it. So we lift the data-plane primitives
//! (`client_handshake` + `run_client_pump`) from `bifrost-vpnd::egress`
//! and wrap them in a `extern "C"` surface that's callable from
//! Java/Kotlin via JNI and from Swift/Objective-C via the C
//! `staticlib`.
//!
//! See `BUILD-MOBILE.md` in the repository root for cross-compile
//! recipes and packaging notes.
//!
//! ## ABI surface
//!
//! The complete C API (matching `include/bifrost_ffi.h`):
//!
//! ```c
//! typedef struct BifrostClient BifrostClient;
//!
//! uint32_t bifrost_ffi_abi_version(void);
//!
//! int32_t bifrost_client_start(
//!     int32_t tun_fd,
//!     const char* node_config_json,
//!     const char* exit_pub_key_hex,
//!     BifrostClient** out_handle);
//!
//! void bifrost_client_stop(BifrostClient* handle);
//!
//! const char* bifrost_last_error(void);
//! ```
//!
//! `bifrost_client_start` returns one of the [`BifrostStatus`]
//! values; on `BIFROST_OK` the caller owns the handle and must
//! pass it to `bifrost_client_stop` to release resources. On any
//! non-OK status the handle is left as-is and the caller can pull
//! a human-readable reason via `bifrost_last_error`.

use std::cell::RefCell;
use std::ffi::{c_char, CStr};
use std::ptr;

use anyhow::{anyhow, Context, Result};
use bifrost_core::mux::MeshMux;
use bifrost_vpnd::egress::{client_handshake, run_client_pump};
use norn_rs::{config::NodeConfig, node::Node};
use tokio::runtime::Runtime;
use tracing::{error, info};

mod host_tun;

use host_tun::HostTun;

// ── ABI status codes ────────────────────────────────────────────

/// One of the integer values returned by [`bifrost_client_start`].
/// Mirrors the `BifrostStatus` enum in `include/bifrost_ffi.h`.
#[repr(i32)]
#[non_exhaustive]
pub enum BifrostStatus {
    Ok = 0,
    /// A C string argument was NULL, malformed UTF-8, or otherwise
    /// failed length / hex validation.
    InvalidArg = 1,
    /// The provided TUN file descriptor could not be duplicated
    /// (the host probably closed it before we got to it).
    TunFdErr = 2,
    /// `Node::new` / `node.start()` failed — usually a bad config
    /// (unreadable key, conflicting port) or no network.
    NodeInitErr = 3,
    /// `client_handshake` failed: exit peer wasn't reachable in
    /// the 60s window, or it refused the OpenAck.
    HandshakeErr = 4,
    /// Generic catch-all for runtime errors thrown by the pump.
    RuntimeErr = 5,
}

const ABI_VERSION: u32 = 1;

// ── Last-error state ─────────────────────────────────────────────
//
// Mobile callers can't catch Rust panics or pull the chained
// anyhow::Error structure out of the FFI surface. So on every
// failure we stash a string description into a thread-local that
// `bifrost_last_error` reads back. The string lives until the
// next call mutates it.

thread_local! {
    static LAST_ERROR: RefCell<std::ffi::CString> = RefCell::new(
        std::ffi::CString::new("no error").unwrap()
    );
}

fn set_last_error<S: Into<String>>(msg: S) {
    let cstr = std::ffi::CString::new(msg.into())
        .unwrap_or_else(|_| std::ffi::CString::new("invalid error message").unwrap());
    LAST_ERROR.with(|cell| *cell.borrow_mut() = cstr);
}

// ── Public FFI ───────────────────────────────────────────────────

/// ABI version. Hosts compile against `BIFROST_FFI_ABI_VERSION` from
/// the header and assert equality at app launch — mismatches mean
/// the .so / .a was built against a different schema and the JSON
/// config shape may have shifted.
///
/// # Safety
///
/// Safe to call from any thread at any time.
#[unsafe(no_mangle)]
pub extern "C" fn bifrost_ffi_abi_version() -> u32 {
    ABI_VERSION
}

/// Spin up the client data plane. See the crate docs for the C
/// signature and parameter semantics.
///
/// # Safety
///
/// * `node_config_json` and `exit_pub_key_hex` must point at
///   NUL-terminated valid UTF-8 strings.
/// * `out_handle` must point at writable memory for one pointer.
/// * `tun_fd` must be a valid file descriptor (Linux/Darwin) the
///   host is willing to share — we `dup(2)` it so the caller is
///   free to close their copy. The host is responsible for the
///   TUN being already configured with the lease address + routes
///   (iOS does this in `setTunnelNetworkSettings`; Android in
///   `VpnService.Builder` before `.establish()`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_client_start(
    tun_fd: i32,
    node_config_json: *const c_char,
    exit_pub_key_hex: *const c_char,
    out_handle: *mut *mut BifrostClient,
) -> i32 {
    if node_config_json.is_null() || exit_pub_key_hex.is_null() || out_handle.is_null() {
        set_last_error("null pointer argument");
        return BifrostStatus::InvalidArg as i32;
    }
    // SAFETY: null check above; caller asserts `out_handle` points
    // at writable memory for one pointer.
    unsafe { *out_handle = ptr::null_mut() };

    install_log_sink_once();

    // SAFETY: caller asserts both pointers are NUL-terminated valid
    // UTF-8 C strings (see crate-level docs).
    let cfg_json = match unsafe { CStr::from_ptr(node_config_json) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("node_config_json not UTF-8: {e}"));
            return BifrostStatus::InvalidArg as i32;
        }
    };
    let exit_hex = match unsafe { CStr::from_ptr(exit_pub_key_hex) }.to_str() {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("exit_pub_key_hex not UTF-8: {e}"));
            return BifrostStatus::InvalidArg as i32;
        }
    };
    let exit_peer = match parse_pub_key(exit_hex) {
        Ok(k) => k,
        Err(e) => {
            set_last_error(format!("exit_pub_key_hex: {e:#}"));
            return BifrostStatus::InvalidArg as i32;
        }
    };
    let mut cfg: NodeConfig = match serde_json::from_str(cfg_json) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(format!("node_config_json parse: {e}"));
            return BifrostStatus::InvalidArg as i32;
        }
    };
    // Force the mesh TUN off: the host owns the single tun_fd
    // we're handed, and a second reader inside norn-rs would steal
    // frames from MeshMux. (Same defence bifrost-vpnd applies in
    // exit/client mode.)
    cfg.tun_name = None;

    // Duplicate the host fd so the caller is free to close theirs.
    let dup_fd = match dup_fd(tun_fd) {
        Ok(fd) => fd,
        Err(e) => {
            set_last_error(format!("dup(tun_fd={tun_fd}): {e}"));
            return BifrostStatus::TunFdErr as i32;
        }
    };

    // Build a multi-thread runtime. Mobile cores hit thermal caps
    // fast on single-thread; tokio's work-stealing scheduler
    // keeps the encrypt + framing work spread across cores.
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("bifrost-ffi")
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            // safe to close the dup since nothing's owning it yet
            unsafe { libc::close(dup_fd) };
            set_last_error(format!("tokio runtime build: {e}"));
            return BifrostStatus::RuntimeErr as i32;
        }
    };

    // SAFETY: same out_handle invariant as the earlier write. We
    // hand the ownership of the dup'd fd into HostTun::from_owned_fd
    // inside the runtime block_on; on the error path we close it
    // explicitly to avoid a leak.
    let result: Result<BifrostClientInner> = runtime.block_on(async {
        let node = Node::new(cfg).await.context("Node::new")?;
        node.start().await.context("node.start")?;
        let conn = node.conn.clone();
        info!(
            "bifrost-ffi: node up; pub_key={}",
            hex::encode(conn.pub_key)
        );
        let (mux, _accept_rx) = MeshMux::new(conn);
        let (mesh, hello) = client_handshake(mux.clone(), exit_peer)
            .await
            .context("client_handshake")?;
        info!(
            "bifrost-ffi: allocated v4={} v6={:?} mtu={}",
            hello.allocated_v4, hello.allocated_v6, hello.mtu
        );
        let host = HostTun::from_owned_fd(dup_fd)
            .context("wrapping host TUN fd")?;
        let (r, w) = tokio::io::split(host);
        run_client_pump(r, w, mux, exit_peer, mesh)
            .await
            .context("run_client_pump")?;
        Ok(BifrostClientInner { _node: node })
    });

    match result {
        Ok(inner) => {
            let boxed = Box::new(BifrostClient {
                runtime: Some(runtime),
                _inner: inner,
            });
            // SAFETY: `out_handle` was checked non-null above and
            // the caller asserts it's writable.
            unsafe { *out_handle = Box::into_raw(boxed) };
            set_last_error("ok");
            BifrostStatus::Ok as i32
        }
        Err(e) => {
            // close the duplicated fd so we don't leak it on error
            // (the pump owns the AsyncFd only on the happy path)
            // SAFETY: `dup_fd` is a kernel fd we hold exclusively.
            unsafe { libc::close(dup_fd) };
            drop(runtime);
            let msg = format!("{e:#}");
            error!("bifrost_client_start failed: {msg}");
            set_last_error(msg);
            // Best-effort classification — handshake errors carry
            // the literal context string we attached above.
            let err_str = format!("{e:#}");
            let code = if err_str.contains("Node::new") || err_str.contains("node.start")
            {
                BifrostStatus::NodeInitErr
            } else if err_str.contains("client_handshake") {
                BifrostStatus::HandshakeErr
            } else {
                BifrostStatus::RuntimeErr
            };
            code as i32
        }
    }
}

/// Tear down a client previously returned by
/// [`bifrost_client_start`]. Safe to call with `NULL` (no-op).
///
/// # Safety
///
/// `handle` must be a pointer previously returned from a successful
/// `bifrost_client_start`, and must not be freed twice. The call
/// blocks until the tokio runtime has shut down — usually a few
/// hundred milliseconds.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bifrost_client_stop(handle: *mut BifrostClient) {
    if handle.is_null() {
        return;
    }
    // SAFETY: caller asserts `handle` came from a successful
    // `bifrost_client_start` and hasn't been freed yet.
    let boxed = unsafe { Box::from_raw(handle) };
    // Drop ordering matters: Box::drop runs BifrostClient::drop
    // (which stops the runtime via shutdown_background) *then*
    // drops the inner Node — runtime must wind down before its
    // task world disappears.
    drop(boxed);
}

/// Borrow the last error string. Returns a pointer that's valid
/// until the next call into this FFI module from the same thread.
///
/// # Safety
///
/// The returned pointer is owned by `bifrost-ffi`; the caller must
/// not free it.
#[unsafe(no_mangle)]
pub extern "C" fn bifrost_last_error() -> *const c_char {
    LAST_ERROR.with(|cell| cell.borrow().as_ptr())
}

// ── Internals ────────────────────────────────────────────────────

/// Public to the FFI surface as an opaque pointer.
pub struct BifrostClient {
    /// `Option` so Drop can take it out and call `shutdown_background`
    /// in a controlled order.
    runtime: Option<Runtime>,
    _inner: BifrostClientInner,
}

struct BifrostClientInner {
    /// Held to keep the norn-rs node alive for the runtime
    /// lifetime. Dropping the runtime aborts all spawned tasks; the
    /// node's PacketConn cleans up its listener sockets via Drop.
    _node: Node,
}

impl Drop for BifrostClient {
    fn drop(&mut self) {
        if let Some(rt) = self.runtime.take() {
            // `shutdown_background` returns immediately and lets the
            // worker threads tear themselves down asynchronously,
            // which is what we want from `bifrost_client_stop` —
            // a synchronous full join could block the host UI
            // thread for seconds on a slow TCP close.
            rt.shutdown_background();
        }
    }
}

fn parse_pub_key(hex_str: &str) -> Result<[u8; 32]> {
    if hex_str.len() != 64 {
        return Err(anyhow!(
            "expected 64 hex chars, got {}",
            hex_str.len()
        ));
    }
    let bytes =
        hex::decode(hex_str).map_err(|e| anyhow!("hex decode: {e}"))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(unix)]
fn dup_fd(fd: i32) -> std::io::Result<i32> {
    // Use `dup3` with O_CLOEXEC on Linux/Android so the duplicate
    // is closed across `exec(2)`; macOS/iOS don't expose `dup3` so
    // fall back to `dup` + a separate `fcntl(F_SETFD, FD_CLOEXEC)`.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        // pick a high target fd; the kernel rejects collisions and
        // we want to avoid clobbering 0/1/2. Using `dup` (not `dup3`)
        // with a kernel-chosen slot is simpler and just as safe.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(dup)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let dup = unsafe { libc::dup(fd) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Set CLOEXEC explicitly — `dup(2)` clears it on the
        // duplicate by spec.
        let flags = unsafe { libc::fcntl(dup, libc::F_GETFD) };
        if flags >= 0 {
            unsafe { libc::fcntl(dup, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
        }
        Ok(dup)
    }
}

#[cfg(not(unix))]
fn dup_fd(_fd: i32) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "bifrost-ffi requires a unix platform (android/ios)",
    ))
}

/// Install a no-op tracing subscriber once per process so events
/// don't panic the runtime on missing global default. The host app
/// is expected to capture stderr via its own logging pipeline
/// (Android `Process.exec` redirect; iOS `dup2` over the `os_log`
/// fd). See `Cargo.toml` for the rationale on not pulling
/// `tracing-android` / `tracing-oslog`.
fn install_log_sink_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing::subscriber::NoSubscriber::default(),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn abi_version_is_pinned() {
        // Bump this assertion when bumping ABI_VERSION; the test
        // exists to make ABI bumps an explicit gate rather than an
        // accident.
        assert_eq!(bifrost_ffi_abi_version(), 1);
    }

    #[test]
    fn parse_pub_key_round_trip() {
        let hex_s = "00112233445566778899aabbccddeeff\
                     00112233445566778899aabbccddeeff";
        let key = parse_pub_key(hex_s).unwrap();
        assert_eq!(hex::encode(key), hex_s);
    }

    #[test]
    fn parse_pub_key_rejects_wrong_length() {
        let err = parse_pub_key("dead").unwrap_err();
        assert!(format!("{err:#}").contains("64 hex"));
    }

    #[test]
    fn parse_pub_key_rejects_non_hex() {
        let err = parse_pub_key(&"z".repeat(64)).unwrap_err();
        assert!(format!("{err:#}").contains("hex decode"));
    }

    #[test]
    fn start_rejects_null_pointers() {
        let mut handle: *mut BifrostClient = ptr::null_mut();
        let status = unsafe {
            bifrost_client_start(
                0,
                ptr::null(),
                ptr::null(),
                &mut handle as *mut _,
            )
        };
        assert_eq!(status, BifrostStatus::InvalidArg as i32);
        assert!(handle.is_null());
    }

    #[test]
    fn start_rejects_short_exit_key() {
        let cfg = CString::new("{}").unwrap();
        let short = CString::new("deadbeef").unwrap();
        let mut handle: *mut BifrostClient = ptr::null_mut();
        let status = unsafe {
            bifrost_client_start(
                0,
                cfg.as_ptr(),
                short.as_ptr(),
                &mut handle as *mut _,
            )
        };
        assert_eq!(status, BifrostStatus::InvalidArg as i32);
    }

    #[test]
    fn stop_is_null_safe() {
        unsafe { bifrost_client_stop(ptr::null_mut()) };
    }

    #[test]
    fn last_error_is_initialised() {
        // Trigger a known failure so the thread-local has a stable
        // value, then read it back.
        let _ = parse_pub_key("nope");
        set_last_error("seeded");
        let ptr = bifrost_last_error();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, "seeded");
    }
}
