//! Android JNI bridge.
//!
//! A Kotlin `VpnService` can't call the crate's `extern "C"` surface
//! directly — JNI needs functions named `Java_<pkg>_<Class>_<method>`.
//! This module is that thin layer: it converts the JVM argument types,
//! calls into the C ABI in [`crate`], and hands back a status code.
//! Compiled only for `*-linux-android` targets.
//!
//! It also installs a file-backed `tracing` subscriber so the
//! Rust-side connect / handshake logs (the ones that actually explain
//! a failed tunnel) land in a file the app can read back — the C ABI's
//! default `install_log_sink_once` otherwise drops them on the floor.
//!
//! Kotlin side (`org.norn.bifrost.NativeBridge`):
//!
//! ```kotlin
//! object NativeBridge {
//!     init { System.loadLibrary("bifrost_ffi") }
//!     external fun nativeAbiVersion(): Int
//!     external fun nativeRunClient(tunFd: Int, configJson: String,
//!                                  exitKeyHex: String, logPath: String): Int
//!     external fun nativeLastError(): String
//! }
//! ```
//!
//! `nativeRunClient` **blocks for the whole VPN session** — call it on
//! a dedicated background thread; stop the tunnel by closing the TUN
//! file descriptor.

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Once;

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

use crate::BifrostStatus;

/// Install a `tracing` subscriber that appends every Rust log event to
/// `path`. Once per process — the global default can only be set once,
/// so the first `nativeRunClient` call wins. `bifrost_client_start`'s
/// own `install_log_sink_once` then no-ops (global already set), so the
/// norn-rs transport / egress logs flow into this file instead of being
/// discarded.
fn install_file_log(path: &str) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let p = path.to_owned();
        // Open per event — log volume during connection setup is tiny,
        // and this keeps the writer dead simple (no shared handle).
        let make = move || -> Box<dyn std::io::Write + Send> {
            match std::fs::OpenOptions::new().create(true).append(true).open(&p) {
                Ok(f) => Box::new(f),
                Err(_) => Box::new(std::io::sink()),
            }
        };
        let subscriber = tracing_subscriber::fmt()
            .with_writer(make)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        tracing::info!("bifrost-ffi: file log opened");
    });
}

/// `NativeBridge.nativeAbiVersion()` — the ABI version the `.so` was
/// built with.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    crate::bifrost_ffi_abi_version() as jint
}

/// `NativeBridge.nativeRunClient(tunFd, configJson, exitKeyHex, logPath)`
/// — install the file log, bring up the client tunnel over the host
/// TUN fd, and pump traffic until the session ends. Returns a
/// [`BifrostStatus`] code (`0` = clean exit). **Blocks.**
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeRunClient<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    exit_key_hex: JString<'local>,
    log_path: JString<'local>,
) -> jint {
    let cfg = match env.get_string(&config_json) {
        Ok(s) => String::from(s),
        Err(_) => return BifrostStatus::InvalidArg as jint,
    };
    let key = match env.get_string(&exit_key_hex) {
        Ok(s) => String::from(s),
        Err(_) => return BifrostStatus::InvalidArg as jint,
    };
    // The log path is best-effort — a bad/empty one just means no file log.
    if let Ok(s) = env.get_string(&log_path) {
        let lp = String::from(s);
        if !lp.is_empty() {
            install_file_log(&lp);
        }
    }
    tracing::info!("nativeRunClient: starting (tun_fd={tun_fd})");

    let (cfg_c, key_c) = match (CString::new(cfg), CString::new(key)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return BifrostStatus::InvalidArg as jint,
    };

    let mut handle: *mut crate::BifrostClient = ptr::null_mut();
    // SAFETY: both C strings are valid NUL-terminated UTF-8 for the
    // call; `handle` points at writable pointer-sized storage.
    let status = unsafe {
        crate::bifrost_client_start(tun_fd, cfg_c.as_ptr(), key_c.as_ptr(), &mut handle)
    };
    tracing::info!("nativeRunClient: bifrost_client_start returned status={status}");
    if !handle.is_null() {
        // SAFETY: `handle` came from the successful call above.
        unsafe { crate::bifrost_client_stop(handle) };
    }
    status as jint
}

/// `NativeBridge.nativeLastError()` — the most recent failure string.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeLastError<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    // SAFETY: `bifrost_last_error` always returns a valid pointer to a
    // NUL-terminated string owned by the FFI thread-local.
    let msg = unsafe { CStr::from_ptr(crate::bifrost_last_error()) }
        .to_string_lossy()
        .into_owned();
    env.new_string(msg)
        .map(|s| s.into_raw())
        .unwrap_or(ptr::null_mut())
}
