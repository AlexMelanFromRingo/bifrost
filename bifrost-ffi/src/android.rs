//! Android JNI bridge.
//!
//! A Kotlin `VpnService` can't call the crate's `extern "C"` surface
//! directly — JNI needs functions named `Java_<pkg>_<Class>_<method>`.
//! This module is that thin layer. Compiled only for `*-linux-android`.
//!
//! It also installs a file-backed `tracing` subscriber so the
//! Rust-side connect / handshake logs land in a file the app can read.
//!
//! ## Lifecycle
//!
//! `bifrost_client_start` is **non-blocking**: it runs the handshake,
//! then `run_client_pump` *spawns* the data-plane tasks onto the tokio
//! runtime and returns. So `nativeClientStart` returns a handle to a
//! *live, running* tunnel — the caller must hold that handle for the
//! whole session and only pass it to `nativeClientStop` to tear down.
//!
//! Kotlin side (`org.norn.bifrost.NativeBridge`):
//!
//! ```kotlin
//! object NativeBridge {
//!     init { System.loadLibrary("bifrost_ffi") }
//!     external fun nativeAbiVersion(): Int
//!     external fun nativeClientStart(tunFd: Int, configJson: String,
//!                                    exitKeyHex: String, logPath: String): Long
//!     external fun nativeClientStop(handle: Long)
//!     external fun nativeLastError(): String
//! }
//! ```

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Once;

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jstring};
use jni::JNIEnv;

/// Install a `tracing` subscriber that appends every Rust log event to
/// `path`. Once per process — `bifrost_client_start`'s own
/// `install_log_sink_once` then no-ops, so the norn-rs transport /
/// egress logs flow into this file instead of being discarded.
fn install_file_log(path: &str) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let p = path.to_owned();
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

/// `NativeBridge.nativeAbiVersion()`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    crate::bifrost_ffi_abi_version() as jint
}

/// `NativeBridge.nativeClientStart(tunFd, configJson, exitKeyHex, logPath)`
/// — bring up the client tunnel over the host TUN fd. **Blocks** for
/// the handshake (~seconds), then returns: the data plane keeps
/// running on the native runtime. Returns an opaque handle (as a
/// `jlong`) the caller must keep and later pass to `nativeClientStop`;
/// `0` means the connection failed (see `nativeLastError`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeClientStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    exit_key_hex: JString<'local>,
    log_path: JString<'local>,
) -> jlong {
    let cfg = match env.get_string(&config_json) {
        Ok(s) => String::from(s),
        Err(_) => return 0,
    };
    let key = match env.get_string(&exit_key_hex) {
        Ok(s) => String::from(s),
        Err(_) => return 0,
    };
    if let Ok(s) = env.get_string(&log_path) {
        let lp = String::from(s);
        if !lp.is_empty() {
            install_file_log(&lp);
        }
    }
    tracing::info!("nativeClientStart: starting (tun_fd={tun_fd})");

    let (cfg_c, key_c) = match (CString::new(cfg), CString::new(key)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return 0,
    };

    let mut handle: *mut crate::BifrostClient = ptr::null_mut();
    // SAFETY: both C strings are valid NUL-terminated UTF-8 for the
    // call; `handle` points at writable pointer-sized storage.
    let status = unsafe {
        crate::bifrost_client_start(tun_fd, cfg_c.as_ptr(), key_c.as_ptr(), &mut handle)
    };
    tracing::info!(
        "nativeClientStart: status={status} handle={}",
        if handle.is_null() { "null" } else { "live" }
    );
    // On success `handle` is a live, running tunnel — hand it back so
    // the caller keeps it alive. On failure it stays null → 0.
    handle as jlong
}

/// `NativeBridge.nativeClientStop(handle)` — tear down a tunnel from
/// `nativeClientStart`. Null-safe; idempotent if the caller zeroes its
/// copy after the call.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeClientStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    tracing::info!("nativeClientStop: stopping");
    // SAFETY: `handle` is a pointer previously returned by
    // `nativeClientStart` (a `bifrost_client_start` handle); the Kotlin
    // side calls this exactly once per handle.
    unsafe { crate::bifrost_client_stop(handle as *mut crate::BifrostClient) };
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
