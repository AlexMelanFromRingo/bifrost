//! Android JNI bridge.
//!
//! A Kotlin `VpnService` can't call the crate's `extern "C"` surface
//! directly — JNI needs functions named `Java_<pkg>_<Class>_<method>`.
//! This module is that thin layer. Compiled only for `*-linux-android`.
//!
//! It also installs a file-backed `tracing` subscriber so the
//! Rust-side connect / handshake logs land in a file the app can read.
//!
//! ## Lifecycle — two phases
//!
//! `VpnService` must commit the TUN's IP address *before* it hands us
//! the fd, but the address is assigned by the exit mid-handshake. So
//! bring-up is split:
//!
//!  1. `nativeClientConnect` runs the handshake and returns the
//!     exit-assigned IPv4 lease + MTU (plus an opaque handle).
//!  2. Kotlin configures `VpnService.Builder` with that address and
//!     calls `establish()`.
//!  3. `nativeClientRun` attaches the fd and starts the data plane.
//!
//! The handle stays live for the whole session; pass it to
//! `nativeClientStop` to tear down (also on a failed `run`).
//!
//! Kotlin side (`org.norn.bifrost.NativeBridge`):
//!
//! ```kotlin
//! object NativeBridge {
//!     init { System.loadLibrary("bifrost_ffi") }
//!     external fun nativeAbiVersion(): Int
//!     // [handle, leaseV4, mtu] on success, [0] on failure.
//!     external fun nativeClientConnect(configJson: String,
//!                                      exitKeyHex: String,
//!                                      logPath: String): LongArray
//!     external fun nativeClientRun(handle: Long, tunFd: Int): Int
//!     external fun nativeClientStop(handle: Long)
//!     external fun nativeLastError(): String
//! }
//! ```

use std::ffi::{CStr, CString};
use std::ptr;
use std::sync::Once;

use jni::objects::{JClass, JString};
use jni::sys::{jint, jlong, jlongArray, jstring};
use jni::JNIEnv;

/// Install a `tracing` subscriber that appends every Rust log event to
/// `path`. Once per process — `bifrost_client_connect`'s own
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

/// Build the single-element `[0]` `LongArray` that marks a failed
/// `nativeClientConnect`. Returns a null `jlongArray` only if even the
/// array allocation fails (OOM) — Kotlin treats both as failure.
fn connect_failure(env: &mut JNIEnv) -> jlongArray {
    match env.new_long_array(1) {
        Ok(arr) => {
            let _ = env.set_long_array_region(&arr, 0, &[0]);
            arr.into_raw()
        }
        Err(_) => ptr::null_mut(),
    }
}

/// `NativeBridge.nativeClientConnect(configJson, exitKeyHex, logPath)`
/// — phase 1: start the node and run the egress handshake. **Blocks**
/// for the handshake (~seconds); call on a background thread.
///
/// Returns a `LongArray`: `[handle, leaseV4, mtu]` on success
/// (`leaseV4` is the exit-assigned IPv4 in host byte order), or `[0]`
/// on failure (see `nativeLastError`). The caller keeps `handle`,
/// passes it to `nativeClientRun`, and finally `nativeClientStop`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeClientConnect<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    exit_key_hex: JString<'local>,
    log_path: JString<'local>,
) -> jlongArray {
    let cfg = match env.get_string(&config_json) {
        Ok(s) => String::from(s),
        Err(_) => return connect_failure(&mut env),
    };
    let key = match env.get_string(&exit_key_hex) {
        Ok(s) => String::from(s),
        Err(_) => return connect_failure(&mut env),
    };
    if let Ok(s) = env.get_string(&log_path) {
        let lp = String::from(s);
        if !lp.is_empty() {
            install_file_log(&lp);
        }
    }
    tracing::info!("nativeClientConnect: starting handshake");

    let (cfg_c, key_c) = match (CString::new(cfg), CString::new(key)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return connect_failure(&mut env),
    };

    let mut handle: *mut crate::BifrostClient = ptr::null_mut();
    let mut lease_v4: u32 = 0;
    let mut mtu: u16 = 0;
    // SAFETY: both C strings are valid NUL-terminated UTF-8 for the
    // call; the three out-params point at the locals above.
    let status = unsafe {
        crate::bifrost_client_connect(
            cfg_c.as_ptr(),
            key_c.as_ptr(),
            &mut handle,
            &mut lease_v4,
            &mut mtu,
        )
    };
    tracing::info!(
        "nativeClientConnect: status={status} handle={} lease_v4={lease_v4:#010x} mtu={mtu}",
        if handle.is_null() { "null" } else { "live" },
    );
    if status != 0 || handle.is_null() {
        return connect_failure(&mut env);
    }

    // [handle, leaseV4, mtu] — handle is a pointer; arm64/x86_64
    // Android are both LP64 so it round-trips through a jlong cleanly.
    let arr = match env.new_long_array(3) {
        Ok(a) => a,
        Err(_) => {
            // Can't hand the handle back — free it so it doesn't leak.
            unsafe { crate::bifrost_client_stop(handle) };
            return connect_failure(&mut env);
        }
    };
    let vals: [jlong; 3] = [handle as jlong, lease_v4 as jlong, mtu as jlong];
    if env.set_long_array_region(&arr, 0, &vals).is_err() {
        unsafe { crate::bifrost_client_stop(handle) };
        return connect_failure(&mut env);
    }
    arr.into_raw()
}

/// `NativeBridge.nativeClientRun(handle, tunFd)` — phase 2: attach the
/// established TUN fd and start the data plane. Returns a
/// `BifrostStatus` code (`0` = ok). The data plane keeps running on
/// the native runtime; the caller still owns `handle` and must pass it
/// to `nativeClientStop` to tear down (including after a failed run).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeClientRun(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    tun_fd: jint,
) -> jint {
    if handle == 0 {
        return crate::BifrostStatus::InvalidArg as jint;
    }
    tracing::info!("nativeClientRun: starting data plane (tun_fd={tun_fd})");
    // SAFETY: `handle` came from a successful `nativeClientConnect`;
    // the Kotlin side calls `run` at most once per handle.
    let status =
        unsafe { crate::bifrost_client_run(handle as *mut crate::BifrostClient, tun_fd) };
    tracing::info!("nativeClientRun: status={status}");
    status as jint
}

/// `NativeBridge.nativeClientStop(handle)` — tear down a tunnel from
/// `nativeClientConnect`. Null-safe; idempotent if the caller zeroes
/// its copy after the call.
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
    // `nativeClientConnect`; the Kotlin side calls this exactly once
    // per handle.
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
