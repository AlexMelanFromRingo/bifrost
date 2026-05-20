//! Android JNI bridge.
//!
//! A Kotlin `VpnService` can't call the crate's `extern "C"` surface
//! directly — JNI needs functions named `Java_<pkg>_<Class>_<method>`.
//! This module is that thin layer: it converts the JVM argument types,
//! calls straight into the C ABI in [`crate`], and hands back a plain
//! status code. Compiled only for `*-linux-android` targets (see the
//! `Cargo.toml` target gate), so desktop and iOS builds never see it.
//!
//! Kotlin side (`org.norn.bifrost.NativeBridge`):
//!
//! ```kotlin
//! object NativeBridge {
//!     init { System.loadLibrary("bifrost_ffi") }
//!     external fun nativeAbiVersion(): Int
//!     external fun nativeRunClient(tunFd: Int, configJson: String, exitKeyHex: String): Int
//!     external fun nativeLastError(): String
//! }
//! ```
//!
//! `nativeRunClient` **blocks for the whole VPN session** — the
//! underlying `bifrost_client_start` runs the data-plane pump to
//! completion. The host must call it on a dedicated background thread
//! and stop the tunnel by closing the TUN file descriptor, which makes
//! the pump's TUN read fail and unwinds the call cleanly.

use std::ffi::{CStr, CString};
use std::ptr;

use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;

use crate::BifrostStatus;

/// `NativeBridge.nativeAbiVersion()` — the ABI version the `.so` was
/// built with. The app asserts it against its compiled-in constant at
/// launch to catch a stale `libbifrost_ffi.so`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    crate::bifrost_ffi_abi_version() as jint
}

/// `NativeBridge.nativeRunClient(tunFd, configJson, exitKeyHex)` —
/// bring up the client tunnel over the host-provided TUN fd and pump
/// traffic until the session ends. Returns a [`BifrostStatus`] code
/// (`0` = clean exit). **Blocks** — call from a background thread.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_norn_bifrost_NativeBridge_nativeRunClient<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    exit_key_hex: JString<'local>,
) -> jint {
    // JString → owned Rust String → C string. A conversion failure is
    // an InvalidArg, same class as a null pointer at the C boundary.
    let cfg = match env.get_string(&config_json) {
        Ok(s) => String::from(s),
        Err(_) => return BifrostStatus::InvalidArg as jint,
    };
    let key = match env.get_string(&exit_key_hex) {
        Ok(s) => String::from(s),
        Err(_) => return BifrostStatus::InvalidArg as jint,
    };
    let (cfg_c, key_c) = match (CString::new(cfg), CString::new(key)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => return BifrostStatus::InvalidArg as jint, // embedded NUL
    };

    let mut handle: *mut crate::BifrostClient = ptr::null_mut();
    // SAFETY: both C strings are valid NUL-terminated UTF-8 for the
    // duration of the call; `handle` points at writable pointer-sized
    // storage. `bifrost_client_start` blocks until the pump ends.
    let status = unsafe {
        crate::bifrost_client_start(tun_fd, cfg_c.as_ptr(), key_c.as_ptr(), &mut handle)
    };
    // On a clean exit `start` hands back a live handle whose only
    // remaining job is to wind the tokio runtime down — do that now so
    // the JNI call is fully self-contained and nothing leaks.
    if !handle.is_null() {
        // SAFETY: `handle` came from the successful call above and is
        // released exactly once here.
        unsafe { crate::bifrost_client_stop(handle) };
    }
    status as jint
}

/// `NativeBridge.nativeLastError()` — the most recent failure string,
/// for surfacing in the app UI.
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
