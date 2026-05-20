package org.norn.bifrost

/**
 * Kotlin face of `libbifrost_ffi.so`. The `.so` is cross-built ahead of
 * time by cargo-ndk (see `bifrost-android/README.md`) and ships in
 * `jniLibs/<abi>/`. The JNI entry points live in the Rust crate's
 * `src/android.rs`.
 */
object NativeBridge {
    init { System.loadLibrary("bifrost_ffi") }

    /** ABI version the loaded `.so` was built with. */
    external fun nativeAbiVersion(): Int

    /**
     * Bring up the client tunnel over [tunFd]. **Blocks** for the
     * handshake (a few seconds) — call on a background thread — then
     * returns: the data plane keeps running on the native runtime.
     *
     * Returns an opaque handle to the live tunnel; keep it and pass it
     * to [nativeClientStop] to tear down. `0` means the connection
     * failed (see [nativeLastError]).
     *
     * [logPath] is a plain filesystem path the native side appends its
     * `tracing` log to. Empty disables the native file log.
     */
    external fun nativeClientStart(
        tunFd: Int, configJson: String, exitKeyHex: String, logPath: String,
    ): Long

    /** Tear down a tunnel returned by [nativeClientStart]. Null-safe (0 = no-op). */
    external fun nativeClientStop(handle: Long)

    /** Human-readable description of the most recent native failure. */
    external fun nativeLastError(): String

    /** ABI version this app was compiled against; assert against the .so. */
    const val EXPECTED_ABI_VERSION = 1
}
