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
     * Bring up the client tunnel over [tunFd] and pump traffic until
     * the session ends. **Blocks for the whole session** — must be
     * called on a dedicated background thread. Returns a BifrostStatus
     * code: 0 = clean exit, non-zero = failure (see [nativeLastError]).
     *
     * [logPath] is a plain filesystem path the native side appends its
     * `tracing` log to (the norn-rs connect/handshake events). Empty
     * disables the native file log.
     */
    external fun nativeRunClient(
        tunFd: Int, configJson: String, exitKeyHex: String, logPath: String,
    ): Int

    /** Human-readable description of the most recent native failure. */
    external fun nativeLastError(): String

    /** ABI version this app was compiled against; assert against the .so. */
    const val EXPECTED_ABI_VERSION = 1
}
