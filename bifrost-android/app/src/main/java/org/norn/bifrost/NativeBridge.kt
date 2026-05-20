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
     * Phase 1 — start the node and run the egress handshake.
     * **Blocks** for the handshake (a few seconds); call on a
     * background thread.
     *
     * Returns a `LongArray`: `[handle, leaseV4, mtu]` on success, or
     * `[0]` on failure (see [nativeLastError]). `leaseV4` is the
     * exit-assigned IPv4 address in host byte order; configure the TUN
     * with *that* address, then call [nativeClientRun].
     *
     * [logPath] is a plain filesystem path the native side appends its
     * `tracing` log to. Empty disables the native file log.
     */
    external fun nativeClientConnect(
        configJson: String, exitKeyHex: String, logPath: String,
    ): LongArray

    /**
     * Phase 2 — attach the established TUN [tunFd] and start the data
     * plane on the session from [nativeClientConnect]. Returns a
     * status code (`0` = ok). The data plane keeps running on the
     * native runtime; keep [handle] and pass it to [nativeClientStop].
     */
    external fun nativeClientRun(handle: Long, tunFd: Int): Int

    /** Tear down a tunnel from [nativeClientConnect]. Null-safe (0 = no-op). */
    external fun nativeClientStop(handle: Long)

    /** Human-readable description of the most recent native failure. */
    external fun nativeLastError(): String

    /** ABI version this app was compiled against; assert against the .so. */
    const val EXPECTED_ABI_VERSION = 2
}
