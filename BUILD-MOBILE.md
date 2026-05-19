# Cross-compiling `bifrost-ffi` for Android and iOS

`bifrost-ffi` is the C-ABI shim that lets a mobile host
(`VpnService` on Android, `NEPacketTunnelProvider` on iOS) drive
the same client-side data plane that `bifrost-vpnd` uses on
desktop Linux. It re-exports `client_handshake` +
`run_client_pump` from `bifrost-vpnd::egress` through an
`extern "C"` surface; the C header lives at
`bifrost-ffi/include/bifrost_ffi.h`.

This document describes the *cross-build* recipe. The desktop
build is the usual `cargo build -p bifrost-ffi --release` and
produces both a `.a` and a `.so`.

## ABI pinning

The header defines `BIFROST_FFI_ABI_VERSION`. Match it against
`bifrost_ffi_abi_version()` at app launch; abort if they
disagree. Bump the constant in lockstep on every breaking
signature change (param order, JSON config schema, status enum).

## Android

### Targets

```
aarch64-linux-android        # 64-bit ARM — every modern phone
armv7-linux-androideabi      # 32-bit ARM — old budget devices
x86_64-linux-android         # emulator / x86 tablets
i686-linux-android           # legacy emulator
```

The `cdylib` output (`libbifrost_ffi.so`) lands in
`target/<triple>/release/`. Drop one per ABI under
`app/src/main/jniLibs/<abi>/` in the Android project, then load
it with `System.loadLibrary("bifrost_ffi")`.

### Toolchain

The Android NDK ships a Clang toolchain that's compatible with
Rust's `cc`/`linker` settings. Pin to NDK r26d (LTS as of
2026-05); newer NDKs may rename `libgcc` → `libunwind` in a way
that breaks the `clang_rt.builtins` linkage on older targets.

```bash
# One-time setup
rustup target add aarch64-linux-android armv7-linux-androideabi \
                   x86_64-linux-android i686-linux-android
cargo install cargo-ndk
export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/26.3.11579264
```

### Build

```bash
cd bifrost
cargo ndk \
    -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 \
    -o ./android-libs/ \
    build -p bifrost-ffi --release
```

`cargo-ndk` resolves the per-ABI sysroot, sets `CC`/`AR`/`LINKER`
appropriately, and copies `libbifrost_ffi.so` into the
`android-libs/<abi>/` tree ready for `jniLibs/` ingestion.

### Java glue

A minimal Kotlin wrapper around the C symbols:

```kotlin
object Bifrost {
    init { System.loadLibrary("bifrost_ffi") }

    external fun abiVersion(): Int
    external fun clientStart(
        tunFd: Int,
        nodeConfigJson: String,
        exitPubKeyHex: String
    ): Long /* handle */
    external fun clientStop(handle: Long)
    external fun lastError(): String
}
```

The `external` declarations need matching JNI thunks; the easiest
path is `jnigen` or hand-rolled `JNIEnv*` wrappers around the C
functions. The TUN fd comes from
`VpnService.Builder.establish()`; convert with
`ParcelFileDescriptor.detachFd()` so the kernel fd outlives the
Java reference.

## iOS

### Targets

```
aarch64-apple-ios            # device
aarch64-apple-ios-sim        # arm64 simulator (M-series Macs)
x86_64-apple-ios             # x86_64 simulator (Intel Macs, deprecated)
```

The `staticlib` (`libbifrost_ffi.a`) is linked into the host
`.framework`/`.xcframework` via Xcode's "Link Binary With Libraries"
build phase. Apple's tooling won't accept a `cdylib` here — iOS
apps must statically link non-system code.

### Toolchain

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
# On a macOS host with full Xcode installed; cross-compiling iOS
# from Linux is not supported by Apple (no SDK headers).
```

### Build

```bash
cd bifrost
cargo build -p bifrost-ffi --release --target aarch64-apple-ios
cargo build -p bifrost-ffi --release --target aarch64-apple-ios-sim
```

To bundle both into one `.xcframework` (recommended for any
Swift Package consumer):

```bash
xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libbifrost_ffi.a \
        -headers bifrost-ffi/include \
    -library target/aarch64-apple-ios-sim/release/libbifrost_ffi.a \
        -headers bifrost-ffi/include \
    -output BifrostFFI.xcframework
```

Drop `BifrostFFI.xcframework` into your Xcode project; bridge to
Swift with a module map:

```
// bifrost-ffi/include/module.modulemap
module BifrostFFI {
    header "bifrost_ffi.h"
    export *
}
```

### Swift glue

```swift
import BifrostFFI

func startTunnel(tunFd: Int32, exitPubKey: String) -> OpaquePointer? {
    var handle: UnsafeMutablePointer<BifrostClient>? = nil
    let cfg = #"{"private_key": "...", "peers": ["tcp://1.2.3.4:9001"]}"#
    let status = bifrost_client_start(
        tunFd, cfg, exitPubKey, &handle
    )
    guard status == BIFROST_OK else {
        let err = String(cString: bifrost_last_error())
        NSLog("bifrost start failed: \(err)")
        return nil
    }
    return OpaquePointer(handle)
}
```

The TUN fd on iOS comes from `NEPacketTunnelProvider`'s
`packetFlow.value(forKey: "socket.fileDescriptor")` — undocumented
but stable since iOS 12; alternative is the `dup` trick over the
`NEPacketTunnelFlow` for explicit hand-off.

## Verification on the host

The crate compiles on desktop Linux/Darwin too, which gives a
fast feedback loop without dragging the cross toolchains in:

```bash
cargo test -p bifrost-ffi      # 11 tests, all on socketpair(2)
cargo clippy -p bifrost-ffi --all-targets -- -D warnings
```

The ABI surface is tested by `start_rejects_null_pointers`,
`start_rejects_short_exit_key`, and `stop_is_null_safe`; the
`HostTun` async wrapper is exercised end-to-end via a
`socketpair(2)`-backed round trip in `pipe_roundtrip_byte_stream`.
This is the same coverage you'd get from a CI runner without
CAP_NET_ADMIN — a real device test still needs a real TUN.

## Open work

* **No GSO/GRO on the host fd.** The kernel-side virtio framing
  (`IFF_VNET_HDR`) is intentionally NOT plumbed through the
  caller-provided TUN — `VpnService.Builder.establish()`'s
  contract is plain per-packet IP, and bypassing it disables the
  system VPN UI. If a future iOS/Android API exposes the
  underlying virtio path, we can re-use `bifrost-vpnd::tun_dev`
  with minor changes.
* **No platform log sinks.** `tracing-android` and
  `tracing-oslog` are unmaintained / NDK-incompatible at the
  moment. Capture stderr from the JNI / ObjC side instead. See
  the comment block in `bifrost-ffi/Cargo.toml`.
