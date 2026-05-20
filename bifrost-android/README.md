# bifrost-android

A minimal but complete Android client for the Bifrost mesh VPN — a
`VpnService` app that drives the same `bifrost-vpnd` client data plane
the desktop client uses, via the `bifrost-ffi` JNI bridge.

It is deliberately dependency-light: no AndroidX, no layout XML, no
CMake. The UI is built in code; the native library is cross-built
ahead of time and dropped into `jniLibs/`.

## Layout

```
bifrost-android/
  app/src/main/
    java/org/norn/bifrost/
      NativeBridge.kt      — external fun declarations + System.loadLibrary
      BifrostVpnService.kt — VpnService: builds the TUN, runs the native pump
      MainActivity.kt      — one-screen UI: exit key, TUN address, config
    jniLibs/<abi>/libbifrost_ffi.so   — cross-built native library
    res/values/strings.xml
    AndroidManifest.xml
  build.gradle.kts, settings.gradle.kts, app/build.gradle.kts
```

The JNI entry points (`Java_org_norn_bifrost_NativeBridge_*`) live in
the Rust crate at `bifrost-ffi/src/android.rs`, compiled only for
`*-linux-android` targets.

## Building

### 1. The native library

Cross-built with [`cargo-ndk`](https://github.com/bbqsrc/cargo-ndk)
(`cargo install cargo-ndk`) against the Android NDK:

```bash
cd /path/to/bifrost
ANDROID_NDK_HOME=$ANDROID_SDK/ndk/<version> \
  cargo ndk -t arm64-v8a -t x86_64 \
    -o ./bifrost-android/app/src/main/jniLibs \
    build --release -p bifrost-ffi
```

`arm64-v8a` covers virtually every real device; `x86_64` is for the
emulator. Add `-t armeabi-v7a` for 32-bit ARM if needed.

### 2. The APK

```bash
cd bifrost-android
./gradlew assembleDebug
# → app/build/outputs/apk/debug/app-debug.apk
```

`local.properties` must point `sdk.dir` at your Android SDK. Install
with `adb install -r app/build/outputs/apk/debug/app-debug.apk`.

## Using it

1. **Exit node public key** — the 64-hex key of the `bifrost-vpnd`
   exit you are connecting to.
2. **TUN address** — the IPv4 the exit leases you. With persistent
   leases (roadmap #6) a returning client keeps the same address;
   set this to that lease.
3. **Node config (JSON)** — a `norn-rs` `NodeConfig`. Fill in a real
   `private_key` (e.g. from `nornd genconfig`) and the exit's mesh
   address under `peers`. `tun_name` is forced to `null` by the FFI —
   the host owns the single TUN fd.

"Connect" asks for the system VPN consent, then starts the tunnel.
Native logs land in logcat under the tag `BifrostVpn`.

## Known limitations (this is a test client)

* **`nativeRunClient` blocks for the whole session.** The Kotlin side
  runs it on a worker thread; "Disconnect" closes the TUN, which makes
  the native pump's reads fail and unwinds the call. A non-blocking
  start / explicit stop signal would need an FFI change.
* **The TUN address is entered by hand.** `VpnService.Builder` needs
  the address before `.establish()`, but the exit allocates it during
  the handshake. A production client would split handshake from
  establish; here the user supplies the lease address directly.
* No foreground-service notification, no auto-reconnect, no DNS
  beyond a hardcoded resolver — all intentionally out of scope for a
  test harness.
