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
      MainActivity.kt      — one-screen UI: exit key, exit address, identity
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
2. **Exit address** — the exit's mesh address, `tcp://host:port`.
3. **Your private key** — the node identity, generated on first
   launch and reused so the exit hands this device the same sticky
   lease every time.

The TUN address is **not** configured by hand: the exit leases it
during the handshake and the service applies it (see below).

"Connect" asks for the system VPN consent, then starts the tunnel.
Native logs land in logcat under the tag `BifrostVpn`.

## Two-phase bring-up

`VpnService.Builder` must commit the TUN's IP address before it hands
the app the fd, yet that address is leased by the exit *during* the
handshake. So `BifrostVpnService` brings the tunnel up in two native
phases (`bifrost-ffi`'s `bifrost_client_connect` then
`bifrost_client_run`): connect + handshake first, then `establish()`
with the leased address, then attach the fd and start the data plane.

## Roaming & auto-reconnect

The tunnel is built to survive a network change (Wi-Fi ↔ LTE) without
the user reconnecting by hand:

* The native data plane (`run_client_pump`) runs a supervisor that
  re-handshakes the exit whenever the control stream drops. The
  address lease is sticky by public key, so the TUN never has to be
  re-established.
* The service runs in the foreground with an ongoing notification, so
  the OS won't reclaim it during the roam window.
* A default-network callback re-pins the VPN underlay
  (`setUnderlyingNetworks`) on every roam.

## Known limitations (this is a test client)

* DNS is a hardcoded pair of public resolvers; there's no split-tunnel
  UI and no IPv6 inside the tunnel — out of scope for a test harness.
* The mesh transport socket is kept off the tunnel by a route
  exclusion rather than `VpnService.protect()`. Correct in practice; a
  native `protect()` hook would be marginally more robust on exotic
  roams.
