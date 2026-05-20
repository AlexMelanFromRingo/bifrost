plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.norn.bifrost"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.norn.bifrost"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            // No release signing config wired here — `assembleDebug`
            // is what produces an installable, debug-signed APK.
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    // The native library is cross-built ahead of time by cargo-ndk into
    // src/main/jniLibs/<abi>/libbifrost_ffi.so — AGP just packages it.
    // No externalNativeBuild / CMake step.
}
