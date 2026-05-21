import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// Exit-server defaults are injected from a gitignored `exit.properties`
// at the project root, so the committed source never carries a real
// server address. Absent file → blank defaults (the user types the
// address once; it then persists in SharedPreferences).
val exitProps = Properties().apply {
    val f = rootProject.file("exit.properties")
    if (f.exists()) f.inputStream().use { load(it) }
}

android {
    namespace = "org.norn.bifrost"
    compileSdk = 34

    defaultConfig {
        applicationId = "org.norn.bifrost"
        // 29 (Android 10): MediaStore.Downloads lets the app drop its
        // log into the public Downloads folder with no permissions.
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"

        // Server defaults from exit.properties (see top of file).
        buildConfigField(
            "String", "DEFAULT_EXIT_KEY",
            "\"${exitProps.getProperty("exit.key", "")}\"",
        )
        buildConfigField(
            "String", "DEFAULT_EXIT_ADDR",
            "\"${exitProps.getProperty("exit.addr", "")}\"",
        )
    }

    buildFeatures {
        // Required for the custom buildConfigField()s above.
        buildConfig = true
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

dependencies {
    // Pure-Java QR codec (no AndroidX) — encode for "Show QR for
    // sharing", decode for the camera scanner. See Qr / QrScanActivity.
    implementation("com.google.zxing:core:3.5.3")
}
