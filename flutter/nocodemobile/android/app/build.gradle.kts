import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val keystoreProps = Properties().apply {
    val f = rootProject.file("key.properties")
    if (f.exists()) {
        load(FileInputStream(f))
    }
}

android {
    namespace = "com.modlix.nocodemobile"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    signingConfigs {
        create("release") {
            storeFile = file("keystore/release.keystore")
            keyAlias = keystoreProps["keyAlias"] as String
            keyPassword = keystoreProps["keyPassword"] as String
            storePassword = keystoreProps["storePassword"] as String
        }
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.modlix.nocodemobile"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // Custom URL scheme used by flutter_web_auth_2 to receive the social-login
        // (Google/Meta) callback from the system browser. Unique per app; make.py
        // overwrites this with "modlix.<clientCode>.<appCode>" at build time.
        manifestPlaceholders["ssoCallbackScheme"] = "modlix"
    }

    buildTypes {
        release {
            // Use the release signing config
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
        debug {
            // Keep debug signing for development
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

// flutter_web_auth_2 (social login) transitively pulls androidx.browser:1.9.0,
// whose AAR metadata requires AGP 8.9.1+. This project pins AGP 8.7.3, so pin
// androidx.browser to 1.8.0 (compatible with 8.7.3 and sufficient for Custom Tabs)
// to avoid a toolchain-wide AGP bump. Remove if/when AGP is upgraded to >= 8.9.1.
configurations.all {
    resolutionStrategy {
        force("androidx.browser:browser:1.8.0")
    }
}
