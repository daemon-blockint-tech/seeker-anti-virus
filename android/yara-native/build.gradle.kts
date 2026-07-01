plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.daemonblockint.sync.yara"
    compileSdk = 34

    defaultConfig {
        minSdk = 26

        externalNativeBuild {
            cmake {
                cppFlags("-std=c++17", "-fexceptions", "-frtti")
                arguments("-DANDROID_STL=c++_shared")
            }
        }

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    testImplementation(libs.junit)
    testImplementation(libs.mockk)
}
