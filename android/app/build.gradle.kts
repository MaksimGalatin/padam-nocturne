plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
}

val padamAbiProp = (findProperty("padamAbi") as String?)?.trim()
val targetAbis = if (!padamAbiProp.isNullOrEmpty()) {
    padamAbiProp.split(",").map { it.trim() }.filter { it.isNotEmpty() }
} else {
    listOf("arm64-v8a", "x86_64")
}

val generatedPadamPy = layout.buildDirectory.dir("generated/padam_py")

val syncPadamPackage = tasks.register<Sync>("syncPadamPackage") {
    from(rootProject.file("../padam")) {
        exclude("**/__pycache__/**", "**/*.pyc", "**/*.pyo")
    }
    into(generatedPadamPy.map { it.dir("padam") })
}

android {
    namespace = "com.codeofdigitaleternity.padam"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.codeofdigitaleternity.padam"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.6.2-android"

        ndk {
            abiFilters += targetAbis
        }
    }

    buildTypes {
        release {
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

    sourceSets {
        getByName("main") {
            // Подключаем локальный мост Android и сгенерированную копию пакета padam/
            // (через python.srcDirs в chaquopy ниже)
        }
    }
}

chaquopy {
    defaultConfig {
        version = "3.11"
        pip {
            install("numpy")
            install("requests")
            install("cryptography")
        }
    }
    sourceSets {
        getByName("main") {
            srcDirs("src/main/python", generatedPadamPy.get().asFile.absolutePath)
        }
    }
}

tasks.named("preBuild") {
    dependsOn(syncPadamPackage)
}

tasks.configureEach {
    if (name.startsWith("merge") && name.endsWith("PythonSources")) {
        dependsOn(syncPadamPackage)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
}
