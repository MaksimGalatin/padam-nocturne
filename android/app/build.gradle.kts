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
    // Бенчмарк AIFaSecurity-100 кладётся внутрь пакета, как в колесе PyPI (padam/aifa_security).
    // Без него кнопка «Запустить 100 проверок» в APK 0.7.0 отвечала «package not found» (отчёт Сестры 20.11.2026).
    from(rootProject.file("../benchmarks/aifa_security")) {
        include("*.py")
        into("aifa_security")
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
        versionCode = 12
        versionName = "0.9.0"

        ndk {
            abiFilters += targetAbis
        }
    }

    signingConfigs {
        val ksPath = System.getenv("PADAM_KEYSTORE_PATH")?.trim()
        val ksPass = System.getenv("PADAM_KEYSTORE_PASS")?.trim()
        val ksAlias = System.getenv("PADAM_KEY_ALIAS")?.trim()
        val ksKeyPass = System.getenv("PADAM_KEY_PASS")?.trim()
        if (!ksPath.isNullOrEmpty() && !ksPass.isNullOrEmpty() && !ksAlias.isNullOrEmpty() && !ksKeyPass.isNullOrEmpty()) {
            create("release") {
                storeFile = file(ksPath)
                storePassword = ksPass
                keyAlias = ksAlias
                keyPassword = ksKeyPass
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfigs.findByName("release")?.let { signingConfig = it }
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
