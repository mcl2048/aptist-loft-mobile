plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

val loftReleaseVersion = providers.fileContents(rootProject.layout.projectDirectory.file("../VERSION")).asText.map { it.trim() }
val loftAbi = providers.gradleProperty("loftTestAbi").orElse("arm64-v8a").get()
val loftNativeRoot = providers.gradleProperty("loftNativeGeneratedRoot")
    .map { file(it) }.getOrElse(layout.projectDirectory.dir("build/generated").asFile)

android {
    namespace = "net.aptist.loft"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    ndkVersion = "28.2.13676358"
    defaultConfig {
        applicationId = "net.aptist.loft"
        minSdk = 29
        targetSdk = 36
        versionCode = 6
        versionName = loftReleaseVersion.get()
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        buildConfigField("String", "PRODUCT_ID", "\"loft\"")
        ndk { abiFilters += listOf(loftAbi) }
    }
    buildFeatures {
        compose = true
        aidl = true
        buildConfig = true
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets {
        getByName("main") {
            java.srcDir(loftNativeRoot.resolve("uniffi"))
            jniLibs.srcDir(loftNativeRoot.resolve("jniLibs"))
            assets.srcDir(layout.buildDirectory.dir("generated/license-assets"))
        }
        getByName("test") { java.srcDir("src/testCommon/kotlin") }
        getByName("androidTest") { java.srcDir("src/testCommon/kotlin") }
    }
    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            ndk { debugSymbolLevel = "SYMBOL_TABLE" }
            // The production release is unsigned. The integrator signs an explicitly
            // labelled development artifact outside Gradle using a local private key.
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    packaging {
        jniLibs { useLegacyPackaging = false }
        resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
    }
    lint { abortOnError = true }
}

val prepareLicenseAssets by tasks.registering(Sync::class) {
    from(rootProject.layout.projectDirectory.dir("../licenses"))
    into(layout.buildDirectory.dir("generated/license-assets/licenses"))
}
tasks.named("preBuild") { dependsOn(prepareLicenseAssets) }

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

dependencies {
    implementation(project(":ui-foundation"))
    implementation(platform("androidx.compose:compose-bom:2026.03.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.10.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.10.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.window:window:1.5.1")
    implementation("androidx.camera:camera-camera2:1.5.3")
    implementation("androidx.camera:camera-lifecycle:1.5.3")
    implementation("androidx.camera:camera-view:1.5.3")
    implementation("com.google.zxing:core:3.5.4")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation(files(loftNativeRoot.resolve("gomobile/loft-engine.aar")))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:core:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}
