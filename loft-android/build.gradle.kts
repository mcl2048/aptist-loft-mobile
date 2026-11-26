import java.io.File

plugins {
    id("com.android.application") version "8.13.2" apply false
    id("org.jetbrains.kotlin.android") version "2.3.21" apply false
    id("org.jetbrains.kotlin.jvm") version "2.3.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.3.21" apply false
}

val testAbi = providers.gradleProperty("loftTestAbi").orNull
val nativeRoot = providers.gradleProperty("loftNativeGeneratedRoot").orNull
require((testAbi == null) == (nativeRoot == null)) { "Test ABI and generated native root must be supplied together" }
require(testAbi == null || testAbi == "x86_64") { "Only x86_64 is a supported test ABI" }
require(nativeRoot == null || File(nativeRoot).isAbsolute) { "Test native root must be an absolute path" }
require(providers.gradleProperty("loftAbi").orNull in setOf(null, "arm64-v8a")) { "Use loftTestAbi with an isolated native root for emulator tests" }
if (testAbi != null) {
    layout.buildDirectory.set(layout.projectDirectory.dir("build/test-x86_64"))
    subprojects { layout.buildDirectory.set(layout.projectDirectory.dir("build/test-x86_64")) }
}
