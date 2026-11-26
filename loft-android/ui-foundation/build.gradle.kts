plugins { id("org.jetbrains.kotlin.jvm") }
// The standalone test entry must not share Kotlin incremental outputs with
// the Android root build when the integrator coordinates separate checks.
if (rootProject.name == "loft-ui-foundation") {
    layout.buildDirectory.set(layout.projectDirectory.dir("build/standalone"))
}
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    jvmToolchain(21)
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}
dependencies { testImplementation("junit:junit:4.13.2") }
tasks.test { useJUnit() }
