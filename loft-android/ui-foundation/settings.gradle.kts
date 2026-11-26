// Standalone entry point for boundary tests without Android SDK/native inputs.
pluginManagement {
    repositories { mavenCentral(); gradlePluginPortal() }
    plugins { id("org.jetbrains.kotlin.jvm") version "2.3.21" }
}
dependencyResolutionManagement { repositories { mavenCentral() } }
rootProject.name = "loft-ui-foundation"
