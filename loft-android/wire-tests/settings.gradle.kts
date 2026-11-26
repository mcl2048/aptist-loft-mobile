pluginManagement {
    repositories { gradlePluginPortal(); google(); mavenCentral() }
    plugins { kotlin("jvm") version "2.3.21" }
}
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "loft-wire-tests"
