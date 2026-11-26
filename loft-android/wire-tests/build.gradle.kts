plugins { kotlin("jvm") }
java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin {
    jvmToolchain(21)
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    sourceSets {
        main {
            kotlin.srcDirs("../app/src/main/kotlin", "../app/build/generated/uniffi", "../ui-foundation/src/main/kotlin")
            kotlin.include("net/aptist/loft/service/SnapshotWire.kt", "net/aptist/loft/service/SnapshotPublisher.kt",
                "net/aptist/loft/service/SnapshotConsumer.kt", "net/aptist/loft/core/generated/*.kt",
                "net/aptist/loft/service/GoVpnSnapshot.kt",
                "net/aptist/loft/service/GoNetworkPrivacyFacts.kt",
                "net/aptist/loft/service/GoRuntimeInfo.kt",
                "net/aptist/loft/service/GoNetworkPolicy.kt",
                "net/aptist/loft/service/NetworkPrivacyAdapter.kt",
                "net/aptist/loft/service/NetworkPrivacyReceipts.kt",
                "net/aptist/loft/service/NetworkResourceSnapshot.kt",
                "net/aptist/loft/service/VpnNotificationProjection.kt",
                "net/aptist/loft/service/GoSnapshotAdmission.kt",
                "net/aptist/loft/service/CoreAvailabilityGuard.kt",
                "net/aptist/loft/service/NodePageWire.kt", "net/aptist/loft/service/NodePageConsumer.kt", "net/aptist/loft/service/NodeChoice.kt",
                "net/aptist/loft/foundation/ControlCodec.kt", "net/aptist/loft/foundation/NetworkPrivacyDraft.kt",
                "net/aptist/loft/foundation/SnapshotSequence.kt")
        }
        test {
            kotlin.srcDir("../app/src/test/kotlin")
            kotlin.srcDir("../app/src/testCommon/kotlin")
            kotlin.include("net/aptist/loft/service/SnapshotWireTest.kt", "net/aptist/loft/service/SnapshotPublicationTest.kt",
                "net/aptist/loft/service/GoVpnSnapshotTest.kt")
            kotlin.include("net/aptist/loft/service/GoRuntimeInfoTest.kt")
            kotlin.include("net/aptist/loft/service/GoNetworkPolicyTest.kt", "net/aptist/loft/testing/NetworkPrivacyFixtures.kt")
            kotlin.include("net/aptist/loft/service/NetworkPrivacyReceiptsTest.kt")
            kotlin.include("net/aptist/loft/service/NetworkResourceSnapshotTest.kt")
            kotlin.include("net/aptist/loft/service/VpnNotificationProjectionTest.kt")
            kotlin.include("net/aptist/loft/service/GoSnapshotAdmissionTest.kt")
            kotlin.include("net/aptist/loft/service/GoPendingStartupReceiptTest.kt")
            kotlin.include("net/aptist/loft/service/CoreAvailabilityGuardTest.kt")
            kotlin.include("net/aptist/loft/service/NodePageWireTest.kt", "net/aptist/loft/service/NodePageSelectionTest.kt")
        }
    }
}
sourceSets.test { resources.srcDir("../app/src/test/resources") }
dependencies {
    val sdk = providers.environmentVariable("ANDROID_HOME").orElse(providers.environmentVariable("ANDROID_SDK_ROOT")).get()
    compileOnly(files("$sdk/platforms/android-36/android.jar"))
    compileOnly("androidx.annotation:annotation-jvm:1.9.1")
    implementation("net.java.dev.jna:jna:5.18.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20250517")
}
tasks.test { useJUnit() }
