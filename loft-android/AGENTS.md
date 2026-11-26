# Native Android framework

This subtree owns Compose UI, Android Binder/system boundaries and presentation-only drafts. Read the root AGENTS.md, docs/contracts/framework.md and docs/contracts/encrypted-storage.md. Do not initialize AppCore outside the private :vpn service or introduce a Kotlin business state machine.

The retained activity ViewModel owns one service binding for the UI session. STARTED visibility subscribes; STOPPED visibility unsubscribes. Theme/language/activity recreation must preserve the binding. Native snapshots and receipts drive displayed business state. No timers/polling, TUN, VPN permission, authentication, mail, scanning or verification success is simulated.

Unsubmitted imports and draft inputs stay in memory. The private command worker opens one Rust SQLCipher store using a transient database key unwrapped by Android Keystore. Backup and device-transfer exclusions cover the database and key envelope. A failed open preserves existing files and uses typed local recovery status. The import route uses FLAG_SECURE, disables autofill and clears raw material on successful import/discard. Presentation preferences may persist only locale and theme. No sensitive values enter logs, activity state, event summaries or ordinary preference storage.

Generate UniFFI, Rust JNI libraries and gomobile AAR into app/build/generated, never committed source. Gradle 8.13 / AGP 8.13.2 / Kotlin 2.3.21 / Compose BOM 2026.03.01 / SDK 36 / minimum API 29 are pinned. Production release is unsigned by default. Native packaging is uncompressed and final ELF/ZIP alignment is verified by the root integrator.

Use TDD for navigation, catalog, input-size/decoder, routing-draft and lifecycle boundaries. Only run large builds when the root integrator grants a build slot. Verified commands and limitations live in PROGRESS.md; do not claim device acceptance from compilation.
