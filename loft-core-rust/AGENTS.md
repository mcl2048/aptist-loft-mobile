# Rust core ownership

Own `loft-core-rust/` only unless the active task explicitly authorizes another subtree. Read the root `AGENTS.md`, `docs/contracts/framework.md` and this workspace's `Readme.md`. Gateway/Portal sources are read-only inputs. Task files can contain real credentials; never print or copy them.

Keep client business state in Rust. `loft-core` does not depend on Android, Go, UniFFI or an implemented protocol transport. Its import material adapter uses maintained Rust parsing/crypto libraries without networking. `loft-ffi` only serializes access and converts boundary types. The service is the single owner of `AppCore`; no UI-owned success snapshots or fake engine receipts.

All imports, routing/profile mutations and lifetime/error behavior use TDD with real values/components. Watch expected behavior fail before implementation, then run the affected suite and the complete workspace suite. Never use source-text assertions, mock-only tests, real task secrets, production nodes or invented connection/security outcomes.

Retain finite count/byte limits and atomic commits. Credentials stay session-local in zeroizing buffers until a separately verified encrypted storage implementation exists. Origin normalization is not TLS or compatibility verification. Keep X application UDP at 1..1024 and Pro at 0..65507; do not treat Pro's envelope size as payload or an empty packet as EOF.

Actual VPN startup uses a service-only opaque single-use ticket, a frozen effective shared-UID routing set and matching engine/TUN/protection receipts. Attempt IDs are separate from UI/config generations. Never expose a ticket URI through Binder/UI, acknowledge original TUN closure from only a Go duplicate, or create Blocked without TUN-held/drop proof. Priority cancellation must not wait for the normal state mutex; poison queries return Unavailable from immutable published metadata. Preserve the Android capture-sequence ordering contract for equal-generation late frames.

Coordinate any exported API/error/record change with Android and the root integrator before generation. UniFFI 0.32 CLI configuration lives at `bindings/uniffi.toml`; per-crate Kotlin settings live at `crates/loft-ffi/uniffi.toml`. Generate bindings with the tool rather than editing them. Preserve immutable records and disposal ownership.

Use the pinned toolchain and at most two build workers. Coordinate release/NDK/Gradle builds. Required Rust checks from this directory: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked --no-fail-fast`. The root native build script owns Android link flags, packaging and 16 KiB alignment evidence.

Record actual red/green/failure commands and remaining boundaries in `docs/validation.md`. Exclude target output, private materials and generated binaries from delivery. Do not commit or push from an explicitly delegated ownership task unless the root integrator authorizes it.
