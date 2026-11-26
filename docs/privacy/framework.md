# Framework data handling

The default guest business path is local. It does not call APTIST Portal, a cloud telemetry service, an application-reputation service or an automatic speed test. LOFT network operations begin for an explicit VPN/test operation; node bootstrap resolution is separate from tunneled business DNS. The merged APK retains standard AndroidX Emoji2/lifecycle/profileinstaller initialization; the current absence of configured push SDKs or added business polling does not imply that all platform initialization is absent.

| Data | Current location and purpose | Retention / disclosure |
| --- | --- | --- |
| Node credential URI/material | SQLCipher in app-private storage, Rust working set and short-lived private service → Go startup | Encrypted across restarts and excluded from ordinary saved state, reports and diagnostic exports |
| Redacted node metadata | Immutable Rust snapshot/page → private Binder → visible UI | One page and bounded selected metadata; endpoint/label is still local connection metadata |
| Appearance and navigation | Retained ViewModel; only theme/locale preferences persist | No node/identity secrets in ordinary preferences |
| Routing packages | Encrypted Rust draft and exact confirmed PackageManager-reported Builder scope | Local. Android 11+ discovery covers the reported MAIN+LAUNCHER scope and uses no QUERY_ALL permission |
| Network policy/scope | Rust ticket → private service → Go current session | Canonical policy is immutable, secret-free and idempotent while live; raw credentials stay one-use. Actual UID/package scope remains private, diagnostics publish a scoped correlation hash and modes |
| Synthetic DNS domains/aliases | Current bounded Go mapping, at most256 entries/256 KiB | Restore original FQDN only through the selected proxy; maximum advertised TTL and atomic/live-I/O leases bound reuse; fully joined Stop clears dynamic domain state |
| DNS address quarantine | Process-owned65,534-slot deadline table, fixed528 KiB inside8 MiB | Retains only address deadlines/cursor/origin, no domain history; passive expiry permits reuse, process exit frees the fixed metadata |
| Socket/TUN resource facts | Go → private service → Rust receipt/UI | Versions, counters, generations and booleans; no traffic payload or credential URI |
| Closed privacy totals | One redacted final Go Facts record | Same ended epoch/scope until next policy/attempt; all active flags false/off and dynamic ownership zero, never a live protection proof |
| Cloud server candidate | Encrypted Rust normalized HTTPS origin | Staged as unverified. The candidate receives no credentials |
| Account/mail/Shield | Unavailable framework adapters | No password/PVS/clientSecret/Portal bearer capture, fabricated inbox or malware verdict |
| System notifications | VPN foreground lease/channel; independent default-denied mail boundary | Native icon and actual state only; permission/channel visibility is separate from running FGS. API29 posted-icon/FGS/Stop is recorded; real mail source/subscription/provider remains unconfigured, no mail payloads are produced |
| Private TEST/Task inputs | Local ignored files; bounded test/transport helpers only | One-use Android test staging, no APK asset/argument; Git index/artifact scan before delivery |

Rust clears its owned sensitive buffers with zeroize. Go/Kotlin immutable strings and runtime copies cannot offer a blanket memory-erasure guarantee; bound their lifetime, avoid logs/caches and never claim that clearing one byte array erased every copy.

Android backup and device transfer rules exclude the guest store. Android Keystore protects the database key. Permanent key loss requires clearing LOFT app storage in Android Settings and re-importing the nodes. [Encrypted storage contract](../contracts/encrypted-storage.md)

Delivery excludes guide, Prompt, tmp, build outputs, local signing keys and private probes. The secret verifier reads actual Git-index blobs and bounded archive members, including known PAT and private URI/key forms; it never prints credential values. Its verification is a concrete delivery check, not a universal detection claim.

Handset screenshots and diagnostics must use public synthetic metadata or explicitly protected redaction. The design PNG/PDF are reference layouts rather than device evidence. Any future software reputation, remote audit or mailbox export must document its actual fields, destination, purpose, authorization and retention before it is enabled.
