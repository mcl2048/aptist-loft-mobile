# LOFT v3.6 architecture context

The Android MVP uses native Compose, stable welcome/vpn/shield/mail/audit/setting/account/totp module IDs, four locales (en, zh, ja, de) and light/dark themes. A private service owns business state in Rust, generated UniFFI bindings cross the language boundary, and gomobile packages the actual source-pinned Go VPN adapter and its retained legacy controller. The runtime adapter supplies TUN/resource facts rather than business authority. Kotlin has no second authoritative state machine.

The full plan additionally calls for SOCKS5/hyrakenx/hyraken-pro QR/link import, selected-app proxy with unselected apps direct, physical socket protection, encrypted storage, Shield software/attestation policies, optional Portal BFF login and own-user mail. They are staged P0–P5 work: a framework release must identify what is implemented, planned and unverified.

The current framework implements three-protocol link parsing, a Keystore-wrapped SQLCipher guest store, the 200-node/50-row directory, VPN ownership and Stop, shared node-domain Fake-IP/RTC rules and native notification boundaries. LOFT Hub supplies durable Portal browser enrollment, scoped mail and the offline vault backup through Pages, Rust Workers and D1. QR, large FD imports, live TUN replacement/reconnect and Shield remain later adapters. The active Readme, requirements and task report record verified status.

The source inputs on this server are:

| Input | Exact path and pin |
| --- | --- |
| HyrakenX core | `/home/coder/Loft-Gateway/modules/hyrakenx`; Gateway `a984911c8aa0e932c885bb298134031432eb82b7` |
| Hyraken Pro core | `/home/coder/Loft-Gateway/pkg/hyrakenpro`; same Gateway pin |
| Node DNS/Firewall/Hydra | `/home/coder/Loft-Gateway/modules/dns`, `/home/coder/Loft-Gateway/modules/firewall`, `/home/coder/Loft-Gateway/modules/firewall/hydra` |
| Portal IDP/Mail | `/home/coder/aptist-portal/modules/idp`, `/home/coder/aptist-portal/modules/mail`; Portal `4ab2b37d08f9d7e304ae4d420d36d15c54dffa36` |

GhostX protocol/config adapters and `class-loft-saas-gateway.php` provide the integration/share contract. Reproducible mobile builds use the owned Go snapshot and `loft-vpn-engine-go/third_party/SOURCE-LOCK.json`, without requiring those upstream checkouts. DNS/Firewall rule libraries remain gateway subsystems; do not put their full data into the APK or turn an HTTPS/mail link into a global block decision. Shared mobile DNS/RTC guards precede all transport adapters; Hydra shaping is independent/Disabled by default and QUBF remains a separate future transport.

Portal provides `/api/idp`, exact issuer discovery, authorize, Basic token redemption, JWKS, UserInfo and mail list/detail/attachments. Confidential BFF credentials remain server-side. A pure Portal deployment does not yet provide LOFT's proposed `/.well-known/loft-app` or `/v1` endpoints. Public native OAuth requires a separately implemented and reviewed provider extension.

Physical quotas, UDP payload boundaries, lifetime and half-close semantics and source-account authorization are source-derived constraints. Guest persistence is local to the private VPN owner. Identity registration and Gateway enforcement remain later work. Actual protected-FD and routing execution, mobile resources and 72-hour battery acceptance need device evidence.
