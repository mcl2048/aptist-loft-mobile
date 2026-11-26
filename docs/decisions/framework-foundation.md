# Foundation decisions

The framework task is `loftmobile-1125-01`. Its architecture comes from the two local v3.6 design documents. A framework build does not complete their P0–P5 product roadmap. Protocol access, Portal identity and Shield evidence are separate inputs.

Rust owns validated configuration, frozen VPN attempts and confirmed business state. Its domain crate uses reviewed crypto/config dependencies and std synchronization; a dormant framework does not allocate an async runtime for unavailable cloud features. Kotlin owns Android UI, Binder and resource operations. Go reuses source-pinned protocols and the mature TUN stack. Operational socket/FD ownership is an adapter concern; a successful adapter capability query is never a successful VPN receipt.

The UI main process communicates with a non-exported controller in `:vpn`. The OS VPN service is a separate permission-protected entry in that same process. One owner shares the Rust core; Go starts only for an explicit VPN or diagnostic operation. UI unbinding, themes, languages and Fold resizing do not own the VPN lifetime. Stop has a priority cancellation path outside ordinary import work.

Nodes and sensitive drafts remain session-local until encrypted storage exists. No plaintext persistence is introduced to imply restart support. The server-origin editor normalizes a candidate without claiming TLS or server verification. Portal's confidential OAuth requires a Rust BFF with server-only clientSecret; OAuth, mail, policy enforcement and software verdicts remain unavailable until their adapters and acceptance tests are implemented.

Pixel/Samsung Fold support derives from actual window/inset/hinge data, including medium inner screens, not model names. The retained ViewModel preserves drafts and selections during Activity recreation; sensitive drafts do not enter ordinary saved state. Native rail/navigation and layout-policy tests are the foundation. Actual Fold devices, TalkBack and power remain independent acceptance work.

The VPN extension uses authenticated protected sockets, a real TUN and exact applied-package receipts. An established TUN is retained on forwarding/authentication/network failure until explicit Stop/revoke; resource closure precedes Disconnected. Initial IPv6 is explicitly blocked in VPN scope. DNS remains inside the selected tunnel with no direct fallback; an allowed upstream must be tested for the actual node deployment. No Gateway DNS/Firewall integration is inferred from tunnel encryption.

Builds use fixed Rust/Go/JDK/Gradle/SDK/NDK inputs, generated bindings, source hashes and retained third-party notices. `verify_architecture.py` guards the direct production dependency boundary of loft-core, including workspace aliases and target-specific sections. It does not claim a complete audit of transitive dependencies. Final source and APK checks precede a normal, history-preserving push.
