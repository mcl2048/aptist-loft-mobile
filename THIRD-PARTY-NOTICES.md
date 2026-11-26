# Third-party source and distribution notices

The linked Android application uses GPL-3.0-or-later sing/sing-tun code. The combined application and Go adapter are delivered under compatible GPL terms; independent Rust crates retain the Apache-2.0 metadata. Full GPL and Apache texts are in `licenses/`. Original component notices remain applicable.

Gateway input: `/home/coder/Loft-Gateway` commit `231f14813f2b45cb6f0bde984181c57cba1d02fd` (8.0.32-LYNX). Selected protocol/QUIC/Hydra/traffic-profile and SOCKS source is copied under `loft-vpn-engine-go/third_party`; upstream files are not modified. The source manifest records copied hashes and local adapter/stack differences. The QUIC fork retains its MIT license. GhostX/sing copyright and name/association restrictions are retained, without implying endorsement.

HyrakenX/Pro crypto notices describe the existing Rocca-S/Ascon/AEGIS lineage and its original validation material. They do not constitute an independent mobile cryptographic audit. Test-only C references and private test nodes are not linked into the APK. Original notices and referenced license texts accompany the selected source snapshot.

Resolved Rust components and exact available texts are recorded in `docs/dependencies/rust-android-resolved.json` and `rust-license-inventory.json`; the graph includes host proc macros and is not a binary reachability claim. UniFFI's shared MPL2 text is retained. The Go inventory in `docs/dependencies/go-resolved.json` distinguishes runtime, tools/host graph inputs, cached license files and unresolved provenance. Available dependency texts are copied under `licenses/dependencies/` for the application license assets.

The inventory records eleven uncached external graph modules and missing module-root texts for some local protocol/helper modules. Existing source headers and crypto notices remain preserved; no missing license is inferred from a dependency name. This framework inventory is a reproducible evidence record, not a complete legal or production-release certification.

Go modules are locked by `go.mod/go.sum`, Rust crates by Cargo.lock, and Android runtime artifacts by fixed dependency versions. The final release dependency inventory records actual resolved inputs; third-party notice assets are read only when needed, not preloaded into the VPN runtime.

APTIST Portal is a read-only architecture/API reference at commit `4ab2b37d08f9d7e304ae4d420d36d15c54dffa36`. Its credentials, deployment files, source and mail content are not copied into this application.
