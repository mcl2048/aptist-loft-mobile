# Offline TOTP and password vault

The native TOTP module accepts a QR scan or manual `otpauth` URI, a manual Base32 TOTP key, or a password entry. Rust validates data and generates IDs. TOTP supports SHA-1, SHA-256 and SHA-512 with six or eight digits. Users can edit, archive and unarchive entries. Vault pages show metadata. An explicit action and Android device authentication reveal one code or password. A code disappears at the end of its validity window. The user can explicitly reveal a new code. Leaving the page, returning to the background or closing the reveal releases the displayed secret.

The existing Keystore-wrapped SQLCipher store migrates schema 1 to schema 2 in a transaction. It keeps separate encrypted private records for the vault and Hub session. The app can edit and use its vault while offline or signed out. Cloud signing out clears Hub access and leaves local entries intact. The vault accepts at most 200 entries and its stored image is bounded. Each page contains at most 30 entries. QR analysis uses the Android camera only while scanning and decodes the image locally.

## Explicit backup

The user enters a recovery passphrase on each sync. A successful first sync associates unassigned entries with the current account's exact origin, issuer and subject. Entries linked to a different account stay local. Argon2id derives a 256-bit key from a 16-byte salt using 64 MiB, three passes and four lanes. AES-256-GCM uses a fresh nonce and authenticates the scope and revision. D1 holds ciphertext and a revision counter. The passphrase, vault keys, password text and active codes remain on the device. A forgotten passphrase prevents recovery from that encrypted backup.

The mobile client admits one sync, checks the current Hub and local generations before applying results, and uses revision-based three-way merge. Concurrent incompatible edits to the same entry return a conflict and preserve the local record. Archival propagates as a record change. The first version retains metadata and one selected reveal in the UI. Its queue and memory bounds do not establish handset PSS or scanning performance.

[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) · [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) · [Android Keystore](https://developer.android.com/privacy-and-security/keystore)
