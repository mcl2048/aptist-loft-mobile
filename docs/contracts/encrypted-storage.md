# Encrypted local configuration

The private `:vpn` process owns the guest configuration store. Android supplies the app-private path and uses an Android Keystore AES-GCM key to wrap a randomly generated 32-byte database key. Rust opens one SQLCipher connection and owns the schema, validation and durable commits. Only the serial control worker provisions and opens the store. Priority Stop continues to cancel and fence forwarding independently of storage work.

| Data | Durable owner |
| --- | --- |
| Imported SOCKS5, HyrakenX and Hyraken Pro nodes | Encrypted, bounded credential material with stable node IDs and order |
| Settings | Staged app routing, network privacy policy and unverified server origin |
| Device runtime | Recomputed after each service process start. TUN leases, attempts, verified routing and applied protection remain live receipts |
| Appearance | Existing Android locale and theme preferences |

Writes validate inputs and commit the affected encrypted records before publishing a configuration change. Node removal retains the monotonic identity allocator. Reopen revalidates stored data at the domain boundary and reconstructs a disconnected owner. An expired certificate remains removable. New connections recheck certificate validity before issuing a service ticket. Restoring a server origin preserves its unverified status. The guest repository holds up to 200 nodes and an 8 MiB validated working set. SQLCipher caps the database at 64 MiB and uses a 2 MiB page cache, memory-backed temp storage and a rollback journal with `EXTRA` synchronization.

## Provisioning and recovery

The key envelope and database live in app-private, credential-protected `noBackupFilesDir` storage. The envelope authenticates its format and provisioning state. Once provisioning is complete, reopening requires the existing database and authenticated envelope. A failed open preserves the existing files. If a commit has an indeterminate outcome, the current owner fences configuration writes and VPN starts until an authenticated reopen reconciles the durable state. The Settings screen offers a local reopen action once the VPN is idle. If the key is permanently lost or recovery fails, the recovery instructions point to Android Settings to clear LOFT app data and re-import the nodes. That action also clears LOFT preferences.

The store uses schema version checks and transactional schema creation. Unsupported schemas fail closed. A future migration must update the schema inside a transaction, test interruption and retain an explicit compatibility window. Backup and device transfer exclusions apply to the database, wrapping envelope and auxiliary files. An update signed with the same app identity can keep the existing store. Uninstall or Android Clear storage requires re-import unless a future explicit export and recovery facility has been designed and verified.

LOFT 0.1.2 kept imported nodes only in process memory. Users upgrading from that version need the original links for a one-time re-import into the encrypted store. Imports committed by 0.1.3 are available after process restart.

## Threat boundaries

Android app-private storage limits filesystem access by ordinary apps. Encrypted database pages protect a copied store, and the Keystore key stays behind the platform API. Keystore availability and hardware backing depend on the Android device. File confidentiality at rest does not establish protection from an already compromised app process, Android OS or unlocked-device operator. An authenticated older copy of the same local database remains a possible rollback by an actor with filesystem write access. Physical rollback resistance needs a separate trustworthy version authority.

The app keeps credentials out of Binder snapshots, diagnostic output, ordinary preferences and saved UI state. Buffers owned by Rust and mutable key arrays owned by Android are cleared after use. JCA, JNI and managed runtime copies have platform-controlled lifetimes. Local size and queue limits remain separate from real-device PSS and power acceptance.

## Design references

- Android documents Keystore key extraction protections, device-dependent security levels and AES-GCM key parameters. [Android Keystore](https://developer.android.com/privacy-and-security/keystore) · [KeyGenParameterSpec](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- Android documents no-backup directories and distinct Android 12+ cloud and device-transfer rules. [Android Auto Backup](https://developer.android.com/identity/data/autobackup)
- Zetetic documents SQLCipher page authentication, raw key handling and its native crypto dependency. [SQLCipher source](https://github.com/sqlcipher/sqlcipher) · [SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/)
- SQLite documents rollback journaling, synchronization, version pragmas and recoverable commit behavior. [Atomic Commit](https://www.sqlite.org/atomiccommit.html) · [SQLite pragmas](https://www.sqlite.org/pragma.html)
- The local privacy boundaries map to storage-at-rest and leakage controls. [OWASP MASVS Storage](https://mas.owasp.org/MASVS/05-MASVS-STORAGE/)
