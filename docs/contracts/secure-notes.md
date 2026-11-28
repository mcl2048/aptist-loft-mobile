# Secure Notes

Notes are available offline. The Rust core commits local changes to the existing Keystore-wrapped SQLCipher repository before reporting success. The native editor keeps an unsaved draft and cursor in memory. List and search return up to 20 summaries per page, with bodies read separately. App protection uses a six-digit PIN when enabled. Android can satisfy the same temporary page authorization with a successful strong biometric prompt. The sensitive route applies window capture and obscured-touch protections.

## Local deletion

A confirmed delete removes the local record and synchronizes its removal to paired devices. SQLite secure deletion reclaims deleted contents within the database's logical pages. Android flash translation, an offline peer and D1 backup history have independent retention and sanitization behavior. Device and cloud hardware erasure are outside the app's ability to verify. Ciphertext retained in service backups remains protected by the client-held pairing key. [SQLite secure_delete](https://www.sqlite.org/pragma.html#pragma_secure_delete) · [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final) · [Cloudflare Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)

## Optional enterprise sync

The user enables sync with a verified Hub profile and a durable Hub session. Pairing requires the same account and a random 256-bit client-held key provisioned to each participating device. AES-256-GCM authenticates content against the account scope and revision, with an HKDF-SHA-256-derived revision key. The verified origin, exact Portal issuer and Portal subject define the account scope. Portal UserInfo exposes no enterprise license or role claim. Availability comes from the enterprise Hub's advertised product capability. The account bearer authenticates requests and the pairing key protects their contents independently.

Notes created before pairing remain device-local. Notes created while sync is enabled belong to that account's collection and stay editable offline under the restored session. Signing out or switching accounts hides that collection until the same verified account returns. Disabling sync preserves local access for the signed-in account. Deletion markers contain opaque note IDs and take priority during merge. A note's logical revision and a random tie breaker converge simultaneous edits. An editor holding an older version receives a conflict on save.

Discovery clients advertise `X-Loft-Capabilities: notes-sync/1` to receive the `notes_sync` descriptor module. Existing clients receive the original `mail` descriptor. All responses are private and carry `Cache-Control: private, no-store`.

| Request | Result |
| --- | --- |
| `GET /v1/notes` | HTTP 200 with `revision` and base64url `ciphertext`, or HTTP 404 when no revision exists |
| `GET /v1/notes` with `If-None-Match: "<revision>"` | An authenticated matching revision returns HTTP 304 and an empty body. D1 returns only the revision to the Worker in this case |
| `PUT /v1/notes` with `baseRevision` and `ciphertext` | HTTP 200 with the new revision. HTTP 409 if another device advanced the revision. HTTP 401 if the durable session is unavailable |

D1 retains one current ciphertext per verified owner with a 256 KiB decoded ceiling. SQL resolves the owner from the presented session and compares the base revision atomically with the write. One Worker isolate admits up to four concurrent notes requests. The server can observe authorization, transfer sizes, times and revision metadata. A durable session may outlive its original Portal authorization because Portal supplies no back-channel revocation for enrolled Hub sessions.

WorkManager schedules a periodic pull every 60 minutes with a 15-minute flex window. Edit-triggered work coalesces for 30 seconds. Both jobs require network access and a battery above Android's low threshold. A run is bounded to three attempts with exponential backoff. A clean 304 avoids collection cloning, encryption and database writes. Without pairing and an eligible session, the scheduler makes no notes requests. When LOFT VPN is active, notes traffic requires a confirmed applicable VPN route. A routing configuration that excludes LOFT delays sync. Local editing remains available independent of system scheduling, Hub reachability and VPN mode. [Android WorkManager](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work) · [Android biometric authentication](https://developer.android.com/identity/sign-in/biometric-auth)
