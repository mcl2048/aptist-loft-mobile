# Secure Notes

Notes are available offline. The Rust core commits local changes to the existing Keystore-wrapped SQLCipher repository before reporting success. The native editor keeps an unsaved draft and cursor in memory. List and search return up to 20 summaries per page, with bodies read separately. App protection uses a six-digit PIN when enabled. Android can satisfy the same temporary page authorization with a successful strong biometric prompt. The sensitive route applies window capture and obscured-touch protections.

## Local deletion

A confirmed delete removes the local record and synchronizes its removal to paired devices. SQLite secure deletion reclaims deleted contents within the database's logical pages. Android flash translation, an offline peer and D1 backup history have independent retention and sanitization behavior. Device and cloud hardware erasure are outside the app's ability to verify. Ciphertext retained in service backups remains protected by the client-held pairing key. [SQLite secure_delete](https://www.sqlite.org/pragma.html#pragma_secure_delete) · [NIST SP 800-88 Rev. 2](https://csrc.nist.gov/pubs/sp/800/88/r2/final) · [Cloudflare Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)

## Optional enterprise sync

The user enables sync with a verified Hub profile and a durable Hub session. Pairing requires the same account and a random 256-bit client-held key provisioned to each participating device. AES-256-GCM authenticates content against the account scope and revision, with an HKDF-SHA-256-derived revision key. The verified origin, exact Portal issuer and Portal subject define the account scope. Portal UserInfo exposes no enterprise license or role claim. Availability comes from the enterprise Hub's advertised product capability. The account bearer authenticates requests and the pairing key protects their contents independently.

Notes created before pairing remain device-local. Notes created while sync is enabled belong to that account's collection and stay editable offline under the restored session. Signing out or switching accounts hides that collection until the same verified account returns. Disabling sync preserves local access for the signed-in account. Deletion markers contain opaque note IDs and take priority during merge. A persisted common revision lets the client merge edits to separate notes. Divergent updates to the same note retain both devices' copies and display a conflict. An editor holding an older version receives a conflict on save.

Discovery clients advertise `X-Loft-Capabilities: notes-sync/2` to receive `notes_sync` and `notes_reset`. Older clients advertising `notes-sync/1` receive `notes_sync`. Discovery without the request header receives the original `mail` descriptor. All responses are private and carry `Cache-Control: private, no-store`.

| Request | Result |
| --- | --- |
| `GET /v1/notes` | HTTP 200 with `revision`, base64url `ciphertext` and `keyEpoch` when the key has been reset, or HTTP 404 when no revision exists |
| `GET /v1/notes` with `If-None-Match: "<revision>"` | An authenticated matching revision returns HTTP 304 and an empty body. D1 returns only the revision to the Worker in this case |
| `PUT /v1/notes` with `baseRevision`, `ciphertext` and optional `keyEpoch` | HTTP 200 with the new revision. HTTP 409 when the current revision or key epoch differs. HTTP 401 if the durable session is unavailable |
| `POST /v1/notes/reset` with `baseRevision`, `ciphertext` and `operationId` | HTTP 200 with the new `revision` and `operationId`. The base revision and ciphertext identity must match to recover an earlier receipt for the active key epoch. A superseded operation returns HTTP 409 |

D1 retains one current ciphertext per verified owner with a 256 KiB decoded ceiling. SQL resolves the owner from the presented session and compares the base revision atomically with the write. One Worker isolate admits up to four concurrent notes requests. The server can observe authorization, transfer sizes, times and revision metadata. A durable session may outlive its original Portal authorization because Portal supplies no back-channel revocation for enrolled Hub sessions.

## Reset and re-pair

Resetting the key requires an explicit choice to keep notes or erase them. Keeping notes merges the current account revision before re-encryption. Erasing the notes replaces the current cloud collection with authenticated encryption of an empty collection and deletes the confirmed device-local notes once the receipt commits. Other local account collections remain separately scoped. A new pairing code becomes available after the receipt. Other devices must enter it before syncing the new epoch.

Local encrypted storage retains the reset intent and the information needed to reproduce the same ciphertext across a retry. D1 atomically increments the existing revision and stores the new key epoch with the reset receipt. An ordinary update must present the active epoch. Historical Cloudflare backups and previously downloaded device copies follow their own retention, even after the current cloud revision changes. [Cloudflare D1](https://developers.cloudflare.com/d1/worker-api/d1-database/) · [SQLite UPSERT](https://sqlite.org/lang_upsert.html)

WorkManager schedules a periodic pull every 60 minutes with a 15-minute flex window. Edit-triggered work coalesces for 30 seconds. Both jobs require network access and a battery above Android's low threshold. A run is bounded to three attempts with exponential backoff. A clean 304 avoids collection cloning, encryption and database writes. Without pairing and an eligible session, the scheduler makes no notes requests. When LOFT VPN is active, notes traffic requires a confirmed applicable VPN route. A routing configuration that excludes LOFT delays sync. Local editing remains available independent of system scheduling, Hub reachability and VPN mode. [Android WorkManager](https://developer.android.com/develop/background-work/background-tasks/persistent/getting-started/define-work) · [Android biometric authentication](https://developer.android.com/identity/sign-in/biometric-auth)
