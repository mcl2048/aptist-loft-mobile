# LOFT Hub contract

LOFT uses one active HTTPS Hub origin and stages user-supplied addresses as candidates. Discovery over that origin confirms protocol compatibility and returns the exact Portal issuer. The user supplies the trust decision when activating the server and authorizing in the browser. Guest startup stays local. Changing the account server or losing a cloud session does not stop a user-provided VPN.

## Deployment and authority

A Cloudflare Pages service binding forwards the original request to a Rust Worker and keeps the same public HTTPS origin for discovery, browser callback and APP requests. The Worker holds the Portal client secret and stores sealed grant, session and backup records in D1. The Portal client grants `openid email` and optionally `mail.read` after user consent. Machine tenant delegation is absent. Portal handles user credentials, PVS, eligibility and mailbox ownership through its own account directory. Roles, tenant IDs and organization privileges are excluded from APP identity projection.

## API version 1

| Method and path | Contract |
| --- | --- |
| `GET /.well-known/loft-app` | Public descriptor with `version`, `product`, `authMode`, `issuer`, and `modules` |
| `POST /v1/auth/portal/transactions` | `proofChallenge` uses SHA-256 of the original 256-bit base64url APP proof. `mailRead` selects mail consent. The response has `transactionId`, `authorizationUrl`, `expiresAt` |
| `GET /v1/auth/portal/callback` | The registered browser return validates issuer and state before one upstream code redemption. The Worker verifies S256 PKCE, RS256 signature, nonce, audience, expiry and the UserInfo subject. The browser response tells the user to return to LOFT |
| `POST /v1/auth/portal/transactions/:id/complete` | Original `proof` required. HTTP 202 means pending. HTTP 200 yields the scoped Hub session. Retrying the same completed proof recovers the same session within its validity window |
| `POST /v1/auth/portal/transactions/:id/cancel` | Original `proof` required. Cancels pending work and invalidates any associated Hub session |
| `GET /v1/session` and `POST /v1/logout` | The Hub bearer grants access to its enrolled session. Legacy short sessions verify current Portal authority. Explicit logout invalidates the corresponding Hub session |
| `GET /v1/mail/messages` | Hub session bearer with `mail.read`. `folder` is `inbox` or `trash`, and `cursor` continues the source page of up to 20 items |
| `GET /v1/mail/messages/:id` | Bounded safe text preview with source metadata and attachments. HTML-only content is converted to text |
| `GET /v1/mail/messages/:id/content` | Full safe text for explicit save |
| `GET /v1/mail/messages/:id/attachments/:attachmentId` | Request-dispatched inert download, bounded to 2 MiB |
| `GET /v1/vault/:id` | Durable Hub bearer. Returns the current `revision` and opaque base64url `ciphertext` for this verified account |
| `PUT /v1/vault/:id` | Durable Hub bearer with `baseRevision` and `ciphertext`. Conditional write returns the new revision or HTTP 409 |

Clients opt in to durable enrollment with `durable: true` when creating a transaction. The long-lived Hub bearer is encrypted in the APP's SQLCipher store, and D1 indexes its scoped hash. Each account can enroll up to 32 Hub sessions. Issuer and account remain bound to the enrollment. Logout removes the corresponding authorization, while local vault records survive. Portal currently provides no revocation signal for durable Hub identity after its short grant expires.

Transaction and mail expiry fields use Unix seconds. Portal's user grant remains capped at 300 seconds. A durable session reports `mailRead: false` and zero mail expiry when fresh mail consent is required. The APP can initiate a new explicit browser transaction against the same Hub identity to renew that grant. Mail calls enforce the current Portal grant and keep the source read state. Legacy clients retain the short v1 request and response contract.

D1 admits at most eight backup IDs for each verified account, with at most 256 KiB of decoded ciphertext per object and four in-flight backup requests per Worker isolate. Authorization and revision checks are part of the same D1 statement. The API receives ciphertext from the client and performs no TOTP or password computation. [Vault contract](vault.md)

[Cloudflare Workers Rust](https://developers.cloudflare.com/workers/languages/rust/) · [Cloudflare Pages service bindings](https://developers.cloudflare.com/pages/functions/bindings/#service-bindings) · [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700) · [OAuth for native apps](https://www.rfc-editor.org/rfc/rfc8252) · [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
