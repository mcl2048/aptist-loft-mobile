# LOFT Hub contract

LOFT uses one active HTTPS Hub origin and stages user-supplied addresses as candidates. Discovery over that origin confirms protocol compatibility and returns the exact Portal issuer. The user supplies the trust decision when activating the server and authorizing in the browser. Guest startup stays local. Changing the account server or losing a cloud session does not stop a user-provided VPN.

## Deployment and authority

A Cloudflare Pages service binding forwards the original request to a Rust Worker and keeps the same public HTTPS origin for discovery, browser callback and APP requests. The Worker holds the Portal client secret and seals short-lived authorization records in D1. The Portal client grants `openid email` and optionally `mail.read` after user consent. Machine tenant delegation is absent. Portal handles user credentials, PVS, eligibility and mailbox ownership through its own account directory. Roles, tenant IDs and organization privileges are excluded from APP identity projection.

## API version 1

| Method and path | Contract |
| --- | --- |
| `GET /.well-known/loft-app` | Public descriptor with `version`, `product`, `authMode`, `issuer`, and `modules` |
| `POST /v1/auth/portal/transactions` | `proofChallenge` uses SHA-256 of the original 256-bit base64url APP proof. `mailRead` selects mail consent. The response has `transactionId`, `authorizationUrl`, `expiresAt` |
| `GET /v1/auth/portal/callback` | The registered browser return validates issuer and state before one upstream code redemption. The Worker verifies S256 PKCE, RS256 signature, nonce, audience, expiry and the UserInfo subject. The browser response tells the user to return to LOFT |
| `POST /v1/auth/portal/transactions/:id/complete` | Original `proof` required. HTTP 202 means pending. HTTP 200 yields the scoped Hub session. Retrying the same completed proof recovers the same session within its validity window |
| `POST /v1/auth/portal/transactions/:id/cancel` | Original `proof` required. Cancels pending work and invalidates any associated Hub session |
| `GET /v1/session` and `POST /v1/logout` | Hub session bearer. Session confirmation checks live source authority. Logout invalidates Hub state |
| `GET /v1/mail/messages` | Hub session bearer with `mail.read`. `folder` is `inbox` or `trash`, and `cursor` continues the source page of up to 20 items |
| `GET /v1/mail/messages/:id` | Bounded safe text preview with source metadata and attachments. HTML-only content is converted to text |
| `GET /v1/mail/messages/:id/content` | Full safe text for explicit save |
| `GET /v1/mail/messages/:id/attachments/:attachmentId` | Request-dispatched inert download, bounded to 2 MiB |

Session and transaction expiry fields use Unix seconds. Sessions expire at the verified source deadline within 300 seconds. There is no refresh token. Any successful mail call uses the current Hub session and the corresponding Portal user bearer, preserving Portal’s source read state. No target-account parameter, browser cookie forwarding or background mail polling is used. The APP holds its short Hub bearer in service memory and receives mail or account projections through bounded private Binder results.

[Cloudflare Workers Rust](https://developers.cloudflare.com/workers/languages/rust/) · [Cloudflare Pages service bindings](https://developers.cloudflare.com/pages/functions/bindings/#service-bindings) · [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700) · [OAuth for native apps](https://www.rfc-editor.org/rfc/rfc8252) · [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
