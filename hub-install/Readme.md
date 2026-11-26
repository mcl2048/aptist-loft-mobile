# Deploy LOFT Hub

Run on Linux with Bash, Python 3, Node.js 22.12 or newer, npm, rustup and the system linker used by Cargo. The installer installs the pinned Rust target, `worker-build` and locked Wrangler dependencies. Cloudflare needs account-level access to manage Pages, Workers Scripts and D1. Supply `CLOUDFLARE_ACCOUNT_ID` and `CLOUDFLARE_API_TOKEN` through the environment or the installer prompts.

1. Run `./hub-install/install.sh prepare`. Cloudflare provisions the Pages project and D1 database and returns the actual HTTPS callback to register.
2. In Portal, sign in as a current SYSTEM Administrator. Register a confidential client with the printed callback and `openid`, `email`, `mail.read`. Leave tenant access unset so eligible users can sign in from any connected tenant. Capture the client secret when Portal displays it.
3. Run `./hub-install/install.sh deploy`. On first deployment, enter the registered client ID and secret when prompted, or supply `PORTAL_CLIENT_ID` and `PORTAL_CLIENT_SECRET` through the environment. For a different Portal, set `LOFT_PORTAL_ISSUER` to the exact HTTPS issuer ending in `/api/idp`. Set `LOFT_HUB_PROJECT` before provisioning to use a different project name.
4. Enter the resulting Pages HTTPS origin in LOFT’s server address candidate, verify it, then confirm the displayed Portal issuer before opening the browser. Return to LOFT after granting consent and select the action to complete login. Enable mail access during authorization when needed.

Redeploy the same Hub with `./hub-install/install.sh deploy`. The installer resolves the existing Portal binding and preserves Cloudflare’s current secrets when no replacement values are supplied. Provide the new `PORTAL_CLIENT_SECRET` after an intentional Portal rotation. `HUB_ENCRYPTION_KEY` is optional at the first deployment and generated securely when absent. Retain it across deployments. Replacing it invalidates access to the encrypted contents of outstanding D1 sessions and transactions.

Pages routes Hub API paths through a service binding to the Rust Worker. The public origin and Portal callback are the exact Pages hostname returned by the Cloudflare API. D1 holds bounded short-lived authorization state. Migrations run before the Worker is deployed and the installer checks the public compatibility descriptor after Pages publishes.
