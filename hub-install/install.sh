#!/usr/bin/env bash
set +x
set -euo pipefail
umask 077
install_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
hub_dir="$(dirname -- "$install_dir")/hub"
command="${1:-deploy}"
project="${LOFT_HUB_PROJECT:-aptist-loft-hub}"

if [[ "$command" == --help ]]; then
  printf '%s\n' 'Usage: hub-install/install.sh [prepare|deploy]' \
    'Cloudflare credentials are read from CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN or prompted.' \
    'prepare provisions the Pages hostname and D1 database. deploy also builds and publishes the Hub.'
  exit 0
fi
[[ "$command" == prepare || "$command" == deploy ]] || exit 2
command -v python3 >/dev/null || { printf '%s\n' 'Python 3 is required.' >&2; exit 2; }
if [[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]]; then
  read -r -p 'Cloudflare account ID: ' CLOUDFLARE_ACCOUNT_ID
fi
if [[ -z "${CLOUDFLARE_API_TOKEN:-}" ]]; then
  read -rs -p 'Cloudflare API token: ' CLOUDFLARE_API_TOKEN
  printf '\n' >&2
fi
export CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_API_TOKEN
provisioned="$(python3 "$install_dir/provision.py" "$project")"
read -r hub_origin database_id <<< "$provisioned"
if [[ "$command" == prepare ]]; then
  printf 'Pages origin %s\nRegister this Portal redirect URI: %s/v1/auth/portal/callback\n' "$hub_origin" "$hub_origin"
  exit 0
fi

# Keep secret variables out of dependency installers and the compilation environment.
cloudflare_token="$CLOUDFLARE_API_TOKEN"
portal_secret="${PORTAL_CLIENT_SECRET:-}"
hub_key="${HUB_ENCRYPTION_KEY:-}"
unset CLOUDFLARE_API_TOKEN PORTAL_CLIENT_SECRET HUB_ENCRYPTION_KEY
if ! command -v rustup >/dev/null && [[ -x "${CARGO_HOME:-$HOME/.cargo}/bin/rustup" ]]; then
  export PATH="${CARGO_HOME:-$HOME/.cargo}/bin:$PATH"
fi
for tool in node npm rustup; do
  command -v "$tool" >/dev/null || { printf '%s is required on the Linux deployment host.\n' "$tool" >&2; exit 2; }
done
node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || major === 22 && minor >= 12 ? 0 : 1)' || {
  printf '%s\n' 'Use Node.js 22.12 or newer.' >&2
  exit 2
}
work="$(mktemp -d "${TMPDIR:-/tmp}/loft-hub.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
export WRANGLER_SEND_METRICS=false

runtime_tools="${LOFT_HUB_TOOL_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/loft-hub}"
export RUSTUP_TOOLCHAIN=1.100.0 CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
if ! rustup target list --installed --toolchain "$RUSTUP_TOOLCHAIN" 2>/dev/null | grep -Fxq wasm32-unknown-unknown; then
  rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal --target wasm32-unknown-unknown
fi
if [[ ! -x "$runtime_tools/bin/worker-build" || "$("$runtime_tools/bin/worker-build" --version)" != 0.9.0 ]]; then
  rustup run "$RUSTUP_TOOLCHAIN" cargo install --locked --version '=0.9.0' --root "$runtime_tools" worker-build
fi
(cd "$hub_dir" && "$runtime_tools/bin/worker-build" --release --locked)
npm --prefix "$install_dir" ci --no-audit --no-fund
wrangler="$install_dir/node_modules/.bin/wrangler"

# A zero-version first deployment needs both secrets; subsequent deploys preserve them.
export CLOUDFLARE_API_TOKEN="$cloudflare_token"
worker_state="$(python3 "$install_dir/provision.py" "$project" worker-state)"
read -r deployment previous_issuer previous_client <<< "$worker_state"
LOFT_FIRST_WORKER_DEPLOY=0
if [[ "$deployment" == new ]]; then
  LOFT_FIRST_WORKER_DEPLOY=1
else
  export LOFT_PORTAL_ISSUER="${LOFT_PORTAL_ISSUER:-$previous_issuer}"
  PORTAL_CLIENT_ID="${PORTAL_CLIENT_ID:-$previous_client}"
fi
export LOFT_FIRST_WORKER_DEPLOY
if [[ -z "${PORTAL_CLIENT_ID:-}" ]]; then
  read -r -p 'Registered Portal OAuth client ID: ' PORTAL_CLIENT_ID
fi
if [[ "$LOFT_FIRST_WORKER_DEPLOY" == 1 && -z "$portal_secret" ]]; then
  read -rs -p 'Registered Portal OAuth client secret: ' portal_secret
  printf '\n' >&2
fi
PORTAL_CLIENT_ID="$PORTAL_CLIENT_ID" PORTAL_CLIENT_SECRET="$portal_secret" HUB_ENCRYPTION_KEY="$hub_key" \
  python3 "$install_dir/configure.py" "$work" "$project" "$hub_origin" "$database_id"
unset cloudflare_token portal_secret hub_key

"$wrangler" d1 migrations apply "$project" --remote --config "$work/worker.json"
secret_args=()
if [[ -f "$work/secrets.json" ]]; then
  secret_args=(--secrets-file "$work/secrets.json")
fi
"$wrangler" deploy --config "$work/worker.json" "${secret_args[@]}"
rm -f -- "$work/secrets.json"
(cd "$work" && "$wrangler" pages deploy ./pages --project-name "$project" --branch main)
python3 "$install_dir/provision.py" "$project" check "$hub_origin"
printf 'LOFT Hub deployed at %s\n' "$hub_origin"
