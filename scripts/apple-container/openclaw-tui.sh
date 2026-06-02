#!/usr/bin/env bash
# Open the OpenClaw TUI inside the running Apple Container from macOS.

set -euo pipefail

OPENCLAW_HOME="${HOME:-}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${OPENCLAW_HOME}/.openclaw}"
ENV_FILE="${OPENCLAW_CONFIG_DIR}/apple-container.env"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Missing dependency: $1"
  fi
}

load_env_file() {
  local file="$1" key="" value="" line=""
  if [[ -f "$file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" || "$line" == \#* ]] && continue
      [[ "$line" == *=* ]] || fail "Invalid env file line in $file: expected KEY=value."
      key="${line%%=*}"
      value="${line#*=}"
      [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || fail "Invalid env key in $file: $key"
      if [[ -z "${!key:-}" ]]; then
        export "$key=$value"
      fi
    done <"$file"
  fi
}

require_cmd container
require_cmd /usr/bin/security

load_env_file "$ENV_FILE"

OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
KEYCHAIN_SERVICE="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE:-ai.openclaw.apple-container.gateway-token}"
KEYCHAIN_ACCOUNT="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT:-${USER:-openclaw}}"
RUNTIME="${OPENCLAW_APPLE_CONTAINER_TUI_RUNTIME:-auto}"

case "$RUNTIME" in
  auto|node|bun) ;;
  *) fail "Invalid OPENCLAW_APPLE_CONTAINER_TUI_RUNTIME: expected auto, node, or bun." ;;
esac

if ! container ls --quiet 2>/dev/null | grep -qx "$OPENCLAW_CONTAINER_NAME"; then
  fail "Container '${OPENCLAW_CONTAINER_NAME}' is not running. Run: scripts/apple-container/run.sh"
fi

tmp_env="$(mktemp "${TMPDIR:-/tmp}/openclaw-tui-env.XXXXXX")"
cleanup() {
  rm -f "$tmp_env"
}
trap cleanup EXIT INT TERM

chmod 600 "$tmp_env"
printf 'OPENCLAW_GATEWAY_TOKEN=%s\n' "$(
  /usr/bin/security find-generic-password \
    -a "$KEYCHAIN_ACCOUNT" \
    -s "$KEYCHAIN_SERVICE" \
    -w
)" >"$tmp_env"

exec_args=(exec -i)
if [[ -t 0 && -t 1 ]]; then
  exec_args+=(-t)
fi

container "${exec_args[@]}" \
  --user 1000:1000 \
  --workdir /app \
  --env-file "$tmp_env" \
  -e HOME=/home/node \
  -e OPENCLAW_STATE_DIR=/home/node/.openclaw \
  -e OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json \
  "$OPENCLAW_CONTAINER_NAME" \
  sh -lc '
    set -eu
    runtime="$1"
    shift
    node - <<'"'"'NODE'"'"'
const crypto = require("node:crypto");
const fs = require("node:fs");
const configPath = process.env.OPENCLAW_CONFIG_PATH || "/home/node/.openclaw/openclaw.json";
const token = (process.env.OPENCLAW_GATEWAY_TOKEN || "").trim();
if (token) {
  const content = fs.readFileSync(configPath, "utf8");
  const sig = crypto.createHmac("sha256", token).update(content).digest("hex");
  fs.writeFileSync(`${configPath}.sig`, sig, { mode: 0o600 });
}
NODE
    if [ "$runtime" = auto ]; then
      if command -v bun >/dev/null 2>&1; then runtime=bun; else runtime=node; fi
    fi
    token_file="$(mktemp /tmp/openclaw-tui-token.XXXXXX)"
    cleanup_token_file() {
      rm -f "$token_file"
    }
    trap cleanup_token_file EXIT INT TERM
    chmod 600 "$token_file"
    printf "%s" "$OPENCLAW_GATEWAY_TOKEN" >"$token_file"
    unset OPENCLAW_GATEWAY_TOKEN
    "$runtime" /app/openclaw.mjs tui --url ws://127.0.0.1:18789 --token-file "$token_file" "$@"
  ' \
  sh "$RUNTIME" "$@"
