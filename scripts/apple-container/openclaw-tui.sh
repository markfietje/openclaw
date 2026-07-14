#!/usr/bin/env bash
# Open the OpenClaw TUI inside the running Apple Container from macOS.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/preflight.sh
source "${SCRIPT_DIR}/lib/preflight.sh"
# shellcheck source=lib/container-json.sh
source "${SCRIPT_DIR}/lib/container-json.sh"

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

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: $(basename "$0") [tui-args...]"
  echo ""
  echo "Open the OpenClaw TUI inside the running Apple Container from macOS."
  echo "Reads the gateway token from the host env file, then exec's into the"
  echo "container's bundled openclaw.mjs tui command."
  echo ""
  echo "Environment:"
  echo "  OPENCLAW_APPLE_CONTAINER_NAME            Container name (default: openclaw)"
  echo "  OPENCLAW_APPLE_CONTAINER_TUI_RUNTIME     Runtime inside container: auto|node|bun"
  echo ""
  echo "Prerequisite: the container must be running. Start it with:"
  echo "  scripts/apple-container/run.sh"
  exit 0
fi

if [[ "${OPENCLAW_SKIP_PREFLIGHT:-0}" != "1" ]]; then
  preflight_check_macos >/dev/null || fail "This script only runs on macOS."
  preflight_check_apple_container_cli >/dev/null || fail "Apple Container CLI is missing."
fi

load_env_file "$ENV_FILE"

OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
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
tui_token="$(read_gateway_token "$ENV_FILE" 2>/dev/null || true)"
[[ -n "$tui_token" ]] || fail "No gateway token in ${ENV_FILE} (run setup.sh first)."
printf 'OPENCLAW_GATEWAY_TOKEN=%s\n' "$tui_token" >"$tmp_env"

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
    token_file="$(mktemp "${TMPDIR:-/tmp}/openclaw-tui-token.XXXXXX")"
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
