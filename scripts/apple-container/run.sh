#!/usr/bin/env bash
# Secure run script for OpenClaw in Apple Container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/preflight.sh
source "${SCRIPT_DIR}/lib/preflight.sh"
# shellcheck source=lib/container-json.sh
source "${SCRIPT_DIR}/lib/container-json.sh"

OPENCLAW_HOME="${HOME:-}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${OPENCLAW_HOME}/.openclaw}"
ENV_FILE="${OPENCLAW_CONFIG_DIR}/apple-container.env"
CONFIG_JSON="${OPENCLAW_CONFIG_DIR}/openclaw.json"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing dependency: $1" >&2
    exit 1
  fi
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

info() {
  echo "==> $*"
}

warn() {
  echo "WARN: $*" >&2
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

upsert_env_var() {
  local file="$1" key="$2" value="$3" tmp="" dir=""
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.env.tmp.XXXXXX")"
  awk -v k="$key" -v v="$value" '$0 !~ ("^" k "=") { print } END { print k "=" v }' "$file" >"$tmp"
  mv "$tmp" "$file"
}

validate_port() {
  local label="$1" value="$2" numeric=""
  [[ "$value" =~ ^[0-9]{1,5}$ ]] || fail "Invalid $label: must be numeric."
  numeric=$((10#$value))
  ((numeric >= 1 && numeric <= 65535)) || fail "Invalid $label: out of range (1-65535)."
}

is_enabled() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

is_container_running() {
  local name="$1"
  container ls --quiet 2>/dev/null | grep -qx "$name"
}

require_existing_file() {
  local label="$1" file="$2"
  [[ -f "$file" ]] || fail "Missing $label: $file. Run: scripts/apple-container/setup.sh"
  [[ ! -L "$file" ]] || fail "Unsafe $label: symlinks are not allowed ($file)"
}

generate_token_hex_32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return 0
  fi
  node -e 'console.log(require("node:crypto").randomBytes(32).toString("hex"))'
}

pid_is_running() {
  local pid="$1"
  [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" >/dev/null 2>&1
}

show_help() {
  echo "Usage: $(basename "$0") [command]"
  echo ""
  echo "Commands:"
  echo "  (none)     Start container in detached mode"
  echo "  --open     Start container and open the authenticated Control UI"
  echo "  --attach   Start container in foreground mode"
  echo "  --stop     Stop running container"
  echo "  --status   Show container status and health"
  echo "  --copy-token         Copy the gateway token from Keychain to the clipboard"
  echo "  --copy-dashboard-url Copy the tokenized dashboard URL to the clipboard"
  echo "  --open-dashboard     Open the tokenized dashboard URL in the browser"
  echo "  --help     Show this help"
  echo ""
  echo "Environment variables:"
  echo "  OPENCLAW_CONFIG_DIR                       Config directory (default: ~/.openclaw)"
  echo "  OPENCLAW_APPLE_CONTAINER_IMAGE            Image name (default: openclaw:apple-arm64)"
  echo "  OPENCLAW_APPLE_CONTAINER_NAME             Container name (default: openclaw)"
  echo "  OPENCLAW_APPLE_CONTAINER_NETWORK          Network name (default: openclaw-net)"
  echo "  OPENCLAW_APPLE_CONTAINER_NETWORK_SUBNET   Pinned IPv4 CIDR for the network (default: 172.31.224.0/24; empty = auto)"
  echo "  OPENCLAW_APPLE_CONTAINER_HOST_PORT        Host port (default: 18789)"
  echo "  OPENCLAW_APPLE_CONTAINER_CPUS             CPU limit (default: 2)"
  echo "  OPENCLAW_APPLE_CONTAINER_MEMORY           Memory limit (default: 1g)"
  echo "  OPENCLAW_APPLE_CONTAINER_RUNTIME          Runtime: node or bun (default: node)"
  echo "  OPENCLAW_APPLE_CONTAINER_OPEN_DASHBOARD   Open dashboard after start (1/true/yes/on)"
  echo "  OPENCLAW_APPLE_CONTAINER_STATE_VOLUME     State volume (default: openclaw-state)"
  echo "  OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME Workspace volume (default: openclaw-workspace)"
  echo "  OPENCLAW_APPLE_CONTAINER_WORKSPACE_HOST_DIR Host directory to bind-mount as the workspace (optional; makes the workspace visible/synced on the Mac host)"
  echo "  OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN      Host bridge DNS name"
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

require_cmd container
require_cmd node
require_cmd curl
NODE_BIN="$(command -v node)"

if [[ "${OPENCLAW_SKIP_PREFLIGHT:-0}" != "1" ]]; then
  preflight_check_macos >/dev/null || fail "This script only runs on macOS."
  preflight_check_arm64 >/dev/null || fail "This script requires Apple Silicon (arm64)."
  preflight_check_apple_container_cli >/dev/null || fail "Apple Container CLI is missing."
  preflight_check_apple_container_runtime >/dev/null || fail "Apple Container runtime is not running. Run: container system start"
fi

load_env_file "$ENV_FILE"

SKIP_CLIPBOARD="${OPENCLAW_RUN_NO_CLIPBOARD:-}"
SKIP_DASHBOARD="${OPENCLAW_RUN_NO_DASHBOARD:-}"
SKIP_TAILSCALE="${OPENCLAW_RUN_NO_TAILSCALE:-}"
for arg in "$@"; do
  case "$arg" in
    --no-clipboard) SKIP_CLIPBOARD=1 ;;
    --no-dashboard) SKIP_DASHBOARD=1 ;;
    --no-tailscale) SKIP_TAILSCALE=1 ;;
  esac
done
if [[ -n "$SKIP_TAILSCALE" ]]; then
  export OPENCLAW_SKIP_TAILSCALE_CHECK=1
fi

OPENCLAW_IMAGE="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"
OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
OPENCLAW_NETWORK_NAME="${OPENCLAW_APPLE_CONTAINER_NETWORK:-openclaw-net}"
# Optional deterministic subnet pinned at `container network create` time
# (see setup.sh). When set, this is the most authoritative source for the
# container subnet — it does not require any running container or network
# inspect call. Empty means Apple Container auto-allocates the subnet.
OPENCLAW_NETWORK_SUBNET="${OPENCLAW_APPLE_CONTAINER_NETWORK_SUBNET:-}"
HOST_PORT="${OPENCLAW_APPLE_CONTAINER_HOST_PORT:-18789}"
CONTAINER_PORT="${OPENCLAW_APPLE_CONTAINER_PORT:-18789}"
CONTAINER_CPUS="${OPENCLAW_APPLE_CONTAINER_CPUS:-2}"
CONTAINER_MEMORY="${OPENCLAW_APPLE_CONTAINER_MEMORY:-1g}"
CONTAINER_RUNTIME="${OPENCLAW_APPLE_CONTAINER_RUNTIME:-node}"
OPEN_DASHBOARD="${OPENCLAW_APPLE_CONTAINER_OPEN_DASHBOARD:-}"
STATE_VOLUME="${OPENCLAW_APPLE_CONTAINER_STATE_VOLUME:-openclaw-state}"
WORKSPACE_VOLUME="${OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME:-openclaw-workspace}"
WORKSPACE_HOST_DIR="${OPENCLAW_APPLE_CONTAINER_WORKSPACE_HOST_DIR:-}"
if [[ -n "$WORKSPACE_HOST_DIR" ]]; then
  WORKSPACE_MOUNT_SPEC=(--mount "type=bind,source=${WORKSPACE_HOST_DIR},target=/home/node/.openclaw/workspace")
else
  WORKSPACE_MOUNT_SPEC=(--mount "type=volume,source=${WORKSPACE_VOLUME},target=/home/node/.openclaw/workspace")
fi
HOST_DOMAIN="${OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN:-host.container.internal}"
HOST_LOCALHOST_IP="${OPENCLAW_APPLE_CONTAINER_HOST_LOCALHOST_IP:-203.0.113.113}"

# Gateway auth token. Sourced from the host env file; generated on first run.
# It is passed into the container at launch via OPENCLAW_GATEWAY_TOKEN.
GATEWAY_TOKEN="$(read_gateway_token "$ENV_FILE" 2>/dev/null || true)"
if [[ -z "$GATEWAY_TOKEN" ]]; then
  GATEWAY_TOKEN="$(generate_token_hex_32)"
  upsert_env_var "$ENV_FILE" "OPENCLAW_GATEWAY_TOKEN" "$GATEWAY_TOKEN"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
fi

copy_gateway_token() {
  local token="$GATEWAY_TOKEN"
  if [[ -z "$token" ]]; then
    fail "No gateway token available."
  fi
  if [[ -n "$SKIP_CLIPBOARD" ]]; then
    printf '%s\n' "$token"
    info "Clipboard skipped (--no-clipboard); printed token to stdout."
    return 0
  fi
  if command -v pbcopy >/dev/null 2>&1; then
    printf '%s' "$token" | pbcopy
    info "Copied gateway token to the clipboard."
  else
    printf '%s\n' "$token"
    warn "pbcopy not found; printed token to stdout instead."
  fi
}

# Detect the Tailscale Serve origin (e.g. https://machine.tail12345.ts.net)
# from `tailscale serve status` output. Bounded by watchdog_kill_after because
# `tailscale serve status` can hang when the local daemon is wedged.
detect_tailscale_origin() {
  local origin="" tmpfile=""
  tmpfile="$(mktemp "${TMPDIR:-/tmp}/openclaw-ts-origin.XXXXXX")"
  (
    parse_tailscale_origin >"$tmpfile"
  ) &
  local serve_pid=$!
  watchdog_kill_after "$serve_pid" 5
  wait "$serve_pid" 2>/dev/null || true
  watchdog_cancel
  origin="$(<"$tmpfile")"
  rm -f "$tmpfile"
  printf '%s' "$origin"
}

dashboard_url() {
  local token="$GATEWAY_TOKEN"
  local base_url="${OPENCLAW_DASHBOARD_URL:-}"
  [[ -n "$SKIP_DASHBOARD" ]] && return 0
  if [[ -z "$base_url" ]]; then
    local tailscale_origin=""
    if [[ -z "$SKIP_TAILSCALE" ]] && command -v tailscale >/dev/null 2>&1; then
      tailscale_origin="$(detect_tailscale_origin)"
    fi
    if [[ -n "$tailscale_origin" ]]; then
      base_url="${tailscale_origin}/"
    else
      base_url="http://127.0.0.1:${HOST_PORT}/"
    fi
  fi

  printf '%s' "$token" |
    OPENCLAW_DASHBOARD_BASE_URL="$base_url" \
      OPENCLAW_DASHBOARD_GATEWAY_URL="${OPENCLAW_DASHBOARD_GATEWAY_URL:-}" \
      node -e '
let token = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  token += chunk;
});
process.stdin.on("end", () => {
  const url = new URL(process.env.OPENCLAW_DASHBOARD_BASE_URL);
  const explicitGatewayUrl = process.env.OPENCLAW_DASHBOARD_GATEWAY_URL?.trim();
  const gatewayUrl = explicitGatewayUrl || `${url.protocol === "https:" ? "wss" : "ws"}://${url.host}/gateway`;
  const hashParams = new URLSearchParams(url.hash.startsWith("#") ? url.hash.slice(1) : url.hash);
  hashParams.set("gatewayUrl", gatewayUrl);
  hashParams.set("token", token.trim());
  url.hash = hashParams.toString();
  process.stdout.write(`${url.toString()}\n`);
});
'
}

copy_dashboard_url() {
  local url
  [[ -n "$SKIP_DASHBOARD" ]] && fail "Dashboard URL skipped (--no-dashboard)."
  url="$(dashboard_url || true)"
  if [[ -z "$url" ]]; then
    fail "Could not build dashboard URL (Keychain token missing?)."
  fi
  if [[ -n "$SKIP_CLIPBOARD" ]]; then
    printf '%s\n' "$url"
    info "Clipboard skipped (--no-clipboard); printed dashboard URL to stdout."
    return 0
  fi
  if command -v pbcopy >/dev/null 2>&1; then
    printf '%s' "$url" | pbcopy
    info "Copied tokenized dashboard URL to the clipboard."
  else
    printf '%s\n' "$url"
    warn "pbcopy not found; printed dashboard URL to stdout instead."
  fi
}

open_dashboard() {
  local url=""
  [[ -n "$SKIP_DASHBOARD" ]] && fail "Dashboard skipped (--no-dashboard)."
  url="$(dashboard_url || true)"
  if [[ -z "$url" ]]; then
    return 1
  fi
  if command -v open >/dev/null 2>&1; then
    open "$url"
    info "Opened Control UI in the default browser."
  else
    printf '%s\n' "$url"
    warn "'open' not found; printed dashboard URL to stdout instead."
  fi
}

# Check that Tailscale is running and serve is configured for the gateway port.
# Skipped when OPENCLAW_SKIP_TAILSCALE_CHECK is set.
require_tailscale() {
  if is_enabled "${OPENCLAW_SKIP_TAILSCALE_CHECK:-0}"; then
    return 0
  fi
  if ! command -v tailscale >/dev/null 2>&1; then
    info "tailscale CLI not found; skipping Tailscale pre-check."
    return 0
  fi
  local backend_state=""
  backend_state="$(parse_tailscale_backend_state)"
  if [[ "$backend_state" != "Running" ]]; then
    fail "Tailscale is not running (state: ${backend_state}). Start it with: tailscale up"
  fi
  local serve_output=""
  serve_output="$(tailscale serve status 2>/dev/null)" || true
  if [[ -z "$serve_output" ]]; then
    fail "Tailscale Serve is not configured. Run: tailscale serve --bg --set-path / http://127.0.0.1:${HOST_PORT}"
  fi
  if ! printf '%s' "$serve_output" | grep -qF "127.0.0.1:${HOST_PORT}"; then
    fail "Tailscale Serve is not proxying to 127.0.0.1:${HOST_PORT}. Run: tailscale serve --bg --set-path / http://127.0.0.1:${HOST_PORT}"
  fi
  info "Tailscale: running, serve configured for 127.0.0.1:${HOST_PORT}"
}


stage_runtime_volumes() {
  local temp_name="${OPENCLAW_CONTAINER_NAME}-stage"
  local config_stage_dir=""
  config_stage_dir="$(mktemp -d "${OPENCLAW_CONFIG_DIR:-${TMPDIR:-/tmp}}/.apple-container-config.XXXXXX")"
  chmod 700 "$config_stage_dir"
  # Copy the host openclaw.json verbatim if present. The container gateway uses
  # its default config otherwise — exactly like the normal Docker image, so a
  # standard local openclaw.json works without any Apple-Container-specific edits.
  if [[ -f "$CONFIG_JSON" ]]; then
    cp "$CONFIG_JSON" "$config_stage_dir/openclaw.json"
    chmod 600 "$config_stage_dir/openclaw.json"
  fi

  container delete "$temp_name" >/dev/null 2>&1 || true
  info "Preparing runtime volumes..."
  if ! container run \
    --rm \
    --name "$temp_name" \
    --read-only \
    --tmpfs /tmp \
    --user 0:0 \
    --mount "type=volume,source=${STATE_VOLUME},target=/home/node/.openclaw" \
    "${WORKSPACE_MOUNT_SPEC[@]}" \
    --mount "type=bind,source=${config_stage_dir},target=/openclaw-host-config,readonly" \
    "$OPENCLAW_IMAGE" \
    sh -lc '
      set -eu
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw
      install -d -m 0700 -o 1000 -g 1000 /home/node/.openclaw/credentials
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw/agents
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw/workspace
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw/workspace/skills
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw/workspace/scripts
      install -d -m 0700 -o 1000 -g 1000 /home/node/.openclaw/workspace/credentials
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw/workspace/agents-workspaces
      install -d -m 0750 -o 1000 -g 1000 /home/node/.openclaw/workspace/memory/lancedb
      if [ -f /openclaw-host-config/openclaw.json ]; then
        install -m 0640 -o 1000 -g 1000 /openclaw-host-config/openclaw.json /home/node/.openclaw/openclaw.json
      fi
    '; then
    rm -rf "$config_stage_dir"
    container delete "$temp_name" >/dev/null 2>&1 || true
    fail "Failed to prepare runtime volumes."
  fi
  rm -rf "$config_stage_dir"
}

NETWORK_ARGS=()
if container network list --quiet >/dev/null 2>&1; then
  if container network list --quiet 2>/dev/null | grep -qx "$OPENCLAW_NETWORK_NAME"; then
    NETWORK_ARGS=(--network "$OPENCLAW_NETWORK_NAME")
    info "Using isolated network: ${OPENCLAW_NETWORK_NAME}"
  else
    info "Network '${OPENCLAW_NETWORK_NAME}' not found, using default network."
  fi
else
  info "Network commands unavailable, using default network."
fi

# ── Code overlay volume (set by sync-hot.sh) ───────────────────
# When OPENCLAW_APPLE_CONTAINER_CODE_VOLUME names an existing volume,
# mount it at /app to overlay the image's dist/, skills/, etc.
# Security: named volumes are isolated ext4 images — the main container
# NEVER sees the host filesystem. Volume is populated by sync-hot.sh
# via a short-lived, restricted staging container.
CODE_OVERLAY_MOUNTS=()
CODE_VOLUME="${OPENCLAW_APPLE_CONTAINER_CODE_VOLUME:-}"
if [[ -n "$CODE_VOLUME" ]]; then
  [[ "$CODE_VOLUME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
    fail "Invalid code volume: $CODE_VOLUME"
  if container volume list --quiet 2>/dev/null | grep -qx "$CODE_VOLUME"; then
    CODE_OVERLAY_MOUNTS+=(--mount "type=volume,source=${CODE_VOLUME},target=/app")
    info "Code overlay: volume '${CODE_VOLUME}' mounted at /app"
  fi
fi

do_stop() {
  if is_container_running "$OPENCLAW_CONTAINER_NAME"; then
    info "Stopping container '${OPENCLAW_CONTAINER_NAME}'..."
    container stop "$OPENCLAW_CONTAINER_NAME"
    info "Container stopped."
  else
    info "Container '${OPENCLAW_CONTAINER_NAME}' is not running."
  fi
}

do_status() {
  echo "Container: ${OPENCLAW_CONTAINER_NAME}"
  echo "Image:     ${OPENCLAW_IMAGE}"
  echo "Runtime:   ${CONTAINER_RUNTIME}"
  echo "Network:   ${NETWORK_ARGS[*]:-<default>}${OPENCLAW_NETWORK_SUBNET:+ (pinned subnet ${OPENCLAW_NETWORK_SUBNET})}"
  echo "Port:      127.0.0.1:${HOST_PORT} -> :${CONTAINER_PORT}"
  echo "Resources: ${CONTAINER_CPUS} CPUs, ${CONTAINER_MEMORY} RAM"
  echo "Config:    ${CONFIG_JSON}"
  echo "State:     ${STATE_VOLUME}"
  echo "Host DNS:  ${HOST_DOMAIN}"
  echo "Workspace: ${WORKSPACE_HOST_DIR:-${WORKSPACE_VOLUME}}"
  echo ""

  if is_container_running "$OPENCLAW_CONTAINER_NAME"; then
    echo "Status:    RUNNING"
    echo ""
    local http_code=""
    http_code="$(curl -s -o /dev/null -w "%{http_code}" \
      "http://127.0.0.1:${HOST_PORT}/healthz" 2>/dev/null || true)"
    if [[ "$http_code" == "200" ]]; then
      echo "Health:    /healthz 200 OK"
    else
      echo "Health:    /healthz ${http_code} (may still be starting)"
    fi
  else
    echo "Status:    STOPPED"
  fi
}

# Shared container run arguments. Eliminates duplication between initial
# start and the sync-hot restart.
# Usage: container_run_gateway <detach_arg> <runtime_command...>
container_run_gateway() {
  local detach_arg=()
  if [[ -n "${1:-}" ]]; then
    detach_arg=("$1")
  fi
  shift
  container run \
    "${detach_arg[@]}" \
    --name "$OPENCLAW_CONTAINER_NAME" \
    --read-only \
    --tmpfs /tmp \
    --tmpfs /home/node/.cache \
    --tmpfs /app/node_modules/.cache \
    --tmpfs /home/node/.ssh \
    --cap-drop ALL \
    --init \
    --user 1000:1000 \
    --cpus "$CONTAINER_CPUS" \
    --memory "$CONTAINER_MEMORY" \
    -p "127.0.0.1:${HOST_PORT}:${CONTAINER_PORT}" \
    --env "NODE_ENV=production" \
    --env "HOME=/home/node" \
    --env "TERM=xterm-256color" \
    --env "OPENCLAW_STATE_DIR=/home/node/.openclaw" \
    --env "OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json" \
    --env "OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}" \
    --env "NPM_CONFIG_CACHE=/home/node/.cache/npm" \
    --mount "type=volume,source=${STATE_VOLUME},target=/home/node/.openclaw" \
    "${WORKSPACE_MOUNT_SPEC[@]}" \
    "${NETWORK_ARGS[@]}" \
    "${CODE_OVERLAY_MOUNTS[@]}" \
    "$OPENCLAW_IMAGE" \
    "$@"
}

do_run() {
  local detach_arg=(--detach)
  local open_after_start="${OPEN_DASHBOARD}"
  if [[ "${1:-}" == "--attach" ]]; then
    detach_arg=()
    info "Starting in foreground mode..."
  elif [[ "${1:-}" == "--open" ]]; then
    open_after_start=1
    info "Starting in detached mode..."
  else
    info "Starting in detached mode..."
  fi

  if is_container_running "$OPENCLAW_CONTAINER_NAME"; then
    info "Stopping existing container '${OPENCLAW_CONTAINER_NAME}'..."
    container stop "$OPENCLAW_CONTAINER_NAME" >/dev/null 2>&1 || true
    # Apple Container can take a few seconds to fully release a VM.
    local stop_wait=0
    while is_container_running "$OPENCLAW_CONTAINER_NAME" && (( stop_wait < 10 )); do
      sleep 1
      stop_wait=$((stop_wait + 1))
    done
  fi

  container delete "$OPENCLAW_CONTAINER_NAME" >/dev/null 2>&1 || true

  require_tailscale

  stage_runtime_volumes

  local runtime_command=()
  if [[ "$CONTAINER_RUNTIME" == "bun" ]]; then
    runtime_command=(bun /app/openclaw.mjs gateway --bind lan --port "$CONTAINER_PORT")
  else
    runtime_command=(node /app/openclaw.mjs gateway --bind lan --port "$CONTAINER_PORT")
  fi

  if ! container_run_gateway "${detach_arg[*]}" "${runtime_command[@]}"; then
    fail "Container failed to start."
  fi

  if [[ "${#detach_arg[@]}" -gt 0 ]]; then
    sleep 1
    if ! is_container_running "$OPENCLAW_CONTAINER_NAME"; then
      fail "Container exited during startup. Check: container logs ${OPENCLAW_CONTAINER_NAME}"
    fi
    echo ""
    info "Container '${OPENCLAW_CONTAINER_NAME}' started."
    info "Gateway:  http://127.0.0.1:${HOST_PORT}"
    info "Runtime:  ${CONTAINER_RUNTIME}"
    info "Auth:     gateway token via OPENCLAW_GATEWAY_TOKEN (host env file)"
    info "Logs:     container logs ${OPENCLAW_CONTAINER_NAME}"
    info "Status:   scripts/apple-container/run.sh --status"
    info "Stop:     scripts/apple-container/run.sh --stop"
    echo ""

    local http_code=""
    for _ in {1..30}; do
      http_code="$(curl -s --connect-timeout 1 --max-time 2 -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:${HOST_PORT}/healthz" 2>/dev/null || true)"
      [[ "$http_code" == "200" ]] && break
      sleep 1
    done
    if [[ "$http_code" == "200" ]]; then
      info "Health check: OK (/healthz returned 200)"

      if is_enabled "${OPENCLAW_APPLE_CONTAINER_SKIP_OPEN_DASHBOARD:-0}"; then
        if command -v pbcopy >/dev/null 2>&1; then
          copy_dashboard_url
        fi
      else
        if ! open_dashboard; then
          info "Dashboard URL available via: scripts/apple-container/run.sh --open-dashboard"
        fi
      fi
    else
      info "Health check: /healthz returned ${http_code} (may still be starting)"
    fi
  fi
}

case "${1:-}" in
  --stop)
    do_stop
    ;;
  --status)
    do_status
    ;;
  --copy-token)
    copy_gateway_token
    ;;
  --copy-dashboard-url)
    copy_dashboard_url
    ;;
  --open-dashboard)
    open_dashboard
    ;;
  --open)
    do_run --open
    ;;
  --attach)
    do_run --attach
    ;;
  --help|-h)
    show_help
    ;;
  *)
    do_run
    ;;
esac
