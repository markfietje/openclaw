#!/usr/bin/env bash
# OpenClaw Apple Container — one-line install, run, and upgrade.
#
# Usage (first time — downloads and saves script locally):
#   bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh)
#
# After install, the script is saved to ~/.openclaw/bin/openclaw-container.sh.
# Subsequent commands use the local copy:
#   ~/.openclaw/bin/openclaw-container.sh run
#   ~/.openclaw/bin/openclaw-container.sh stop
#   ~/.openclaw/bin/openclaw-container.sh upgrade
#   ~/.openclaw/bin/openclaw-container.sh status
#   ~/.openclaw/bin/openclaw-container.sh logs
#   ~/.openclaw/bin/openclaw-container.sh uninstall
#
# You can also continue using the curl one-liner for any command.
#
# If you have the repo cloned, use scripts/apple-container/setup.sh instead.
#
# ── Design note: one installer, one config path ────────────────
# This is the single-file installer: self-contained, easy to audit
# (one script, one token volume, one inline sh -c). It pulls a
# prebuilt image and creates a hardened, read-only container.
#
# The gateway token is passed into the container via the OPENCLAW_GATEWAY_TOKEN
# environment variable (read natively by the gateway's env secret provider).
#
# Config: the state volume is mounted at /home/node/.openclaw (the
# gateway's default config dir, via OPENCLAW_STATE_DIR/
# OPENCLAW_CONFIG_PATH). Users add providers/channels with
# `container exec <name> openclaw onboard --mode local`, which writes
# into that volume and persists across restarts. Host
# ~/.openclaw/openclaw.json is NOT shared with the container.
#
# scripts/apple-container/setup.sh + run.sh remain available as the
# "build the image from source" path (power users, reverse-proxy).
# Both paths share the same hardening: --read-only, --cap-drop ALL,
# --init, non-root user, 127.0.0.1-only port binding.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/preflight.sh
source "${SCRIPT_DIR}/lib/preflight.sh"
# shellcheck source=lib/container-json.sh
source "${SCRIPT_DIR}/lib/container-json.sh"

# ── Config ──────────────────────────────────────────────────────
IMAGE="ghcr.io/markfietje/openclaw:apple-arm64"
# Accept both OPENCLAW_APPLE_CONTAINER_NAME (written to the env file by setup.sh)
# and the legacy OPENCLAW_CONTAINER_NAME for back-compat with manual exports.
CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-${OPENCLAW_CONTAINER_NAME:-openclaw}}"
HOST_PORT="${OPENCLAW_HOST_PORT:-18789}"
CONFIG_DIR="${HOME}/.openclaw"
ENV_FILE="${CONFIG_DIR}/apple-container.env"
NETWORK_NAME="openclaw-net"
STATE_VOLUME="openclaw-state"
WORKSPACE_VOLUME="openclaw-workspace"
HOST_DOMAIN="host.container.internal"
HOST_LOCALHOST_IP="203.0.113.113"
# Runtime: node (default) or bun. Overridable via env or --runtime.
CONTAINER_RUNTIME="${OPENCLAW_APPLE_CONTAINER_RUNTIME:-node}"

# ── Local script path ───────────────────────────────────────────
LOCAL_SCRIPT_DIR="${CONFIG_DIR}/bin"
LOCAL_SCRIPT="${LOCAL_SCRIPT_DIR}/openclaw-container.sh"
SCRIPT_URL="https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh"

# ── Helpers ─────────────────────────────────────────────────────
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  GREEN=$'\033[32m'
  RED=$'\033[31m'
  YELLOW=$'\033[33m'
  DIM=$'\033[2m'
  RESET=$'\033[0m'
else
  BOLD="" GREEN="" RED="" YELLOW="" DIM="" RESET=""
fi

step()   { echo "${BOLD}==> $*${RESET}"; }
ok()     { echo "${GREEN}  ✓ $*${RESET}"; }
warn()   { echo "${YELLOW}  ⚠ $*${RESET}"; }
fail()   { echo "${RED}  ✗ $*${RESET}" >&2; exit 1; }
info()   { echo "${DIM}  $*${RESET}"; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Missing: $1. Install it first."
  fi
}

# ── Checks ──────────────────────────────────────────────────────
preflight() {
  preflight_check_macos || return 1
  preflight_check_arm64 || return 1

  if ! command -v container >/dev/null 2>&1; then
    echo ""
    step "Apple Container is not installed"
    echo ""
    echo "  Download the installer from the GitHub releases page:"
    echo "    https://github.com/apple/container/releases"
    echo ""
    echo "  Double-click the .pkg file, enter your admin password, then restart Terminal."
    echo ""
    read -rp "  Press Enter after installing, or Ctrl+C to cancel... " _
    if ! command -v container >/dev/null 2>&1; then
      fail "Still can't find 'container'. Please restart your terminal and try again."
    fi
  fi
  ok "Apple Container CLI found"

  # Use JSON status to avoid the "is not running" substring-match bug.
  local _state=""
  _state="$(parse_container_system_status)"
  if [[ "$_state" != "running" ]]; then
    step "Starting Apple Container runtime..."
    container system start 2>/dev/null || {
      warn "Need admin privileges to start the runtime."
      sudo container system start 2>/dev/null || fail "Could not start Apple Container runtime."
    }
    local retries=0
    while (( retries < 30 )); do
      _state="$(parse_container_system_status)"
      if [[ "$_state" == "running" ]]; then
        ok "Apple Container runtime started"
        return 0
      fi
      retries=$((retries + 1))
      sleep 1
    done
    fail "Apple Container runtime did not start in time. Try: container system start"
  fi
  ok "Apple Container runtime is running"

  preflight_check_curl
  preflight_check_token_source
  require_cmd curl
}

# ── Generate token ──────────────────────────────────────────────
generate_token() {
  local token=""
  if command -v openssl >/dev/null 2>&1; then
    token="$(openssl rand -hex 32)"
  elif command -v ruby >/dev/null 2>&1; then
    token="$(ruby -e 'require "securerandom"; puts SecureRandom.hex(32)')"
  else
    token="$(head -c 32 /dev/urandom | xxd -p -c 64)"
  fi
  echo "$token"
}

# ── Token ───────────────────────────────────────────────────────
# The gateway token is stored in the host env file (OPENCLAW_GATEWAY_TOKEN)
# and passed into the container at launch. No macOS Keychain involved.
store_token() {
  local token="$1"
  upsert_env_var "$ENV_FILE" "OPENCLAW_GATEWAY_TOKEN" "$token"
  chmod 600 "$ENV_FILE" 2>/dev/null || true
}

read_token() {
  read_gateway_token "$ENV_FILE" 2>/dev/null || true
}

# ── Validate runtime ────────────────────────────────────────────
validate_runtime() {
  case "$CONTAINER_RUNTIME" in
    node|bun) ;;
    *) fail "Invalid CONTAINER_RUNTIME: '$CONTAINER_RUNTIME' (expected node or bun)." ;;
  esac
}

# ── Ensure volumes ──────────────────────────────────────────────
ensure_volume() {
  local name="$1"
  if container volume list --quiet 2>/dev/null | grep -qx "$name"; then
    return
  fi
  if ! container volume create "$name" >/dev/null 2>&1; then
    fail "Failed to create volume '${name}'."
  fi
}

# ── Write env file ──────────────────────────────────────────────
write_env() {
  mkdir -p "$CONFIG_DIR"
  cat > "$ENV_FILE" << EOF
# OpenClaw Apple Container environment
OPENCLAW_APPLE_CONTAINER_IMAGE=$IMAGE
OPENCLAW_APPLE_CONTAINER_NAME=$CONTAINER_NAME
OPENCLAW_APPLE_CONTAINER_NETWORK=$NETWORK_NAME
OPENCLAW_APPLE_CONTAINER_HOST_PORT=$HOST_PORT
OPENCLAW_APPLE_CONTAINER_STATE_VOLUME=$STATE_VOLUME
OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME=$WORKSPACE_VOLUME
OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN=$HOST_DOMAIN
OPENCLAW_APPLE_CONTAINER_HOST_LOCALHOST_IP=$HOST_LOCALHOST_IP
EOF
  chmod 600 "$ENV_FILE"
}

# ── Self-install ────────────────────────────────────────────────

self_install() {
  mkdir -p "$LOCAL_SCRIPT_DIR"
  # Determine the source of this script
  local source=""
  if [[ -n "${BASH_SOURCE[0]:-}" ]] && [[ -f "${BASH_SOURCE[0]}" ]]; then
    cp "${BASH_SOURCE[0]}" "$LOCAL_SCRIPT"
    chmod +x "$LOCAL_SCRIPT"
    ok "Script saved to $LOCAL_SCRIPT"
  else
    # Running via curl pipe — download directly
    curl -fsSL "$SCRIPT_URL" -o "$LOCAL_SCRIPT"
    chmod +x "$LOCAL_SCRIPT"
    ok "Script downloaded to $LOCAL_SCRIPT"
  fi
}

# ── Commands ────────────────────────────────────────────────────

cmd_install() {
  echo ""
  step "OpenClaw Apple Container Setup"
  echo ""

  # 1. Check prerequisites
  step "Checking prerequisites..."
  preflight
  validate_runtime
  ok "macOS + Apple Silicon + Apple Container"

  # 2. Check if already installed
  if container list --quiet 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    warn "Container '$CONTAINER_NAME' already exists."
    echo ""
    echo "  To reinstall: run 'bootstrap.sh uninstall' first, then 'bootstrap.sh install' again."
    echo "  To upgrade:   run 'bootstrap.sh upgrade'"
    echo "  To start:     run 'bootstrap.sh run'"
    return 0
  fi

  # 3. Pull image
  step "Pulling image..."
  if ! container image list 2>/dev/null | awk 'NR>1{print $1,$2}' | grep -q "^${IMAGE%%:*} ${IMAGE##*:}"; then
    container image pull "$IMAGE"
    ok "Image pulled"
  else
    ok "Image already present"
  fi

  # 4. Create volumes
  step "Creating volumes..."
  ensure_volume "$STATE_VOLUME"
  ensure_volume "$WORKSPACE_VOLUME"
  ok "Volumes created"

  # 5. Create network
  step "Creating network..."
  if ! container network list --quiet 2>/dev/null | grep -qx "$NETWORK_NAME"; then
    if ! container network create "$NETWORK_NAME" >/dev/null 2>&1; then
      fail "Failed to create network '${NETWORK_NAME}'."
    fi
  fi
  ok "Network ready"

  # 6. Generate and store token
  step "Generating gateway token..."
  local token
  token="$(generate_token)"
  store_token "$token"
  ok "Token stored in macOS Keychain"

  # 7. Write config
  step "Writing config..."
  write_env
  ok "Config written to $ENV_FILE"

  # 8. Create container
  step "Creating container..."
  container create \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --publish "127.0.0.1:${HOST_PORT}:18789" \
    --volume "$STATE_VOLUME:/home/node/.openclaw" \
    --volume "$WORKSPACE_VOLUME:/home/node/.openclaw/workspace" \
    --env "HOME=/home/node" \
    --env "OPENCLAW_STATE_DIR=/home/node/.openclaw" \
    --env "OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json" \
    --env "OPENCLAW_GATEWAY_TOKEN=$token" \
    --tmpfs /tmp \
    --tmpfs /home/node/.cache \
    --read-only \
    --cap-drop ALL \
    --init \
    --user 1000:1000 \
    --cpus 2 \
    --memory 1g \
    "$IMAGE" \
    sh -c "
      if [ -f /app/openclaw.mjs ]; then
        exec '$CONTAINER_RUNTIME' /app/openclaw.mjs gateway --allow-unconfigured --host 0.0.0.0 --port 18789
      else
        echo 'Gateway not found in image.' && exit 1
      fi
    " 2>&1 | sed -e 's/^/    /'
  if ! container list --quiet --all 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    fail "Container '$CONTAINER_NAME' was not created. See output above."
  fi

  ok "Container created (runtime: $CONTAINER_RUNTIME)"

  # 9. Self-install
  self_install

  # 10. Done
  echo ""
  step "Setup complete!"
  echo ""
  echo "  Gateway token:  ${DIM}(stored in ${ENV_FILE} as OPENCLAW_GATEWAY_TOKEN)${RESET}"
  echo "  Gateway port:   ${HOST_PORT}"
  echo "  Config dir:     ${CONFIG_DIR}"
  echo "  Script:         ${LOCAL_SCRIPT}"
  echo ""
  ok "Next steps:"
  echo ""
  echo "  ${BOLD}1. Start the gateway:${RESET}"
  echo "     ${LOCAL_SCRIPT} run"
  echo ""
  echo "  ${BOLD}2. Add an AI provider (OpenAI, Anthropic, Google) + channels:${RESET}"
  echo "     container exec -it ${CONTAINER_NAME} openclaw onboard --mode local"
  echo "     ${DIM}(writes config into the container volume; persists across restarts)${RESET}"
  echo ""
  echo "  ${BOLD}3. Restart so the new config takes effect:${RESET}"
  echo "     ${LOCAL_SCRIPT} stop && ${LOCAL_SCRIPT} run"
  echo ""
  echo "  ${BOLD}4. Chat:${RESET}"
  echo "     npx openclaw chat --url ws://localhost:${HOST_PORT} --token \"\$(grep '^OPENCLAW_GATEWAY_TOKEN=' ${ENV_FILE} | cut -d= -f2-)\""
  echo ""
  info "Add aliases for quick access:"
  echo "     alias oc-run='${LOCAL_SCRIPT} run'"
  echo "     alias oc-stop='${LOCAL_SCRIPT} stop'"
  echo "     alias oc-upgrade='${LOCAL_SCRIPT} upgrade'"
  echo ""
}

cmd_run() {
  preflight

  if ! container list --quiet --all 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    fail "Container '$CONTAINER_NAME' not found. Run 'bootstrap.sh install' first."
  fi

  step "Starting OpenClaw gateway..."
  if ! container start "$CONTAINER_NAME"; then
    fail "Failed to start container '$CONTAINER_NAME'. Run: container logs $CONTAINER_NAME"
  fi

  # Wait for gateway
  local retries=0
  while [ $retries -lt 15 ]; do
    if curl -s "http://localhost:${HOST_PORT}/health" >/dev/null 2>&1; then
      echo ""
      ok "Gateway is running on port ${HOST_PORT}"
      echo ""
      echo "  Health:  http://localhost:${HOST_PORT}/health"
      echo "  Config:  inside the container at /home/node/.openclaw/openclaw.json"
      echo ""
      info "First time? Add an AI provider + channels:"
      echo "  ${BOLD}container exec -it ${CONTAINER_NAME} openclaw onboard --mode local${RESET}"
      echo ""
      info "Then chat:"
      echo "  ${BOLD}npx openclaw chat --url ws://localhost:${HOST_PORT} --token \"\$(grep '^OPENCLAW_GATEWAY_TOKEN=' ${ENV_FILE} | cut -d= -f2-)\"${RESET}"
      echo ""
      info "Or connect any WebSocket client to ws://localhost:${HOST_PORT}"
      return 0
    fi
    retries=$((retries + 1))
    sleep 1
  done

  warn "Gateway hasn't responded yet. Check logs:"
  echo "  container logs $CONTAINER_NAME"
}

cmd_stop() {
  preflight
  step "Stopping OpenClaw..."
  container kill "$CONTAINER_NAME" 2>/dev/null || true
  ok "Stopped"
}

cmd_upgrade() {
  preflight
  validate_runtime

  step "Upgrading OpenClaw..."
  echo ""

  # Stop if running
  container kill "$CONTAINER_NAME" 2>/dev/null || true

  # Pull latest
  step "Pulling latest image..."
  container image pull "$IMAGE"
  ok "Image updated"

  # Delete old container (volumes are preserved)
  step "Recreating container..."
  container delete "$CONTAINER_NAME" 2>/dev/null || true

  # Re-read token
  local token
  token="$(read_token)"
  if [[ -z "$token" ]]; then
    token="$(generate_token)"
    store_token "$token"
    warn "Generated new token (old token not found in Keychain)"
  fi

  # Recreate container with same settings
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi

  # Recreate container with same settings
  container create \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --publish "127.0.0.1:${HOST_PORT}:18789" \
    --volume "$STATE_VOLUME:/home/node/.openclaw" \
    --volume "$WORKSPACE_VOLUME:/home/node/.openclaw/workspace" \
    --env "HOME=/home/node" \
    --env "OPENCLAW_STATE_DIR=/home/node/.openclaw" \
    --env "OPENCLAW_CONFIG_PATH=/home/node/.openclaw/openclaw.json" \
    --env "OPENCLAW_GATEWAY_TOKEN=$token" \
    --tmpfs /tmp \
    --tmpfs /home/node/.cache \
    --read-only \
    --cap-drop ALL \
    --init \
    --user 1000:1000 \
    --cpus 2 \
    --memory 1g \
    "$IMAGE" \
    sh -c "
      if [ -f /app/openclaw.mjs ]; then
        exec '$CONTAINER_RUNTIME' /app/openclaw.mjs gateway --allow-unconfigured --host 0.0.0.0 --port 18789
      else
        echo 'Gateway not found in image.' && exit 1
      fi
    " 2>&1 | sed -e 's/^/    /'
  if ! container list --quiet --all 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    fail "Container '$CONTAINER_NAME' was recreated. See output above."
  fi

  ok "Container recreated (state preserved in volumes, runtime: $CONTAINER_RUNTIME)"

  # Start
  echo ""
  cmd_run
}

cmd_uninstall() {
  preflight

  step "Uninstalling OpenClaw..."
  echo ""

  if [[ ! -t 0 ]]; then
    fail "Refusing to uninstall non-interactively. Re-run from a terminal."
  fi
  local confirm=""
  read -rp "  Delete container, volumes, and config? This removes ALL data. [y/N] " confirm
  shopt -s nocasematch
  case "${confirm:-n}" in
    y|yes) ;;
    *) echo "  Cancelled."; return 0 ;;
  esac

  container kill "$CONTAINER_NAME" 2>/dev/null || true
  container delete "$CONTAINER_NAME" 2>/dev/null || true
  ok "Container deleted"

  container volume delete "$STATE_VOLUME" 2>/dev/null || true
  container volume delete "$WORKSPACE_VOLUME" 2>/dev/null || true
  ok "Volumes deleted"

  rm -rf "$CONFIG_DIR"
  ok "Config removed"

  # Remove local script
  if [[ -f "$LOCAL_SCRIPT" ]]; then
    rm -f "$LOCAL_SCRIPT"
    # Remove bin dir only if empty
    rmdir "$LOCAL_SCRIPT_DIR" 2>/dev/null || true
    ok "Local script removed"
  fi

  echo ""
  ok "Uninstalled. Reinstall with:"
  echo "  bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) install"
}

cmd_status() {
  preflight
  echo ""
  step "OpenClaw Status"
  echo ""

  # Image
  if container image list 2>/dev/null | awk 'NR>1{print $1,$2}' | grep -q "^${IMAGE%%:*} ${IMAGE##*:}"; then
    ok "Image: $IMAGE"
  else
    warn "Image: not pulled"
  fi

  # Container
  if container list --quiet 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    ok "Container: running ($CONTAINER_NAME)"
  elif container list --quiet --all 2>/dev/null | grep -qx "$CONTAINER_NAME"; then
    warn "Container: stopped ($CONTAINER_NAME)"
  else
    warn "Container: not created"
  fi

  # Token
  local token
  token="$(read_token)"
  if [[ -n "$token" ]]; then
    ok "Token: stored in Keychain"
  else
    warn "Token: not found"
  fi

  # Volumes
  for vol in "$STATE_VOLUME" "$WORKSPACE_VOLUME"; do
    if container volume list --quiet 2>/dev/null | grep -qx "$vol"; then
      ok "Volume: $vol"
    else
      warn "Volume: $vol (missing)"
    fi
  done

  # Gateway health
  if curl -s "http://localhost:${HOST_PORT}/health" >/dev/null 2>&1; then
    ok "Gateway: healthy on port ${HOST_PORT}"
  else
    warn "Gateway: not responding on port ${HOST_PORT}"
  fi

  # Config (lives inside the container volume, not on the host)
  if container list --quiet --all 2>/dev/null | grep -qx "$CONTAINER_NAME" \
    && container exec "$CONTAINER_NAME" test -f /home/node/.openclaw/openclaw.json 2>/dev/null; then
    ok "Config: /home/node/.openclaw/openclaw.json (in container)"
  else
    warn "Config: not yet created — run: container exec -it $CONTAINER_NAME openclaw onboard --mode local"
  fi

  echo ""
}

cmd_logs() {
  container logs "${CONTAINER_NAME}" "${@}"
}

# ── Main ────────────────────────────────────────────────────────
COMMAND="${1:-install}"
shift 2>/dev/null || true

# Parse runtime flag (must come before subcommand dispatch).
# Usage: bootstrap.sh install --runtime bun
#        bootstrap.sh upgrade --runtime node
while [[ "${1:-}" == --* ]]; do
  case "$1" in
    --runtime)
      shift
      CONTAINER_RUNTIME="${1:-}"
      [[ -n "$CONTAINER_RUNTIME" ]] || fail "--runtime requires a value (node or bun)."
      shift
      ;;
    --runtime=*)
      CONTAINER_RUNTIME="${1#--runtime=}"
      shift
      ;;
    *)
      break
      ;;
  esac
done

case "$COMMAND" in
  install|setup)  cmd_install ;;
  run|start)      cmd_run ;;
  stop)           cmd_stop ;;
  upgrade|update) cmd_upgrade ;;
  uninstall)      cmd_uninstall ;;
  status)         cmd_status ;;
  logs)           cmd_logs "$@" ;;
  -h|--help|help)
    echo ""
    echo "OpenClaw Apple Container"
    echo ""
    echo "Usage: bootstrap.sh <command> [--runtime node|bun]"
    echo ""
    echo "Commands:"
    echo "  install    First-time setup (pull, configure, create container) [default]"
    echo "  run        Start the gateway"
    echo "  stop       Stop the gateway"
    echo "  upgrade    Pull latest image and recreate container (preserves state)"
    echo "  status     Show installation status"
    echo "  logs       Show container logs"
    echo "  uninstall  Remove everything (container, volumes, config, token)"
    echo ""
    echo "Flags:"
    echo "  --runtime node|bun  JS runtime inside the container (default: node)"
    echo "                       Override with env: OPENCLAW_APPLE_CONTAINER_RUNTIME"
    echo ""
    echo "One-line install:"
    echo '  bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh)'
    ;;
  *)
    fail "Unknown command: $COMMAND. Run 'bootstrap.sh help' for usage."
    ;;
esac
