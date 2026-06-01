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

set -euo pipefail

# ── Config ──────────────────────────────────────────────────────
IMAGE="ghcr.io/markfietje/openclaw:apple-arm64"
CONTAINER_NAME="${OPENCLAW_CONTAINER_NAME:-openclaw}"
HOST_PORT="${OPENCLAW_HOST_PORT:-18789}"
CONFIG_DIR="${HOME}/.openclaw"
ENV_FILE="${CONFIG_DIR}/apple-container.env"
KEYCHAIN_SERVICE="ai.openclaw.apple-container.gateway-token"
KEYCHAIN_ACCOUNT="$(id -un)"
NETWORK_NAME="openclaw-net"
STATE_VOLUME="openclaw-state"
TOKEN_KEY_VOLUME="openclaw-token-key"
WORKSPACE_VOLUME="openclaw-workspace"
HOST_DOMAIN="host.container.internal"
HOST_LOCALHOST_IP="203.0.113.113"

# ── Local script path ───────────────────────────────────────────
LOCAL_SCRIPT_DIR="${CONFIG_DIR}/bin"
LOCAL_SCRIPT="${LOCAL_SCRIPT_DIR}/openclaw-container.sh"
SCRIPT_URL="https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh"

# ── Helpers ─────────────────────────────────────────────────────
BOLD='\033[1m'
GREEN='\033[32m'
RED='\033[31m'
YELLOW='\033[33m'
DIM='\033[2m'
RESET='\033[0m'

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
  if [[ "$(uname)" != "Darwin" ]]; then
    fail "Apple Container only runs on macOS."
  fi

  if ! sysctl -n hw.optional.arm64 >/dev/null 2>&1; then
    fail "Apple Silicon (M1/M2/M3/M4) is required."
  fi

  # Check if container CLI is installed
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

  require_cmd security

  # Ensure the container runtime is running
  if ! container system status 2>/dev/null | grep -q "running"; then
    step "Starting Apple Container runtime..."
    container system start 2>/dev/null || {
      # Retry with sudo if needed
      warn "Need admin privileges to start the runtime."
      sudo container system start 2>/dev/null || fail "Could not start Apple Container runtime."
    }
    # Wait for builder to be ready
    local retries=0
    while [ $retries -lt 30 ]; do
      if container system status 2>/dev/null | grep -q "running"; then
        ok "Apple Container runtime started"
        return 0
      fi
      retries=$((retries + 1))
      sleep 1
    done
    fail "Apple Container runtime did not start in time. Try: container system start"
  fi
  ok "Apple Container runtime is running"
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

# ── Store token in Keychain ─────────────────────────────────────
store_token() {
  local token="$1"
  # Delete existing if present
  security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1 || true
  security add-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w "$token" >/dev/null
}

read_token() {
  security find-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" -w 2>/dev/null || echo ""
}

# ── Ensure volumes ──────────────────────────────────────────────
ensure_volume() {
  local name="$1"
  if container volume list --quiet 2>/dev/null | grep -qx "$name"; then
    return
  fi
  container volume create "$name" >/dev/null
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
OPENCLAW_APPLE_CONTAINER_TOKEN_KEY_VOLUME=$TOKEN_KEY_VOLUME
OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME=$WORKSPACE_VOLUME
OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE=$KEYCHAIN_SERVICE
OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT=$KEYCHAIN_ACCOUNT
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
  ensure_volume "$TOKEN_KEY_VOLUME"
  ensure_volume "$WORKSPACE_VOLUME"
  ok "Volumes created"

  # 5. Create network
  step "Creating network..."
  if ! container network list --quiet 2>/dev/null | grep -qx "$NETWORK_NAME"; then
    container network create "$NETWORK_NAME" >/dev/null 2>&1 || true
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
    --publish "${HOST_PORT}:18789" \
    --volume "$STATE_VOLUME:/state" \
    --volume "$TOKEN_KEY_VOLUME:/token-key" \
    --volume "$WORKSPACE_VOLUME:/workspace" \
    --read-only \
    --cap-drop ALL \
    --init \
    "$IMAGE" \
    sh -c "
      if [ -f /app/openclaw.mjs ]; then
        exec node /app/openclaw.mjs gateway --host 0.0.0.0 --port 18789 --token \"\$(cat /token-key/token 2>/dev/null || true)\"
      else
        echo 'Gateway not found in image.' && exit 1
      fi
    " 2>/dev/null || true

  # Store token in volume too
  local staging
  staging="$(mktemp -d)"
  echo "$token" > "$staging/token"
  chmod 400 "$staging/token"
  container cp "$staging/token" "$CONTAINER_NAME:/token-key/token" 2>/dev/null || true
  rm -rf "$staging"

  ok "Container created"

  # 9. Self-install
  self_install

  # 10. Done
  echo ""
  step "Setup complete!"
  echo ""
  echo "  Gateway token:  ${DIM}(stored in Keychain — you don't need it)${RESET}"
  echo "  Gateway port:   ${HOST_PORT}"
  echo "  Config dir:     ${CONFIG_DIR}"
  echo "  Script:         ${LOCAL_SCRIPT}"
  echo ""
  ok "Next steps:"
  echo ""
  echo "  ${BOLD}1. Start the gateway:${RESET}"
  echo "     ${LOCAL_SCRIPT} run"
  echo ""
  echo "  ${BOLD}2. Configure channels (Telegram, Discord, etc.):${RESET}"
  echo "     nano ~/.openclaw/openclaw.json"
  echo ""
  echo "  ${BOLD}3. Add AI providers (OpenAI, Anthropic, Google):${RESET}"
  echo "     Edit ~/.openclaw/openclaw.json — add your API keys under models.providers"
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
  container start "$CONTAINER_NAME" 2>/dev/null || true

  # Wait for gateway
  local retries=0
  while [ $retries -lt 15 ]; do
    if curl -s "http://localhost:${HOST_PORT}/health" >/dev/null 2>&1; then
      echo ""
      ok "Gateway is running on port ${HOST_PORT}"
      echo ""
      echo "  Health:  http://localhost:${HOST_PORT}/health"
      echo "  Config:  ${CONFIG_DIR}/openclaw.json"
      echo ""
      info "Connect with the TUI (requires repo clone):"
      echo "  ${BOLD}scripts/apple-container/openclaw-tui.sh${RESET}"
      echo ""
      info "Or connect any WebSocket client to:"
      echo "  ${BOLD}ws://localhost:${HOST_PORT}${RESET}"
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

  container create \
    --name "$CONTAINER_NAME" \
    --network "$NETWORK_NAME" \
    --publish "${HOST_PORT}:18789" \
    --volume "$STATE_VOLUME:/state" \
    --volume "$TOKEN_KEY_VOLUME:/token-key" \
    --volume "$WORKSPACE_VOLUME:/workspace" \
    --read-only \
    --cap-drop ALL \
    --init \
    "$IMAGE" \
    sh -c "
      if [ -f /app/openclaw.mjs ]; then
        exec node /app/openclaw.mjs gateway --host 0.0.0.0 --port 18789 --token \"\$(cat /token-key/token 2>/dev/null || true)\"
      else
        echo 'Gateway not found in image.' && exit 1
      fi
    " 2>/dev/null || true

  # Re-store token in volume
  local staging
  staging="$(mktemp -d)"
  echo "$token" > "$staging/token"
  chmod 400 "$staging/token"
  container cp "$staging/token" "$CONTAINER_NAME:/token-key/token" 2>/dev/null || true
  rm -rf "$staging"

  ok "Container recreated (state preserved in volumes)"

  # Start
  echo ""
  cmd_run
}

cmd_uninstall() {
  preflight

  step "Uninstalling OpenClaw..."
  echo ""

  read -rp "  Delete container, volumes, and config? This removes ALL data. [y/N] " confirm
  shopt -s nocasematch
  [[ "$confirm" == "y" ]] || { echo "  Cancelled."; return 0; }

  container kill "$CONTAINER_NAME" 2>/dev/null || true
  container delete "$CONTAINER_NAME" 2>/dev/null || true
  ok "Container deleted"

  container volume delete "$STATE_VOLUME" 2>/dev/null || true
  container volume delete "$TOKEN_KEY_VOLUME" 2>/dev/null || true
  container volume delete "$WORKSPACE_VOLUME" 2>/dev/null || true
  ok "Volumes deleted"

  security delete-generic-password -s "$KEYCHAIN_SERVICE" -a "$KEYCHAIN_ACCOUNT" >/dev/null 2>&1 || true
  ok "Keychain token removed"

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
  for vol in "$STATE_VOLUME" "$TOKEN_KEY_VOLUME" "$WORKSPACE_VOLUME"; do
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

  # Config
  if [[ -f "${CONFIG_DIR}/openclaw.json" ]]; then
    ok "Config: ${CONFIG_DIR}/openclaw.json"
  else
    warn "Config: not found — run 'bootstrap.sh install' first"
  fi

  echo ""
}

cmd_logs() {
  container logs "${CONTAINER_NAME}" "${@}"
}

# ── Main ────────────────────────────────────────────────────────
COMMAND="${1:-install}"
shift 2>/dev/null || true

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
    echo "Usage: bootstrap.sh <command>"
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
    echo "One-line install:"
    echo '  bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh)'
    ;;
  *)
    fail "Unknown command: $COMMAND. Run 'bootstrap.sh help' for usage."
    ;;
esac
