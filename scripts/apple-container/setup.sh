#!/usr/bin/env bash
# One-time setup for running OpenClaw in Apple Container.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/preflight.sh
source "${SCRIPT_DIR}/lib/preflight.sh"
# shellcheck source=lib/container-json.sh
source "${SCRIPT_DIR}/lib/container-json.sh"

REPO_PATH="${OPENCLAW_REPO_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
OPENCLAW_USER="$(id -un)"
OPENCLAW_HOME="${HOME:-}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${OPENCLAW_HOME}/.openclaw}"
OPENCLAW_IMAGE="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"
OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
OPENCLAW_NETWORK_NAME="${OPENCLAW_APPLE_CONTAINER_NETWORK:-openclaw-net}"
# Pin the isolated network to a deterministic subnet so the container's
# subnet stays identical across rebuilds, reinstalls, and `container network delete`.
# Default is an RFC5737 documentation range that will not collide with the
# 192.168.64-79.0/24 blocks Apple Container auto-allocates. Set
# OPENCLAW_APPLE_CONTAINER_NETWORK_SUBNET empty to let Apple Container pick.
OPENCLAW_NETWORK_SUBNET="${OPENCLAW_APPLE_CONTAINER_NETWORK_SUBNET:-172.31.224.0/24}"
OPENCLAW_HOST_PORT="${OPENCLAW_APPLE_CONTAINER_HOST_PORT:-18789}"
OPENCLAW_CONTAINER_RUNTIME="${OPENCLAW_APPLE_CONTAINER_RUNTIME:-node}"
OPENCLAW_EXTENSIONS="${OPENCLAW_EXTENSIONS:-}"
OPENCLAW_STATE_VOLUME="${OPENCLAW_APPLE_CONTAINER_STATE_VOLUME:-openclaw-state}"
OPENCLAW_WORKSPACE_VOLUME="${OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME:-openclaw-workspace}"
OPENCLAW_WORKSPACE_HOST_DIR="${OPENCLAW_APPLE_CONTAINER_WORKSPACE_HOST_DIR:-}"
OPENCLAW_INSTALL_BUN_RUNTIME="${OPENCLAW_INSTALL_BUN_RUNTIME:-1}"
OPENCLAW_HOST_DOMAIN="${OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN:-host.container.internal}"
OPENCLAW_HOST_LOCALHOST_IP="${OPENCLAW_APPLE_CONTAINER_HOST_LOCALHOST_IP:-203.0.113.113}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing dependency: $1" >&2
    exit 1
  fi
}

fail() {
  echo "$*" >&2
  exit 1
}

is_enabled() {
  local value
  value="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$value" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

validate_single_line_value() {
  local label="$1" value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    fail "Invalid $label: control characters are not allowed."
  fi
}

validate_absolute_path() {
  local label="$1" value="$2"
  validate_single_line_value "$label" "$value"
  [[ "$value" == /* ]] || fail "Invalid $label: expected an absolute path."
  [[ "$value" != *"//"* ]] || fail "Invalid $label: repeated slashes are not allowed."
  [[ "$value" != *"/./"* && "$value" != */. && "$value" != *"/../"* && "$value" != */.. ]] ||
    fail "Invalid $label: dot path segments are not allowed."
}

validate_name() {
  local label="$1" value="$2"
  validate_single_line_value "$label" "$value"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail "Invalid $label: $value"
}

validate_dns_name() {
  local label="$1" value="$2"
  validate_single_line_value "$label" "$value"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*[A-Za-z0-9]$ ]] || fail "Invalid $label: $value"
  [[ "$value" == *.* ]] || fail "Invalid $label: expected a dotted DNS name."
}

validate_ipv4() {
  local label="$1" value="$2" part="" IFS=.
  local -a parts=()
  validate_single_line_value "$label" "$value"
  read -r -a parts <<<"$value"
  [[ "${#parts[@]}" -eq 4 ]] || fail "Invalid $label: expected IPv4 address."
  for part in "${parts[@]}"; do
    [[ "$part" =~ ^[0-9]{1,3}$ ]] || fail "Invalid $label: expected IPv4 address."
    ((10#$part >= 0 && 10#$part <= 255)) || fail "Invalid $label: octet out of range."
  done
}

ensure_volume() {
  local volume="$1"
  if container volume list --quiet 2>/dev/null | grep -qx "$volume"; then
    echo "==> Volume '${volume}' already exists."
    return
  fi
  echo "==> Creating volume '${volume}'..."
  if ! container volume create "$volume" >/dev/null 2>&1; then
    fail "Failed to create volume '${volume}'."
  fi
}

validate_image_name() {
  local value="$1"
  validate_single_line_value "image name" "$value"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || fail "Invalid image name: $value"
}

validate_port() {
  local label="$1" value="$2" numeric=""
  [[ "$value" =~ ^[0-9]{1,5}$ ]] || fail "Invalid $label: must be numeric."
  numeric=$((10#$value))
  ((numeric >= 1 && numeric <= 65535)) || fail "Invalid $label: out of range (1-65535)."
}

ensure_safe_existing_dir() {
  local label="$1" dir="$2"
  validate_absolute_path "$label" "$dir"
  [[ -d "$dir" ]] || fail "Missing $label: $dir"
  [[ ! -L "$dir" ]] || fail "Unsafe $label: symlinks are not allowed ($dir)"
}

stat_uid() {
  local path="$1"
  if stat -f '%u' "$path" >/dev/null 2>&1; then
    stat -f '%u' "$path"
  else
    stat -Lc '%u' "$path"
  fi
}

stat_mode() {
  local path="$1"
  if stat -f '%Lp' "$path" >/dev/null 2>&1; then
    stat -f '%Lp' "$path"
  else
    stat -Lc '%a' "$path"
  fi
}

ensure_private_existing_dir_owned_by_user() {
  local label="$1" dir="$2" uid="" mode=""
  ensure_safe_existing_dir "$label" "$dir"
  uid="$(stat_uid "$dir")"
  [[ "$uid" == "$(id -u)" ]] || fail "Unsafe $label: not owned by current user ($dir)"
  mode="$(stat_mode "$dir")"
  (( (8#$mode & 0022) == 0 )) || fail "Unsafe $label: group/other writable ($dir)"
}

ensure_safe_write_file_path() {
  local label="$1" file="$2" dir=""
  validate_absolute_path "$label" "$file"
  if [[ -e "$file" ]]; then
    [[ ! -L "$file" ]] || fail "Unsafe $label: symlinks are not allowed ($file)"
    [[ -f "$file" ]] || fail "Unsafe $label: expected a regular file ($file)"
  fi
  dir="$(dirname "$file")"
  ensure_safe_existing_dir "${label} parent directory" "$dir"
}

write_file_atomically() {
  local file="$1" mode="$2" dir="" tmp=""
  ensure_safe_write_file_path "output file" "$file"
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.tmp.XXXXXX")"
  cat >"$tmp"
  chmod "$mode" "$tmp"
  mv -f "$tmp" "$file"
}

upsert_env_var() {
  local file="$1" key="$2" value="$3" tmp="" dir=""
  ensure_safe_write_file_path "env file" "$file"
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.env.tmp.XXXXXX")"
  if [[ -f "$file" ]]; then
    awk -v k="$key" -v v="$value" '
      BEGIN { found = 0 }
      $0 ~ ("^" k "=") { print k "=" v; found = 1; next }
      { print }
      END { if (!found) print k "=" v }
    ' "$file" >"$tmp"
  else
    printf '%s=%s\n' "$key" "$value" >"$tmp"
  fi
  mv "$tmp" "$file"
  chmod 600 "$file" 2>/dev/null || true
}

remove_env_var() {
  local file="$1" key="$2" tmp="" dir=""
  [[ -f "$file" ]] || return 0
  ensure_safe_write_file_path "env file" "$file"
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.env.tmp.XXXXXX")"
  awk -v k="$key" '$0 !~ ("^" k "=") { print }' "$file" >"$tmp"
  mv "$tmp" "$file"
  chmod 600 "$file" 2>/dev/null || true
}

read_env_gateway_token() {
  local file="$1" line="" token=""
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" == OPENCLAW_GATEWAY_TOKEN=* ]]; then
      token="${line#OPENCLAW_GATEWAY_TOKEN=}"
    fi
  done <"$file"
  if [[ -n "$token" ]]; then
    printf '%s' "$token"
  fi
}

read_config_gateway_token() {
  local config_path="$1"
  [[ -f "$config_path" ]] || return 0
  if command -v node >/dev/null 2>&1; then
    node - "$config_path" <<'NODE'
const fs = require("node:fs");
const configPath = process.argv[2];
let JSON5;
try {
  JSON5 = require("json5");
} catch {
  JSON5 = undefined;
}
try {
  const raw = fs.readFileSync(configPath, "utf8");
  const cfg = JSON5 ? JSON5.parse(raw) : JSON.parse(raw);
  const token = cfg?.gateway?.auth?.token;
  if (
    typeof token === "string" &&
    token.trim().length > 0 &&
    !token.includes("${")
  ) {
    process.stdout.write(token.trim());
  }
} catch {
  // Existing config may be JSON5 before dependencies are installed; ignore it.
}
NODE
  fi
}


ensure_host_bridge_dns() {
  local existing=""
  if existing="$(container system dns list --quiet 2>/dev/null)"; then
    if echo "$existing" | grep -qx "$OPENCLAW_HOST_DOMAIN"; then
      echo "==> Host bridge DNS '${OPENCLAW_HOST_DOMAIN}' already exists."
      return
    fi
  fi

  echo "==> Creating host bridge DNS '${OPENCLAW_HOST_DOMAIN}' for Apple Container..."
  echo "    This may prompt for administrator approval and can disable Private Relay while active."
  sudo container system dns create --localhost "$OPENCLAW_HOST_LOCALHOST_IP" "$OPENCLAW_HOST_DOMAIN" >/dev/null
}

generate_token_hex_32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
    return 0
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
    return 0
  fi
  fail "Missing dependency: need openssl or python3 to generate gateway token."
}

show_help() {
  echo "Usage: $(basename "$0") [options]"
  echo ""
  echo "Options:"
  echo "  --extensions LIST        Bundled plugins to include"
  echo "  --runtime node|bun       Gateway runtime (default: node)"
  echo "  --install-bun-runtime    Include Bun for faster TUI startup (default)"
  echo "  --no-install-bun-runtime Omit Bun for the smallest image"
  echo ""
  echo "Environment:"
  echo "  OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN      Host bridge DNS name"
  echo "  OPENCLAW_INSTALL_BUN_RUNTIME=0            Omit Bun unless --runtime bun is used"
  echo "  -h, --help               Show this help"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      show_help
      exit 0
      ;;
    --extensions)
      OPENCLAW_EXTENSIONS="${2:?--extensions requires a value}"
      shift 2
      ;;
    --extensions=*)
      OPENCLAW_EXTENSIONS="${1#*=}"
      shift
      ;;
    --runtime)
      OPENCLAW_CONTAINER_RUNTIME="${2:?--runtime requires a value}"
      shift 2
      ;;
    --runtime=*)
      OPENCLAW_CONTAINER_RUNTIME="${1#*=}"
      shift
      ;;
    --install-bun-runtime)
      OPENCLAW_INSTALL_BUN_RUNTIME=1
      shift
      ;;
    --no-install-bun-runtime)
      OPENCLAW_INSTALL_BUN_RUNTIME=0
      shift
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

require_cmd container
require_cmd node
require_cmd /usr/bin/security

if [[ "${OPENCLAW_SKIP_PREFLIGHT:-0}" != "1" ]]; then
  preflight_check_macos >/dev/null || fail "This script only runs on macOS."
  preflight_check_arm64 >/dev/null || fail "This script requires Apple Silicon (arm64)."
  preflight_check_curl >/dev/null || true
  preflight_check_token_source >/dev/null || true
fi

[[ -n "$OPENCLAW_HOME" ]] || fail "Unable to resolve HOME for user $OPENCLAW_USER."
validate_absolute_path "home directory" "$OPENCLAW_HOME"
validate_absolute_path "config directory" "$OPENCLAW_CONFIG_DIR"
validate_name "container name" "$OPENCLAW_CONTAINER_NAME"
validate_name "network name" "$OPENCLAW_NETWORK_NAME"
validate_name "state volume" "$OPENCLAW_STATE_VOLUME"
if [[ -z "$OPENCLAW_WORKSPACE_HOST_DIR" ]]; then
  validate_name "workspace volume" "$OPENCLAW_WORKSPACE_VOLUME"
else
  validate_absolute_path "workspace host directory" "$OPENCLAW_WORKSPACE_HOST_DIR"
fi
validate_dns_name "host bridge DNS name" "$OPENCLAW_HOST_DOMAIN"
validate_ipv4 "host bridge localhost IP" "$OPENCLAW_HOST_LOCALHOST_IP"
validate_image_name "$OPENCLAW_IMAGE"
validate_port "host port" "$OPENCLAW_HOST_PORT"

case "$OPENCLAW_CONTAINER_RUNTIME" in
  node|bun) ;;
  *) fail "Invalid runtime: expected node or bun." ;;
esac

if [[ "$OPENCLAW_CONTAINER_RUNTIME" == "bun" ]]; then
  OPENCLAW_INSTALL_BUN_RUNTIME=1
fi

[[ -f "$REPO_PATH/Dockerfile.apple_arm64" ]] ||
  fail "Dockerfile.apple_arm64 not found. Set OPENCLAW_REPO_PATH to the repo root."

if ! container system status --format json >/dev/null 2>&1; then
  fail "Apple Container is not running. Run: container system start"
fi

install -d -m 700 "$OPENCLAW_CONFIG_DIR"
ensure_private_existing_dir_owned_by_user "config directory" "$OPENCLAW_CONFIG_DIR"
ensure_volume "$OPENCLAW_STATE_VOLUME"
if [[ -z "$OPENCLAW_WORKSPACE_HOST_DIR" ]]; then
  ensure_volume "$OPENCLAW_WORKSPACE_VOLUME"
else
  install -d -m 0750 "$OPENCLAW_WORKSPACE_HOST_DIR" ||
    fail "Could not create workspace host directory: $OPENCLAW_WORKSPACE_HOST_DIR"
fi
ensure_host_bridge_dns

ENV_FILE="$OPENCLAW_CONFIG_DIR/apple-container.env"
CONFIG_JSON="$OPENCLAW_CONFIG_DIR/openclaw.json"
EXISTING_CONFIG_TOKEN="$(read_config_gateway_token "$CONFIG_JSON" || true)"
EXISTING_ENV_TOKEN="$(read_env_gateway_token "$ENV_FILE" || true)"

BUILD_ARGS=()
if [[ -n "$OPENCLAW_EXTENSIONS" ]]; then
  BUILD_ARGS+=(--build-arg "OPENCLAW_EXTENSIONS=${OPENCLAW_EXTENSIONS}")
fi
if is_enabled "$OPENCLAW_INSTALL_BUN_RUNTIME"; then
  BUILD_ARGS+=(--build-arg "OPENCLAW_INSTALL_BUN_RUNTIME=1")
fi

echo "==> Building image ${OPENCLAW_IMAGE}..."
"$REPO_PATH/scripts/apple-container/build.sh" -t "$OPENCLAW_IMAGE" "${BUILD_ARGS[@]}"
echo "==> Build complete: ${OPENCLAW_IMAGE}"

# Resolve the gateway token: prefer an existing token, otherwise generate one.
# It is stored in the host env file and passed into the container at launch via
# OPENCLAW_GATEWAY_TOKEN (no macOS Keychain involved).
TOKEN="${EXISTING_CONFIG_TOKEN:-${EXISTING_ENV_TOKEN:-$(generate_token_hex_32)}}"
if [[ -n "$EXISTING_CONFIG_TOKEN" ]]; then
  echo "==> Reusing existing gateway.auth.token"
elif [[ -n "$EXISTING_ENV_TOKEN" ]]; then
  echo "==> Reusing existing OPENCLAW_GATEWAY_TOKEN"
else
  echo "==> Generated gateway token"
fi

if [[ ! -f "$ENV_FILE" ]]; then
  (
    umask 077
    write_file_atomically "$ENV_FILE" 600 <<'EOF'
# OpenClaw Apple Container runtime settings.
# The gateway auth token is stored as OPENCLAW_GATEWAY_TOKEN below.
EOF
  )
fi
upsert_env_var "$ENV_FILE" "OPENCLAW_GATEWAY_TOKEN" "$TOKEN"

upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_IMAGE" "$OPENCLAW_IMAGE"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_NAME" "$OPENCLAW_CONTAINER_NAME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_NETWORK" "$OPENCLAW_NETWORK_NAME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_NETWORK_SUBNET" "$OPENCLAW_NETWORK_SUBNET"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_HOST_PORT" "$OPENCLAW_HOST_PORT"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_RUNTIME" "$OPENCLAW_CONTAINER_RUNTIME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_STATE_VOLUME" "$OPENCLAW_STATE_VOLUME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME" "$OPENCLAW_WORKSPACE_VOLUME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_WORKSPACE_HOST_DIR" "$OPENCLAW_WORKSPACE_HOST_DIR"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN" "$OPENCLAW_HOST_DOMAIN"

  if EXISTING_NETWORK="$(container network list --quiet 2>/dev/null)"; then
    # Validate the pinned subnet, if any. Accept empty (auto-allocate) or a
    # strict a.b.c.d/mask IPv4 CIDR.
    if [[ -n "$OPENCLAW_NETWORK_SUBNET" ]]; then
      if [[ ! "$OPENCLAW_NETWORK_SUBNET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$ ]]; then
        fail "Invalid OPENCLAW_APPLE_CONTAINER_NETWORK_SUBNET: '$OPENCLAW_NETWORK_SUBNET' (expected empty or IPv4 CIDR like 172.31.224.0/24)."
      fi
    fi

    if echo "$EXISTING_NETWORK" | grep -qx "$OPENCLAW_NETWORK_NAME"; then
      echo "==> Network '${OPENCLAW_NETWORK_NAME}' already exists."
      # Reconcile subnet: if a deterministic subnet is pinned and the existing
      # network's subnet differs, recreate the network so the subnet stays
      # stable across rebuilds. Any
      # running containers must be stopped first; container networks are
      # immutable once created, so delete + recreate is the only path.
      if [[ -n "$OPENCLAW_NETWORK_SUBNET" ]]; then
        local existing_subnet=""
        existing_subnet="$(parse_container_network_subnet "$OPENCLAW_NETWORK_NAME")"
        if [[ -n "$existing_subnet" && "$existing_subnet" != "$OPENCLAW_NETWORK_SUBNET" ]]; then
          echo "==> Network subnet is ${existing_subnet}, pinned subnet is ${OPENCLAW_NETWORK_SUBNET}; reconciling."
          # Networks cannot be deleted while a container is attached, and the
          # container VM needs a moment to release after `stop` before `delete`
          # succeeds. Stop+wait, then delete with a short retry.
          if container ls --quiet 2>/dev/null | grep -qx "$OPENCLAW_CONTAINER_NAME"; then
            echo "==> Stopping container '$OPENCLAW_CONTAINER_NAME' to recreate network."
            container stop "$OPENCLAW_CONTAINER_NAME" >/dev/null 2>&1 || true
            local reconcile_wait=0
            while container ls --quiet 2>/dev/null | grep -qx "$OPENCLAW_CONTAINER_NAME" && (( reconcile_wait < 15 )); do
              sleep 1
              reconcile_wait=$((reconcile_wait + 1))
            done
            container delete "$OPENCLAW_CONTAINER_NAME" >/dev/null 2>&1 || true
          fi
          local net_deleted=0
          if container network delete "$OPENCLAW_NETWORK_NAME" >/dev/null 2>&1; then
            net_deleted=1
          else
            # Retry once after a beat: the VM teardown can lag the stop call.
            sleep 2
            if container network delete "$OPENCLAW_NETWORK_NAME" >/dev/null 2>&1; then
              net_deleted=1
            fi
          fi
          if [[ "$net_deleted" != "1" ]]; then
            echo "    (could not delete network '${OPENCLAW_NETWORK_NAME}' (still in use?); keeping existing subnet ${existing_subnet})" >&2
          fi
          # Fall through to the create path below.
          EXISTING_NETWORK="$(container network list --quiet 2>/dev/null || true)"
        fi
      fi
    fi

    if ! echo "$EXISTING_NETWORK" | grep -qx "$OPENCLAW_NETWORK_NAME"; then
      echo "==> Creating isolated network '${OPENCLAW_NETWORK_NAME}'"${OPENCLAW_NETWORK_SUBNET:+ (subnet ${OPENCLAW_NETWORK_SUBNET})}"..."
      local create_args=("$OPENCLAW_NETWORK_NAME")
      [[ -n "$OPENCLAW_NETWORK_SUBNET" ]] && create_args=(--subnet "$OPENCLAW_NETWORK_SUBNET" "${create_args[@]}")
      if ! container network create "${create_args[@]}" 2>&1; then
        echo "    (network creation failed; using default network at run time)" >&2
      fi
    fi
  else
    echo "==> Network commands unavailable, using default network at run time."
  fi

echo ""
echo "Setup complete."
echo ""
echo "Next steps:"
echo "  scripts/apple-container/run.sh --open"
echo "  curl -s http://127.0.0.1:${OPENCLAW_HOST_PORT}/healthz"
echo ""
echo "Runtime env: ${ENV_FILE}"
echo "Config:    ${CONFIG_JSON}"
echo "State:     ${OPENCLAW_STATE_VOLUME}"
echo "Host DNS:  ${OPENCLAW_HOST_DOMAIN}"
echo "Workspace: ${OPENCLAW_WORKSPACE_HOST_DIR:-${OPENCLAW_WORKSPACE_VOLUME}}"
echo "Image:     ${OPENCLAW_IMAGE}"
echo "Network:   ${OPENCLAW_NETWORK_NAME}"
