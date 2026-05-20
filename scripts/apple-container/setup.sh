#!/usr/bin/env bash
# One-time setup for running OpenClaw in Apple Container.

set -euo pipefail

REPO_PATH="${OPENCLAW_REPO_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
OPENCLAW_USER="$(id -un)"
OPENCLAW_HOME="${HOME:-}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${OPENCLAW_HOME}/.openclaw}"
OPENCLAW_IMAGE="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"
OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
OPENCLAW_NETWORK_NAME="${OPENCLAW_APPLE_CONTAINER_NETWORK:-openclaw-net}"
OPENCLAW_HOST_PORT="${OPENCLAW_APPLE_CONTAINER_HOST_PORT:-18789}"
OPENCLAW_CONTAINER_RUNTIME="${OPENCLAW_APPLE_CONTAINER_RUNTIME:-node}"
OPENCLAW_EXTENSIONS="${OPENCLAW_EXTENSIONS:-}"
OPENCLAW_STATE_VOLUME="${OPENCLAW_APPLE_CONTAINER_STATE_VOLUME:-openclaw-state}"
OPENCLAW_LEGACY_TOKEN_KEY_VOLUME="${OPENCLAW_APPLE_CONTAINER_TOKEN_KEY_VOLUME:-openclaw-token-key}"
OPENCLAW_WORKSPACE_VOLUME="${OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME:-openclaw-workspace}"
OPENCLAW_INSTALL_BUN_RUNTIME="${OPENCLAW_INSTALL_BUN_RUNTIME:-1}"
OPENCLAW_KEYCHAIN_SERVICE="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE:-ai.openclaw.apple-container.gateway-token}"
OPENCLAW_KEYCHAIN_ACCOUNT="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT:-$OPENCLAW_USER}"
OPENCLAW_KEYCHAIN_TRUST_SECURITY_CLI="${OPENCLAW_APPLE_CONTAINER_TRUST_SECURITY_CLI:-0}"
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
  container volume create "$volume" >/dev/null
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

sync_keychain_gateway_token_config() {
  local config_path="$1" host_port="$2"
  node - "$config_path" "$host_port" <<'NODE'
const fs = require("node:fs");
const path = require("node:path");
const configPath = process.argv[2];
const hostPort = process.argv[3];
let JSON5;
try {
  JSON5 = require("json5");
} catch {
  JSON5 = undefined;
}

let cfg = {};
if (fs.existsSync(configPath)) {
  const raw = fs.readFileSync(configPath, "utf8");
  cfg = JSON5 ? JSON5.parse(raw) : JSON.parse(raw);
}
cfg.gateway ??= {};
cfg.gateway.mode = "local";
cfg.gateway.port = 18789;
cfg.gateway.bind = "lan";
cfg.gateway.auth ??= {};
cfg.gateway.auth.mode = "token";
cfg.gateway.auth.token = { source: "exec", provider: "gateway_token", id: "gateway/token" };
cfg.gateway.auth.rateLimit ??= {
  maxAttempts: 10,
  windowMs: 60000,
  lockoutMs: 300000,
  exemptLoopback: false,
};
cfg.gateway.auth.rateLimit.exemptLoopback = false;
cfg.gateway.controlUi ??= {};
cfg.gateway.controlUi.enabled ??= true;
cfg.gateway.controlUi.allowedOrigins ??= [
  `http://127.0.0.1:${hostPort}`,
  `http://localhost:${hostPort}`,
];
cfg.gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback = false;
cfg.gateway.controlUi.allowInsecureAuth = false;
cfg.gateway.controlUi.dangerouslyDisableDeviceAuth = false;
cfg.gateway.allowRealIpFallback = false;
cfg.gateway.security ??= {};
Object.assign(cfg.gateway.security, {
  disableLocalhostPrivilege: true,
  strictHeaderValidation: true,
  strictProtoValidation: true,
  enableMessageAuthorization: true,
  enableHandshakeTokens: true,
  enableRateLimiting: true,
  requireSubprotocol: true,
  rejectUntrustedProxyHeaders: true,
  autoDisableLocalhostBehindProxy: true,
  validateHostHeader: true,
  enablePingPong: true,
  tlsMinVersion: "TLSv1.3",
  dangerouslyAllowHostHeaderOriginFallback: false,
  dangerouslyAllowLegacyEndpointFallback: false,
  dangerouslyAllowUnmappedMethods: false,
  maxWebSocketConnections: cfg.gateway.security.maxWebSocketConnections ?? 32,
  maxPayloadBytes: cfg.gateway.security.maxPayloadBytes ?? 26214400,
});
cfg.gateway.security.connectionRateLimit ??= {
  maxAttempts: 30,
  windowMs: 10000,
  lockoutMs: 60000,
  exemptLoopback: false,
};
cfg.gateway.security.connectionRateLimit.exemptLoopback = false;
cfg.gateway.security.connectionRateLimit.ipv6SubnetMask ??= 56;
cfg.gateway.http ??= {};
cfg.gateway.http.endpoints ??= {};
cfg.gateway.http.endpoints.chatCompletions ??= { enabled: false };
cfg.gateway.http.endpoints.responses ??= { enabled: false };
cfg.discovery ??= {};
cfg.discovery.mdns ??= { mode: "off" };
cfg.discovery.wideArea ??= { enabled: false };
cfg.session ??= {};
cfg.session.dmScope ??= "per-channel-peer";
cfg.agents ??= {};
cfg.agents.defaults ??= {};
cfg.agents.defaults.workspace ??= "/home/node/.openclaw/workspace";
cfg.agents.defaults.maxConcurrent ??= 1;
cfg.agents.defaults.subagents ??= {};
cfg.agents.defaults.subagents.maxConcurrent ??= 1;
cfg.tools ??= {};
cfg.tools.profile ??= "messaging";
cfg.tools.deny ??= [
  "group:automation",
  "group:runtime",
  "group:fs",
  "sessions_spawn",
  "sessions_send",
];
cfg.tools.fs ??= { workspaceOnly: true };
cfg.tools.exec ??= {};
cfg.tools.exec.host ??= "gateway";
cfg.tools.exec.security ??= "deny";
cfg.tools.exec.ask ??= "always";
cfg.tools.exec.strictInlineEval ??= true;
cfg.tools.exec.applyPatch ??= { workspaceOnly: true };
cfg.tools.elevated ??= { enabled: false };
cfg.tools.loopDetection ??= { enabled: true };
cfg.logging ??= {};
cfg.logging.redactSensitive ??= "tools";
cfg.secrets ??= {};
cfg.secrets.providers ??= {};
cfg.secrets.providers.gateway_token = {
  source: "exec",
  command: "/home/node/.openclaw/openclaw-gateway-token-resolver",
  jsonOnly: true,
  passEnv: [
    "OPENCLAW_KEYCHAIN_BRIDGE_URL",
    "OPENCLAW_KEYCHAIN_BRIDGE_TOKEN_FILE",
    "OPENCLAW_KEYCHAIN_BRIDGE_TIMEOUT_MS",
  ],
  timeoutMs: 5000,
  maxOutputBytes: 4096,
};
fs.mkdirSync(path.dirname(configPath), { recursive: true, mode: 0o700 });
const tmp = `${configPath}.tmp-${process.pid}`;
fs.writeFileSync(tmp, `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o600 });
fs.renameSync(tmp, configPath);
NODE
  chmod 600 "$config_path" 2>/dev/null || true
}

keychain_gateway_token_exists() {
  /usr/bin/security find-generic-password \
    -a "$OPENCLAW_KEYCHAIN_ACCOUNT" \
    -s "$OPENCLAW_KEYCHAIN_SERVICE" \
    -w >/dev/null 2>&1
}

store_gateway_token_in_keychain() {
  local token="$1"
  local -a trust_args=(-T "")
  if is_enabled "$OPENCLAW_KEYCHAIN_TRUST_SECURITY_CLI"; then
    trust_args=(-T /usr/bin/security)
  fi
  validate_single_line_value "gateway token" "$token"
  [[ -n "$token" ]] || fail "Refusing to store an empty gateway token in Keychain."
  /usr/bin/security add-generic-password \
    -a "$OPENCLAW_KEYCHAIN_ACCOUNT" \
    -s "$OPENCLAW_KEYCHAIN_SERVICE" \
    -l "OpenClaw Apple Container Gateway Token" \
    -j "OpenClaw Apple Container gateway.auth.token" \
    -w "$token" \
    "${trust_args[@]}" \
    -U >/dev/null
}

read_legacy_encrypted_gateway_token() {
  local temp_name="${OPENCLAW_CONTAINER_NAME}-token-migrate" output=""
  if ! container image list 2>/dev/null | grep -Fq "${OPENCLAW_IMAGE%%:*}"; then
    return 0
  fi
  if ! container volume list --quiet 2>/dev/null | grep -qx "$OPENCLAW_STATE_VOLUME"; then
    return 0
  fi
  if ! container volume list --quiet 2>/dev/null | grep -qx "$OPENCLAW_LEGACY_TOKEN_KEY_VOLUME"; then
    return 0
  fi
  container delete "$temp_name" >/dev/null 2>&1 || true
  output="$(
    printf '{"protocolVersion":1,"provider":"gateway_token","ids":["gateway/token"]}\n' |
      container run \
        --rm \
        --interactive \
        --name "$temp_name" \
        --read-only \
        --tmpfs /tmp \
        --cap-drop ALL \
        --init \
        --user 1000:1000 \
        --mount "type=volume,source=${OPENCLAW_STATE_VOLUME},target=/home/node/.openclaw" \
        --mount "type=volume,source=${OPENCLAW_LEGACY_TOKEN_KEY_VOLUME},target=/home/node/.openclaw-token-key" \
        "$OPENCLAW_IMAGE" \
        /usr/local/bin/openclaw-gateway-token-resolver 2>/dev/null || true
  )"
  [[ -n "$output" ]] || return 0
  node -e 'const fs=require("node:fs"); try { const p=JSON.parse(fs.readFileSync(0,"utf8")); const v=p?.values?.["gateway/token"]; if (typeof v === "string" && v.trim()) process.stdout.write(v.trim()); } catch {}' <<<"$output"
}

ensure_host_keychain_dns() {
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
  echo "  OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE Keychain service name"
  echo "  OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT Keychain account name"
  echo "  OPENCLAW_APPLE_CONTAINER_TRUST_SECURITY_CLI=1 Allow unattended /usr/bin/security Keychain reads"
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

[[ -n "$OPENCLAW_HOME" ]] || fail "Unable to resolve HOME for user $OPENCLAW_USER."
validate_absolute_path "home directory" "$OPENCLAW_HOME"
validate_absolute_path "config directory" "$OPENCLAW_CONFIG_DIR"
validate_name "container name" "$OPENCLAW_CONTAINER_NAME"
validate_name "network name" "$OPENCLAW_NETWORK_NAME"
validate_name "state volume" "$OPENCLAW_STATE_VOLUME"
validate_name "legacy token key volume" "$OPENCLAW_LEGACY_TOKEN_KEY_VOLUME"
validate_name "workspace volume" "$OPENCLAW_WORKSPACE_VOLUME"
validate_single_line_value "keychain service" "$OPENCLAW_KEYCHAIN_SERVICE"
validate_single_line_value "keychain account" "$OPENCLAW_KEYCHAIN_ACCOUNT"
[[ -n "$OPENCLAW_KEYCHAIN_SERVICE" ]] || fail "Invalid keychain service: empty."
[[ -n "$OPENCLAW_KEYCHAIN_ACCOUNT" ]] || fail "Invalid keychain account: empty."
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
ensure_volume "$OPENCLAW_WORKSPACE_VOLUME"
ensure_host_keychain_dns

ENV_FILE="$OPENCLAW_CONFIG_DIR/apple-container.env"
CONFIG_JSON="$OPENCLAW_CONFIG_DIR/openclaw.json"
EXISTING_CONFIG_TOKEN="$(read_config_gateway_token "$CONFIG_JSON" || true)"
EXISTING_ENV_TOKEN="$(read_env_gateway_token "$ENV_FILE" || true)"
EXISTING_LEGACY_ENCRYPTED_TOKEN="$(read_legacy_encrypted_gateway_token || true)"

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

if keychain_gateway_token_exists; then
  echo "==> Existing gateway token found in macOS Keychain"
else
  TOKEN="${EXISTING_CONFIG_TOKEN:-${EXISTING_ENV_TOKEN:-${EXISTING_LEGACY_ENCRYPTED_TOKEN:-$(generate_token_hex_32)}}}"
  store_gateway_token_in_keychain "$TOKEN"
  if [[ -n "$EXISTING_CONFIG_TOKEN" ]]; then
    echo "==> Migrated existing gateway.auth.token into macOS Keychain"
  elif [[ -n "$EXISTING_ENV_TOKEN" ]]; then
    echo "==> Migrated existing OPENCLAW_GATEWAY_TOKEN into macOS Keychain"
  elif [[ -n "$EXISTING_LEGACY_ENCRYPTED_TOKEN" ]]; then
    echo "==> Migrated existing encrypted gateway token volume into macOS Keychain"
  else
    echo "==> Generated gateway token in macOS Keychain"
  fi
fi

if [[ ! -f "$ENV_FILE" ]]; then
  (
    umask 077
    write_file_atomically "$ENV_FILE" 600 <<'EOF'
# OpenClaw Apple Container runtime settings.
# The gateway auth token is stored in macOS Keychain.
EOF
  )
fi
remove_env_var "$ENV_FILE" "OPENCLAW_GATEWAY_TOKEN"
remove_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_TOKEN_KEY_VOLUME"

upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_IMAGE" "$OPENCLAW_IMAGE"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_NAME" "$OPENCLAW_CONTAINER_NAME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_NETWORK" "$OPENCLAW_NETWORK_NAME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_HOST_PORT" "$OPENCLAW_HOST_PORT"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_RUNTIME" "$OPENCLAW_CONTAINER_RUNTIME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_STATE_VOLUME" "$OPENCLAW_STATE_VOLUME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME" "$OPENCLAW_WORKSPACE_VOLUME"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE" "$OPENCLAW_KEYCHAIN_SERVICE"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT" "$OPENCLAW_KEYCHAIN_ACCOUNT"
upsert_env_var "$ENV_FILE" "OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN" "$OPENCLAW_HOST_DOMAIN"

sync_keychain_gateway_token_config "$CONFIG_JSON" "$OPENCLAW_HOST_PORT"
echo "==> Configured gateway.auth.token as macOS Keychain SecretRef in ${CONFIG_JSON}"

if EXISTING_NETWORK="$(container network list --quiet 2>/dev/null)"; then
  if echo "$EXISTING_NETWORK" | grep -qx "$OPENCLAW_NETWORK_NAME"; then
    echo "==> Network '${OPENCLAW_NETWORK_NAME}' already exists."
  else
    echo "==> Creating isolated network '${OPENCLAW_NETWORK_NAME}'..."
    container network create "$OPENCLAW_NETWORK_NAME" || {
      echo "    (network creation failed; using default network at run time)" >&2
    }
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
echo "Keychain:  ${OPENCLAW_KEYCHAIN_SERVICE} (${OPENCLAW_KEYCHAIN_ACCOUNT})"
echo "Host DNS:  ${OPENCLAW_HOST_DOMAIN}"
echo "Workspace: ${OPENCLAW_WORKSPACE_VOLUME}"
echo "Image:     ${OPENCLAW_IMAGE}"
echo "Network:   ${OPENCLAW_NETWORK_NAME}"
