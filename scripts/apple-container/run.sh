#!/usr/bin/env bash
# Secure run script for OpenClaw in Apple Container.

set -euo pipefail

OPENCLAW_HOME="${HOME:-}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${OPENCLAW_HOME}/.openclaw}"
ENV_FILE="${OPENCLAW_CONFIG_DIR}/apple-container.env"
CONFIG_JSON="${OPENCLAW_CONFIG_DIR}/openclaw.json"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYCHAIN_BRIDGE_SCRIPT="${SCRIPT_DIR}/keychain-bridge.mjs"

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
  echo "  OPENCLAW_APPLE_CONTAINER_HOST_PORT        Host port (default: 18789)"
  echo "  OPENCLAW_APPLE_CONTAINER_CPUS             CPU limit (default: 2)"
  echo "  OPENCLAW_APPLE_CONTAINER_MEMORY           Memory limit (default: 1g)"
  echo "  OPENCLAW_APPLE_CONTAINER_RUNTIME          Runtime: node or bun (default: node)"
  echo "  OPENCLAW_APPLE_CONTAINER_OPEN_DASHBOARD   Open dashboard after start (1/true/yes/on)"
  echo "  OPENCLAW_APPLE_CONTAINER_STATE_VOLUME     State volume (default: openclaw-state)"
  echo "  OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME Workspace volume (default: openclaw-workspace)"
  echo "  OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE Keychain service name"
  echo "  OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT Keychain account name"
  echo "  OPENCLAW_APPLE_CONTAINER_KEYCHAIN_BRIDGE_TIMEOUT_MS Bridge request timeout (default: 15000)"
  echo "  OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN      Host bridge DNS name"
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  show_help
  exit 0
fi

require_cmd container
require_cmd node
require_cmd /usr/bin/security
require_cmd curl
NODE_BIN="$(command -v node)"

if ! container system status --format json >/dev/null 2>&1; then
  fail "Apple Container is not running. Run: container system start"
fi

load_env_file "$ENV_FILE"

OPENCLAW_IMAGE="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"
OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
BRIDGE_LAUNCH_LABEL="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_BRIDGE_LABEL:-ai.openclaw.apple-container.keychain-bridge.${OPENCLAW_CONTAINER_NAME}}"
OPENCLAW_NETWORK_NAME="${OPENCLAW_APPLE_CONTAINER_NETWORK:-openclaw-net}"
HOST_PORT="${OPENCLAW_APPLE_CONTAINER_HOST_PORT:-18789}"
CONTAINER_PORT="${OPENCLAW_APPLE_CONTAINER_PORT:-18789}"
CONTAINER_CPUS="${OPENCLAW_APPLE_CONTAINER_CPUS:-2}"
CONTAINER_MEMORY="${OPENCLAW_APPLE_CONTAINER_MEMORY:-1g}"
CONTAINER_RUNTIME="${OPENCLAW_APPLE_CONTAINER_RUNTIME:-node}"
OPEN_DASHBOARD="${OPENCLAW_APPLE_CONTAINER_OPEN_DASHBOARD:-}"
STATE_VOLUME="${OPENCLAW_APPLE_CONTAINER_STATE_VOLUME:-openclaw-state}"
WORKSPACE_VOLUME="${OPENCLAW_APPLE_CONTAINER_WORKSPACE_VOLUME:-openclaw-workspace}"
KEYCHAIN_SERVICE="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_SERVICE:-ai.openclaw.apple-container.gateway-token}"
KEYCHAIN_ACCOUNT="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_ACCOUNT:-${USER:-openclaw}}"
HOST_DOMAIN="${OPENCLAW_APPLE_CONTAINER_HOST_DOMAIN:-host.container.internal}"
HOST_LOCALHOST_IP="${OPENCLAW_APPLE_CONTAINER_HOST_LOCALHOST_IP:-203.0.113.113}"
BRIDGE_DIR="${OPENCLAW_CONFIG_DIR}/apple-container-keychain-bridge"
BRIDGE_PID_FILE="${BRIDGE_DIR}/bridge.pid"
BRIDGE_PORT_FILE="${BRIDGE_DIR}/bridge.port"
BRIDGE_LOG_FILE="${BRIDGE_DIR}/bridge.log"
BRIDGE_ENV_FILE="${BRIDGE_DIR}/bridge.env"
BRIDGE_TOKEN=""
BRIDGE_PORT=""
BRIDGE_TIMEOUT_MS="${OPENCLAW_APPLE_CONTAINER_KEYCHAIN_BRIDGE_TIMEOUT_MS:-15000}"
BRIDGE_TOKEN_FILE_PATH="/home/node/.openclaw/bridge-token"

copy_gateway_token() {
  require_cmd pbcopy
  /usr/bin/security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "$KEYCHAIN_SERVICE" -w |
    pbcopy
  info "Copied gateway token from macOS Keychain to the clipboard."
}

dashboard_url() {
  local token=""
  local base_url="${OPENCLAW_DASHBOARD_URL:-}"
  token="$(/usr/bin/security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "$KEYCHAIN_SERVICE" -w)"
  if [[ -z "$base_url" ]]; then
    local tailscale_origin=""
    if command -v tailscale >/dev/null 2>&1; then
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
  require_cmd pbcopy
  dashboard_url | pbcopy
  info "Copied tokenized dashboard URL to the clipboard."
}

open_dashboard() {
  require_cmd open
  local url=""
  url="$(dashboard_url)"
  open "$url"
  info "Opened Control UI in the default browser."
}

stop_keychain_bridge() {
  local pid=""
  if command -v launchctl >/dev/null 2>&1; then
    launchctl remove "$BRIDGE_LAUNCH_LABEL" >/dev/null 2>&1 || true
    launchctl remove "ai.openclaw.apple-container.keychain-bridge" >/dev/null 2>&1 || true
  fi
  if [[ -f "$BRIDGE_PID_FILE" ]]; then
    pid="$(<"$BRIDGE_PID_FILE")"
    if pid_is_running "$pid"; then
      kill "$pid" >/dev/null 2>&1 || true
      for _ in {1..20}; do
        pid_is_running "$pid" || break
        sleep 0.1
      done
      if pid_is_running "$pid"; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
    fi
  fi
  rm -f "$BRIDGE_PID_FILE" "$BRIDGE_PORT_FILE" "$BRIDGE_ENV_FILE"
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
  backend_state="$(tailscale status --json 2>/dev/null \
    | node -e 'let d="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{try{const j=JSON.parse(d);process.stdout.write(j.BackendState||"unknown")}catch{process.stdout.write("unknown")}})' \
    2>/dev/null)" || true
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

# Detect the container's IPv4 gateway CIDR (e.g. 192.168.64.0/24) from
# the running container's network configuration via `container inspect`.
detect_container_gateway_cidr() {
  local cidr=""
  cidr="$(container inspect "$OPENCLAW_CONTAINER_NAME" 2>/dev/null \
    | node -e '
let d="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{
  try {
    const arr = JSON.parse(d);
    const nets = arr && arr[0] && arr[0].networks;
    if (Array.isArray(nets) && nets.length > 0 && nets[0].ipv4Address) {
      const addr = nets[0].ipv4Address; // e.g. "192.168.64.5/24"
      const parts = addr.split(".");
      const mask = addr.split("/")[1] || "24";
      if (parts.length >= 3) process.stdout.write(parts[0]+"."+parts[1]+"."+parts[2]+".0/"+mask);
    }
  } catch {}
})' \
    2>/dev/null)" || true
  printf '%s' "$cidr"
}

# Detect the Tailscale Serve origin (e.g. https://machine.tail12345.ts.net)
# from `tailscale serve status` output.
detect_tailscale_origin() {
  local origin=""
  origin="$(tailscale serve status 2>/dev/null \
    | node -e '
let d="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>d+=c);process.stdin.on("end",()=>{
  const lines = d.split("\n");
  for (const line of lines) {
    const m = line.match(/^(https?:\/\/[^\s/]+)/);
    if (m) { process.stdout.write(m[1]); return; }
  }
})' \
    2>/dev/null)" || true
  printf '%s' "$origin"
}

# Synchronise gateway.trustedProxies and gateway.controlUi.allowedOrigins in both
# the host config and the container volume config so they match the live
# container subnet and Tailscale origin.  Returns 0 when a restart is needed
# (config changed on the host, so the volume was already re-staged), 1 otherwise.
sync_trusted_proxies() {
  local gateway_cidr=""
  gateway_cidr="$(detect_container_gateway_cidr)"
  if [[ -z "$gateway_cidr" ]]; then
    info "Could not detect container subnet; skipping trustedProxies sync."
    return 1
  fi
  info "Container subnet: ${gateway_cidr}"

  local tailscale_origin=""
  if command -v tailscale >/dev/null 2>&1; then
    tailscale_origin="$(detect_tailscale_origin)"
  fi

  local changed=""
  changed="$(node - "$CONFIG_JSON" "$gateway_cidr" "${tailscale_origin}" <<'SYNCNODE'
const fs = require("node:fs");
const cfgPath = process.argv[2];
const desiredCidr = process.argv[3];
const tailscaleOrigin = process.argv[4] || "";
let raw;
try { raw = fs.readFileSync(cfgPath, "utf8"); } catch { process.exit(1); }
let cfg;
try { cfg = JSON.parse(raw); } catch { process.exit(1); }
let changed = false;

cfg.gateway ??= {};

// Sync trustedProxies — ensure the container subnet CIDR is present.
cfg.gateway.trustedProxies ??= [];
if (!Array.isArray(cfg.gateway.trustedProxies)) cfg.gateway.trustedProxies = [];
if (!cfg.gateway.trustedProxies.includes(desiredCidr)) {
  // Remove any stale 192.168.6x.0/24 entries that are not the current subnet.
  cfg.gateway.trustedProxies = cfg.gateway.trustedProxies.filter(
    (e) => e !== desiredCidr && !/^192\.168\.(6[4-9]|7[0-9])\.0\/24$/.test(e)
  );
  cfg.gateway.trustedProxies.push(desiredCidr);
  changed = true;
}

// Sync allowedOrigins — ensure the Tailscale origin is present.
if (tailscaleOrigin) {
  cfg.gateway.controlUi ??= {};
  cfg.gateway.controlUi.allowedOrigins ??= [];
  if (!Array.isArray(cfg.gateway.controlUi.allowedOrigins)) cfg.gateway.controlUi.allowedOrigins = [];
  if (!cfg.gateway.controlUi.allowedOrigins.includes(tailscaleOrigin)) {
    cfg.gateway.controlUi.allowedOrigins.push(tailscaleOrigin);
    changed = true;
  }
}

if (changed) {
  const tmp = cfgPath + ".tmp-" + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
  fs.renameSync(tmp, cfgPath);
  process.stdout.write("1");
} else {
  process.stdout.write("0");
}
SYNCNODE
  )" || true

  if [[ "$changed" == "1" ]]; then
    info "Updated host config: added subnet ${gateway_cidr} to trustedProxies${tailscale_origin:+, added ${tailscale_origin} to allowedOrigins}."
    return 0
  fi
  return 1
}

bridge_launch_pid() {
  command -v launchctl >/dev/null 2>&1 || return 0
  launchctl list 2>/dev/null |
    awk -v label="$BRIDGE_LAUNCH_LABEL" '$3 == label && $1 ~ /^[0-9]+$/ { print $1; exit }'
}

bridge_is_running() {
  local pid=""
  if [[ -f "$BRIDGE_PID_FILE" ]]; then
    pid="$(<"$BRIDGE_PID_FILE")"
    pid_is_running "$pid" && return 0
  fi
  pid="$(bridge_launch_pid)"
  [[ -n "$pid" ]] && pid_is_running "$pid"
}

if [[ "${1:-}" == "--stop" ]]; then
  if is_container_running "$OPENCLAW_CONTAINER_NAME"; then
    info "Stopping container '${OPENCLAW_CONTAINER_NAME}'..."
    container stop "$OPENCLAW_CONTAINER_NAME"
    info "Container stopped."
  else
    info "Container '${OPENCLAW_CONTAINER_NAME}' is not running."
  fi
  stop_keychain_bridge
  exit 0
fi

if [[ "${1:-}" == "--copy-token" ]]; then
  copy_gateway_token
  exit 0
fi

if [[ "${1:-}" == "--copy-dashboard-url" ]]; then
  copy_dashboard_url
  exit 0
fi

validate_port "host port" "$HOST_PORT"
validate_port "container port" "$CONTAINER_PORT"
[[ "$BRIDGE_TIMEOUT_MS" =~ ^[0-9]{4,5}$ ]] ||
  fail "Invalid OPENCLAW_APPLE_CONTAINER_KEYCHAIN_BRIDGE_TIMEOUT_MS: expected milliseconds between 1000 and 60000."
((BRIDGE_TIMEOUT_MS >= 1000 && BRIDGE_TIMEOUT_MS <= 60000)) ||
  fail "Invalid OPENCLAW_APPLE_CONTAINER_KEYCHAIN_BRIDGE_TIMEOUT_MS: expected milliseconds between 1000 and 60000."
[[ "$OPENCLAW_CONTAINER_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  fail "Invalid container name: $OPENCLAW_CONTAINER_NAME"
[[ "$OPENCLAW_NETWORK_NAME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  fail "Invalid network name: $OPENCLAW_NETWORK_NAME"
[[ "$STATE_VOLUME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  fail "Invalid state volume: $STATE_VOLUME"
[[ "$WORKSPACE_VOLUME" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
  fail "Invalid workspace volume: $WORKSPACE_VOLUME"
require_existing_file "config file" "$CONFIG_JSON"
if ! container volume list --quiet 2>/dev/null | grep -qx "$STATE_VOLUME"; then
  fail "Missing state volume: $STATE_VOLUME. Run: scripts/apple-container/setup.sh"
fi
if ! container volume list --quiet 2>/dev/null | grep -qx "$WORKSPACE_VOLUME"; then
  fail "Missing workspace volume: $WORKSPACE_VOLUME. Run: scripts/apple-container/setup.sh"
fi
if ! container system dns list --quiet 2>/dev/null | grep -qx "$HOST_DOMAIN"; then
  fail "Missing host bridge DNS '${HOST_DOMAIN}'. Run: scripts/apple-container/setup.sh"
fi
if ! /usr/bin/security find-generic-password -a "$KEYCHAIN_ACCOUNT" -s "$KEYCHAIN_SERVICE" -w >/dev/null 2>&1; then
  fail "Missing macOS Keychain gateway token '${KEYCHAIN_SERVICE}' for account '${KEYCHAIN_ACCOUNT}'. Run: scripts/apple-container/setup.sh"
fi

case "$CONTAINER_RUNTIME" in
  node|bun) ;;
  *) fail "Invalid OPENCLAW_APPLE_CONTAINER_RUNTIME: expected node or bun." ;;
esac

if ! container image list 2>/dev/null | grep -Fq "${OPENCLAW_IMAGE%%:*}"; then
  fail "Image '${OPENCLAW_IMAGE}' not found. Run: scripts/apple-container/setup.sh"
fi

start_keychain_bridge() {
  install -d -m 700 "$BRIDGE_DIR"
  require_existing_file "Keychain bridge script" "$KEYCHAIN_BRIDGE_SCRIPT"
  stop_keychain_bridge

  # Reuse the token generated in do_run (before stage_runtime_volumes)
  # or generate a fresh one if called standalone.
  BRIDGE_TOKEN="${BRIDGE_TOKEN:-$(generate_token_hex_32)}"
  rm -f "$BRIDGE_PID_FILE" "$BRIDGE_PORT_FILE" "$BRIDGE_ENV_FILE"
  : > "$BRIDGE_LOG_FILE"

  # Write bridge env to a restricted file so the token is never visible in
  # process argument lists (launchctl submit / ps aux).
  cat >"$BRIDGE_ENV_FILE" <<BRIDGE_ENV
OPENCLAW_KEYCHAIN_BRIDGE_TOKEN=$BRIDGE_TOKEN
OPENCLAW_KEYCHAIN_BRIDGE_HOST=127.0.0.1
OPENCLAW_KEYCHAIN_BRIDGE_PORT=0
OPENCLAW_KEYCHAIN_BRIDGE_PORT_FILE=$BRIDGE_PORT_FILE
OPENCLAW_KEYCHAIN_BRIDGE_PID_FILE=$BRIDGE_PID_FILE
OPENCLAW_KEYCHAIN_SERVICE=$KEYCHAIN_SERVICE
OPENCLAW_KEYCHAIN_ACCOUNT=$KEYCHAIN_ACCOUNT
OPENCLAW_KEYCHAIN_BRIDGE_KEYCHAIN_TIMEOUT_MS=$BRIDGE_TIMEOUT_MS
BRIDGE_ENV
  chmod 600 "$BRIDGE_ENV_FILE"

  # Apple Container routes host.container.internal (203.0.113.113) to the host's
  # loopback, so binding to 127.0.0.1 is sufficient and avoids exposing the bridge
  # on LAN/Wi-Fi interfaces. The per-run bearer token still gates access.
  if command -v launchctl >/dev/null 2>&1; then
    launchctl submit \
      -l "$BRIDGE_LAUNCH_LABEL" \
      -o "$BRIDGE_LOG_FILE" \
      -e "$BRIDGE_LOG_FILE" \
      -- /bin/sh -c 'set -a; . "$1"; set +a; exec "$2" "$3"' \
        bridge-env "$BRIDGE_ENV_FILE" "$NODE_BIN" "$KEYCHAIN_BRIDGE_SCRIPT" || true
    for _ in {1..20}; do
      [[ -s "$BRIDGE_PID_FILE" || -s "$BRIDGE_PORT_FILE" ]] && break
      sleep 0.1
    done
    if [[ ! -s "$BRIDGE_PID_FILE" && ! -s "$BRIDGE_PORT_FILE" ]]; then
      launchctl remove "$BRIDGE_LAUNCH_LABEL" >/dev/null 2>&1 || true
    fi
  fi
  if [[ ! -s "$BRIDGE_PID_FILE" ]] && ! bridge_is_running; then
    nohup /bin/sh -c 'set -a; . "$1"; set +a; exec "$2" "$3"' \
      bridge-env "$BRIDGE_ENV_FILE" "$NODE_BIN" "$KEYCHAIN_BRIDGE_SCRIPT" \
      </dev/null >"$BRIDGE_LOG_FILE" 2>&1 &
    local pid="$!"
    printf '%s\n' "$pid" >"$BRIDGE_PID_FILE"
    disown "$pid" 2>/dev/null || true
  fi
  chmod 600 "$BRIDGE_PID_FILE" "$BRIDGE_LOG_FILE" 2>/dev/null || true

  for _ in {1..50}; do
    if [[ -s "$BRIDGE_PORT_FILE" ]] && bridge_is_running; then
      BRIDGE_PORT="$(tr -d '[:space:]' <"$BRIDGE_PORT_FILE")"
      if [[ "$BRIDGE_PORT" =~ ^[0-9]{1,5}$ ]] &&
        curl -fsS "http://127.0.0.1:${BRIDGE_PORT}/healthz" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 0.1
  done

  stop_keychain_bridge
  fail "macOS Keychain bridge did not start. See: ${BRIDGE_LOG_FILE}"
}

require_keychain_bridge_container_reachable() {
  local temp_name="" output="" status=0
  # Apple Container can transiently fail to start containers ("This operation was aborted")
  # right after volume staging or a previous container stop. Retry with backoff.
  local max_attempts=5 attempt=1

  while [[ "$attempt" -le "$max_attempts" ]]; do
    temp_name="${OPENCLAW_CONTAINER_NAME}-bridge-check-${attempt}"
    container delete "$temp_name" >/dev/null 2>&1 || true

    set +e
    output="$(
      container run \
        --rm \
        --name "$temp_name" \
        --read-only \
        --tmpfs /tmp \
        --cap-drop ALL \
        --init \
        --user 1000:1000 \
        --env "OPENCLAW_KEYCHAIN_BRIDGE_URL=http://${HOST_DOMAIN}:${BRIDGE_PORT}" \
        --env "OPENCLAW_KEYCHAIN_BRIDGE_TOKEN_FILE=${BRIDGE_TOKEN_FILE_PATH}" \
    --env "OPENCLAW_KEYCHAIN_BRIDGE_TIMEOUT_MS=${BRIDGE_TIMEOUT_MS}" \
        --mount "type=volume,source=${STATE_VOLUME},target=/home/node/.openclaw,readonly" \
        "${NETWORK_ARGS[@]}" \
        "$OPENCLAW_IMAGE" \
        /usr/local/bin/openclaw-gateway-token-resolver --check 2>&1
    )"
    status=$?
    set -e

    container delete "$temp_name" >/dev/null 2>&1 || true

    if [[ "$status" -eq 0 ]]; then
      info "Keychain bridge: reachable from Apple Container"
      return 0
    fi

    if [[ "$output" == *"aborted"* ]] && [[ "$attempt" -lt "$max_attempts" ]]; then
      local delay=$((attempt * 2))
      info "Probe container aborted (attempt ${attempt}/${max_attempts}), retrying in ${delay}s..."
      sleep "$delay"
      attempt=$((attempt + 1))
      continue
    fi

    # Non-transient failure or exhausted retries.
    break
  done

  stop_keychain_bridge
  fail "Keychain bridge is not reachable from Apple Container. Probe error: ${output}"
}

stage_runtime_volumes() {
  local temp_name="${OPENCLAW_CONTAINER_NAME}-stage"
  local config_stage_dir=""
  config_stage_dir="$(mktemp -d "${OPENCLAW_CONFIG_DIR}/.apple-container-config.XXXXXX")"
  chmod 700 "$config_stage_dir"
  cp "$CONFIG_JSON" "$config_stage_dir/openclaw.json"
  chmod 600 "$config_stage_dir/openclaw.json"

  # Write the bridge token to a file for mounting into the container.
  # This avoids passing the secret via environment variables which are
  # readable through /proc/self/environ inside the container.
  printf '%s' "${BRIDGE_TOKEN}" >"${config_stage_dir}/bridge-token"
  chmod 600 "${config_stage_dir}/bridge-token"

  container delete "$temp_name" >/dev/null 2>&1 || true
  info "Preparing runtime volumes..."
  if ! container run \
    --rm \
    --name "$temp_name" \
    --read-only \
    --tmpfs /tmp \
    --user 0:0 \
    --mount "type=volume,source=${STATE_VOLUME},target=/home/node/.openclaw" \
    --mount "type=volume,source=${WORKSPACE_VOLUME},target=/home/node/.openclaw/workspace" \
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
      install -m 0500 -o 1000 -g 1000 /usr/local/bin/openclaw-gateway-token-resolver /home/node/.openclaw/openclaw-gateway-token-resolver
      # Write bridge token as a file owned by node, mode 0400 (read-only).
      # The token resolver reads this file instead of /proc/self/environ.
      install -m 0400 -o 1000 -g 1000 /openclaw-host-config/bridge-token /home/node/.openclaw/bridge-token
      node - <<'"'"'NODE'"'"'
const fs = require("node:fs");
const src = "/openclaw-host-config/openclaw.json";
const dest = "/home/node/.openclaw/openclaw.json";
const cfg = JSON.parse(fs.readFileSync(src, "utf8"));
cfg.secrets ??= {};
cfg.secrets.providers ??= {};
cfg.secrets.providers.gateway_token ??= {};
cfg.secrets.providers.gateway_token.command = "/home/node/.openclaw/openclaw-gateway-token-resolver";
cfg.secrets.providers.gateway_token.passEnv = [
  "OPENCLAW_KEYCHAIN_BRIDGE_URL",
  "OPENCLAW_KEYCHAIN_BRIDGE_TOKEN_FILE",
  "OPENCLAW_KEYCHAIN_BRIDGE_TIMEOUT_MS",
];
fs.writeFileSync(dest, `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o440 });
NODE
      chown 0:1000 /home/node/.openclaw/openclaw.json
      chmod 0440 /home/node/.openclaw/openclaw.json
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
  stop_keychain_bridge
}

do_status() {
  echo "Container: ${OPENCLAW_CONTAINER_NAME}"
  echo "Image:     ${OPENCLAW_IMAGE}"
  echo "Runtime:   ${CONTAINER_RUNTIME}"
  echo "Network:   ${NETWORK_ARGS[*]:-<default>}"
  echo "Port:      127.0.0.1:${HOST_PORT} -> :${CONTAINER_PORT}"
  echo "Resources: ${CONTAINER_CPUS} CPUs, ${CONTAINER_MEMORY} RAM"
  echo "Config:    ${CONFIG_JSON}"
  echo "State:     ${STATE_VOLUME}"
  echo "Keychain:  ${KEYCHAIN_SERVICE} (${KEYCHAIN_ACCOUNT})"
  echo "Host DNS:  ${HOST_DOMAIN}"
  echo "Workspace: ${WORKSPACE_VOLUME}"
  if [[ -f "$BRIDGE_PID_FILE" ]]; then
    local pid=""
    pid="$(<"$BRIDGE_PID_FILE")"
    if bridge_is_running; then
      echo "Bridge:    RUNNING (pid ${pid})"
    else
      echo "Bridge:    STOPPED"
    fi
  elif bridge_is_running; then
    echo "Bridge:    RUNNING (launchd)"
  else
    echo "Bridge:    STOPPED"
  fi
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
# start and the sync_trusted_proxies restart, preventing security flag drift.
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
    --env "OPENCLAW_KEYCHAIN_BRIDGE_URL=http://${HOST_DOMAIN}:${BRIDGE_PORT}" \
    --env "OPENCLAW_KEYCHAIN_BRIDGE_TOKEN_FILE=${BRIDGE_TOKEN_FILE_PATH}" \
    --env "OPENCLAW_KEYCHAIN_BRIDGE_TIMEOUT_MS=${BRIDGE_TIMEOUT_MS}" \
    --mount "type=volume,source=${STATE_VOLUME},target=/home/node/.openclaw" \
    --mount "type=volume,source=${WORKSPACE_VOLUME},target=/home/node/.openclaw/workspace" \
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
    container stop "$OPENCLAW_CONTAINER_NAME" 2>/dev/null || true
    sleep 1
  fi

  container delete "$OPENCLAW_CONTAINER_NAME" 2>/dev/null || true

  require_tailscale

  # Generate the bridge token early so stage_runtime_volumes can write it
  # into the state volume as a file for the container-side token resolver.
  BRIDGE_TOKEN="$(generate_token_hex_32)"

  stage_runtime_volumes
  start_keychain_bridge
  require_keychain_bridge_container_reachable
  if [[ "${#detach_arg[@]}" -eq 0 ]]; then
    trap stop_keychain_bridge EXIT INT TERM
  fi

  local runtime_command=()
  if [[ "$CONTAINER_RUNTIME" == "bun" ]]; then
    runtime_command=(bun /app/openclaw.mjs gateway --bind lan --port "$CONTAINER_PORT")
  else
    runtime_command=(node /app/openclaw.mjs gateway --bind lan --port "$CONTAINER_PORT")
  fi

  if ! container_run_gateway "${detach_arg[*]}" "${runtime_command[@]}"; then
    stop_keychain_bridge
    fail "Container failed to start."
  fi

  if [[ "${#detach_arg[@]}" -gt 0 ]]; then
    sleep 1
    if ! is_container_running "$OPENCLAW_CONTAINER_NAME"; then
      stop_keychain_bridge
      fail "Container exited during startup. Check: container logs ${OPENCLAW_CONTAINER_NAME}"
    fi
    echo ""
    info "Container '${OPENCLAW_CONTAINER_NAME}' started."
    info "Gateway:  http://127.0.0.1:${HOST_PORT}"
    info "Runtime:  ${CONTAINER_RUNTIME}"
    info "Auth:     macOS Keychain SecretRef via local bridge"
    info "Logs:     container logs ${OPENCLAW_CONTAINER_NAME}"
    info "Bridge:   ${BRIDGE_LOG_FILE}"
    info "Status:   scripts/apple-container/run.sh --status"
    info "Stop:     scripts/apple-container/run.sh --stop"
    echo ""

    local http_code=""
    for _ in {1..30}; do
      http_code="$(curl -s -o /dev/null -w "%{http_code}" \
        "http://127.0.0.1:${HOST_PORT}/healthz" 2>/dev/null || true)"
      [[ "$http_code" == "200" ]] && break
      sleep 1
    done
    if [[ "$http_code" == "200" ]]; then
      info "Health check: OK (/healthz returned 200)"

      # Auto-detect container subnet and sync trustedProxies/allowedOrigins.
      # If the config changed, restage volumes and restart the container once.
      if sync_trusted_proxies; then
        info "Restarting container with updated network config..."
        container stop "$OPENCLAW_CONTAINER_NAME" 2>/dev/null || true
        sleep 1
        container delete "$OPENCLAW_CONTAINER_NAME" 2>/dev/null || true
        # Re-stage volumes with the updated host config now that the main container
        # is stopped (Apple Container cannot mount the same volume in two VMs at once).
        stage_runtime_volumes
        # Re-run container with the same settings (bridge is still running).
        if ! container_run_gateway "${detach_arg[*]}" "${runtime_command[@]}"; then
          stop_keychain_bridge
          fail "Container failed to start after trustedProxies update."
        fi
        sleep 1
        http_code="$(curl -s -o /dev/null -w "%{http_code}" \
          "http://127.0.0.1:${HOST_PORT}/healthz" 2>/dev/null || true)"
        if [[ "$http_code" == "200" ]]; then
          info "Health check after restart: OK (/healthz returned 200)"
        else
          info "Health check after restart: /healthz returned ${http_code} (may still be starting)"
        fi
      fi

      if is_enabled "${OPENCLAW_APPLE_CONTAINER_SKIP_OPEN_DASHBOARD:-0}"; then
        if command -v pbcopy >/dev/null 2>&1; then
          copy_dashboard_url
        fi
      else
        open_dashboard
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
