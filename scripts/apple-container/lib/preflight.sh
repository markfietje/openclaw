#!/usr/bin/env bash
# OpenClaw Apple Container — shared preflight + helpers.
# Source-only; never executed directly.
# shellcheck shell=bash

# ── Output primitives ───────────────────────────────────────────
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
  _PF_GREEN=$'\033[32m'
  _PF_RED=$'\033[31m'
  _PF_YELLOW=$'\033[33m'
  _PF_DIM=$'\033[2m'
  _PF_BOLD=$'\033[1m'
  _PF_RESET=$'\033[0m'
else
  _PF_GREEN=""; _PF_RED=""; _PF_YELLOW=""; _PF_DIM=""; _PF_BOLD=""; _PF_RESET=""
fi

_PF_OK=0
_PF_FAIL=0
_PF_SKIP=0
_PF_TITLE=""

preflight_init() {
  _PF_OK=0; _PF_FAIL=0; _PF_SKIP=0
  _PF_TITLE="${1:-OpenClaw Apple Container preflight}"
  printf "%s%s%s\n" "$_PF_BOLD" "$_PF_TITLE" "$_PF_RESET"
}

preflight_pass() {
  local label="$1" detail="${2:-}"
  printf "  %s✓%s %s" "$_PF_GREEN" "$_PF_RESET" "$label"
  if [[ -n "$detail" ]]; then
    printf " %s(%s)%s" "$_PF_DIM" "$detail" "$_PF_RESET"
  fi
  printf "\n"
  _PF_OK=$((_PF_OK + 1))
}

preflight_fail() {
  local label="$1" hint="${2:-}"
  printf "  %s✗%s %s" "$_PF_RED" "$_PF_RESET" "$label"
  if [[ -n "$hint" ]]; then
    printf " %s— %s%s" "$_PF_DIM" "$hint" "$_PF_RESET"
  fi
  printf "\n"
  _PF_FAIL=$((_PF_FAIL + 1))
}

preflight_skip() {
  local label="$1" reason="${2:-}"
  printf "  %s•%s %s" "$_PF_YELLOW" "$_PF_RESET" "$label"
  if [[ -n "$reason" ]]; then
    printf " %s— %s%s" "$_PF_DIM" "$reason" "$_PF_RESET"
  fi
  printf "\n"
  _PF_SKIP=$((_PF_SKIP + 1))
}

preflight_summary() {
  printf "\n"
  if (( _PF_FAIL > 0 )); then
    printf "%s✗%s %s: %d failed, %d skipped, %d passed\n" \
      "$_PF_RED" "$_PF_RESET" "$_PF_TITLE" "$_PF_FAIL" "$_PF_SKIP" "$_PF_OK"
    return 1
  fi
  if (( _PF_SKIP > 0 )); then
    printf "%s•%s %s: %d skipped, %d passed (warnings only)\n" \
      "$_PF_YELLOW" "$_PF_RESET" "$_PF_TITLE" "$_PF_SKIP" "$_PF_OK"
  else
    printf "%s✓%s %s: %d passed\n" \
      "$_PF_GREEN" "$_PF_RESET" "$_PF_TITLE" "$_PF_OK"
  fi
  return 0
}

# ── Individual checks ───────────────────────────────────────────

preflight_check_macos() {
  local detail
  detail="$(uname -sr 2>/dev/null || echo unknown)"
  if [[ "$(uname)" != "Darwin" ]]; then
    preflight_fail "macOS" "Apple Container is macOS-only (got $(uname))"
    return 1
  fi
  preflight_pass "macOS" "$detail"
}

preflight_check_arm64() {
  if ! sysctl -n hw.optional.arm64 >/dev/null 2>&1; then
    preflight_fail "Apple Silicon (M1+)" "Apple Container requires arm64"
    return 1
  fi
  preflight_pass "Apple Silicon (arm64)"
}

preflight_check_apple_container_cli() {
  if ! command -v container >/dev/null 2>&1; then
    preflight_fail "Apple Container CLI" "Install from https://github.com/apple/container/releases"
    return 1
  fi
  local version
  version="$(container --version 2>/dev/null | head -1 || true)"
  preflight_pass "Apple Container CLI" "$version"
}

# Read runtime state via --format json to avoid substring bugs.
preflight_check_apple_container_runtime() {
  local status_json state
  status_json="$(container system status --format json 2>/dev/null || true)"
  state="$(printf '%s' "$status_json" | node -e '
let d="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>d+=c);
process.stdin.on("end",()=>{try{const j=JSON.parse(d);process.stdout.write(j.status||"")}catch{}})' 2>/dev/null || true)"
  if [[ "$state" == "running" ]]; then
    preflight_pass "Apple Container runtime" "running"
  else
    preflight_fail "Apple Container runtime" "Run: container system start (state: ${state:-unknown})"
    return 1
  fi
}

preflight_check_curl() {
  if ! command -v curl >/dev/null 2>&1; then
    preflight_fail "curl" "Install with: brew install curl"
    return 1
  fi
  preflight_pass "curl" "$(curl --version 2>/dev/null | head -1 | awk '{print $1, $2}')"
}

preflight_check_node() {
  if ! command -v node >/dev/null 2>&1; then
    preflight_fail "node" "Install with: brew install node (or use --runtime bun)"
    return 1
  fi
  local major
  major="$(node -e 'process.stdout.write(process.versions.node.split(".")[0])' 2>/dev/null || echo 0)"
  if (( major < 22 )); then
    preflight_fail "node ≥ 22" "Found node $major.x"
    return 1
  fi
  preflight_pass "node ≥ 22" "v$(node -e 'process.stdout.write(process.versions.node)' 2>/dev/null)"
}

preflight_check_rsync() {
  if ! command -v rsync >/dev/null 2>&1; then
    preflight_fail "rsync" "Install with: brew install rsync (required for build context)"
    return 1
  fi
  preflight_pass "rsync"
}

preflight_check_pnpm() {
  if ! command -v pnpm >/dev/null 2>&1; then
    preflight_fail "pnpm" "Install with: brew install pnpm (only required for sync-hot.sh)"
    return 1
  fi
  preflight_pass "pnpm" "$(pnpm --version 2>/dev/null)"
}

preflight_check_token_source() {
  if command -v openssl >/dev/null 2>&1; then
    preflight_pass "openssl" "token generation"
  elif command -v python3 >/dev/null 2>&1; then
    preflight_skip "openssl" "python3 will be used for token generation"
  elif command -v ruby >/dev/null 2>&1; then
    preflight_skip "openssl" "ruby will be used for token generation"
  else
    preflight_fail "token generator" "Need one of: openssl, python3, or ruby"
    return 1
  fi
}

preflight_check_pbcopy() {
  if command -v pbcopy >/dev/null 2>&1; then
    preflight_pass "pbcopy" "clipboard"
  else
    preflight_skip "pbcopy" "URL will be printed to stdout instead"
  fi
}

preflight_check_open() {
  if command -v open >/dev/null 2>&1; then
    preflight_pass "open" "browser"
  else
    preflight_skip "open" "Use --open-dashboard to print the URL"
  fi
}

preflight_check_tailscale() {
  if [[ -n "${OPENCLAW_SKIP_TAILSCALE_CHECK:-}" ]]; then
    preflight_skip "tailscale" "OPENCLAW_SKIP_TAILSCALE_CHECK is set"
    return 0
  fi
  if ! command -v tailscale >/dev/null 2>&1; then
    preflight_skip "tailscale" "not installed; run.sh will skip the pre-check"
    return 0
  fi
  local backend_state
  backend_state="$(tailscale status --json 2>/dev/null | node -e '
let d="";process.stdin.setEncoding("utf8");process.stdin.on("data",c=>d+=c);
process.stdin.on("end",()=>{try{const j=JSON.parse(d);process.stdout.write(j.BackendState||"")}catch{}})' 2>/dev/null || true)"
  if [[ "$backend_state" != "Running" ]]; then
    preflight_fail "tailscale running" "Run: tailscale up (state: ${backend_state:-unknown})"
    return 1
  fi
  preflight_pass "tailscale" "running"
}

preflight_check_tailscale_serve() {
  local host_port="${1:-}"
  if ! command -v tailscale >/dev/null 2>&1; then return 0; fi
  if [[ -z "$host_port" ]]; then return 0; fi
  local serve
  serve="$(tailscale serve status 2>/dev/null || true)"
  if [[ -z "$serve" ]]; then
    preflight_fail "tailscale serve" "Run: tailscale serve --bg --set-path / http://127.0.0.1:${host_port}"
    return 1
  fi
  if ! printf '%s' "$serve" | grep -qF "127.0.0.1:${host_port}"; then
    preflight_fail "tailscale serve" "Not proxying 127.0.0.1:${host_port}; run: tailscale serve --bg --set-path / http://127.0.0.1:${host_port}"
    return 1
  fi
  preflight_pass "tailscale serve" "127.0.0.1:${host_port}"
}

preflight_check_image() {
  local image="${1:-}"
  if [[ -z "$image" ]]; then return 0; fi
  if ! container image list 2>/dev/null | awk 'NR>1{print $1,$2}' | grep -q "^${image%%:*} ${image##*:}"; then
    preflight_fail "image '${image}'" "Run: scripts/apple-container/build.sh (or setup.sh)"
    return 1
  fi
  preflight_pass "image" "$image"
}

# ── Composite suites ────────────────────────────────────────────

preflight_run_default() {
  preflight_init "${1:-OpenClaw Apple Container preflight}"
  preflight_check_macos
  preflight_check_arm64
  preflight_check_apple_container_cli
  preflight_check_apple_container_runtime
  preflight_check_curl
  preflight_check_node
  preflight_check_token_source
  preflight_check_pbcopy
  preflight_check_open
  preflight_summary
}

preflight_run_build() {
  preflight_init "${1:-OpenClaw Apple Container build preflight}"
  preflight_check_macos
  preflight_check_arm64
  preflight_check_apple_container_cli
  preflight_check_apple_container_runtime
  preflight_check_node
  preflight_check_rsync
  preflight_check_curl
  preflight_summary
}

preflight_run_setup() {
  preflight_init "${1:-OpenClaw Apple Container setup preflight}"
  preflight_check_macos
  preflight_check_arm64
  preflight_check_apple_container_cli
  preflight_check_apple_container_runtime
  preflight_check_curl
  preflight_check_node
  preflight_check_token_source
  preflight_check_image "${4:-}"
  preflight_check_pbcopy
  preflight_check_open
  preflight_check_tailscale
  preflight_summary
}

preflight_run_sync() {
  preflight_init "${1:-OpenClaw Apple Container sync-hot preflight}"
  preflight_check_macos
  preflight_check_arm64
  preflight_check_apple_container_cli
  preflight_check_apple_container_runtime
  preflight_check_curl
  preflight_check_node
  preflight_check_rsync
  preflight_check_pnpm
  preflight_summary
}

# ── Safe mktemp (avoids /-prefix when OPENCLAW_CONFIG_DIR is empty) ─
safe_mktemp_dir() {
  local template="${1:-}"
  local base="${TMPDIR:-/tmp}"
  if [[ -n "$template" && "$template" != *XXXXXX* ]]; then
    fail "safe_mktemp_dir: template must contain XXXXXX"
  fi
  mktemp -d "${base}${template}"
}

# ── bash-native watchdog (replaces GNU timeout; macOS has no timeout by default) ─
watchdog_kill_after() {
  local pid="$1" seconds="$2"
  (
    sleep "$seconds"
    kill -TERM "$pid" 2>/dev/null || true
    sleep 1
    kill -KILL "$pid" 2>/dev/null || true
  ) &
  WATCHDOG_PID=$!
  disown 2>/dev/null || true
}

watchdog_cancel() {
  if [[ -n "${WATCHDOG_PID:-}" ]]; then
    kill -TERM "$WATCHDOG_PID" 2>/dev/null || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
    unset WATCHDOG_PID
  fi
}
