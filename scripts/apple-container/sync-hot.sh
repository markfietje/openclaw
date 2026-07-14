#!/usr/bin/env bash
# sync-hot.sh — Fast, secure code sync from macOS host to running Apple Container.
#
# Builds on macOS, stages validated output into a named volume via an
# ephemeral container, then restarts the gateway with the volume mounted.
# No building or downloading inside the container. All existing security
# hardening preserved (--read-only, --cap-drop ALL, --init, non-root).
#
# Architecture:
#   1. Build on macOS host (pnpm build + pnpm ui:build + pnpm qa:lab:build)
#   2. Stage ONLY platform-independent build output to a hardened temp dir
#   3. Validate: reject symlinks, sensitive patterns, size/count bounds
#   4. Copy into a named volume via short-lived ephemeral container:
#      - First sync: seeds volume from image's /app/ (node_modules, extensions, etc.)
#      - Every sync: overlays host-built dist/, skills/, qa/, docs/, openclaw.mjs
#   5. Restart gateway container with the named volume mounted at /app
#   6. Health check + automatic rollback on failure
#
# Security model:
#   The main gateway container NEVER sees the host filesystem. It only sees:
#     - Named volumes (state, workspace, code — isolated ext4 images)
#     - tmpfs (in-memory caches)
#   The ephemeral staging container is short-lived (~3-5s), heavily restricted
#   (--cap-drop ALL, --read-only), and only purpose is copying validated files
#   from a temporary host bind mount into the isolated named volume.
#   Same pattern as run.sh's stage_runtime_volumes().
#
# Performance:
#   Named volumes use native ext4 inside the VM — 4× faster file reads than
#   bind mounts (which go through virtiofs translation). First sync seeds the
#   full /app/ from image; subsequent syncs only update changed code paths.
#
# Runtime:
#   Bun is preferred for faster startup (36%) and lower memory (20% less RSS).
#   Node is available as fallback (--runtime node) for extensions requiring
#   native addons (e.g., matrix-sdk-crypto). The gateway core is pure JS.
#
# Usage:
#   scripts/apple-container/sync-hot.sh              # build + sync + restart
#   scripts/apple-container/sync-hot.sh --no-build   # sync only (pre-built)
#   scripts/apple-container/sync-hot.sh --rollback   # undo — restart without overlays
#   scripts/apple-container/sync-hot.sh --runtime node  # use Node.js instead of Bun
#
# Prerequisites:
#   - Image built once via: scripts/apple-container/setup.sh
#   - Container configured via: scripts/apple-container/setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/preflight.sh
source "${SCRIPT_DIR}/lib/preflight.sh"

# ── Constants ────────────────────────────────────────────────────
STAGE_DIR_NAME="openclaw-sync-staging"
CODE_VOLUME_NAME="${OPENCLAW_APPLE_CONTAINER_CODE_VOLUME:-openclaw-code}"
MAX_STAGED_SIZE_BYTES=$((256 * 1024 * 1024)) # 256 MB
MAX_STAGED_FILE_COUNT=20000
OVERLAY_SUBPATHS=(dist skills qa docs src/agents/templates openclaw.mjs package.json)
STAMP_FILE=".openclaw-code-volume-stamp.json"

# ── Helpers ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

fail()  { echo "ERROR: $*" >&2; exit 1; }
info()  { echo "==> $*"; }
warn()  { echo "WARN: $*" >&2; }

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "Missing dependency: $1"
  fi
}

validate_single_line_value() {
  local label="$1" value="$2"
  if [[ "$value" == *$'\n'* || "$value" == *$'\r'* ]]; then
    fail "Invalid $label: control characters are not allowed."
  fi
}

validate_name() {
  local label="$1" value="$2"
  validate_single_line_value "$label" "$value"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || fail "Invalid $label: $value"
}

validate_absolute_path() {
  local label="$1" value="$2"
  validate_single_line_value "$label" "$value"
  [[ "$value" == /* ]] || fail "Invalid $label: expected an absolute path."
  [[ "$value" != *"//"* ]] || fail "Invalid $label: repeated slashes are not allowed."
  [[ "$value" != *"/./"* && "$value" != */. && "$value" != *"/../"* && "$value" != */.. ]] ||
    fail "Invalid $label: dot path segments are not allowed."
}

ensure_safe_stage_dir() {
  validate_absolute_path "config directory" "$OPENCLAW_CONFIG_DIR"
  validate_absolute_path "staging directory" "$STAGE_DIR"
  [[ "$(basename "$STAGE_DIR")" == "$STAGE_DIR_NAME" ]] ||
    fail "Invalid staging directory: unexpected basename."
  [[ "$STAGE_DIR" == "$OPENCLAW_CONFIG_DIR/$STAGE_DIR_NAME" ]] ||
    fail "Invalid staging directory: expected it under config directory."
  [[ "$STAGE_DIR" != "/" && "$STAGE_DIR" != "$HOME" ]] ||
    fail "Refusing unsafe staging directory: $STAGE_DIR"
  if [[ -e "$STAGE_DIR" ]]; then
    [[ ! -L "$STAGE_DIR" ]] || fail "Unsafe staging directory: symlinks are not allowed."
    [[ -d "$STAGE_DIR" ]] || fail "Unsafe staging directory: expected a directory."
  fi
}

container_image_id() {
  container image list 2>/dev/null |
    awk -v image="$IMAGE" '
      NR == 1 { next }
      $0 ~ image {
        for (i = 1; i <= NF; i++) {
          if ($i ~ /^sha256:/) {
            print $i
            exit
          }
        }
        print $0
        exit
      }
    '
}

code_volume_exists() {
  container volume list --quiet 2>/dev/null | grep -qx "$CODE_VOLUME_NAME"
}

# ── Config ───────────────────────────────────────────────────────
OPENCLAW_HOME="${HOME:-}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-${OPENCLAW_HOME}/.openclaw}"
ENV_FILE="${OPENCLAW_CONFIG_DIR}/apple-container.env"
CONFIG_JSON="${OPENCLAW_CONFIG_DIR}/openclaw.json"
STAGE_DIR="${OPENCLAW_CONFIG_DIR}/${STAGE_DIR_NAME}"
IMAGE="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"

# ── Load env (same as run.sh) ───────────────────────────────────
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

load_env_file "$ENV_FILE"

# Reload from env
IMAGE="${OPENCLAW_APPLE_CONTAINER_IMAGE:-$IMAGE}"
CODE_VOLUME_NAME="${OPENCLAW_APPLE_CONTAINER_CODE_VOLUME:-$CODE_VOLUME_NAME}"
OPENCLAW_CONTAINER_NAME="${OPENCLAW_APPLE_CONTAINER_NAME:-openclaw}"
HOST_PORT="${OPENCLAW_APPLE_CONTAINER_HOST_PORT:-18789}"
SYNC_RUNTIME="${OPENCLAW_APPLE_CONTAINER_SYNC_RUNTIME:-}"
RUN_SH="${SCRIPT_DIR}/run.sh"

# ── Argument parsing ─────────────────────────────────────────────
DO_BUILD=true
DO_ROLLBACK=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-build)
      DO_BUILD=false
      shift
      ;;
    --rollback)
      DO_ROLLBACK=true
      shift
      ;;
    --runtime)
      SYNC_RUNTIME="${2:?--runtime requires a value}"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $(basename "$0") [--no-build] [--rollback] [--runtime bun|node]"
      echo ""
      echo "  (none)           Build on host, sync to volume, restart container"
      echo "  --no-build       Skip build, sync existing dist/ only"
      echo "  --rollback       Delete code volume, restart from image"
      echo "  --runtime VALUE  Override runtime for this sync (bun or node)"
      echo "  -h,--help        Show this help"
      echo ""
      echo "Environment:"
      echo "  OPENCLAW_APPLE_CONTAINER_CODE_VOLUME   Volume name (default: openclaw-code)"
      echo "  OPENCLAW_APPLE_CONTAINER_SYNC_RUNTIME  Runtime override (bun or node)"
      exit 0
      ;;
    *)
      fail "Unknown argument: $1"
      ;;
  esac
done

# ── Preflight ────────────────────────────────────────────────────
require_cmd container
require_cmd node
require_cmd rsync
require_cmd curl

if [[ "${OPENCLAW_SKIP_PREFLIGHT:-0}" != "1" ]]; then
  preflight_check_macos >/dev/null || fail "This script only runs on macOS."
  preflight_check_arm64 >/dev/null || fail "This script requires Apple Silicon (arm64)."
  preflight_check_apple_container_cli >/dev/null || fail "Apple Container CLI is missing."
fi

[[ -f "$CONFIG_JSON" ]] || fail "Missing config: $CONFIG_JSON. Run: scripts/apple-container/setup.sh"
[[ -f "$RUN_SH" ]]      || fail "Missing run.sh: $RUN_SH"
ensure_safe_stage_dir
validate_name "container name" "$OPENCLAW_CONTAINER_NAME"
validate_name "code volume" "$CODE_VOLUME_NAME"
if [[ -n "$SYNC_RUNTIME" ]]; then
  case "$SYNC_RUNTIME" in
    node|bun) ;;
    *) fail "Invalid runtime: expected node or bun." ;;
  esac
fi

if ! container system status --format json >/dev/null 2>&1; then
  fail "Apple Container is not running. Run: container system start"
fi

if ! container image list 2>/dev/null | grep -Fq "${IMAGE%%:*}"; then
  fail "Image '${IMAGE}' not found. Run: scripts/apple-container/setup.sh first."
fi

# ── Rollback mode ────────────────────────────────────────────────
if $DO_ROLLBACK; then
  info "Rolling back — deleting code volume, restarting from image..."
  "$RUN_SH" --stop 2>/dev/null || true
  container volume delete "$CODE_VOLUME_NAME" 2>/dev/null || true
  rm -rf "$STAGE_DIR"
  OPENCLAW_APPLE_CONTAINER_CODE_VOLUME="" "$RUN_SH"
  info "Rollback complete. Container running from image."
  exit 0
fi

# Whether the resolved `pnpm` is a corepack shim. Corepack shims are JS
# launchers that reference corepack; the standalone pnpm CLI does not. Older
# corepack versions cannot parse the `+sha512` hash suffix in packageManager
# and fail with "expected a semver version".
is_corepack_pnpm_shim() {
  local pnpm_path
  pnpm_path="$(command -v pnpm 2>/dev/null || true)"
  [[ -n "$pnpm_path" ]] || return 1
  head -c 4096 "$pnpm_path" 2>/dev/null | grep -q "corepack"
}

# Resolve a pnpm binary that can build the repo. The repo pins pnpm with a
# `+sha512` hash suffix in packageManager (e.g. pnpm@11.12.0+sha512....);
# a corepack shim rejects that hash. Mirror the Dockerfile.apple_arm64 build
# workaround: when the available pnpm is a corepack shim, install the pinned
# pnpm directly via npm (under .local/, gitignored) and use that instead.
# Users with a standalone pnpm keep using the system binary unchanged.
PNPM_BIN=""
resolve_build_pnpm() {
  if [[ -n "$PNPM_BIN" ]]; then
    return 0
  fi
  if command -v pnpm >/dev/null 2>&1 && ! is_corepack_pnpm_shim; then
    PNPM_BIN="pnpm"
    return 0
  fi
  local pinned pnpm_dir pnpm_bin
  pinned="$(node -p "require('${REPO_ROOT}/package.json').packageManager.split('@')[1].split('+')[0]" 2>/dev/null || true)"
  [[ -n "$pinned" ]] || fail "Could not determine pinned pnpm version from package.json packageManager."
  pnpm_dir="${REPO_ROOT}/.local/apple-container/pnpm"
  pnpm_bin="${pnpm_dir}/node_modules/.bin/pnpm"
  if [[ ! -x "$pnpm_bin" ]]; then
    require_cmd npm
    info "Installing pinned pnpm@${pinned} for the host build (bypasses corepack hash parsing)..."
    install -d -m 700 "$pnpm_dir"
    ( cd "$pnpm_dir" && npm install "pnpm@${pinned}" --no-save --prefix "$pnpm_dir" >/dev/null 2>&1 ) ||
      fail "Failed to install pnpm@${pinned} via npm for the host build."
    [[ -x "$pnpm_bin" ]] || fail "pnpm@${pinned} install did not produce a usable binary."
  fi
  PNPM_BIN="$pnpm_bin"
}

# ── Build on host ────────────────────────────────────────────────
if $DO_BUILD; then
  resolve_build_pnpm
  info "Building on macOS host..."
  cd "$REPO_ROOT"

  if [[ ! -d "node_modules" ]]; then
    fail "node_modules not found. Run: pnpm install"
  fi

  info "  pnpm build..."
  if ! "${PNPM_BIN}" build 2>&1; then
    fail "pnpm build failed. Fix errors and retry."
  fi

  info "  pnpm ui:build..."
  if ! "${PNPM_BIN}" ui:build 2>&1; then
    fail "pnpm ui:build failed. Fix errors and retry."
  fi

  info "  pnpm qa:lab:build..."
  if ! "${PNPM_BIN}" qa:lab:build 2>&1; then
    fail "pnpm qa:lab:build failed. Fix errors and retry."
  fi

  info "Build complete."
fi

# Verify dist/ exists and is non-empty
if [[ ! -d "$REPO_ROOT/dist" ]] || [[ -z "$(ls -A "$REPO_ROOT/dist/" 2>/dev/null)" ]]; then
  fail "dist/ is empty or missing. Run with --no-build only after a successful build."
fi

# ── Prepare hardened staging directory ───────────────────────────
info "Staging build output..."

rm -rf "$STAGE_DIR"
install -d -m 0700 "$STAGE_DIR"

rsync -a \
  --no-links \
  --exclude='.DS_Store' \
  --exclude='._*' \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='.env.*' \
  "$REPO_ROOT/dist/" "$STAGE_DIR/dist/"

for subdir in skills qa docs; do
  if [[ -d "$REPO_ROOT/$subdir" ]]; then
    rsync -a \
      --no-links \
      --exclude='.DS_Store' \
      --exclude='._*' \
      --exclude='.git' \
      --exclude='node_modules' \
      --exclude='.env' \
      --exclude='.env.*' \
      "$REPO_ROOT/$subdir/" "$STAGE_DIR/$subdir/"
  fi
done

if [[ -d "$REPO_ROOT/src/agents/templates" ]]; then
  install -d -m 0755 "$STAGE_DIR/src/agents"
  rsync -a \
    --no-links \
    --exclude='.DS_Store' \
    --exclude='._*' \
    "$REPO_ROOT/src/agents/templates/" "$STAGE_DIR/src/agents/templates/"
fi

if [[ -f "$REPO_ROOT/openclaw.mjs" ]]; then
  cp "$REPO_ROOT/openclaw.mjs" "$STAGE_DIR/openclaw.mjs"
fi

if [[ -f "$REPO_ROOT/package.json" ]]; then
  cp "$REPO_ROOT/package.json" "$STAGE_DIR/package.json"
fi

IMAGE_ID="$(container_image_id)"
STAMP_JSON="$(node - "$REPO_ROOT" "$IMAGE" "$IMAGE_ID" <<'STAMPNODE'
const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");

const root = process.argv[2];
const image = process.argv[3];
const imageId = process.argv[4] || "";
const inputs = [
  "Dockerfile.apple_arm64",
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  ".npmrc",
];
const hash = crypto.createHash("sha256");
for (const rel of inputs) {
  const file = path.join(root, rel);
  if (!fs.existsSync(file)) continue;
  hash.update(rel);
  hash.update("\0");
  hash.update(fs.readFileSync(file));
  hash.update("\0");
}
process.stdout.write(JSON.stringify({
  protocolVersion: 1,
  image,
  imageId,
  inputHash: hash.digest("hex"),
}));
STAMPNODE
)"
printf '%s\n' "$STAMP_JSON" >"$STAGE_DIR/$STAMP_FILE"

# ── Security validation ──────────────────────────────────────────
info "Validating staged output..."

# 1. Ownership and permissions
STAGE_UID="$(stat -f '%u' "$STAGE_DIR" 2>/dev/null || stat -Lc '%u' "$STAGE_DIR")"
STAGE_MODE="$(stat -f '%Lp' "$STAGE_DIR" 2>/dev/null || stat -Lc '%a' "$STAGE_DIR")"
[[ "$STAGE_UID" == "$(id -u)" ]] || fail "Staging directory not owned by current user."
[[ "$((8#$STAGE_MODE & 0077))" -eq 0 ]] || fail "Staging directory is group/other accessible (mode $STAGE_MODE)."

# 2. Symlink rejection — no symlinks allowed in staged output
SYMLINK_COUNT="$(find "$STAGE_DIR" -type l 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$SYMLINK_COUNT" -gt 0 ]]; then
  echo "  Symlinks found:" >&2
  find "$STAGE_DIR" -type l -ls >&2
  fail "Symlinks in staged output — rejecting for security. Possible path traversal."
fi

# 3. Sensitive file pattern scan
# dist/ contains JS bundles like "credentials-ABC123.js" — compiled code, NOT secrets.
# Only flag actual secret files (SSH keys, PEM, .env, credential JSON).
SENSITIVE_FILES="$(find "$STAGE_DIR" -type f 2>/dev/null | grep -iE '\.(pem|key|p12|pfx|jks|keystore)$|(^|/)\.env$|(^|/)\.env\.(local|dev|prod|staging)$|(^|/)id_rsa$|(^|/)id_ed25519$|(^|/)id_ecdsa$|(^|/)id_rsa\.pub$|(^|/)id_ed25519\.pub$|(^|/)\.ssh/|(^|/)\.gitconfig$|(^|/)\.netrc$|(^|/)(authorization|token|auth)\.json$' || true)"
if [[ -n "$SENSITIVE_FILES" ]]; then
  echo "  Sensitive files found:" >&2
  echo "$SENSITIVE_FILES" >&2
  fail "Sensitive file patterns in staged output — rejecting for security."
fi

# 4. Native binary rejection — no .node/.so/.dylib/.dll
NATIVE_FILES="$(find "$STAGE_DIR" -type f \( -name '*.node' -o -name '*.so' -o -name '*.dylib' -o -name '*.dll' \) 2>/dev/null || true)"
if [[ -n "$NATIVE_FILES" ]]; then
  echo "  Native binaries found:" >&2
  echo "$NATIVE_FILES" >&2
  fail "Native binaries in staged output — rejecting. Use build.sh for native addon changes."
fi

# 5. Size bounds
STAGED_BYTES="$(du -sk "$STAGE_DIR" 2>/dev/null | cut -f1)"
STAGED_MB="$((STAGED_BYTES / 1024))"
if [[ "$((STAGED_BYTES * 1024))" -gt "$MAX_STAGED_SIZE_BYTES" ]]; then
  fail "Staged output exceeds size limit (${STAGED_MB} MB). Something is wrong."
fi

# 6. File count bounds
STAGED_FILES="$(find "$STAGE_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"
if [[ "$STAGED_FILES" -gt "$MAX_STAGED_FILE_COUNT" ]]; then
  fail "Staged output exceeds file limit (${STAGED_FILES} files). Something is wrong."
fi

info "  Validation passed: ${STAGED_MB} MB, ${STAGED_FILES} files, 0 symlinks, 0 sensitive patterns."

# ── Stage into named volume via ephemeral container ───────────────
# This is the security boundary: the main container NEVER sees the host
# filesystem. The ephemeral staging container is short-lived, heavily
# restricted, and exists solely to copy validated files into the volume.
#
# First sync: the volume is empty, so we seed it from the image's /app/
# (node_modules, extensions, package.json, etc.), then overlay host code.
# Subsequent syncs: only overlay the changed code paths.

STAGE_CONTAINER="${OPENCLAW_CONTAINER_NAME}-code-stage"
VOLUME_EXISTS=false
FULL_SEED=false
if code_volume_exists; then
  VOLUME_EXISTS=true
fi

if $VOLUME_EXISTS; then
  CURRENT_STAMP="$(
    container run \
      --rm \
      --name "${STAGE_CONTAINER:-${OPENCLAW_CONTAINER_NAME}-code-stage}-stamp" \
      --read-only \
      --tmpfs /tmp \
      --cap-drop ALL \
      --user 1000:1000 \
      --mount "type=volume,source=${CODE_VOLUME_NAME},target=/app,readonly" \
      "$IMAGE" \
      sh -c "cat \"/app/$STAMP_FILE\" 2>/dev/null || true" 2>/dev/null || true
  )"
  if [[ "$CURRENT_STAMP" != "$STAMP_JSON" ]]; then
    info "Code volume stamp differs from current image/package inputs; reseeding."
    "$RUN_SH" --stop 2>/dev/null || true
    container delete "$OPENCLAW_CONTAINER_NAME" >/dev/null 2>&1 || true
    if container volume delete "$CODE_VOLUME_NAME" >/dev/null 2>&1; then
      VOLUME_EXISTS=false
    elif code_volume_exists; then
      warn "Could not delete code volume '${CODE_VOLUME_NAME}'; reseeding it in place."
      VOLUME_EXISTS=true
    else
      VOLUME_EXISTS=false
    fi
    FULL_SEED=true
  fi
fi

container delete "$STAGE_CONTAINER" >/dev/null 2>&1 || true

if ! $VOLUME_EXISTS; then
  info "Creating code volume '${CODE_VOLUME_NAME}' (first sync — seeding from image)..."
  if ! container volume create "$CODE_VOLUME_NAME" >/dev/null 2>&1; then
    fail "Failed to create code volume '${CODE_VOLUME_NAME}'."
  fi
  FULL_SEED=true
fi

if $FULL_SEED; then
  if $VOLUME_EXISTS; then
    info "Reseeding code volume '${CODE_VOLUME_NAME}' from image..."
  fi
  if ! container run \
    --rm \
    --name "$STAGE_CONTAINER" \
    --read-only \
    --tmpfs /tmp \
    --cap-drop ALL \
    --user 0:0 \
    --mount "type=bind,source=${STAGE_DIR},target=/stage,readonly" \
    --mount "type=volume,source=${CODE_VOLUME_NAME},target=/app-seed" \
    "$IMAGE" \
    sh -c '
      set -eu
      find /app-seed -mindepth 1 -maxdepth 1 -exec rm -rf {} +
      cp -a /app/. /app-seed/
      echo "  Seeded $(find /app-seed -type f 2>/dev/null | wc -l) files from image."

      for subpath in dist skills qa docs src/agents/templates openclaw.mjs package.json '"$STAMP_FILE"'; do
        if [ -e "/stage/$subpath" ]; then
          rm -rf "/app-seed/$subpath"
          mkdir -p "$(dirname "/app-seed/$subpath")"
          cp -a "/stage/$subpath" "/app-seed/$subpath"
        fi
      done
      if [ -d /app-seed/src ]; then
        find /app-seed/src -type d -exec chmod 0755 {} +
        find /app-seed/src -type f -exec chmod 0644 {} +
      fi
      test -s /app-seed/openclaw.mjs
      test -d /app-seed/dist
      test -f /app-seed/src/agents/templates/HEARTBEAT.md
      test -s "/app-seed/'"$STAMP_FILE"'"
      echo "  Volume ready: $(find /app-seed -type f 2>/dev/null | wc -l) files total."
    ' 2>&1; then
    container delete "$STAGE_CONTAINER" >/dev/null 2>&1 || true
    container volume delete "$CODE_VOLUME_NAME" 2>/dev/null || true
    fail "Failed to seed code volume."
  fi
else
  info "Updating code volume '${CODE_VOLUME_NAME}' (overlay only)..."

  # Subsequent syncs: only overlay the changed code paths.
  # The volume already has node_modules, extensions, etc. from the seed.
  if ! container run \
    --rm \
    --name "$STAGE_CONTAINER" \
    --read-only \
    --tmpfs /tmp \
    --cap-drop ALL \
    --user 0:0 \
    --mount "type=bind,source=${STAGE_DIR},target=/stage,readonly" \
    --mount "type=volume,source=${CODE_VOLUME_NAME},target=/app" \
    "$IMAGE" \
    sh -c '
      set -eu
      for subpath in dist skills qa docs src/agents/templates openclaw.mjs package.json '"$STAMP_FILE"'; do
        if [ -e "/stage/$subpath" ]; then
          rm -rf "/app/$subpath"
          mkdir -p "$(dirname "/app/$subpath")"
          cp -a "/stage/$subpath" "/app/$subpath"
        fi
      done
      if [ -d /app/src ]; then
        find /app/src -type d -exec chmod 0755 {} +
        find /app/src -type f -exec chmod 0644 {} +
      fi
      test -s /app/openclaw.mjs
      test -d /app/dist
      test -f /app/src/agents/templates/HEARTBEAT.md
      test -s "/app/'"$STAMP_FILE"'"
      echo "  Updated $(ls /stage | wc -l) paths."
    ' 2>&1; then
    container delete "$STAGE_CONTAINER" >/dev/null 2>&1 || true
    fail "Failed to update code volume."
  fi
fi

info "  Volume staged successfully."
rm -rf "$STAGE_DIR"

# ── Stop and restart with volume mount ───────────────────────────
info "Stopping current container..."
"$RUN_SH" --stop 2>/dev/null || true

info "Restarting with code volume '${CODE_VOLUME_NAME}'..."
if [[ -n "$SYNC_RUNTIME" ]]; then
  env OPENCLAW_APPLE_CONTAINER_CODE_VOLUME="$CODE_VOLUME_NAME" \
    OPENCLAW_APPLE_CONTAINER_RUNTIME="$SYNC_RUNTIME" \
    OPENCLAW_APPLE_CONTAINER_SKIP_OPEN_DASHBOARD=1 \
    "$RUN_SH"
else
  env OPENCLAW_APPLE_CONTAINER_CODE_VOLUME="$CODE_VOLUME_NAME" \
    OPENCLAW_APPLE_CONTAINER_SKIP_OPEN_DASHBOARD=1 \
    "$RUN_SH"
fi

# ── Health check ─────────────────────────────────────────────────
info "Waiting for health check..."
HTTP_CODE=""
for _ in {1..30}; do
  HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${HOST_PORT}/healthz" 2>/dev/null || true)"
  [[ "$HTTP_CODE" == "200" ]] && break
  sleep 1
done

if [[ "$HTTP_CODE" == "200" ]]; then
  info "Health check: OK (/healthz returned 200)"
  info "Sync complete. Gateway running with updated code from volume."
  "$RUN_SH" --open-dashboard 2>/dev/null || true
else
  echo ""
  warn "Health check failed (/healthz returned ${HTTP_CODE})."
  warn "Rolling back to image-built code..."
  "$RUN_SH" --stop 2>/dev/null || true
  container volume delete "$CODE_VOLUME_NAME" 2>/dev/null || true
  OPENCLAW_APPLE_CONTAINER_CODE_VOLUME="" "$RUN_SH"
  for _ in {1..30}; do
    HTTP_CODE="$(curl -s -o /dev/null -w "%{http_code}" \
      "http://127.0.0.1:${HOST_PORT}/healthz" 2>/dev/null || true)"
    [[ "$HTTP_CODE" == "200" ]] && break
    sleep 1
  done
  if [[ "$HTTP_CODE" == "200" ]]; then
    warn "Rollback successful — container running from image. Fix build errors and retry."
  else
    fail "Rollback also failed. Check: container logs $OPENCLAW_CONTAINER_NAME"
  fi
  exit 1
fi
