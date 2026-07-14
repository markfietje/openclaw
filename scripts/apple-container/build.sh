#!/usr/bin/env bash
# Build the OpenClaw Apple Container image for Linux/arm64.
#
# Uses an allowlist to copy only the files the Dockerfile needs into a small,
# deterministic build context under /tmp. This avoids streaming gigabytes of
# macOS/Swift/iOS build caches, node_modules, media assets, and editor state
# into the Apple Container builder over gRPC — which causes "Stream
# unexpectedly closed" errors when the context exceeds ~1-2 GB.
#
# The Linux/arm64 container image does not need SwiftPM build caches
# (apps/shared/OpenClawKit/.build), DerivedData, ModuleCache, or any
# Darwin-specific native artifacts. Including them only wastes bandwidth to
# the builder VM and risks stream timeouts.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

TAG="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"
DOCKERFILE="${OPENCLAW_APPLE_CONTAINER_DOCKERFILE:-Dockerfile.apple_arm64}"
ARCH="${OPENCLAW_APPLE_CONTAINER_ARCH:-arm64}"
BUILDER_CPUS="${BUILDER_CPUS:-4}"
BUILDER_MEMORY="${BUILDER_MEMORY:-10g}"
BUILDER_DNS="${OPENCLAW_APPLE_CONTAINER_BUILDER_DNS:-9.9.9.9}"
BUILD_CONTEXT="${BUILD_CONTEXT:-}"

EXTRA_ARGS=()
NO_CACHE=false
RESET_BUILDER=false
SHOW_CONTEXT_TOP=false
KEEP_CONTEXT=false

# ── Global exclude flags applied to every rsync ─────────────────
# These strip build outputs, caches, and platform-specific artifacts
# from every path we copy, even inside allowed directories.
RSYNC_EXCLUDES=(
  --exclude='.git'
  --exclude='.worktrees'
  --exclude='node_modules'
  --exclude='**/node_modules'
  --exclude='.pnpm-store'
  --exclude='**/.pnpm-store'
  --exclude='.pnpm-offline-store'
  --exclude='**/.pnpm-offline-store'
  --exclude='.turbo'
  --exclude='**/.turbo'
  --exclude='.cache'
  --exclude='**/.cache'
  --exclude='.next'
  --exclude='**/.next'
  --exclude='.bun'
  --exclude='.bun-cache'
  --exclude='**/.bun-cache'
  --exclude='.tmp'
  --exclude='**/.tmp'
  --exclude='.DS_Store'
  --exclude='**/.DS_Store'
  --exclude='.build'
  --exclude='**/.build'
  --exclude='.swiftpm'
  --exclude='**/.swiftpm'
  --exclude='DerivedData'
  --exclude='**/DerivedData'
  --exclude='ModuleCache'
  --exclude='**/ModuleCache'
  --exclude='dist'
  --exclude='**/dist'
  --exclude='build'
  --exclude='**/build'
  --exclude='out'
  --exclude='**/out'
  --exclude='.svelte-kit'
  --exclude='**/.svelte-kit'
  --exclude='.vite'
  --exclude='**/.vite'
  --exclude='coverage'
  --exclude='**/coverage'
  --exclude='__openclaw_vitest__'
  --exclude='test-fixtures'
  --exclude='.vscode'
  --exclude='.idea'
  --exclude='.claude'
  --exclude='.codex'
  --exclude='.agents'
  --exclude='docs/.generated'
  --exclude='**/.generated'
  --exclude='*.log'
  --exclude='*.trace'
  --exclude='*.png'
  --exclude='*.jpg'
  --exclude='*.jpeg'
  --exclude='*.webp'
  --exclude='*.gif'
  --exclude='*.mp4'
  --exclude='*.mov'
  --exclude='*.wav'
  --exclude='*.mp3'
)

usage() {
  cat <<USAGE
Usage: $0 [options]

Options:
  -t, --tag TAG          Image tag (default: openclaw:apple-arm64)
  -f, --file FILE        Dockerfile relative to repo root (default: Dockerfile.apple_arm64)
  --arch ARCH            Target architecture (default: arm64)
  --no-cache             Disable build cache for this build
  --reset-builder        Stop/delete/recreate the Apple Container builder before building
  --show-context-top     Print the 50 largest paths in the build context after preparing it
  --keep-context         Keep existing context directory (do not rm -rf before rsync)
  --build-arg K=V        Pass a build argument; repeatable
  --context PATH         Override build context directory
  -h, --help             Show this help

Environment:
  OPENCLAW_APPLE_CONTAINER_IMAGE=TAG
  OPENCLAW_APPLE_CONTAINER_DOCKERFILE=FILE
  OPENCLAW_APPLE_CONTAINER_ARCH=arm64
  BUILDER_CPUS=N             Builder VM CPUs (default: 4)
  BUILDER_MEMORY=Xg          Builder VM RAM (default: 10g)
  OPENCLAW_APPLE_CONTAINER_BUILDER_DNS=IP
                          Builder VM DNS server (default: 9.9.9.9)

Examples:
  $0
  $0 --show-context-top
  $0 --reset-builder --no-cache
  BUILDER_CPUS=6 BUILDER_MEMORY=12g $0   # for 32 GB+ hosts; 10g caps tsdown old-space
USAGE
}

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

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

validate_image_name() {
  local value="$1"
  validate_single_line_value "image name" "$value"
  [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._/:@-]*$ ]] || fail "Invalid image name: $value"
}

validate_arch() {
  local value="$1"
  validate_single_line_value "architecture" "$value"
  [[ "$value" =~ ^[A-Za-z0-9_.-]+$ ]] || fail "Invalid architecture: $value"
}

validate_dockerfile_path() {
  local value="$1"
  validate_single_line_value "Dockerfile path" "$value"
  [[ "$value" != /* ]] || fail "Invalid Dockerfile path: expected a repo-relative path."
  [[ "$value" != *"/./"* && "$value" != */. && "$value" != *"/../"* && "$value" != */.. ]] ||
    fail "Invalid Dockerfile path: dot path segments are not allowed."
}

resolve_context_path() {
  local raw="$1" parent="" base=""
  validate_single_line_value "build context" "$raw"
  [[ -n "$raw" ]] || fail "Invalid build context: empty."
  if [[ "$raw" != /* ]]; then
    raw="$(pwd)/$raw"
  fi
  parent="$(dirname "$raw")"
  base="$(basename "$raw")"
  [[ "$base" =~ ^openclaw-apple-build-context([._-].*)?$ ]] ||
    fail "Invalid build context: basename must start with openclaw-apple-build-context."
  mkdir -p "$parent"
  parent="$(cd "$parent" && pwd -P)"
  printf '%s/%s' "$parent" "$base"
}

ensure_safe_build_context() {
  local context="$1" repo_parent=""
  repo_parent="$(cd "$REPO_ROOT/.." && pwd -P)"
  [[ "$context" == /* ]] || fail "Invalid build context: expected an absolute path."
  [[ "$context" != "/" ]] || fail "Refusing to use / as build context."
  [[ "$context" != "$REPO_ROOT" && "$context" != "$REPO_ROOT"/* ]] ||
    fail "Refusing to use a path inside the repo as build context: $context"
  [[ "$context" != "$HOME" ]] || fail "Refusing to use HOME as build context."
  [[ "$context" == "$repo_parent"/openclaw-apple-build-context* ||
    "$context" == "${TMPDIR:-/tmp}"/openclaw-apple-build-context* ||
    "$context" == /tmp/openclaw-apple-build-context* ||
    "$context" == /private/tmp/openclaw-apple-build-context* ]] ||
    fail "Refusing unsafe build context path: $context"
  if [[ -e "$context" ]]; then
    [[ ! -L "$context" ]] || fail "Unsafe build context: symlinks are not allowed ($context)"
    [[ -d "$context" ]] || fail "Invalid build context: expected a directory ($context)"
  fi
}

memory_to_mb() {
  local value="$1" numeric="" suffix=""
  validate_single_line_value "builder memory" "$value"
  [[ "$value" =~ ^[0-9]+([mMgG])?$ ]] || fail "Invalid builder memory: $value"
  numeric="${value%[mMgG]}"
  suffix="${value:${#numeric}}"
  case "$suffix" in
    g|G) echo $((10#$numeric * 1024)) ;;
    m|M|"") echo $((10#$numeric)) ;;
    *) fail "Invalid builder memory: $value" ;;
  esac
}

builder_memory_mb() {
  container builder status 2>/dev/null |
    awk 'NR == 2 && $(NF) == "MB" && $(NF - 1) ~ /^[0-9]+$/ { print $(NF - 1); exit }'
}

builder_state() {
  container builder status 2>/dev/null |
    awk 'NR == 2 { print $3; exit }'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -t|--tag)
      TAG="${2:?--tag requires a value}"
      shift 2
      ;;
    --no-cache)
      NO_CACHE=true
      shift
      ;;
    -f|--file)
      DOCKERFILE="${2:?--file requires a value}"
      shift 2
      ;;
    --arch)
      ARCH="${2:?--arch requires a value}"
      shift 2
      ;;
    --build-arg)
      EXTRA_ARGS+=("--build-arg" "${2:?--build-arg requires a value}")
      shift 2
      ;;
    --context)
      BUILD_CONTEXT="${2:?--context requires a value}"
      shift 2
      ;;
    --reset-builder)
      RESET_BUILDER=true
      shift
      ;;
    --show-context-top)
      SHOW_CONTEXT_TOP=true
      shift
      ;;
    --keep-context)
      KEEP_CONTEXT=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# ── Preflight checks ─────────────────────────────────────────────
echo "=== Preflight checks ==="

require_cmd container
require_cmd rsync
validate_image_name "$TAG"
validate_arch "$ARCH"
validate_dockerfile_path "$DOCKERFILE"

if ! container system status >/dev/null 2>&1; then
  fail "Apple Container system is not running. Run: container system start"
fi

CLI_VERSION="$(container --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo unknown)"
echo "  container CLI: $CLI_VERSION"
echo "  target image:  $TAG"
echo "  dockerfile:    $DOCKERFILE"
echo "  arch:          $ARCH"

if [[ ! -f "$REPO_ROOT/$DOCKERFILE" ]]; then
  fail "$DOCKERFILE not found in repo root: $REPO_ROOT"
fi

# ── Resolve build context path ───────────────────────────────────
if [[ -z "$BUILD_CONTEXT" ]]; then
  BUILD_CONTEXT="$(cd "$REPO_ROOT/.." && pwd)/openclaw-apple-build-context"
fi
BUILD_CONTEXT="$(resolve_context_path "$BUILD_CONTEXT")"
ensure_safe_build_context "$BUILD_CONTEXT"
echo "  context:       $BUILD_CONTEXT"

# ── Allowlist-based context preparation ──────────────────────────
# Copy only paths the Dockerfile actually references. The Dockerfile uses
#   COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
#   COPY ui/package.json ./ui/package.json
#   COPY patches ./patches
#   COPY scripts/... ./scripts/
#   COPY . .
# The final "COPY . ." pulls everything in the context, so we include source
# dirs the build needs — but exclude Swift/macOS caches, node_modules, etc.
echo ""
echo "=== Preparing allowlist build context ==="

if ! $KEEP_CONTEXT; then
  rm -rf "$BUILD_CONTEXT"
fi
mkdir -p "$BUILD_CONTEXT"

# Helper: copy a repo-relative path into the context with global excludes.
# Silently skips paths that don't exist.
copy_path() {
  local rel="$1"
  if [[ -e "$REPO_ROOT/$rel" ]]; then
    mkdir -p "$BUILD_CONTEXT/$(dirname "$rel")"
    rsync -a --no-links "${RSYNC_EXCLUDES[@]}" \
      "$REPO_ROOT/$rel" "$BUILD_CONTEXT/$(dirname "$rel")/"
  fi
}

copy_required_control_ui_public_asset() {
  local name="$1"
  local src="$REPO_ROOT/ui/public/$name"
  local dest_dir="$BUILD_CONTEXT/ui/public"
  if [[ -f "$src" ]]; then
    mkdir -p "$dest_dir"
    cp "$src" "$dest_dir/$name"
  fi
}

# ── Root config files ────────────────────────────────────────────
copy_path "$DOCKERFILE"
copy_path package.json
copy_path pnpm-lock.yaml
copy_path pnpm-workspace.yaml
copy_path .npmrc
copy_path openclaw.mjs

# Config files that may or may not exist — copy what's there.
for glob in tsconfig.json tsconfig.*.json tsdown.config.* tsdown.ai.config.* turbo.json vite.config.* vitest.config.* eslint.config.* oxlint.json; do
  # shellcheck disable=SC2086
  for f in "$REPO_ROOT"/$glob; do
    [[ -e "$f" ]] || continue
    [[ ! -L "$f" ]] || continue
    base="$(basename "$f")"
    cp "$f" "$BUILD_CONTEXT/$base"
  done
done

# ── Source directories ───────────────────────────────────────────
# These are required by "COPY . ." and the pnpm/ts build.
copy_path src
copy_path ui
copy_required_control_ui_public_asset apple-touch-icon.png
copy_required_control_ui_public_asset favicon-32.png
copy_path packages
copy_path extensions
copy_path scripts
copy_path patches
copy_path skills
copy_path qa
copy_path docs
copy_path apps/shared/OpenClawKit/Sources/OpenClawKit/Resources/tool-display.json
# Directories NOT included (not referenced by Dockerfile build/runtime stages):
#   vendor/, config/, security/, deploy/, changelog/, most of apps/shared/
#   The UI build needs one generated OpenClawKit JSON resource; copy only that.

# ── Write .dockerignore for the builder ──────────────────────────
# Even though our context is already filtered, an explicit .dockerignore
# prevents the builder from scanning for files we accidentally included.
cat >"$BUILD_CONTEXT/.dockerignore" <<'DOCKERIGNORE'
.git
.worktrees
.env
.env.*
*.pem
*.key
*.p12
*.mobileprovision
node_modules
**/node_modules
.pnpm-store
**/.pnpm-store
.pnpm-offline-store
**/.pnpm-offline-store
npm-cache
.yarn/cache
.turbo
**/.turbo
.cache
**/.cache
.next
**/.next
.bun-cache
.bun
.tmp
**/.tmp
.DS_Store
**/.DS_Store
.AppleDouble
.LSOverride
.build
**/.build
.swiftpm
**/.swiftpm
DerivedData
**/DerivedData
ModuleCache
**/ModuleCache
dist
**/dist
build
**/build
coverage
**/coverage
__openclaw_vitest__
test-fixtures
*.log
*.trace
*.png
*.jpg
*.jpeg
*.webp
*.gif
*.mp4
*.mov
*.wav
*.mp3
!ui/public/apple-touch-icon.png
!ui/public/favicon-32.png
.vscode
.idea
.claude
.codex
.agents
apps/macos
apps/ios
apps/android
Peekaboo
Swabble
Core
assets
vendor/a2ui
docs/.generated
**/.generated
DOCKERIGNORE

# ── Context summary ──────────────────────────────────────────────
CTX_SIZE="$(du -sh "$BUILD_CONTEXT" 2>/dev/null | cut -f1 || echo unknown)"
CTX_FILES="$(find "$BUILD_CONTEXT" -type f 2>/dev/null | wc -l | tr -d ' ' || echo unknown)"
echo "  Context size: $CTX_SIZE"
echo "  Context files: $CTX_FILES"

if $SHOW_CONTEXT_TOP; then
  echo ""
  echo "=== Largest paths in context ==="
  du -ah "$BUILD_CONTEXT" 2>/dev/null | sort -hr | head -50
fi

if [[ ! -f "$BUILD_CONTEXT/$DOCKERFILE" ]]; then
  fail "$DOCKERFILE not found inside build context: $BUILD_CONTEXT"
fi

if find "$BUILD_CONTEXT" -type l -print -quit 2>/dev/null | grep -q .; then
  find "$BUILD_CONTEXT" -type l -print >&2
  fail "Build context contains symlinks; refusing to build."
fi

cd "$BUILD_CONTEXT"

# ── Builder management ───────────────────────────────────────────
echo ""
echo "=== Configuring builder (${BUILDER_CPUS} CPUs, ${BUILDER_MEMORY} RAM) ==="
DESIRED_BUILDER_MEMORY_MB="$(memory_to_mb "$BUILDER_MEMORY")"
BUILDER_JUST_STARTED=false

if $RESET_BUILDER; then
  echo "  Resetting builder by request..."
  container builder stop 2>/dev/null || true
  container builder delete --force 2>/dev/null || true
fi

if container builder status >/dev/null 2>&1; then
  CURRENT_BUILDER_MEMORY_MB="$(builder_memory_mb)"
  CURRENT_BUILDER_STATE="$(builder_state)"
  if [[ -n "$CURRENT_BUILDER_MEMORY_MB" && "$CURRENT_BUILDER_MEMORY_MB" != "$DESIRED_BUILDER_MEMORY_MB" ]]; then
    echo "  Builder memory is ${CURRENT_BUILDER_MEMORY_MB} MB; recreating with ${DESIRED_BUILDER_MEMORY_MB} MB."
    container builder stop 2>/dev/null || true
    container builder delete --force 2>/dev/null || true
    container builder start --cpus "$BUILDER_CPUS" --memory "$BUILDER_MEMORY" --dns "$BUILDER_DNS"
    BUILDER_JUST_STARTED=true
    echo "  Builder restarted."
  elif [[ "$CURRENT_BUILDER_STATE" != "running" ]]; then
    container builder start --cpus "$BUILDER_CPUS" --memory "$BUILDER_MEMORY" --dns "$BUILDER_DNS"
    BUILDER_JUST_STARTED=true
    echo "  Builder started."
  else
    echo "  Builder already running; keeping cache."
  fi
else
  container builder start --cpus "$BUILDER_CPUS" --memory "$BUILDER_MEMORY" --dns "$BUILDER_DNS"
  BUILDER_JUST_STARTED=true
  echo "  Builder started."
fi

# Wait for the buildkit VM to accept gRPC connections after a fresh start.
# "Stream unexpectedly closed" occurs when the build fires before the VM's
# gRPC endpoint is fully bound. Probe with a tiny no-op build to confirm.
if $BUILDER_JUST_STARTED; then
  echo -n "  Waiting for builder readiness"
  for _i in $(seq 1 20); do
    sleep 1
    # A dummy image list call exercises the gRPC path without starting a build.
    if container image list 2>/dev/null >/dev/null; then
      sleep 1
      break
    fi
    echo -n "."
  done
  echo " ready."
fi

# ── Build ────────────────────────────────────────────────────────
echo ""
echo "=== Building $TAG ==="

BUILD_ARGS=(
  --arch "$ARCH"
  --cpus "$BUILDER_CPUS"
  --memory "$BUILDER_MEMORY"
  -t "$TAG"
  -f "$DOCKERFILE"
  --progress plain
)

if $NO_CACHE; then
  BUILD_ARGS+=(--no-cache)
fi

BUILD_ARGS+=("${EXTRA_ARGS[@]}")
BUILD_ARGS+=("$BUILD_CONTEXT")

printf '  container build'
printf ' %q' "${BUILD_ARGS[@]}"
printf '\n\n'

cd "$BUILD_CONTEXT"
# Unset CONTAINER_DEFAULT_PLATFORM so the builder doesn't inject a platform
# annotation that may conflict with the --arch flag.
env -u CONTAINER_DEFAULT_PLATFORM container build "${BUILD_ARGS[@]}"

echo ""
echo "=== Build complete ==="
container image list | grep -E "NAME|openclaw|${TAG%%:*}" || true
echo ""
echo "To run the container:"
echo "  scripts/apple-container/run.sh"
