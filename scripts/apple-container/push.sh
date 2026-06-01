#!/usr/bin/env bash
# Push the OpenClaw Apple Container image to a registry.
#
# Defaults to GitHub Container Registry (ghcr.io) using the repo owner
# derived from the git remote. Override with OPENCLAW_CONTAINER_REGISTRY
# and OPENCLAW_CONTAINER_REPO.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

LOCAL_TAG="${OPENCLAW_APPLE_CONTAINER_IMAGE:-openclaw:apple-arm64}"

# ── Resolve registry defaults from git remote ──────────────────
resolve_registry() {
  local remote_url
  remote_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  if [[ "$remote_url" == *"github.com"* ]]; then
    echo "ghcr.io"
  else
    echo ""
  fi
}

resolve_repo() {
  local remote_url
  remote_url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  # Handle both HTTPS and SSH URLs
  # https://github.com/owner/repo.git → owner/repo
  # git@github.com:owner/repo.git → owner/repo
  local repo
  repo="$(echo "$remote_url" | sed -E 's|.*github\.com[:/]||; s|\.git$||')"
  echo "$repo"
}

REGISTRY="${OPENCLAW_CONTAINER_REGISTRY:-$(resolve_registry)}"
REPO="${OPENCLAW_CONTAINER_REPO:-$(resolve_repo)}"
TAG_SUFFIX="${OPENCLAW_CONTAINER_TAG_SUFFIX:-}"

DRY_RUN=false
FORCE=false
EXTRA_TAGS=()

usage() {
  cat <<USAGE
Usage: $0 [options]

Push the Apple Container image to a registry.

Options:
  -r, --registry REGISTRY   Target registry (default: auto-detected from git remote)
  --repo OWNER/REPO         Repository path (default: auto-detected from git remote)
  --tag-suffix SUFFIX       Append suffix to the tag (e.g. "-beta" → ghcr.io/owner/repo:apple-arm64-beta)
  -t, --extra-tag TAG       Additional tag to push; repeatable
  --local-tag TAG           Local image tag (default: openclaw:apple-arm64)
  --dry-run                 Print commands without executing
  --force                   Push even if the image already exists in the registry
  -h, --help                Show this help

Environment:
  OPENCLAW_APPLE_CONTAINER_IMAGE=TAG   Local image tag (default: openclaw:apple-arm64)
  OPENCLAW_CONTAINER_REGISTRY=HOST     Override registry (default: ghcr.io)
  OPENCLAW_CONTAINER_REPO=OWNER/REPO   Override repository path

Prerequisites:
  container registry login ghcr.io -u OWNER --password-stdin < TOKEN

Examples:
  $0
  $0 --dry-run
  $0 --tag-suffix -beta
  $0 -t ghcr.io/markfietje/openclaw:latest
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--registry) REGISTRY="${2:?--registry requires a value}"; shift 2 ;;
    --repo) REPO="${2:?--repo requires a value}"; shift 2 ;;
    --tag-suffix) TAG_SUFFIX="${2:?--tag-suffix requires a value}"; shift 2 ;;
    -t|--extra-tag) EXTRA_TAGS+=("${2:?--extra-tag requires a value}"); shift 2 ;;
    --local-tag) LOCAL_TAG="${2:?--local-tag requires a value}"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    --force) FORCE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [[ -z "$REGISTRY" ]]; then
  echo "ERROR: Could not auto-detect registry. Set OPENCLAW_CONTAINER_REGISTRY or use --registry." >&2
  exit 1
fi

if [[ -z "$REPO" ]]; then
  echo "ERROR: Could not auto-detect repository. Set OPENCLAW_CONTAINER_REPO or use --repo." >&2
  exit 1
fi

# ── Resolve tags ────────────────────────────────────────────────
REMOTE_TAG="${REGISTRY}/${REPO}:apple-arm64${TAG_SUFFIX}"

ALL_TAGS=("$REMOTE_TAG")
for extra in "${EXTRA_TAGS[@]+"${EXTRA_TAGS[@]}"}"; do
  ALL_TAGS+=("$extra")
done

# ── Verify local image exists ───────────────────────────────────
echo "=== Push OpenClaw Apple Container image ==="
echo "  local image:  $LOCAL_TAG"
echo "  registry:     $REGISTRY"
echo "  repository:   $REPO"
echo "  remote tags:  ${ALL_TAGS[*]}"
echo ""

if ! container image list | awk 'NR>1 {print $1, $2}' | grep -q "^${LOCAL_TAG%%:*} ${LOCAL_TAG##*:}"; then
  echo "ERROR: Local image '$LOCAL_TAG' not found. Run scripts/apple-container/build.sh first." >&2
  exit 1
fi

# ── Tag ─────────────────────────────────────────────────────────
echo "=== Tagging ==="
for tag in "${ALL_TAGS[@]}"; do
  if $DRY_RUN; then
    echo "  [dry-run] container image tag $LOCAL_TAG $tag"
  else
    container image tag "$LOCAL_TAG" "$tag"
    echo "  tagged: $tag"
  fi
done

# ── Push ────────────────────────────────────────────────────────
echo ""
echo "=== Pushing ==="
for tag in "${ALL_TAGS[@]}"; do
  if $DRY_RUN; then
    echo "  [dry-run] container image push $tag"
  else
    echo "  pushing: $tag"
    container image push "$tag"
    echo "  pushed:  $tag"
  fi
done

echo ""
echo "=== Done ==="
if ! $DRY_RUN; then
  echo "Pull with:"
  echo "  container image pull ${ALL_TAGS[0]}"
  echo ""
  echo "For ghcr.io: go to github.com → Packages → Package settings → Manage Actions access"
  echo "to link the package to your repo and set visibility to Public (free, no auth to pull)."
fi
