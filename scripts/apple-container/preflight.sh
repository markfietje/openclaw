#!/usr/bin/env bash
# OpenClaw Apple Container — standalone preflight check.
# Verifies the host has everything the other apple-container scripts need.
#
# Usage:
#   scripts/apple-container/preflight.sh
#   scripts/apple-container/preflight.sh --all   # also run build/sync preflights
#
# Exit code: 0 on full pass (warnings allowed), 1 on any hard failure.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/preflight.sh
source "${SCRIPT_DIR}/lib/preflight.sh"

show_help() {
  cat <<USAGE
Usage: $(basename "$0") [--all]

Checks the host for everything the OpenClaw Apple Container scripts need:
macOS, Apple Silicon, Apple Container CLI + runtime, Keychain, curl, node,
optional clipboard / browser / launchctl / tailscale, and token-source.

Flags:
  --all    Also run the stricter preflights used by build.sh and sync-hot.sh
USAGE
}

case "${1:-}" in
  -h|--help|"") ;;
  --all)
    if ! preflight_run_default; then exit 1; fi
    printf "\n"
    if ! preflight_run_build; then exit 1; fi
    printf "\n"
    if ! preflight_run_sync; then exit 1; fi
    exit 0
    ;;
  *)
    show_help >&2
    exit 2
    ;;
esac

preflight_run_default
