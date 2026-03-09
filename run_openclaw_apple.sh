#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="openclaw"
RAM_MB=4096
PERSISTENT_DIR="$HOME/.openclaw-container"

mkdir -p "$PERSISTENT_DIR"

echo "🚀 Running OpenClaw in Apple Container..."

apple-container run \
  --name "$CONTAINER_NAME" \
  --volume "$PERSISTENT_DIR:/home/node/.openclaw" \
  --volume "$PERSISTENT_DIR/tailscale-state:/var/lib/tailscale" \
  --memory "${RAM_MB}M" \
  ghcr.io/openclaw/openclaw:latest

echo "✅ Container running! Data: $PERSISTENT_DIR"
echo "   Check status: apple-container list"
