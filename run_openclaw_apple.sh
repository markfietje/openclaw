#!/bin/bash
set -e

# -------------------------------
# Configuration
# -------------------------------
# Persistent output folder on host
HOST_DATA_DIR="$HOME/Sites/openclaw/data"
mkdir -p "$HOST_DATA_DIR"

# Container image and name
IMAGE_NAME="openclaw-fork"
CONTAINER_NAME="openclaw-test"

# RAM allocation
MEMORY="4g"

# CLI command to run inside container (adjust as needed)
CLI_CMD="openclaw run --output /app/data"

# -------------------------------
# Step 1: Build container using existing Dockerfile
# -------------------------------
echo "Building container image '$IMAGE_NAME' from existing Dockerfile..."
container build -t "$IMAGE_NAME" .

# -------------------------------
# Step 2: Run container with 4 GB RAM and persistent volume
# -------------------------------
echo "Running container '$CONTAINER_NAME' with $MEMORY RAM..."
container run \
  --memory "$MEMORY" \
  -v "$HOST_DATA_DIR:/app/data" \
  --name "$CONTAINER_NAME" \
  -it "$IMAGE_NAME" \
  $CLI_CMD

echo "Done! Outputs/logs are persisted in $HOST_DATA_DIR"
