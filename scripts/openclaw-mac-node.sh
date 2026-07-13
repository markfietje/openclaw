#!/usr/bin/env bash
# Manage the OpenClaw macOS CLI node connection.
#
# `openclaw-mac connect --role node` is a one-shot probe: it connects, fetches
# gateway health, then exits. This script wraps it in a background reconnect
# loop so the Mac stays registered as a node between cycles.
#
# Usage:
#   scripts/openclaw-mac-node.sh --start    Start the node loop in the background
#   scripts/openclaw-mac-node.sh --stop     Stop the background node loop
#   scripts/openclaw-mac-node.sh --status   Show running state + last connect result
#
# The gateway token is read from ~/.openclaw/openclaw.json (gateway.remote.token)
# and never printed. The gateway URL defaults to gateway.remote.url, falling back
# to ws://127.0.0.1:18789/gateway.

set -euo pipefail

CLI="openclaw-mac"
CONFIG_JSON="${HOME}/.openclaw/openclaw.json"
PID_FILE="${TMPDIR:-/tmp}/openclaw-mac-node.pid"
LOG_FILE="${TMPDIR:-/tmp}/openclaw-mac-node.log"
RECONNECT_DELAY=10

resolve_url() {
  node -e '
    const fs = require("node:fs");
    let cfg = {};
    try { cfg = JSON.parse(fs.readFileSync(process.env.HOME + "/.openclaw/openclaw.json", "utf8")); } catch {}
    const url = cfg && cfg.gateway && cfg.gateway.remote && cfg.gateway.remote.url;
    if (url && String(url).trim()) {
      // gateway.remote.url already includes the WS path (e.g. /gateway); use it verbatim.
      process.stdout.write(String(url).trim());
      process.exit(0);
    }
    process.stdout.write("ws://127.0.0.1:18789/gateway");
  ' 2>/dev/null
}

resolve_token() {
  node -e '
    const fs = require("node:fs");
    let cfg = {};
    try { cfg = JSON.parse(fs.readFileSync(process.env.HOME + "/.openclaw/openclaw.json", "utf8")); } catch {}
    const t = cfg && cfg.gateway && cfg.gateway.remote && cfg.gateway.remote.token;
    process.stdout.write(t && String(t).trim() ? String(t).trim() : "");
  ' 2>/dev/null
}

is_running() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

cmd_start() {
  if is_running; then
    echo "macOS node already running (pid $(cat "$PID_FILE"))."
    return 0
  fi
  local token url
  token="$(resolve_token)"
  url="$(resolve_url)"
  if [[ -z "$token" ]]; then
    echo "ERROR: could not read gateway token from $CONFIG_JSON" >&2
    exit 1
  fi
  echo "Starting macOS node -> $url"
  URL="$url" TOKEN="$token" LOG="$LOG_FILE" DELAY="$RECONNECT_DELAY" \
    nohup bash -c '
      while true; do
        openclaw-mac connect --role node --client-mode node --scopes node.invoke \
          --url "$URL" --token "$TOKEN" --json >>"$LOG" 2>&1 || true
        sleep "$DELAY"
      done
    ' >/dev/null 2>&1 &
  echo $! > "$PID_FILE"
  disown 2>/dev/null || true
  echo "Started (pid $(cat "$PID_FILE")). Log: $LOG_FILE"
}

cmd_stop() {
  if ! is_running; then
    echo "macOS node is not running."
    return 0
  fi
  local pid
  pid="$(cat "$PID_FILE")"
  kill "$pid" 2>/dev/null || true
  for _ in {1..10}; do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.3
  done
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$PID_FILE"
  echo "Stopped macOS node."
}

cmd_status() {
  if is_running; then
    echo "macOS node: RUNNING (pid $(cat "$PID_FILE"))"
  else
    echo "macOS node: STOPPED"
  fi
  echo "Last connect result:"
  if [[ -f "$LOG_FILE" ]]; then
    grep -E '"status"' "$LOG_FILE" | tail -1 || echo "  (no results yet)"
    echo "  full log: $LOG_FILE"
  else
    echo "  (no log yet)"
  fi
}

case "${1:-}" in
  --start)  cmd_start ;;
  --stop)   cmd_stop ;;
  --status) cmd_status ;;
  -h|--help)
    echo "Usage: $(basename "$0") [--start|--stop|--status]"
    ;;
  *)
    echo "Usage: $(basename "$0") [--start|--stop|--status]" >&2
    exit 1
    ;;
esac
