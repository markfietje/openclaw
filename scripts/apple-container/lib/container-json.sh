#!/usr/bin/env bash
# OpenClaw Apple Container — shared JSON parsers for container / tailscale CLI output,
# plus a small Keychain helper. Source-only; never executed directly.
# shellcheck shell=bash

# Each parse_* function takes nothing (reads the relevant CLI itself) and
# prints the extracted value (possibly empty) to stdout. Failures are silent
# (return empty) so callers can use `if [[ -n "$(...)" ]]` style checks.
#
# To catch silent regressions when an upstream CLI changes its JSON schema,
# call `_parser_warn_on_drop <label> <raw> <parsed>` immediately before
# printing `parsed`. A non-empty `raw` with an empty `parsed` is treated as
# a parse failure and emits a one-shot warning to stderr. The "warned once"
# state lives in a per-PID log file so it survives the `$(...)` subshells
# callers typically use.

# Emit a single stderr warning the first time <label> drops its payload.
# Args: <label> <raw> <parsed>
_parser_warn_on_drop() {
  local label="$1" raw="$2" parsed="$3"
  if [[ -z "$raw" || -n "$parsed" ]]; then
    return 0
  fi
  local log="${TMPDIR:-/tmp}/openclaw-apple-container-parser-warn-$$.log"
  if [[ -f "$log" ]] && grep -qx "$label" "$log"; then
    return 0
  fi
  echo "$label" >> "$log"
  echo "WARN: ${label} could not parse CLI output. The container/tailscale schema may have changed; check scripts/apple-container/lib/container-json.sh." >&2
}

# Read .status from `container system status --format json`.
# Returns "running", "stopped", or "" on parse failure.
parse_container_system_status() {
  local raw parsed
  raw="$(container system status --format json 2>/dev/null || true)"
  parsed="$(printf '%s' "$raw" | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const j = JSON.parse(d);
    if (typeof j.status === "string") process.stdout.write(j.status);
  } catch {}
});
' 2>/dev/null || true)"
  _parser_warn_on_drop "parse_container_system_status" "$raw" "$parsed"
  printf '%s' "$parsed"
}

# Read .BackendState from `tailscale status --json`.
parse_tailscale_backend_state() {
  local raw parsed
  raw="$(tailscale status --json 2>/dev/null || true)"
  parsed="$(printf '%s' "$raw" | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const j = JSON.parse(d);
    if (typeof j.BackendState === "string") process.stdout.write(j.BackendState);
  } catch {}
});
' 2>/dev/null || true)"
  _parser_warn_on_drop "parse_tailscale_backend_state" "$raw" "$parsed"
  printf '%s' "$parsed"
}

# Extract the first https?:// origin URL from `tailscale serve status` text.
# Empty output is normal (no serve configured) so this parser does not warn.
parse_tailscale_origin() {
  tailscale serve status 2>/dev/null | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  const lines = d.split("\n");
  for (const line of lines) {
    const m = line.match(/^(https?:\/\/[^\s/]+)/);
    if (m) { process.stdout.write(m[1]); return; }
  }
});
' 2>/dev/null || true
}

# Extract the network's IPv4 subnet CIDR (e.g. 192.168.64.0/24) directly from
# `container network inspect <name>` JSON. This is the AUTHORITATIVE subnet
# source: it is fixed at `container network create` time and does not depend
# on any running container, so it is stable across container rebuilds/restarts.
# Empty output is normal (network missing) so this parser does not warn.
parse_container_network_subnet() {
  local name="${1:-}"
  [[ -z "$name" ]] && return 0
  container network inspect "$name" 2>/dev/null | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const arr = JSON.parse(d);
    const subnet = arr && arr[0] && arr[0].status && arr[0].status.ipv4Subnet;
    if (typeof subnet === "string" && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(subnet)) {
      process.stdout.write(subnet);
    }
  } catch {}
});
' 2>/dev/null || true
}

# Extract the network's IPv4 gateway (e.g. 192.168.64.1) from
# `container network inspect <name>` JSON.
# Empty output is normal (network missing) so this parser does not warn.
parse_container_network_gateway() {
  local name="${1:-}"
  [[ -z "$name" ]] && return 0
  container network inspect "$name" 2>/dev/null | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const arr = JSON.parse(d);
    const gw = arr && arr[0] && arr[0].status && arr[0].status.ipv4Gateway;
    if (typeof gw === "string" && /^[0-9.]+$/.test(gw)) process.stdout.write(gw);
  } catch {}
});
' 2>/dev/null || true
}

# Read the gateway token from the host env file (OPENCLAW_GATEWAY_TOKEN).
# - On success, prints the token to stdout.
# - On failure, prints nothing. Callers should check `[[ -n "$token" ]]`.
# Args: <env_file>
read_gateway_token() {
  local env_file="${1:-}"
  [[ -f "$env_file" ]] || return 0
  local line="" token=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" == OPENCLAW_GATEWAY_TOKEN=* ]]; then
      token="${line#OPENCLAW_GATEWAY_TOKEN=}"
    fi
  done <"$env_file"
  printf '%s' "$token"
}

# Set or replace a KEY=value line in an env file, appending if absent.
# Args: <env_file> <key> <value>
upsert_env_var() {
  local file="$1" key="$2" value="$3" tmp="" dir=""
  dir="$(dirname "$file")"
  tmp="$(mktemp "$dir/.env.tmp.XXXXXX")"
  awk -v k="$key" -v v="$value" '$0 !~ ("^" k "=") { print } END { print k "=" v }' "$file" >"$tmp"
  mv "$tmp" "$file"
}
