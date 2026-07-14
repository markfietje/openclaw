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

# Extract the container's IPv4 subnet CIDR (e.g. 192.168.64.0/24) from
# `container inspect <name>` JSON. Returns empty on any error.
#
# Apple Container's `container inspect` nests runtime networks under
# `.status.networks` (NOT top-level `.networks`). Reading the wrong path
# silently returns empty, which made sync_trusted_proxies no-op and left
# stale subnets in openclaw.json — breaking browser WS upgrades (1006)
# because the vmnet NAT gateway fell outside trustedProxies.
#
# Empty output is normal (container stopped, no networks) so this parser
# does not warn.
parse_container_gateway_cidr() {
  local name="${1:-}"
  [[ -z "$name" ]] && return 0
  container inspect "$name" 2>/dev/null | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const arr = JSON.parse(d);
    // Runtime networks live under .status.networks in the Apple Container
    // inspect schema. Fall back to the legacy top-level path for safety.
    const nets = arr && arr[0] && (arr[0].status?.networks || arr[0].networks);
    if (Array.isArray(nets) && nets.length > 0 && nets[0].ipv4Address) {
      const addr = nets[0].ipv4Address;
      const parts = addr.split(".");
      const mask = addr.split("/")[1] || "24";
      if (parts.length >= 3) process.stdout.write(parts[0] + "." + parts[1] + "." + parts[2] + ".0/" + mask);
    }
  } catch {}
});
' 2>/dev/null || true
}

# Extract the network's IPv4 subnet CIDR (e.g. 192.168.64.0/24) directly from
# `container network inspect <name>` JSON. This is the AUTHORITATIVE subnet
# source: it is fixed at `container network create` time and does not depend
# on any running container. Preferred over parse_container_gateway_cidr for
# trustedProxies sync because it is stable across container rebuilds/restarts.
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

# Extract the gateway token from an openclaw-gateway-token-resolver JSON-RPC
# response (e.g. setup.sh's read_legacy_encrypted_gateway_token migration).
# Reads the response on stdin, prints the decrypted token to stdout, returns
# empty on any parse failure. Warns once on schema drop so silent failures
# from a `gateway_token_resolver` API change are loud.
parse_openclaw_jsonrpc_token() {
  local raw parsed
  raw="$(cat 2>/dev/null || true)"
  parsed="$(printf '%s' "$raw" | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const p = JSON.parse(d);
    const v = p && p.values && p.values["gateway/token"];
    if (typeof v === "string" && v.trim()) process.stdout.write(v.trim());
  } catch {}
});
' 2>/dev/null || true)"
  _parser_warn_on_drop "parse_openclaw_jsonrpc_token" "$raw" "$parsed"
  printf '%s' "$parsed"
}

# Read the gateway token from macOS Keychain via `/usr/bin/security`.
# - On success, prints the token to stdout.
# - On failure, prints nothing. Callers should check `[[ -n "$token" ]]`.
# Args: <service> <account>
read_keychain_token() {
  local service="${1:-}" account="${2:-${USER:-openclaw}}"
  if [[ -z "$service" ]]; then return 0; fi
  /usr/bin/security find-generic-password \
    -a "$account" -s "$service" -w 2>/dev/null || true
}

# Check if a Keychain item exists (without printing the secret).
# Args: <service> <account>
# Returns 0 if the item exists, 1 otherwise.
keychain_token_exists() {
  local service="${1:-}" account="${2:-${USER:-openclaw}}"
  if [[ -z "$service" ]]; then return 1; fi
  /usr/bin/security find-generic-password \
    -a "$account" -s "$service" -w >/dev/null 2>&1
}
