#!/usr/bin/env bash
# OpenClaw Apple Container — shared JSON parsers for container / tailscale CLI output,
# plus a small Keychain helper. Source-only; never executed directly.
# shellcheck shell=bash

# Each parse_* function takes nothing (reads the relevant CLI itself) and
# prints the extracted value (possibly empty) to stdout. Failures are silent
# (return empty) so callers can use `if [[ -n "$(...)" ]]` style checks.

# Read .status from `container system status --format json`.
# Returns "running", "stopped", or "" on parse failure.
parse_container_system_status() {
  container system status --format json 2>/dev/null | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const j = JSON.parse(d);
    if (typeof j.status === "string") process.stdout.write(j.status);
  } catch {}
});
' 2>/dev/null || true
}

# Read .BackendState from `tailscale status --json`.
parse_tailscale_backend_state() {
  tailscale status --json 2>/dev/null | node -e '
let d="";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => d += c);
process.stdin.on("end", () => {
  try {
    const j = JSON.parse(d);
    if (typeof j.BackendState === "string") process.stdout.write(j.BackendState);
  } catch {}
});
' 2>/dev/null || true
}

# Extract the first https?:// origin URL from `tailscale serve status` text.
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

# Extract the container's IPv4 gateway CIDR (e.g. 192.168.64.0/24) from
# `container inspect <name>` JSON. Returns empty on any error.
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
    const nets = arr && arr[0] && arr[0].networks;
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

# Extract the network's IPv4 gateway (e.g. 192.168.64.1) from
# `container network inspect <name>` JSON.
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
