/**
 * Canonical network address helpers used by the gateway.
 *
 * These helpers live in the package so both the gateway (`src/gateway/`) and
 * any cross-package consumer can share the same client-IP resolution
 * semantics. The gateway re-exports from here for back-compat with the rest
 * of `src/gateway/`. Cross-package `net-helpers.ts` is now deleted — this
 * file is the single source of truth.
 */
import type { IncomingMessage } from "node:http";
import net from "node:net";
import { isIpInCidr, isLoopbackIpAddress, normalizeIpAddress } from "@openclaw/net-policy/ip";

function normalizeIp(ip: string | undefined): string | undefined {
  return normalizeIpAddress(ip);
}

function stripOptionalPort(ip: string): string {
  if (ip.startsWith("[")) {
    const end = ip.indexOf("]");
    if (end !== -1) {
      return ip.slice(1, end);
    }
  }
  if (net.isIP(ip)) {
    return ip;
  }
  const lastColon = ip.lastIndexOf(":");
  if (lastColon > -1 && ip.includes(".") && ip.indexOf(":") === lastColon) {
    const candidate = ip.slice(0, lastColon);
    if (net.isIP(candidate) === 4) {
      return candidate;
    }
  }
  return ip;
}

function parseIpLiteral(raw: string | undefined): string | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) {
    return undefined;
  }
  const stripped = stripOptionalPort(trimmed);
  const normalized = normalizeIp(stripped);
  if (!normalized || net.isIP(normalized) === 0) {
    return undefined;
  }
  return normalized;
}

function parseRealIp(realIp?: string): string | undefined {
  return parseIpLiteral(realIp);
}

export function isLoopbackAddress(ip: string | undefined): boolean {
  return isLoopbackIpAddress(ip);
}

export function isTrustedProxyAddress(ip: string | undefined, trustedProxies?: string[]): boolean {
  const normalized = normalizeIp(ip);
  if (!normalized || !trustedProxies || trustedProxies.length === 0) {
    return false;
  }

  return trustedProxies.some((proxy) => {
    const candidate = proxy.trim();
    if (!candidate) {
      return false;
    }
    return isIpInCidr(normalized, candidate);
  });
}

/**
 * Walk an `X-Forwarded-For` chain right-to-left and return the first
 * untrusted hop. Exported so callers that need to detect contradictions
 * (e.g. header consistency checks) can share the same logic.
 */
export function resolveForwardedClientIp(params: {
  forwardedFor?: string;
  trustedProxies?: string[];
}): string | undefined {
  const { forwardedFor, trustedProxies } = params;
  if (!trustedProxies?.length) {
    return undefined;
  }

  const forwardedChain: string[] = [];
  for (const entry of forwardedFor?.split(",") ?? []) {
    const normalized = parseIpLiteral(entry);
    if (normalized) {
      forwardedChain.push(normalized);
    }
  }
  if (forwardedChain.length === 0) {
    return undefined;
  }

  // Walk right-to-left and return the first untrusted hop.
  for (let index = forwardedChain.length - 1; index >= 0; index -= 1) {
    const hop = forwardedChain[index];
    if (isLoopbackAddress(hop)) {
      continue;
    }
    if (!isTrustedProxyAddress(hop, trustedProxies)) {
      return hop;
    }
  }
  return undefined;
}

/**
 * Parse RFC 7239 `Forwarded` header and extract the client IP from `for=` fields.
 * Self-contained to avoid circular dependency with forwarded-headers.ts.
 */
export function resolveForwardedHeaderClientIp(params: {
  forwarded?: string;
  trustedProxies?: string[];
}): string | undefined {
  if (!params.forwarded || !params.trustedProxies?.length) {
    return undefined;
  }

  const entries: string[] = [];
  for (const segment of params.forwarded.split(/\s*,\s*/)) {
    const forMatch = segment.match(/for=(?:"([^"]+)"|([^;,]+))/i);
    if (forMatch) {
      const ip = parseIpLiteral(forMatch[1] ?? forMatch[2]);
      if (ip) {
        entries.push(ip);
      }
    }
  }

  // Walk right-to-left and return the first untrusted hop.
  for (let i = entries.length - 1; i >= 0; i--) {
    const hop = entries[i];
    if (isLoopbackAddress(hop)) {
      continue;
    }
    if (!isTrustedProxyAddress(hop, params.trustedProxies)) {
      return hop;
    }
  }
  return undefined;
}

export function resolveClientIp(params: {
  remoteAddr?: string;
  forwardedFor?: string;
  forwarded?: string | string[];
  realIp?: string;
  trustedProxies?: string[];
  /** Default false: only trust X-Real-IP when explicitly enabled. */
  allowRealIpFallback?: boolean;
}): string | undefined {
  const remote = normalizeIp(params.remoteAddr);
  if (!remote) {
    return undefined;
  }
  if (!isTrustedProxyAddress(remote, params.trustedProxies)) {
    return remote;
  }
  // Fail closed when traffic comes from a trusted proxy but client-origin headers
  // are missing or invalid. Falling back to the proxy's own IP can accidentally
  // treat unrelated requests as local/trusted.

  // Try RFC 7239 Forwarded header first (standard takes precedence over X-Forwarded-For).
  const forwardedRaw =
    typeof params.forwarded === "string"
      ? params.forwarded
      : Array.isArray(params.forwarded)
        ? params.forwarded[0]
        : undefined;
  const rfcForwardedIp = resolveForwardedHeaderClientIp({
    forwarded: forwardedRaw,
    trustedProxies: params.trustedProxies,
  });
  if (rfcForwardedIp) {
    return rfcForwardedIp;
  }

  const forwardedIp = resolveForwardedClientIp({
    forwardedFor: params.forwardedFor,
    trustedProxies: params.trustedProxies,
  });
  if (forwardedIp) {
    return forwardedIp;
  }
  if (params.allowRealIpFallback) {
    return parseRealIp(params.realIp);
  }
  // Loopback fallback: when all proxy header resolution fails but the remote
  // address is loopback, the connection is direct (no proxy). Loopback is
  // non-spoofable — only local processes can originate from it — so it is safe
  // to treat the remote address as the client IP. This prevents direct CLI/TUI
  // connections from being misclassified as broken proxy connections when
  // loopback is also listed in trustedProxies (common when Tailscale Serve
  // proxies from the same loopback address).
  if (isLoopbackAddress(remote)) {
    return remote;
  }
  return undefined;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

export function resolveRequestClientIp(
  req?: IncomingMessage,
  trustedProxies?: string[],
  allowRealIpFallback = false,
): string | undefined {
  if (!req) {
    return undefined;
  }
  return resolveClientIp({
    remoteAddr: req.socket?.remoteAddress ?? "",
    forwardedFor: headerValue(req.headers?.["x-forwarded-for"]),
    forwarded: req.headers?.["forwarded"],
    realIp: headerValue(req.headers?.["x-real-ip"]),
    trustedProxies,
    allowRealIpFallback,
  });
}
