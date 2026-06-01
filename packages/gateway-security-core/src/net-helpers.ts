/**
 * Network helpers used by gateway-security-core rate limiters.
 *
 * Mirrors the loopback / client-IP resolution semantics from `src/gateway/net.ts`
 * so the rate-limit modules can run without depending on the gateway module.
 * Keep this surface small — only the helpers the rate limiters need.
 */
import { isLoopbackIpAddress, isIpInCidr, normalizeIpAddress } from "@openclaw/net-policy/ip";

export function isLoopbackAddress(ip: string | undefined): boolean {
  return isLoopbackIpAddress(ip);
}

function normalizeIp(ip: string | undefined): string | undefined {
  return normalizeIpAddress(ip);
}

function isTrustedProxyAddress(ip: string | undefined, trustedProxies?: string[]): boolean {
  const normalized = normalizeIp(ip);
  if (!normalized || !trustedProxies || trustedProxies.length === 0) {
    return false;
  }
  return trustedProxies.some((proxy) => {
    const candidate = proxy.trim();
    return candidate ? isIpInCidr(normalized, candidate) : false;
  });
}

export function resolveClientIp(params: {
  remoteAddr?: string;
  forwardedFor?: string;
  realIp?: string;
  trustedProxies?: string[];
  allowRealIpFallback?: boolean;
}): string | undefined {
  const remote = normalizeIp(params.remoteAddr);
  if (!remote) {
    return undefined;
  }
  if (!isTrustedProxyAddress(remote, params.trustedProxies)) {
    return remote;
  }
  // Loopback fallback: a loopback remote never carries a spoofed peer; safe
  // to treat it as the client IP. Without this, loopback traffic (e.g. a local
  // CLI behind a Tailscale Serve listener on the same loopback) collapses into
  // a single rate-limit bucket keyed on "unknown".
  if (isLoopbackAddress(remote)) {
    return remote;
  }
  return undefined;
}
