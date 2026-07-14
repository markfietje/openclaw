import { isTrustedProxyAddress } from "./net.js";

// Client-IP resolution for proxy headers, walking right-to-left for the first
// untrusted hop. net.ts resolves the effective client IP but not the per-header
// value needed for header-consistency checks, so these stay local.
function firstUntrustedHop(ips: string[], trustedProxies?: string[]): string | undefined {
  for (let i = ips.length - 1; i >= 0; i -= 1) {
    if (!isTrustedProxyAddress(ips[i], trustedProxies)) {
      return ips[i];
    }
  }
  return undefined;
}

function forwardedForClientIp(forwardedFor: string, trustedProxies?: string[]): string | undefined {
  const ips = forwardedFor
    .split(",")
    .map(
      (entry) =>
        entry
          .trim()
          .replace(/^\[|\]$/g, "")
          .split(":")[0],
    )
    .filter(Boolean);
  return firstUntrustedHop(ips, trustedProxies);
}

function resolveForwardedHeaderClientIp(params: {
  forwarded?: string;
  trustedProxies?: string[];
}): string | undefined {
  if (!params.forwarded || !params.trustedProxies?.length) {
    return undefined;
  }
  const ips: string[] = [];
  for (const segment of params.forwarded.split(/\s*,\s*/)) {
    const forMatch = segment.match(/for=(?:"([^"]+)"|([^;,]+))/i);
    if (!forMatch) {
      continue;
    }
    const ip = (forMatch[1] ?? forMatch[2]).replace(/^\[|\]$/g, "").split(":")[0];
    if (ip) {
      ips.push(ip);
    }
  }
  return firstUntrustedHop(ips, params.trustedProxies);
}

export interface ForwardedHeader {
  for?: string;
  by?: string;
  host?: string;
  proto?: string;
}

/**
 * Headers a reverse proxy may set that influence trust/session decisions.
 * When present more than once or comma-chained, the request is malformed or
 * an attempt to smuggle a second value past the proxy.
 */
const SENSITIVE_HEADERS = new Set([
  "host",
  "origin",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-forwarded-for",
  "x-real-ip",
  "forwarded",
]);

function headerValue(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

type StrictHeaderParseResult =
  | { ok: true; value: string }
  | { ok: false; reason: "duplicate" | "chain-not-allowed" | "missing" };

function strictHeader(value: string | string[] | undefined): StrictHeaderParseResult {
  if (value === undefined || value === "") {
    return { ok: false, reason: "missing" };
  }
  if (Array.isArray(value)) {
    if (value.length !== 1) {
      return { ok: false, reason: "duplicate" };
    }
    const single = value[0];
    if (typeof single !== "string" || !single) {
      return { ok: false, reason: "missing" };
    }
    if (single.includes(",")) {
      return { ok: false, reason: "chain-not-allowed" };
    }
    return { ok: true, value: single.trim() };
  }
  if (typeof value !== "string" || !value) {
    return { ok: false, reason: "missing" };
  }
  if (value.includes(",")) {
    return { ok: false, reason: "chain-not-allowed" };
  }
  return { ok: true, value: value.trim() };
}

/**
 * Rejects requests that send sensitive proxy headers more than once or
 * comma-chained. Off by default; enable with `gateway.security.strictHeaderValidation`.
 */
export function validateSensitiveHeaders(
  headers: Record<string, string | string[] | undefined>,
): { ok: false; header: string; reason: string } | { ok: true } {
  for (const headerName of SENSITIVE_HEADERS) {
    const value = headers[headerName];
    if (value === undefined) {
      continue;
    }
    const result = strictHeader(value);
    if (!result.ok) {
      return { ok: false, header: headerName, reason: result.reason };
    }
  }
  return { ok: true };
}

export { SENSITIVE_HEADERS };

export function validateProtoMismatch(params: {
  originProto: string;
  forwardedProto?: string;
  xForwardedProto?: string | string[];
}): { ok: true } | { ok: false; reason: string } {
  const { originProto, forwardedProto, xForwardedProto } = params;

  const originNormalized = originProto.toLowerCase();

  if (forwardedProto) {
    const forwardedNormalized = forwardedProto.toLowerCase();
    if (originNormalized !== forwardedNormalized) {
      return {
        ok: false,
        reason: `origin protocol (${originProto}) does not match Forwarded proto (${forwardedProto})`,
      };
    }
  }

  if (xForwardedProto) {
    const raw = Array.isArray(xForwardedProto) ? xForwardedProto[0] : xForwardedProto;
    if (raw) {
      const xNormalized = raw.trim().toLowerCase();
      if (originNormalized !== xNormalized) {
        return {
          ok: false,
          reason: `origin protocol (${originProto}) does not match X-Forwarded-Proto (${raw})`,
        };
      }
    }
  }

  return { ok: true };
}

/**
 * Detect contradictions between `X-Forwarded-For` and `Forwarded` headers.
 * When both are present, resolve the rightmost untrusted hop from each and
 * verify they agree. Call after `validateSensitiveHeaders` to catch header
 * contradiction attacks where a client forges one proxy header to disagree
 * with the other.
 */
export function validateForwardedHeaderConsistency(
  headers: Record<string, string | string[] | undefined>,
  trustedProxies?: string[],
): { ok: true } | { ok: false; reason: string } {
  const xff = headerValue(headers["x-forwarded-for"]);
  const fwd = headerValue(headers["forwarded"]);

  if (!xff || !fwd) {
    return { ok: true };
  }

  const xffIp = forwardedForClientIp(xff, trustedProxies);
  const fwdIp = resolveForwardedHeaderClientIp({ forwarded: fwd, trustedProxies });

  if (xffIp && fwdIp && xffIp !== fwdIp) {
    return {
      ok: false,
      reason: `forwarded header inconsistency: X-Forwarded-For resolves to ${xffIp} but Forwarded resolves to ${fwdIp}`,
    };
  }

  return { ok: true };
}
