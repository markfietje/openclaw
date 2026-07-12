// Browser Origin validator for gateway HTTP and websocket requests.
import { createHmac, timingSafeEqual } from "node:crypto";
import net from "node:net";
import { isPrivateOrLoopbackIpAddress } from "@openclaw/net-policy/ip";
import { z } from "zod";
import { validateProtoMismatch, type ForwardedHeader } from "./forwarded-headers.js";
import { isLoopbackHost, normalizeHostHeader, resolveHostName } from "./net.js";
import { MapGauge } from "./server/lifecycle/map-gauge.js";

// OWASP LLM02 — Insecure Output Handling. Validate signed token payload with
// Zod schema before accessing properties to prevent malformed data attacks.
const SignedTokenPayloadSchema = z.object({
  sub: z.string().min(1),
  origin: z.string().min(1),
  iat: z.number().int().positive(),
  exp: z.number().int().positive().optional(),
  nonce: z.string().min(1),
});

export interface SignedTokenPayload {
  sub: string;
  origin: string;
  iat: number;
  exp: number;
  nonce: string;
}

export type SignedTokenVerificationResult =
  | { ok: true; user: string }
  | { ok: false; reason: string };

const SIGNED_TOKEN_MAX_AGE_MS = 5 * 60 * 1000;

// Replay defense for signed origin tokens: a captured token is otherwise
// reusable for up to SIGNED_TOKEN_MAX_AGE_MS. Track seen nonces (mapped to their
// exp deadline) in a bounded, self-pruning cache. This is transient
// per-process security state (not app state), so an in-process map is correct;
// it does not need to survive restarts and is not a SQLite concern.
const NONCE_CACHE_MAX_ENTRIES = 4096;
const seenNonces = new MapGauge<string, number>(NONCE_CACHE_MAX_ENTRIES, {
  label: "signedOriginTokenNonces",
});

// Drop expired nonces and enforce the bounded cap. Called on each verify so the
// cache cannot grow unbounded between requests. MapGauge already evicts the
// oldest entry on overflow; this pass also drops entries whose token has
// expired so a nonce frees up as soon as it can no longer be replayed.
function pruneExpiredNonces(now: number): void {
  for (const [nonce, expMs] of seenNonces) {
    if (expMs <= now) {
      seenNonces.delete(nonce);
    }
  }
}

export function verifySignedOriginToken(
  token: string,
  sharedSecret: string,
  expectedOrigin: string,
): SignedTokenVerificationResult {
  if (!token || !sharedSecret) {
    return { ok: false, reason: "missing token or secret" };
  }

  try {
    const parts = token.split(".");
    if (parts.length !== 2) {
      return { ok: false, reason: "invalid token format" };
    }

    const [payloadB64, sigB64] = parts;

    const expectedSig = createHmac("sha256", sharedSecret).update(payloadB64).digest("base64url");

    const sigBuf = Buffer.from(sigB64, "base64url");
    const expectedBuf = Buffer.from(expectedSig, "base64url");
    if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
      return { ok: false, reason: "invalid signature" };
    }

    // Parse and validate payload structure before accessing properties
    const rawPayload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    const parseResult = SignedTokenPayloadSchema.safeParse(rawPayload);
    if (!parseResult.success) {
      return { ok: false, reason: "invalid token payload structure" };
    }
    const payload = parseResult.data;

    if (payload.origin.toLowerCase() !== expectedOrigin.toLowerCase()) {
      return { ok: false, reason: "origin mismatch" };
    }

    const now = Date.now();
    const iatMs = payload.iat * 1000;
    if (iatMs > now + 30000 || iatMs < now - SIGNED_TOKEN_MAX_AGE_MS) {
      return { ok: false, reason: "token expired or not yet valid" };
    }

    if (payload.exp && payload.exp * 1000 < now) {
      return { ok: false, reason: "token expired" };
    }

    // Replay defense: signature, origin, and iat/exp have all passed, so the
    // token is otherwise valid. Reject if this nonce was already accepted
    // within its validity window; otherwise record it bound to its exp.
    // Pruning first keeps the cache bounded and reclaims slots from tokens
    // that can no longer be replayed.
    pruneExpiredNonces(now);
    const expMs = (payload.exp ?? Math.floor(now / 1000) + SIGNED_TOKEN_MAX_AGE_MS / 1000) * 1000;
    if (seenNonces.has(payload.nonce)) {
      return { ok: false, reason: "nonce replayed" };
    }
    seenNonces.set(payload.nonce, expMs);

    return { ok: true, user: payload.sub };
  } catch {
    return { ok: false, reason: "token verification failed" };
  }
}

// Test-only hook: reset the replay cache between deterministic nonce tests.
export const __testing = {
  resetNonceCache(): void {
    seenNonces.clear();
  },
  nonceCacheSize(): number {
    return seenNonces.size;
  },
};

type OriginCheckResult =
  | {
      ok: true;
      matchedBy: "allowlist" | "host-header-fallback" | "private-same-origin" | "local-loopback";
    }
  | { ok: false; reason: string };

type OriginCheckParams = {
  requestHost?: string;
  requestForwardedHost?: string;
  requestForwardedProto?: string;
  origin?: string;
  allowedOrigins?: string[];
  allowHostHeaderOriginFallback?: boolean;
  isLocalClient?: boolean;
  isTrustedProxy?: boolean;
  forwardedHeader?: string | string[];
  strictProtoValidation?: boolean;
  disableLocalhostPrivilege?: boolean;
  validateHostHeader?: boolean;
  secFetchSite?: string;
  /** Allow wildcard "*" origin when local or behind trusted proxy. OWASP A01:2025. */
  allowWildcardOrigin?: boolean;
};

function normalizeOriginToMatchUrlHost(origin: string): string | null {
  try {
    const url = new URL(origin);
    const normalizedHost = normalizeHostToMatchUrlHost(url.host);
    if (!normalizedHost) {
      return null;
    }
    return `${url.protocol.replace(":", "")}://${normalizedHost}`.toLowerCase();
  } catch {
    return null;
  }
}

// Custom schemes that new URL() rejects (tauri://, electron://, etc.).
// OWASP A01:2025 — allow known app origins without accepting arbitrary schemes.
const ALLOWED_CUSTOM_SCHEMES = new Set([
  "tauri",
  "electron",
  "capacitor",
  "ionic",
]) as ReadonlySet<string>;

function parseOrigin(
  originRaw?: string,
): { origin: string; host: string; hostname: string; protocol: string } | null {
  const trimmed = (originRaw ?? "").trim();
  if (!trimmed || trimmed === "null") {
    return null;
  }
  // Support custom schemes that new URL() rejects (tauri://, electron://, etc.)
  const schemeMatch = trimmed.match(/^([a-z][a-z0-9.+-]*):\/\/(.+)$/i);
  if (schemeMatch) {
    const scheme = schemeMatch[1]!.toLowerCase();
    const rest = schemeMatch[2]!.toLowerCase();
    if (ALLOWED_CUSTOM_SCHEMES.has(scheme)) {
      return {
        origin: trimmed.toLowerCase(),
        host: rest,
        hostname: rest.split("/")[0] ?? rest,
        protocol: scheme,
      };
    }
  }
  // URL parsing collapses dot segments. Reject non-origin suffixes before
  // canonicalization so a path cannot inherit its authority's grant.
  if (!/^[a-z][a-z0-9+.-]*:\/\/[^/?#\\]+\/?$/i.test(trimmed)) {
    return null;
  }
  try {
    const url = new URL(trimmed);
    if (url.username || url.password || !url.protocol || !url.host) {
      return null;
    }
    // Hosted app schemes have an opaque URL.origin but a stable authority.
    const origin = url.origin === "null" ? `${url.protocol}//${url.host}` : url.origin;
    return {
      origin: url.origin.toLowerCase(),
      host: url.host.toLowerCase(),
      hostname: url.hostname.toLowerCase(),
      protocol: url.protocol.replace(":", "").toLowerCase(),
    };
  } catch {
    return null;
  }
}

function normalizeHostToMatchUrlHost(host: string | undefined): string | undefined {
  const normalized = normalizeHostHeader(host);
  if (!normalized) {
    return undefined;
  }
  // If it looks like a host:port without scheme, don't use URL parsing
  // (new URL("gateway.tailnet.ts.net:443") treats hostname as scheme, returning empty host)
  // Instead, strip default HTTPS port (:443) directly.
  // Also handle IPv6 with port (e.g. "[::1]:443") — the regex won't match it
  // (starts with '['), so handle it explicitly before the regex check.
  if (normalized.startsWith("[")) {
    const closeBracket = normalized.indexOf("]");
    if (closeBracket > 0) {
      const rest = normalized.slice(closeBracket + 1);
      // IPv6 address with optional port: strip default ports (:443/:80)
      if (/^:\d+$/.test(rest)) {
        return normalized.replace(/:(443|80)$/, "").toLowerCase();
      }
      // IPv6 without port — strip brackets to match URL.host behavior
      return normalized.slice(1, closeBracket).toLowerCase();
    }
  }
  if (!normalized.includes("://") && /^[a-zA-Z0-9.-]+:\d+$/.test(normalized)) {
    // Strip default ports (:443 for HTTPS, :80 for HTTP) to match URL.host behavior
    return normalized.replace(/:(443|80)$/, "").toLowerCase();
  }
  // Use URL parsing for full URLs with scheme
  try {
    const url = new URL(normalized);
    return url.host.toLowerCase();
  } catch {
    // Fallback: just return the normalized value
    return normalized.toLowerCase();
  }
}

/** Validate a browser Origin against explicit allowlist, same-host, and local dev rules. */
export function checkBrowserOrigin(params: OriginCheckParams): OriginCheckResult {
  const parsedOrigin = parseOrigin(params.origin);
  if (!parsedOrigin) {
    return { ok: false, reason: "origin missing or invalid" };
  }

  // Security: Reject cross-site requests via Fetch Metadata (OWASP defense-in-depth).
  // Browsers set Sec-Fetch-Site to "cross-site" for cross-origin navigations.
  // Non-browser clients typically omit this header entirely.
  if (params.secFetchSite) {
    const fetchSite = params.secFetchSite.trim().toLowerCase();
    if (fetchSite === "cross-site") {
      return { ok: false, reason: "cross-site request rejected" };
    }
  }

  const allowlistOrigins = (params.allowedOrigins ?? [])
    .map((value) => value.trim().toLowerCase())
    .filter(Boolean);

  const allowlist = new Set(allowlistOrigins);

  const normalizedOrigin = normalizeOriginToMatchUrlHost(parsedOrigin.origin);
  const normalizedAllowlistOrigins = allowlistOrigins
    .map((o) => normalizeOriginToMatchUrlHost(o))
    .filter((o): o is string => o !== null);
  const normalizedAllowlist = new Set(normalizedAllowlistOrigins);

  const requestForwardedHost = normalizeHostToMatchUrlHost(params.requestForwardedHost);

  // Security: If forwarded-host is present but proxy is NOT trusted, reject outright.
  // This prevents attackers from bypassing checks by spoofing X-Forwarded-Host.
  if (requestForwardedHost && params.isTrustedProxy !== true) {
    return { ok: false, reason: "origin not allowed" };
  }

  // Security: When behind a trusted proxy, validate protocol BEFORE allowlist check.
  // Even allowlisted origins must have matching protocol to prevent SSL stripping attacks.
  if (params.isTrustedProxy === true && params.strictProtoValidation !== false) {
    const forwardedProto = extractProtoFromForwardedHeader(params.forwardedHeader);
    const protoValidation = validateProtoMismatch({
      originProto: parsedOrigin.protocol,
      forwardedProto,
      xForwardedProto: params.requestForwardedProto,
    });
    if (!protoValidation.ok) {
      return protoValidation;
    }
  }

  // OWASP A01:2025 — wildcards are dangerous on public endpoints.
  // Allow only when all three conditions are met:
  //   1. Explicitly enabled via allowWildcardOrigin config
  //   2. Request is local/private OR behind a trusted proxy
  //   3. Not a cross-site request (already checked above)
  if (allowlist.has("*")) {
    if (params.allowWildcardOrigin !== true) {
      return {
        ok: false,
        reason: "wildcard origin allowlist rejected (enable allowWildcardOrigin)",
      };
    }
    if (!params.isLocalClient && params.isTrustedProxy !== true) {
      return { ok: false, reason: "wildcard origin rejected on public connection" };
    }
    return { ok: true, matchedBy: "allowlist" };
  }
  const isInAllowlist =
    allowlist.has(parsedOrigin.origin) ||
    (normalizedOrigin && normalizedAllowlist.has(normalizedOrigin));

  if (isInAllowlist) {
    const validateHostHeader = params.validateHostHeader === true;
    if (validateHostHeader && parsedOrigin.origin && params.requestHost) {
      const hostNormalized = normalizeHostToMatchUrlHost(params.requestHost);
      if (hostNormalized && hostNormalized !== parsedOrigin.host) {
        const normalizedHostOrigin = `https://${hostNormalized}`;
        const hostInAllowlist =
          normalizedAllowlist.has(normalizedHostOrigin) ||
          allowlist.has(`https://${hostNormalized}`);
        if (!hostInAllowlist) {
          return {
            ok: false,
            reason: "host header does not match origin or allowlist",
          };
        }
      }
    }
    return { ok: true, matchedBy: "allowlist" };
  }

  if (params.isTrustedProxy === true) {
    if (requestForwardedHost && parsedOrigin.host !== requestForwardedHost) {
      return { ok: false, reason: "origin does not match forwarded host" };
    }

    if (params.allowHostHeaderOriginFallback === true) {
      // When a trusted proxy is present but X-Forwarded-Host is absent,
      // still validate that the origin matches the direct request host.
      // Without this check, any Origin header would be accepted.
      const directHost = normalizeHostToMatchUrlHost(params.requestHost);
      if (!requestForwardedHost && parsedOrigin.host !== directHost) {
        return {
          ok: false,
          reason: "origin does not match request host in trusted-proxy fallback",
        };
      }
      return {
        ok: true,
        matchedBy: "host-header-fallback",
      };
    }
  }

  const directRequestHost = normalizeHostToMatchUrlHost(params.requestHost);
  if (params.allowHostHeaderOriginFallback === true && parsedOrigin.host === directRequestHost) {
    return {
      ok: true,
      matchedBy: "host-header-fallback",
    };
  }

  if (
    directRequestHost &&
    parsedOrigin.host === directRequestHost &&
    isTrustedSameOriginHost(
      directRequestHost,
      params.isLocalClient,
      params.disableLocalhostPrivilege === true,
    )
  ) {
    return { ok: true, matchedBy: "private-same-origin" };
  }

  if (
    params.disableLocalhostPrivilege !== true &&
    params.isLocalClient &&
    isLoopbackHost(parsedOrigin.hostname)
  ) {
    return { ok: true, matchedBy: "local-loopback" };
  }

  return { ok: false, reason: "origin not allowed" };
}

function isTrustedSameOriginHost(
  hostHeader: string,
  isLocalClient?: boolean,
  disableLocalhostPrivilege?: boolean,
): boolean {
  const hostname = resolveHostName(hostHeader);
  if (!hostname) {
    return false;
  }
  if (isLoopbackHost(hostname)) {
    return disableLocalhostPrivilege !== true && isLocalClient !== false;
  }
  if (net.isIP(hostname) !== 0) {
    return isPrivateOrLoopbackIpAddress(hostname);
  }
  return hostname.endsWith(".local") || hostname.endsWith(".ts.net");
}

function extractProtoFromForwardedHeader(
  header: string | string[] | undefined,
): string | undefined {
  if (!header) {
    return undefined;
  }

  const entries = parseForwardedHeaderForProto(header);
  const firstEntry = entries[0];
  return firstEntry?.proto;
}

function parseForwardedHeaderForProto(header: string | string[] | undefined): ForwardedHeader[] {
  const raw = Array.isArray(header) ? header.join(",") : header;
  if (!raw || typeof raw !== "string") {
    return [];
  }

  const entries: ForwardedHeader[] = [];
  const segments = raw.split(/\s*;\s*(?=[a-z]+=)/i);

  for (const segment of segments) {
    const entry: ForwardedHeader = {};
    const regex = /([a-z]+)=(?:"([^"]+)"|([^;,]+))/gi;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(segment)) !== null) {
      const key = match[1].toLowerCase();
      const value = match[2] ?? match[3];

      if (key === "proto") {
        entry.proto = value?.trim().toLowerCase();
      }
    }

    if (entry.proto) {
      entries.push(entry);
    }
  }

  return entries;
}
