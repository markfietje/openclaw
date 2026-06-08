// Gateway path security canonicalizes repeatedly encoded paths and protects
// plugin HTTP routes even under malformed encoding.
import { normalizeLowercaseStringOrEmpty } from "@openclaw/normalization-core/string-coerce";

type SecurityPathCanonicalization = {
  canonicalPath: string;
  candidates: string[];
  decodePasses: number;
  decodePassLimitReached: boolean;
  malformedEncoding: boolean;
  rawNormalizedPath: string;
};

const MAX_PATH_DECODE_PASSES = 32;
// OWASP A04:2021 — Security Misconfiguration. Maximum path length to prevent
// ReDoS via regex on extremely long paths. Modern regex engines handle simple
// patterns like /{2,}/ well, but this bound prevents edge cases.
const MAX_PATH_LENGTH = 8192;

function normalizePathSeparators(pathname: string): string {
  // Simple regex /{2,}/ is safe from catastrophic backtracking because:
  // 1. It requires at least 2 characters to match
  // 2. No nested quantifiers or alternation
  // 3. No possibility of exponential backtracking
  // The only edge case is extremely long strings, mitigated by MAX_PATH_LENGTH.
  if (pathname.length > MAX_PATH_LENGTH) {
    // Fail closed: truncate to max length. This is safe because we only
    // care about path normalization, not the full content.
    pathname = pathname.slice(0, MAX_PATH_LENGTH);
  }
  const collapsed = pathname.replace(/\/{2,}/g, "/");
  if (collapsed.length <= 1) {
    return collapsed;
  }
  return collapsed.replace(/\/+$/, "");
}

function normalizeProtectedPrefix(prefix: string): string {
  return normalizePathSeparators(normalizeLowercaseStringOrEmpty(prefix)) || "/";
}

function resolveDotSegments(pathname: string): string {
  try {
    return new URL(pathname, "http://localhost").pathname;
  } catch {
    return pathname;
  }
}

function normalizePathForSecurity(pathname: string): string {
  return (
    normalizePathSeparators(normalizeLowercaseStringOrEmpty(resolveDotSegments(pathname))) || "/"
  );
}

function pushNormalizedCandidate(candidates: string[], seen: Set<string>, value: string): void {
  const normalized = normalizePathForSecurity(value);
  if (seen.has(normalized)) {
    return;
  }
  seen.add(normalized);
  candidates.push(normalized);
}

export function buildCanonicalPathCandidates(
  pathname: string,
  maxDecodePasses = MAX_PATH_DECODE_PASSES,
): {
  candidates: string[];
  decodePasses: number;
  decodePassLimitReached: boolean;
  malformedEncoding: boolean;
} {
  // OWASP A04:2021 — Security Misconfiguration. Enforce max path length
  // before any processing to prevent memory exhaustion attacks.
  const truncatedPath =
    pathname.length > MAX_PATH_LENGTH ? pathname.slice(0, MAX_PATH_LENGTH) : pathname;
  const candidates: string[] = [];
  const seen = new Set<string>();
  pushNormalizedCandidate(candidates, seen, truncatedPath);

  let decoded = truncatedPath;
  let malformedEncoding = false;
  let decodePasses = 0;
  for (let pass = 0; pass < maxDecodePasses; pass++) {
    let nextDecoded;
    try {
      nextDecoded = decodeURIComponent(decoded);
    } catch {
      malformedEncoding = true;
      break;
    }
    if (nextDecoded === decoded) {
      break;
    }
    // OWASP A04:2021 — Security Misconfiguration. Truncate decoded result
    // to prevent memory exhaustion from deeply encoded paths.
    if (nextDecoded.length > MAX_PATH_LENGTH) {
      malformedEncoding = true;
      break;
    }
    decodePasses += 1;
    decoded = nextDecoded;
    pushNormalizedCandidate(candidates, seen, decoded);
  }
  let decodePassLimitReached = false;
  if (!malformedEncoding) {
    try {
      decodePassLimitReached = decodeURIComponent(decoded) !== decoded;
    } catch {
      malformedEncoding = true;
    }
  }
  return {
    candidates,
    decodePasses,
    decodePassLimitReached,
    malformedEncoding,
  };
}

export function canonicalizePathVariant(pathname: string): string {
  const { candidates } = buildCanonicalPathCandidates(pathname);
  return candidates[candidates.length - 1] ?? "/";
}

function prefixMatch(pathname: string, prefix: string): boolean {
  return (
    pathname === prefix ||
    pathname.startsWith(`${prefix}/`) ||
    // Fail closed when malformed %-encoding follows the protected prefix.
    pathname.startsWith(`${prefix}%`)
  );
}

export function canonicalizePathForSecurity(pathname: string): SecurityPathCanonicalization {
  const { candidates, decodePasses, decodePassLimitReached, malformedEncoding } =
    buildCanonicalPathCandidates(pathname);

  return {
    canonicalPath: candidates[candidates.length - 1] ?? "/",
    candidates,
    decodePasses,
    decodePassLimitReached,
    malformedEncoding,
    rawNormalizedPath: normalizePathSeparators(normalizeLowercaseStringOrEmpty(pathname)) || "/",
  };
}

const normalizedPrefixesCache = new WeakMap<readonly string[], readonly string[]>();

function getNormalizedPrefixes(prefixes: readonly string[]): readonly string[] {
  const cached = normalizedPrefixesCache.get(prefixes);
  if (cached) {
    return cached;
  }
  const normalized = prefixes.map(normalizeProtectedPrefix);
  normalizedPrefixesCache.set(prefixes, normalized);
  return normalized;
}

export function isPathProtectedByPrefixes(pathname: string, prefixes: readonly string[]): boolean {
  const canonical = canonicalizePathForSecurity(pathname);
  const normalizedPrefixes = getNormalizedPrefixes(prefixes);
  if (
    canonical.candidates.some((candidate) =>
      normalizedPrefixes.some((prefix) => prefixMatch(candidate, prefix)),
    )
  ) {
    return true;
  }
  // Fail closed when canonicalization depth cannot be fully resolved.
  if (canonical.decodePassLimitReached) {
    return true;
  }
  if (!canonical.malformedEncoding) {
    return false;
  }
  return normalizedPrefixes.some((prefix) => prefixMatch(canonical.rawNormalizedPath, prefix));
}

export const PROTECTED_PLUGIN_ROUTE_PREFIXES = ["/api/channels"] as const;

export function isProtectedPluginRoutePath(pathname: string): boolean {
  return isPathProtectedByPrefixes(pathname, PROTECTED_PLUGIN_ROUTE_PREFIXES);
}
