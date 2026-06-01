/**
 * In-memory sliding-window rate limiter for HTTP request endpoints.
 *
 * Tracks request counts by client IP to prevent abuse of REST API endpoints.
 * Designed as a defense-in-depth layer alongside connection-level and
 * auth-level rate limiters.
 *
 * Design mirrors {@link ConnectionRateLimiter} and {@link AuthRateLimiter}
 * for consistency with the existing gateway rate-limiting architecture.
 */

import { isLoopbackAddress, resolveClientIp } from "./net-helpers.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RequestRateLimitConfig {
  /** Maximum requests per window per IP.  @default 120 */
  maxRequests?: number;
  /** Sliding window duration in milliseconds.  @default 60_000 (1 min) */
  windowMs?: number;
  /** Exempt loopback (localhost) addresses.  @default true */
  exemptLoopback?: boolean;
  /** Maximum non-loopback client IPs tracked at once.  @default 10_000 */
  maxEntries?: number;
  /** Background prune interval in milliseconds; set <= 0 to disable auto-prune.  @default 30_000 */
  pruneIntervalMs?: number;
}

export interface RequestRateLimitCheckResult {
  /** Whether the request is allowed to proceed. */
  allowed: boolean;
  /** Remaining requests in the current window. */
  remaining: number;
  /** Milliseconds until the lockout expires (0 when not locked). */
  retryAfterMs: number;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_REQUESTS = 120;
const DEFAULT_WINDOW_MS = 60_000; // 1 minute
const DEFAULT_MAX_ENTRIES = 10_000;
const PRUNE_INTERVAL_MS = 30_000;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function createRequestRateLimiter(config?: RequestRateLimitConfig) {
  const maxRequests = normalizePositiveInteger(config?.maxRequests, DEFAULT_MAX_REQUESTS);
  const windowMs = normalizePositiveInteger(config?.windowMs, DEFAULT_WINDOW_MS);
  const exemptLoopback = config?.exemptLoopback ?? true;
  const maxEntries = normalizePositiveInteger(config?.maxEntries, DEFAULT_MAX_ENTRIES);
  const pruneIntervalMs = config?.pruneIntervalMs ?? PRUNE_INTERVAL_MS;

  interface Entry {
    timestamps: number[];
  }

  function normalizePositiveInteger(value: number | undefined, fallback: number): number {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      return fallback;
    }
    return Math.max(1, Math.floor(value));
  }

  const entries = new Map<string, Entry>();

  const pruneTimer = pruneIntervalMs > 0 ? setInterval(() => prune(), pruneIntervalMs) : null;
  if (pruneTimer?.unref) {
    pruneTimer.unref();
  }

  function normalizeIp(ip: string | undefined): string {
    return resolveClientIp({ remoteAddr: ip }) ?? "unknown";
  }

  function isExempt(ip: string): boolean {
    return exemptLoopback && isLoopbackAddress(ip);
  }

  function slideWindow(entry: Entry, now: number): void {
    const cutoff = now - windowMs;
    entry.timestamps = entry.timestamps.filter((ts) => ts > cutoff);
  }

  function retryAfterForEntry(entry: Entry, now: number): number {
    const oldestTimestamp = entry.timestamps[0];
    if (oldestTimestamp === undefined) {
      return 0;
    }
    return Math.max(0, oldestTimestamp + windowMs - now);
  }

  function retryAfterForFullTable(now: number): number {
    let retryAfterMs: number | undefined;
    for (const entry of entries.values()) {
      const candidate = retryAfterForEntry(entry, now);
      if (candidate <= 0) {
        continue;
      }
      retryAfterMs = retryAfterMs === undefined ? candidate : Math.min(retryAfterMs, candidate);
    }
    return retryAfterMs ?? windowMs;
  }

  function canTrackNewEntry(now: number): boolean {
    if (entries.size < maxEntries) {
      return true;
    }
    prune(now);
    return entries.size < maxEntries;
  }

  function check(ip: string | undefined): RequestRateLimitCheckResult {
    const normalized = normalizeIp(ip);
    if (isExempt(normalized)) {
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    const now = Date.now();
    const entry = entries.get(normalized);

    if (!entry) {
      if (!canTrackNewEntry(now)) {
        return { allowed: false, remaining: 0, retryAfterMs: retryAfterForFullTable(now) };
      }
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    slideWindow(entry, now);
    if (entry.timestamps.length === 0) {
      entries.delete(normalized);
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    const remaining = Math.max(0, maxRequests - entry.timestamps.length);
    if (remaining === 0) {
      return { allowed: false, remaining, retryAfterMs: retryAfterForEntry(entry, now) };
    }
    return { allowed: true, remaining, retryAfterMs: 0 };
  }

  function recordRequest(ip: string | undefined): void {
    const normalized = normalizeIp(ip);
    if (isExempt(normalized)) {
      return;
    }

    const now = Date.now();
    let entry = entries.get(normalized);

    if (!entry) {
      if (!canTrackNewEntry(now)) {
        return;
      }
      entry = { timestamps: [] };
      entries.set(normalized, entry);
    }

    slideWindow(entry, now);
    entry.timestamps.push(now);
    if (entry.timestamps.length > maxRequests) {
      entry.timestamps = entry.timestamps.slice(-maxRequests);
    }
  }

  function prune(now = Date.now()): void {
    for (const [key, entry] of entries) {
      slideWindow(entry, now);
      if (entry.timestamps.length === 0) {
        entries.delete(key);
      }
    }
  }

  function dispose(): void {
    if (pruneTimer) {
      clearInterval(pruneTimer);
    }
    entries.clear();
  }

  function size(): number {
    return entries.size;
  }

  return { check, recordRequest, prune, dispose, size };
}

export type RequestRateLimiter = ReturnType<typeof createRequestRateLimiter>;
