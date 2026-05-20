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

import { isLoopbackAddress, resolveClientIp } from "./net.js";

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
const PRUNE_INTERVAL_MS = 30_000;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function createRequestRateLimiter(config?: RequestRateLimitConfig) {
  const maxRequests = config?.maxRequests ?? DEFAULT_MAX_REQUESTS;
  const windowMs = config?.windowMs ?? DEFAULT_WINDOW_MS;
  const exemptLoopback = config?.exemptLoopback ?? true;
  const pruneIntervalMs = config?.pruneIntervalMs ?? PRUNE_INTERVAL_MS;

  interface Entry {
    timestamps: number[];
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

  function check(ip: string | undefined): RequestRateLimitCheckResult {
    const normalized = normalizeIp(ip);
    if (isExempt(normalized)) {
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    const now = Date.now();
    const entry = entries.get(normalized);

    if (!entry) {
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    slideWindow(entry, now);
    const remaining = Math.max(0, maxRequests - entry.timestamps.length);
    return { allowed: remaining > 0, remaining, retryAfterMs: 0 };
  }

  function recordRequest(ip: string | undefined): void {
    const normalized = normalizeIp(ip);
    if (isExempt(normalized)) {
      return;
    }

    const now = Date.now();
    let entry = entries.get(normalized);

    if (!entry) {
      entry = { timestamps: [] };
      entries.set(normalized, entry);
    }

    slideWindow(entry, now);
    entry.timestamps.push(now);
  }

  function prune(): void {
    const now = Date.now();
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
