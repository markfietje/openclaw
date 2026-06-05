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

import { normalizeIpAddress } from "@openclaw/net-policy/ip";
import { isLoopbackAddress } from "./ip.js";
import { createSlidingWindowStore, type SlidingWindowBucket } from "./sliding-window-store.js";

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
  /**
   * IPv6 subnet mask for rate-limit key generation.
   * Mirrors the connection-rate-limit config; /56 collapses ISP-assigned IPv6 ranges.
   * Set to 0 to disable.  @default 56
   */
  ipv6SubnetMask?: number;
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
const DEFAULT_PRUNE_INTERVAL_MS = 30_000;

function normalizePositiveInteger(value: number | undefined, fallback: number): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return fallback;
  }
  return Math.max(1, Math.floor(value));
}

// ---------------------------------------------------------------------------
// IPv6 subnet masking (mirrors connection-rate-limit for consistency)
// ---------------------------------------------------------------------------

// Expand :: compression to a full 8-block IPv6 address so masking
// operates on a predictable number of blocks.
function expandIPv6(address: string): string {
  if (!address.includes("::")) {
    return address;
  }
  const halves = address.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  const expanded = [...left, ...Array(missing).fill("0"), ...right];
  return expanded.map((p) => p.padStart(4, "0")).join(":");
}

// Apply a bitwise subnet mask to an IPv6 address.
// For example /56 keeps 3 full 16-bit blocks and masks the 4th to
// the first 8 bits (e.g. "abcd" -> "ab00").
function applyIpv6SubnetMask(address: string, maskBits: number): string {
  const expanded = expandIPv6(address);
  const parts = expanded.split(":");
  const fullBlocks = Math.floor(maskBits / 16);
  const remainingBits = maskBits % 16;

  const result: string[] = [];

  for (let i = 0; i < fullBlocks && i < parts.length; i++) {
    result.push(parts[i]);
  }

  if (remainingBits > 0 && fullBlocks < parts.length) {
    const blockValue = Number.parseInt(parts[fullBlocks], 16);
    const mask = 0xffff << (16 - remainingBits);
    result.push((blockValue & mask).toString(16).padStart(4, "0"));
  }

  while (result.length < 8) {
    result.push("0");
  }

  return result.join(":");
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function createRequestRateLimiter(config?: RequestRateLimitConfig) {
  const maxRequests = normalizePositiveInteger(config?.maxRequests, DEFAULT_MAX_REQUESTS);
  const windowMs = normalizePositiveInteger(config?.windowMs, DEFAULT_WINDOW_MS);
  const exemptLoopback = config?.exemptLoopback ?? true;
  const maxEntries = normalizePositiveInteger(config?.maxEntries, DEFAULT_MAX_ENTRIES);
  const pruneIntervalMs = config?.pruneIntervalMs ?? DEFAULT_PRUNE_INTERVAL_MS;
  const ipv6SubnetMask = config?.ipv6SubnetMask ?? 56;

  const store = createSlidingWindowStore({ windowMs, pruneIntervalMs });

  function normalizeIp(ip: string | undefined): string {
    const resolved = ip ?? "unknown";
    const normalized = normalizeIpAddress(resolved);
    if (!normalized) {
      return "unknown";
    }
    // Apply IPv6 subnet masking consistent with connection-rate-limit.
    // Loopback addresses are never masked — they are exempt from rate
    // limiting and must remain identifiable for the isExempt() check.
    if (ipv6SubnetMask > 0 && normalized.includes(":") && !isLoopbackAddress(normalized)) {
      return applyIpv6SubnetMask(normalized, ipv6SubnetMask);
    }
    return normalized;
  }

  function isExempt(ip: string): boolean {
    return exemptLoopback && isLoopbackAddress(ip);
  }

  function retryAfterForEntry(entry: SlidingWindowBucket, now: number): number {
    const oldestTimestamp = entry.timestamps[0];
    if (oldestTimestamp === undefined) {
      return 0;
    }
    return Math.max(0, oldestTimestamp + windowMs - now);
  }

  function retryAfterForFullTable(now: number): number {
    let retryAfterMs: number | undefined;
    for (const entry of store.entries.values()) {
      const candidate = retryAfterForEntry(entry, now);
      if (candidate <= 0) {
        continue;
      }
      retryAfterMs = retryAfterMs === undefined ? candidate : Math.min(retryAfterMs, candidate);
    }
    return retryAfterMs ?? windowMs;
  }

  function canTrackNewEntry(now: number): boolean {
    if (store.entries.size < maxEntries) {
      return true;
    }
    store.prune(now);
    return store.entries.size < maxEntries;
  }

  function check(ip: string | undefined): RequestRateLimitCheckResult {
    const key = normalizeIp(ip);
    if (isExempt(key)) {
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    const now = Date.now();
    const entry = store.entries.get(key);

    if (!entry) {
      if (!canTrackNewEntry(now)) {
        return { allowed: false, remaining: 0, retryAfterMs: retryAfterForFullTable(now) };
      }
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    store.slideWindow(entry, now);
    if (entry.timestamps.length === 0) {
      store.entries.delete(key);
      return { allowed: true, remaining: maxRequests, retryAfterMs: 0 };
    }

    const remaining = Math.max(0, maxRequests - entry.timestamps.length);
    if (remaining === 0) {
      return { allowed: false, remaining, retryAfterMs: retryAfterForEntry(entry, now) };
    }
    return { allowed: true, remaining, retryAfterMs: 0 };
  }

  function recordRequest(ip: string | undefined): void {
    const key = normalizeIp(ip);
    if (isExempt(key)) {
      return;
    }

    const now = Date.now();
    let entry: SlidingWindowBucket | undefined = store.entries.get(key);

    if (!entry) {
      if (!canTrackNewEntry(now)) {
        // Fail closed: callers MUST call check() before recordRequest().
        // When the tracking table is full, check() returns { allowed: false }
        // and the request is rejected before reaching this path. If code
        // reaches here despite check() returning false, silently drop the
        // recording but the request was already rejected upstream.
        return;
      }
      entry = { timestamps: [] };
      store.entries.set(key, entry);
    }

    store.slideWindow(entry, now);
    entry.timestamps.push(now);
    if (entry.timestamps.length > maxRequests) {
      entry.timestamps = entry.timestamps.slice(-maxRequests);
    }
  }

  return {
    check,
    recordRequest,
    prune: () => store.prune(),
    dispose: () => store.dispose(),
    size: () => store.size(),
  };
}

export type RequestRateLimiter = ReturnType<typeof createRequestRateLimiter>;
