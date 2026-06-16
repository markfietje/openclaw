/**
 * In-memory connection rate limiter for pre-handshake DoS protection.
 *
 * Tracks WebSocket connection attempts by client IP before the handshake
 * completes. This is a coarse first line of defense that runs inside
 * `verifyClient` to prevent resource exhaustion from rapid connection
 * attempts before authentication-based rate limiting can take effect.
 *
 * Design decisions:
 * - Pure in-memory Map – no external dependencies; suitable for a single
 *   gateway process. The Map is periodically pruned to avoid unbounded growth.
 * - Loopback addresses (127.0.0.1 / ::1) are exempt by default so that local
 *   CLI sessions and test runners are never blocked.
 * - The module is side-effect-free: callers create an instance via
 *   {@link createConnectionRateLimiter} and pass it where needed.
 */

import { normalizeIpAddress } from "@openclaw/net-policy/ip";
import { isLoopbackAddress } from "./ip.js";
import { applyIpv6SubnetMask } from "./ipv6-subnet.js";
import { createSlidingWindowStore } from "./sliding-window-store.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ConnectionRateLimitConfig {
  /** Maximum connection attempts per window.  @default 30 */
  maxAttempts?: number;
  /** Sliding window duration in milliseconds.  @default 10_000 (10 s) */
  windowMs?: number;
  /** Lockout duration in milliseconds after the limit is exceeded.  @default 60_000 (1 min) */
  lockoutMs?: number;
  /** Exempt loopback (localhost) addresses from rate limiting.  @default true */
  exemptLoopback?: boolean;
  /** Background prune interval in milliseconds; set <= 0 to disable auto-prune.  @default 30_000 */
  pruneIntervalMs?: number;
  /**
   * Hard cap on tracked non-loopback client IPs. When the cap is reached the
   * oldest non-locked entry is evicted to make room, bounding memory against
   * distinct-IP floods (IPv6 rotation / CGNAT).  @default 100_000
   */
  maxEntries?: number;
  /**
   * IPv6 subnet mask for rate-limit key generation.
   * ISPs assign ranges via subnet mask; malicious users could iterate addresses.
   * /56 is moderately aggressive (default); /64 is common for ISPs.
   * Set to 0 or false to disable subnet masking.  @default 56
   */
  ipv6SubnetMask?: number;
}

export interface ConnectionRateLimitCheckResult {
  /** Whether the connection attempt is allowed to proceed. */
  allowed: boolean;
  /** Milliseconds until the lockout expires (0 when not locked). */
  retryAfterMs: number;
}

export interface ConnectionRateLimiter {
  /** Check whether `ip` is currently allowed to attempt a connection. */
  check(ip: string | undefined): ConnectionRateLimitCheckResult;
  /** Record a connection attempt for `ip` (call after `check` returns allowed). */
  recordAttempt(ip: string | undefined): void;
  /** Return the current number of tracked IPs (useful for diagnostics). */
  size(): number;
  /** Remove expired entries and release memory. */
  prune(): void;
  /** Dispose the limiter and cancel periodic cleanup timers. */
  dispose(): void;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_ATTEMPTS = 30;
const DEFAULT_WINDOW_MS = 10_000; // 10 seconds
const DEFAULT_LOCKOUT_MS = 60_000; // 1 minute
const DEFAULT_PRUNE_INTERVAL_MS = 30_000; // prune stale entries every 30 seconds
const DEFAULT_MAX_ENTRIES = 100_000; // bound tracked IPs against distinct-IP floods
const DEFAULT_IPV6_SUBNET = 56; // OWASP recommended /56 for IPv6 rate limiting

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function createConnectionRateLimiter(
  config?: ConnectionRateLimitConfig,
): ConnectionRateLimiter {
  const maxAttempts = config?.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const windowMs = config?.windowMs ?? DEFAULT_WINDOW_MS;
  const lockoutMs = config?.lockoutMs ?? DEFAULT_LOCKOUT_MS;
  const exemptLoopback = config?.exemptLoopback ?? true;
  const pruneIntervalMs = config?.pruneIntervalMs ?? DEFAULT_PRUNE_INTERVAL_MS;
  const maxEntries = config?.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const ipv6SubnetMask = config?.ipv6SubnetMask ?? DEFAULT_IPV6_SUBNET;

  const store = createSlidingWindowStore({ windowMs, pruneIntervalMs, maxEntries });

  function isExempt(ip: string): boolean {
    return exemptLoopback && isLoopbackAddress(ip);
  }

  function normalizeIp(ip: string | undefined, skipMask?: boolean): string {
    const resolved = ip ?? "unknown";
    const normalized = normalizeIpAddress(resolved);
    if (!normalized) {
      return "unknown";
    }

    // Apply IPv6 subnet masking per OWASP best practices.
    // Loopback addresses are never masked — they are exempt from rate
    // limiting and must remain identifiable for the isExempt() check.
    if (
      !skipMask &&
      ipv6SubnetMask > 0 &&
      normalized.includes(":") &&
      !isLoopbackAddress(normalized)
    ) {
      return applyIpv6SubnetMask(normalized, ipv6SubnetMask);
    }

    return normalized;
  }

  function check(ip: string | undefined): ConnectionRateLimitCheckResult {
    const key = normalizeIp(ip);
    if (isExempt(key)) {
      return { allowed: true, retryAfterMs: 0 };
    }

    const now = Date.now();
    const entry = store.entries.get(key);

    if (!entry) {
      return { allowed: true, retryAfterMs: 0 };
    }

    if (entry.lockedUntil && now < entry.lockedUntil) {
      return { allowed: false, retryAfterMs: entry.lockedUntil - now };
    }

    if (entry.lockedUntil && now >= entry.lockedUntil) {
      entry.lockedUntil = undefined;
      entry.timestamps = [];
    }

    store.slideWindow(entry, now);
    const remaining = maxAttempts - entry.timestamps.length;
    return { allowed: remaining > 0, retryAfterMs: 0 };
  }

  function recordAttempt(ip: string | undefined): void {
    const key = normalizeIp(ip);
    if (isExempt(key)) {
      return;
    }

    const now = Date.now();
    // Route insertion through store.reserve() so the maxEntries cap is enforced
    // via evictOldestNonLocked(). A direct store.entries.set would bypass
    // eviction and allow unbounded growth from attacker-controlled distinct IPs.
    const entry = store.reserve(key, now);

    if (entry.lockedUntil && now < entry.lockedUntil) {
      return;
    }

    store.slideWindow(entry, now);
    entry.timestamps.push(now);

    if (entry.timestamps.length >= maxAttempts) {
      entry.lockedUntil = now + lockoutMs;
    }
  }

  return {
    check,
    recordAttempt,
    size: () => store.size(),
    prune: () => store.prune(),
    dispose: () => store.dispose(),
  };
}
