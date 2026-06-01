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
import { isLoopbackAddress, resolveClientIp } from "./net-helpers.js";

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

interface ConnectionRateLimitEntry {
  /** Timestamps (epoch ms) of recent connection attempts inside the window. */
  attempts: number[];
  /** If set, connections from this IP are blocked until this epoch-ms instant. */
  lockedUntil?: number;
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
const PRUNE_INTERVAL_MS = 30_000; // prune stale entries every 30 seconds
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
  const pruneIntervalMs = config?.pruneIntervalMs ?? PRUNE_INTERVAL_MS;
  const ipv6SubnetMask = config?.ipv6SubnetMask ?? DEFAULT_IPV6_SUBNET;

  const entries = new Map<string, ConnectionRateLimitEntry>();

  // Periodic cleanup to avoid unbounded map growth.
  const pruneTimer = pruneIntervalMs > 0 ? setInterval(() => prune(), pruneIntervalMs) : null;
  if (pruneTimer?.unref) {
    pruneTimer.unref();
  }

  function isExempt(ip: string): boolean {
    return exemptLoopback && isLoopbackAddress(ip);
  }

  function normalizeIp(ip: string | undefined): string {
    const resolved = resolveClientIp({ remoteAddr: ip }) ?? "unknown";
    const normalized = normalizeIpAddress(resolved);
    if (!normalized) {
      return "unknown";
    }

    // Apply IPv6 subnet masking per OWASP best practices
    if (ipv6SubnetMask > 0 && normalized.includes(":")) {
      const parts = normalized.split(":");
      const fullBlocks = Math.floor(ipv6SubnetMask / 16);
      const remainingBits = ipv6SubnetMask % 16;

      if (fullBlocks >= parts.length) {
        return normalized;
      }

      const maskedParts = parts.slice(0, fullBlocks);
      if (remainingBits > 0 && fullBlocks < parts.length) {
        maskedParts.push("0".repeat(remainingBits > 0 ? (16 - remainingBits) / 4 : 0));
        while (maskedParts.length < parts.length) {
          maskedParts.push("0");
        }
      }
      return maskedParts.join(":").replace(/:+/g, ":").replace(/:$/, "");
    }

    return normalized;
  }

  function slideWindow(entry: ConnectionRateLimitEntry, now: number): void {
    const cutoff = now - windowMs;
    entry.attempts = entry.attempts.filter((ts) => ts > cutoff);
  }

  function check(ip: string | undefined): ConnectionRateLimitCheckResult {
    const normalized = normalizeIp(ip);
    if (isExempt(normalized)) {
      return { allowed: true, retryAfterMs: 0 };
    }

    const now = Date.now();
    const entry = entries.get(normalized);

    if (!entry) {
      return { allowed: true, retryAfterMs: 0 };
    }

    // Still locked out?
    if (entry.lockedUntil && now < entry.lockedUntil) {
      return {
        allowed: false,
        retryAfterMs: entry.lockedUntil - now,
      };
    }

    // Lockout expired – clear it.
    if (entry.lockedUntil && now >= entry.lockedUntil) {
      entry.lockedUntil = undefined;
      entry.attempts = [];
    }

    slideWindow(entry, now);
    const remaining = maxAttempts - entry.attempts.length;
    return { allowed: remaining > 0, retryAfterMs: 0 };
  }

  function recordAttempt(ip: string | undefined): void {
    const normalized = normalizeIp(ip);
    if (isExempt(normalized)) {
      return;
    }

    const now = Date.now();
    let entry = entries.get(normalized);

    if (!entry) {
      entry = { attempts: [] };
      entries.set(normalized, entry);
    }

    // If currently locked, do nothing (already blocked).
    if (entry.lockedUntil && now < entry.lockedUntil) {
      return;
    }

    slideWindow(entry, now);
    entry.attempts.push(now);

    if (entry.attempts.length >= maxAttempts) {
      entry.lockedUntil = now + lockoutMs;
    }
  }

  function prune(): void {
    const now = Date.now();
    for (const [key, entry] of entries) {
      // If locked out, keep the entry until the lockout expires.
      if (entry.lockedUntil && now < entry.lockedUntil) {
        continue;
      }
      slideWindow(entry, now);
      if (entry.attempts.length === 0) {
        entries.delete(key);
      }
    }
  }

  function size(): number {
    return entries.size;
  }

  function dispose(): void {
    if (pruneTimer) {
      clearInterval(pruneTimer);
    }
    entries.clear();
  }

  return { check, recordAttempt, size, prune, dispose };
}
