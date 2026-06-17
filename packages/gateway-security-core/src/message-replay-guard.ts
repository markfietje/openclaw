/**
 * Per-connection message replay guard.
 *
 * Tracks request ids (or any opaque string key) seen on a single WebSocket
 * connection within a sliding TTL window, rejecting exact reuses. This is the
 * fork's implementation of the OWASP WebSocket Security Cheat Sheet's
 * "Prevent message replay attacks" recommendation (per-message nonce/id
 * validation), layered on top of the handshake nonce challenge.
 *
 * Scope: one guard per connection. Reuse is only meaningful within a single
 * authenticated connection — two different connections may legitimately use
 * the same request id. The store is bounded (LRU eviction) and TTL-pruned so a
 * peer cannot grow it without bound.
 *
 * @see docs/gateway/security/FORK_SECURITY.md § OWASP Gap Analysis
 * @see OWASP WebSocket Security Cheat Sheet — "Prevent message replay attacks"
 */

const DEFAULT_TTL_MS = 60_000;
const DEFAULT_MAX_ENTRIES = 4_096;
const DEFAULT_PRUNE_INTERVAL_MS = 30_000;

export interface MessageReplayGuardConfig {
  /** How long a remembered key blocks reuses, in milliseconds. @default 60_000 */
  ttlMs?: number;
  /**
   * Hard cap on remembered keys. When full, the oldest entry is evicted to make
   * room (LRU). Set to 0 to disable the cap. @default 4_096
   */
  maxEntries?: number;
  /** Background prune interval in ms; set <= 0 to disable auto-prune. @default 30_000 */
  pruneIntervalMs?: number;
}

export type MessageReplayCheckResult = { ok: true } | { ok: false; reason: "reused" };

export interface MessageReplayGuard {
  /**
   * Record `key` and report whether it was already seen within the TTL window.
   * Returns `{ ok: true }` for a new (or expired) key — and records it — or
   * `{ ok: false, reason: "reused" }` if the key is currently remembered.
   */
  checkAndRecord(key: string): MessageReplayCheckResult;
  /** Number of keys currently remembered. */
  size(): number;
  /** Drop expired entries. Exposed for tests. */
  prune(now?: number): void;
  /** Stop the prune timer and clear all state. */
  dispose(): void;
}

function normalizePositiveInteger(value: number | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isFinite(value) || value < 0 || Number.isNaN(value)) {
    return fallback;
  }
  return Math.floor(value);
}

export function createMessageReplayGuard(
  config: MessageReplayGuardConfig = {},
): MessageReplayGuard {
  // ttlMs: explicit non-positive numbers are a programmer error → throw (mirrors
  // sliding-window-store's windowMs handling). undefined / non-finite → default.
  let ttlMs: number;
  if (config.ttlMs === undefined || !Number.isFinite(config.ttlMs)) {
    ttlMs = DEFAULT_TTL_MS;
  } else {
    ttlMs = Math.floor(config.ttlMs);
    if (ttlMs <= 0) {
      throw new Error("messageReplayGuard: ttlMs must be > 0");
    }
  }
  const maxEntries = normalizePositiveInteger(config.maxEntries, DEFAULT_MAX_ENTRIES);
  const pruneIntervalMs = normalizePositiveInteger(
    config.pruneIntervalMs,
    DEFAULT_PRUNE_INTERVAL_MS,
  );

  // Insertion-ordered map (oldest first). Value is the expiry epoch-ms.
  const seen = new Map<string, number>();

  const pruneTimer = pruneIntervalMs > 0 ? setInterval(() => guard.prune(), pruneIntervalMs) : null;
  if (pruneTimer?.unref) {
    pruneTimer.unref();
  }

  function evictOldest(): void {
    if (maxEntries === 0 || seen.size < maxEntries) {
      return;
    }
    // Map iterates in insertion order; the first non-expired entry is the LRU victim.
    const now = Date.now();
    for (const [key, expiresAt] of seen) {
      if (expiresAt <= now) {
        // Expired entries are fair game and free the slot without evicting live data.
        seen.delete(key);
        if (seen.size < maxEntries) {
          return;
        }
        continue;
      }
      seen.delete(key);
      return;
    }
  }

  const guard: MessageReplayGuard = {
    checkAndRecord(key: string): MessageReplayCheckResult {
      if (typeof key !== "string" || key.length === 0) {
        // No key to track — allow through. Replay protection only applies to
        // messages that carry an id; clients without ids are not deduped.
        return { ok: true };
      }
      const now = Date.now();
      const existing = seen.get(key);
      if (existing !== undefined && existing > now) {
        return { ok: false, reason: "reused" };
      }
      evictOldest();
      seen.set(key, now + ttlMs);
      return { ok: true };
    },
    size: () => seen.size,
    prune: (now = Date.now()) => {
      for (const [key, expiresAt] of seen) {
        if (expiresAt <= now) {
          seen.delete(key);
        }
      }
    },
    dispose: () => {
      if (pruneTimer) {
        clearInterval(pruneTimer);
      }
      seen.clear();
    },
  };

  return guard;
}
