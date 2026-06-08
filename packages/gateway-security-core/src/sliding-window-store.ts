/**
 * In-memory keyed sliding-window store. Provides the bookkeeping shared by
 * the connection-level and request-level rate limiters. Each limiter layers
 * its own check/record policy (lockout, IPv6 masking) on top via the returned
 * bucket helpers. The store itself enforces an LRU-style entry cap so a
 * burst of unique keys cannot grow the map without bound.
 */
const DEFAULT_PRUNE_INTERVAL_MS = 30_000;
const DEFAULT_MAX_ENTRIES = 100_000;

export interface SlidingWindowBucket {
  /** Timestamps (epoch ms) of recent events inside the window. */
  timestamps: number[];
  /** If set, events are blocked until this epoch-ms instant. */
  lockedUntil?: number;
}

export interface SlidingWindowStoreConfig {
  /** Sliding window duration in milliseconds. */
  windowMs: number;
  /** Background prune interval in milliseconds; set <= 0 to disable auto-prune. */
  pruneIntervalMs?: number;
  /**
   * Hard cap on tracked keys. When the map is full, the oldest non-locked
   * entry is evicted to make room. Set to 0 to disable the cap. Default 100_000.
   */
  maxEntries?: number;
}

export interface SlidingWindowStore {
  readonly entries: Map<string, SlidingWindowBucket>;
  readonly windowMs: number;
  readonly maxEntries: number;
  slideWindow(bucket: SlidingWindowBucket, now: number): void;
  size(): number;
  prune(now?: number): void;
  /**
   * Reserve a slot for `key`, creating it if missing and evicting the
   * oldest non-locked entry when the cap is reached. Returns the bucket.
   * Locked entries are never evicted.
   */
  reserve(key: string, now: number): SlidingWindowBucket;
  dispose(): void;
}

function normalizeMaxEntries(value: number | undefined): number {
  if (value === undefined) {
    return DEFAULT_MAX_ENTRIES;
  }
  // Guard against NaN, negative values, and non-finite numbers.
  // NaN < 0 is false (NaN comparisons are always false), so we need an
  // explicit isNaN check alongside the isFinite guard.
  if (!Number.isFinite(value) || value < 0 || Number.isNaN(value)) {
    return DEFAULT_MAX_ENTRIES;
  }
  const floored = Math.floor(value);
  // Reject NaN from Math.floor (edge case: Math.floor(1.7976931348623157e+308) = NaN)
  if (Number.isNaN(floored)) {
    return DEFAULT_MAX_ENTRIES;
  }
  return floored;
}

export function createSlidingWindowStore(config: SlidingWindowStoreConfig): SlidingWindowStore {
  const { windowMs, pruneIntervalMs = DEFAULT_PRUNE_INTERVAL_MS } = config;
  if (windowMs <= 0) {
    throw new Error("slidingWindowStore: windowMs must be > 0");
  }
  const maxEntries = normalizeMaxEntries(config.maxEntries);

  const entries = new Map<string, SlidingWindowBucket>();
  const pruneTimer = pruneIntervalMs > 0 ? setInterval(() => store.prune(), pruneIntervalMs) : null;
  if (pruneTimer?.unref) {
    pruneTimer.unref();
  }

  function slideWindow(bucket: SlidingWindowBucket, now: number): void {
    const cutoff = now - windowMs;
    bucket.timestamps = bucket.timestamps.filter((ts) => ts > cutoff);
  }

  function evictOldestNonLocked(now: number): void {
    if (maxEntries === 0 || entries.size < maxEntries) {
      return;
    }
    for (const [key, bucket] of entries) {
      if (bucket.lockedUntil && now < bucket.lockedUntil) {
        continue;
      }
      entries.delete(key);
      return;
    }
    // All entries are locked — let the map briefly exceed the cap rather than
    // dropping an in-flight lockout. The next prune will reclaim space.
  }

  function reserve(key: string, now: number): SlidingWindowBucket {
    const existing = entries.get(key);
    if (existing) {
      return existing;
    }
    evictOldestNonLocked(now);
    const bucket: SlidingWindowBucket = { timestamps: [] };
    entries.set(key, bucket);
    return bucket;
  }

  const store: SlidingWindowStore = {
    entries,
    windowMs,
    maxEntries,
    slideWindow,
    reserve,
    size: () => entries.size,
    prune: (now = Date.now()) => {
      for (const [key, bucket] of entries) {
        if (bucket.lockedUntil && now < bucket.lockedUntil) {
          continue;
        }
        slideWindow(bucket, now);
        if (bucket.timestamps.length === 0) {
          entries.delete(key);
        }
      }
    },
    dispose: () => {
      if (pruneTimer) {
        clearInterval(pruneTimer);
      }
      entries.clear();
    },
  };

  return store;
}
