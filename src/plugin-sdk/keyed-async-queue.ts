// Keyed async queue helpers serialize async plugin work by key while preserving parallelism.
/** Optional lifecycle hooks fired around each queued task. */
export type KeyedAsyncQueueHooks = {
  onEnqueue?: () => void;
  onSettle?: () => void;
};

/** Serialize async work per key while allowing unrelated keys to run concurrently. */
export function enqueueKeyedTask<T>(params: {
  tails: Map<string, Promise<void>>;
  key: string;
  task: () => Promise<T>;
  hooks?: KeyedAsyncQueueHooks;
  /**
   * Optional cap on the number of distinct in-flight keys. When the map is at
   * capacity and a new key arrives, the oldest pending key is evicted to keep
   * memory bounded under floods of unique keys (e.g. one per attacker IP).
   * Defaults to unbounded, preserving the historical contract.
   */
  maxSize?: number;
}): Promise<T> {
  params.hooks?.onEnqueue?.();
  const previous = params.tails.get(params.key) ?? Promise.resolve();
  if (
    typeof params.maxSize === "number" &&
    params.tails.size >= params.maxSize &&
    !params.tails.has(params.key)
  ) {
    // Map preserves insertion order; evict the oldest pending key to bound growth.
    const oldestKey = params.tails.keys().next().value;
    if (oldestKey !== undefined) {
      params.tails.delete(oldestKey);
    }
  }
  const current = previous
    .catch(() => undefined)
    .then(params.task)
    .finally(() => {
      params.hooks?.onSettle?.();
    });
  const tail = current.then(
    () => undefined,
    () => undefined,
  );
  params.tails.set(params.key, tail);
  const cleanup = () => {
    if (params.tails.get(params.key) === tail) {
      params.tails.delete(params.key);
    }
  };
  tail.then(cleanup, cleanup);
  return current;
}

/** Small per-key async queue wrapper for plugin runtimes that need serialized work. */
export class KeyedAsyncQueue {
  private readonly tails = new Map<string, Promise<void>>();
  private readonly maxSize?: number;

  constructor(options?: { maxSize?: number }) {
    this.maxSize = options?.maxSize;
  }

  /** Number of distinct keys with in-flight (or settled-but-uncollected) tails. */
  get size(): number {
    return this.tails.size;
  }

  /**
   * @deprecated Retained for shipped Plugin SDK compatibility. New callers must
   * not depend on queue storage; remove in a declared Plugin SDK breaking window.
   */
  getTailMapForTesting(): Map<string, Promise<void>> {
    return this.tails;
  }

  enqueue<T>(key: string, task: () => Promise<T>, hooks?: KeyedAsyncQueueHooks): Promise<T> {
    return enqueueKeyedTask({
      tails: this.tails,
      key,
      task,
      ...(hooks ? { hooks } : {}),
      ...(this.maxSize !== undefined ? { maxSize: this.maxSize } : {}),
    });
  }

  /**
   * Defense-in-depth sweep that re-checks every in-flight tail for settlement.
   * For tails that have already settled but whose cleanup callback did not run
   * (edge case: the tail was superseded by a newer entry for the same key before
   * the microtask fired), this re-attaches a cleanup handler that fires on the
   * next microtask and removes the stale entry.
   *
   * This complements the per-entry cleanup in `enqueueKeyedTask` and the
   * `maxSize` count-based eviction. Call periodically (e.g. every 60s) to reap
   * settled-but-uncollected entries before they accumulate.
   */
  pruneSettled(): void {
    for (const [key, tail] of this.tails) {
      tail.then(
        () => {
          if (this.tails.get(key) === tail) {
            this.tails.delete(key);
          }
        },
        () => {
          if (this.tails.get(key) === tail) {
            this.tails.delete(key);
          }
        },
      );
    }
  }
}
