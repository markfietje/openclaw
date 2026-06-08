// Gateway auth rate-limit serialization.
// Serializes limiter attempts per IP/scope so concurrent failures count correctly.
import { AUTH_RATE_LIMIT_SCOPE_DEFAULT, normalizeRateLimitClientIp } from "./auth-rate-limit.js";

const MAX_PENDING_ATTEMPTS = 10_000;
const pendingAttempts = new Map<string, Promise<void>>();

function normalizeScope(scope: string | undefined): string {
  return (scope ?? AUTH_RATE_LIMIT_SCOPE_DEFAULT).trim() || AUTH_RATE_LIMIT_SCOPE_DEFAULT;
}

function buildSerializationKey(ip: string | undefined, scope: string | undefined): string {
  return `${normalizeScope(scope)}:${normalizeRateLimitClientIp(ip)}`;
}

/**
 * Periodic cleanup of stale entries in the pendingAttempts Map.
 * Entries become stale when their promise chain completes (tail resolves).
 * Runs every 60 seconds to prevent memory leaks from promise references.
 */
function startCleanupTimer(): void {
  setInterval(() => {
    for (const [key, promise] of pendingAttempts) {
      // If the promise is resolved (not pending), check if we should clean it up.
      // We use a heuristic: if the map has grown large, aggressively clean completed entries.
      if (pendingAttempts.size > MAX_PENDING_ATTEMPTS / 2) {
        promise
          .catch(() => {})
          .then(() => {
            // The promise settled — if we're still the current entry, delete ourselves.
            if (pendingAttempts.get(key) === promise) {
              pendingAttempts.delete(key);
            }
          });
      }
    }
  }, 60_000).unref?.();
}

// Start cleanup timer once at module load
startCleanupTimer();

/** Runs one rate-limit attempt after prior attempts for the same IP/scope finish. */
export async function withSerializedRateLimitAttempt<T>(params: {
  ip: string | undefined;
  scope: string | undefined;
  run: () => Promise<T>;
}): Promise<T> {
  const key = params.key;
  const previous = pendingAttempts.get(key) ?? Promise.resolve();
  let releaseCurrent!: () => void;
  const current = new Promise<void>((resolve) => {
    releaseCurrent = resolve;
  });
  const tail = previous.catch(() => {}).then(() => current);
  if (pendingAttempts.size >= MAX_PENDING_ATTEMPTS && !pendingAttempts.has(key)) {
    // Evict the oldest pending attempt key to prevent unbounded growth.
    // Use a simple FIFO approach - iterate and delete the first non-active entry.
    let evicted = false;
    for (const [existingKey] of pendingAttempts) {
      if (existingKey !== key) {
        pendingAttempts.delete(existingKey);
        evicted = true;
        break;
      }
    }
    // If we couldn't evict (somehow all entries are the current key), skip adding
    if (!evicted && pendingAttempts.size >= MAX_PENDING_ATTEMPTS) {
      // Force eviction of this key's previous entry if it exists
      pendingAttempts.delete(key);
    }
  }
  pendingAttempts.set(key, tail);

  await previous.catch(() => {});
  try {
    return await params.run();
  } finally {
    releaseCurrent();
    if (pendingAttempts.get(key) === tail) {
      pendingAttempts.delete(key);
    }
  }
}

