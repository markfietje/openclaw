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

/** Runs one rate-limit attempt after prior attempts for the same IP/scope finish. */
export async function withSerializedRateLimitAttempt<T>(params: {
  ip: string | undefined;
  scope: string | undefined;
  run: () => Promise<T>;
}): Promise<T> {
  const key = buildSerializationKey(params.ip, params.scope);
  const previous = pendingAttempts.get(key) ?? Promise.resolve();
  let releaseCurrent!: () => void;
  const current = new Promise<void>((resolve) => {
    releaseCurrent = resolve;
  });
  const tail = previous.catch(() => {}).then(() => current);
  if (pendingAttempts.size >= MAX_PENDING_ATTEMPTS && !pendingAttempts.has(key)) {
    // Evict the oldest pending attempt key to prevent unbounded growth.
    const oldestKey = pendingAttempts.keys().next().value;
    if (oldestKey !== undefined) {
      pendingAttempts.delete(oldestKey);
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
