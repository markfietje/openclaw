// Connection lifecycle limits for idle and max-age culling.

export const MAX_CONNECTION_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
export const MAX_IDLE_MS = 30 * 60 * 1000; // 30 min with no activity

// Floor validation: configured values must be positive.
function isPositiveNumber(n: unknown): n is number {
  return typeof n === "number" && n > 0;
}

export function resolveMaxConnectionAgeMs(config?: {
  ws?: { maxConnectionAgeMs?: number };
}): number {
  const configured = config?.ws?.maxConnectionAgeMs;
  return isPositiveNumber(configured) ? configured : MAX_CONNECTION_AGE_MS;
}

export function resolveMaxIdleMs(config?: { ws?: { maxIdleMs?: number } }): number {
  const configured = config?.ws?.maxIdleMs;
  return isPositiveNumber(configured) ? configured : MAX_IDLE_MS;
}
