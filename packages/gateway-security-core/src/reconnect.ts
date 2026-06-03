/**
 * Reconnect delay calculation with exponential backoff and jitter.
 *
 * Prevents thundering-herd reconnection storms by adding random jitter
 * to exponential backoff delays.
 *
 * @see FORK_SECURITY.md § Operational Hardening — Close-code-aware reconnect
 */

export interface ReconnectConfig {
  /** Initial delay in ms. @default 1_000 */
  initialMs?: number;
  /** Maximum delay in ms. @default 30_000 */
  maxMs?: number;
  /** Backoff multiplier per attempt. @default 2 */
  multiplier?: number;
  /** Maximum jitter factor (0-1). @default 0.5 */
  jitter?: number;
}

export function createReconnectDelay(config?: ReconnectConfig): {
  next: () => number;
  reset: () => void;
} {
  const initialMs = config?.initialMs ?? 1_000;
  const maxMs = config?.maxMs ?? 30_000;
  const multiplier = config?.multiplier ?? 2;
  const jitter = config?.jitter ?? 0.5;

  let attempt = 0;

  function next(): number {
    const base = Math.min(initialMs * Math.pow(multiplier, attempt), maxMs);
    const jitterAmount = base * jitter * Math.random();
    attempt += 1;
    return Math.round(base + jitterAmount);
  }

  function reset(): void {
    attempt = 0;
  }

  return { next, reset };
}

/**
 * Calculate a single reconnect delay with jitter.
 * Stateless — use when you track attempts externally.
 */
export function reconnectDelay(attempt: number, config?: ReconnectConfig): number {
  const initialMs = config?.initialMs ?? 1_000;
  const maxMs = config?.maxMs ?? 30_000;
  const multiplier = config?.multiplier ?? 2;
  const jitter = config?.jitter ?? 0.5;

  const base = Math.min(initialMs * Math.pow(multiplier, attempt), maxMs);
  const jitterAmount = base * jitter * Math.random();
  return Math.round(base + jitterAmount);
}
