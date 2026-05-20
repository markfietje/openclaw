/**
 * Per-device authenticated connection budget.
 *
 * Caps the number of concurrent authenticated WebSocket sessions per device
 * identity to prevent abuse when device credentials are compromised.
 *
 * Design mirrors {@link PreauthConnectionBudget} for consistency.
 */

const DEFAULT_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY = 8;
const UNKNOWN_DEVICE_KEY = "__openclaw_unknown_device__";

export function getMaxAuthenticatedConnectionsPerIdentityFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): number {
  const configured =
    env.OPENCLAW_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY ||
    (env.VITEST && env.OPENCLAW_TEST_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY);
  if (!configured) {
    return DEFAULT_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY;
  }
  const parsed = Number(configured);
  if (!Number.isFinite(parsed) || parsed < 1) {
    return DEFAULT_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY;
  }
  return Math.max(1, Math.floor(parsed));
}

export type AuthenticatedConnectionBudget = {
  /** Try to acquire a slot. Returns false if budget exceeded. */
  acquire(deviceId: string | undefined, connId: string): boolean;
  /** Release a slot when a connection closes. */
  release(deviceId: string | undefined, connId: string): void;
  /** Current count for a device. */
  count(deviceId: string | undefined): number;
  /** Dispose and clear all tracking. */
  dispose(): void;
};

export function createAuthenticatedConnectionBudget(
  limit = getMaxAuthenticatedConnectionsPerIdentityFromEnv(),
): AuthenticatedConnectionBudget {
  // Map<deviceId, Set<connId>>
  const connections = new Map<string, Set<string>>();

  const normalizeKey = (deviceId: string | undefined): string => {
    const id = deviceId?.trim();
    return id || UNKNOWN_DEVICE_KEY;
  };

  return {
    acquire(deviceId, connId) {
      const key = normalizeKey(deviceId);
      let set = connections.get(key);
      if (!set) {
        set = new Set<string>();
        connections.set(key, set);
      }
      if (set.size >= limit) {
        return false;
      }
      set.add(connId);
      return true;
    },

    release(deviceId, connId) {
      const key = normalizeKey(deviceId);
      const set = connections.get(key);
      if (!set) {
        return;
      }
      set.delete(connId);
      if (set.size === 0) {
        connections.delete(key);
      }
    },

    count(deviceId) {
      return connections.get(normalizeKey(deviceId))?.size ?? 0;
    },

    dispose() {
      connections.clear();
    },
  };
}
