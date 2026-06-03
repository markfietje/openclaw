export type DeviceSessionAuthoritySnapshot = {
  deviceId: string;
  role: string;
  deviceGeneration: number;
  roleGeneration: number;
};

export type DeviceSessionInvalidation = {
  deviceId: string;
  role?: string;
};

const DEVICE_SCOPE = "*";

const MAX_GENERATION_ENTRIES = 4096;

// Track access time for LRU-style eviction when max entries is reached.
// Each entry stores: [generation, lastAccessMs]
type GenerationEntry = [generation: number, lastAccessMs: number];

function normalizeNonEmpty(value: string): string | null {
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function key(deviceId: string, role: string): string {
  return `${deviceId}\0${role}`;
}

export class DeviceSessionAuthorityTracker {
  // Map from key(deviceId, role) to [generation, lastAccessMs]
  private generations = new Map<string, GenerationEntry>();

  createSnapshot(params: {
    deviceId?: string;
    role?: string;
  }): DeviceSessionAuthoritySnapshot | null {
    const deviceId = params.deviceId ? normalizeNonEmpty(params.deviceId) : null;
    const role = params.role ? normalizeNonEmpty(params.role) : null;
    if (!deviceId || !role) {
      return null;
    }
    // Update access time for LRU tracking
    this.touch(deviceId, role);
    return {
      deviceId,
      role,
      deviceGeneration: this.generationFor(deviceId, DEVICE_SCOPE),
      roleGeneration: this.generationFor(deviceId, role),
    };
  }

  invalidate(params: DeviceSessionInvalidation): void {
    const deviceId = normalizeNonEmpty(params.deviceId);
    if (!deviceId) {
      return;
    }
    const role = params.role ? normalizeNonEmpty(params.role) : null;
    this.bump(deviceId, role ?? DEVICE_SCOPE);
  }

  isStale(snapshot?: DeviceSessionAuthoritySnapshot | null): boolean {
    if (!snapshot) {
      return false;
    }
    return (
      this.generationFor(snapshot.deviceId, DEVICE_SCOPE) !== snapshot.deviceGeneration ||
      this.generationFor(snapshot.deviceId, snapshot.role) !== snapshot.roleGeneration
    );
  }

  private generationFor(deviceId: string, role: string): number {
    const entry = this.generations.get(key(deviceId, role));
    return entry?.[0] ?? 0;
  }

  // Update last-access time for LRU tracking
  private touch(deviceId: string, role: string): void {
    const k = key(deviceId, role);
    const entry = this.generations.get(k);
    if (entry) {
      // Preserve generation, update access time
      entry[1] = Date.now();
    }
  }

  private bump(deviceId: string, role: string): void {
    const generationKey = key(deviceId, role);
    const now = Date.now();
    if (!this.generations.has(generationKey) && this.generations.size >= MAX_GENERATION_ENTRIES) {
      // OWASP A04:2021 — Security Misconfiguration. Evict the least-recently
      // accessed entry (LRU) instead of oldest insertion order to preserve
      // frequently-used generations in long-running gateways.
      let oldestKey: string | undefined;
      let oldestAccess = Infinity;
      for (const [k, entry] of this.generations) {
        if (entry[1] < oldestAccess) {
          oldestAccess = entry[1];
          oldestKey = k;
        }
      }
      if (oldestKey !== undefined) {
        this.generations.delete(oldestKey);
      }
    }
    const existing = this.generations.get(generationKey);
    const generation = existing ? existing[0] + 1 : 1;
    this.generations.set(generationKey, [generation, now]);
  }

  /** Clear all tracked generations. Call on gateway shutdown. */
  dispose(): void {
    this.generations.clear();
  }

  /** Clear all tracked generations. Call on gateway shutdown. */
  dispose(): void {
    this.generations.clear();
  }
}
