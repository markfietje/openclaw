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

function normalizeNonEmpty(value: string): string | null {
  const normalized = value.trim();
  return normalized ? normalized : null;
}

function key(deviceId: string, role: string): string {
  return `${deviceId}\0${role}`;
}

export class DeviceSessionAuthorityTracker {
  private generations = new Map<string, number>();

  createSnapshot(params: {
    deviceId?: string;
    role?: string;
  }): DeviceSessionAuthoritySnapshot | null {
    const deviceId = params.deviceId ? normalizeNonEmpty(params.deviceId) : null;
    const role = params.role ? normalizeNonEmpty(params.role) : null;
    if (!deviceId || !role) {
      return null;
    }
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
    return this.generations.get(key(deviceId, role)) ?? 0;
  }

  private bump(deviceId: string, role: string): void {
    const generationKey = key(deviceId, role);
    this.generations.set(generationKey, (this.generations.get(generationKey) ?? 0) + 1);
  }
}
