import { describe, expect, it } from "vitest";
import { DeviceSessionAuthorityTracker } from "./device-session-authority.js";

describe("DeviceSessionAuthorityTracker", () => {
  describe("createSnapshot", () => {
    it("creates a snapshot with valid inputs", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(snapshot).toEqual({
        deviceId: "device-1",
        role: "operator",
        deviceGeneration: 0,
        roleGeneration: 0,
      });
    });

    it("returns null when deviceId is missing", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ role: "operator" })).toBeNull();
    });

    it("returns null when role is missing", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: "device-1" })).toBeNull();
    });

    it("returns null when both are missing", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({})).toBeNull();
    });

    it("returns null for blank strings", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: "  ", role: "operator" })).toBeNull();
      expect(tracker.createSnapshot({ deviceId: "device-1", role: "  " })).toBeNull();
    });

    it("trims whitespace from inputs", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: " device-1 ", role: " operator " });
      expect(snapshot?.deviceId).toBe("device-1");
      expect(snapshot?.role).toBe("operator");
    });
  });

  describe("invalidate", () => {
    it("bumps device generation on wildcard invalidate", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const before = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(before?.deviceGeneration).toBe(0);

      tracker.invalidate({ deviceId: "device-1" });
      const after = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(after?.deviceGeneration).toBe(1);
      expect(after?.roleGeneration).toBe(0);
    });

    it("bumps only role-specific generation when role is specified", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      tracker.invalidate({ deviceId: "device-1", role: "operator" });

      const opSnapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      const adminSnapshot = tracker.createSnapshot({ deviceId: "device-1", role: "admin" });

      expect(opSnapshot?.roleGeneration).toBe(1);
      expect(adminSnapshot?.roleGeneration).toBe(0);
      expect(opSnapshot?.deviceGeneration).toBe(0);
    });

    it("increments multiple times correctly", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      tracker.invalidate({ deviceId: "device-1" });
      tracker.invalidate({ deviceId: "device-1" });
      tracker.invalidate({ deviceId: "device-1" });

      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(snapshot?.deviceGeneration).toBe(3);
    });

    it("does not affect other devices", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      tracker.invalidate({ deviceId: "device-1" });

      const snapshot = tracker.createSnapshot({ deviceId: "device-2", role: "operator" });
      expect(snapshot?.deviceGeneration).toBe(0);
    });

    it("ignores blank deviceId", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      tracker.invalidate({ deviceId: "  " });
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(snapshot?.deviceGeneration).toBe(0);
    });
  });

  describe("isStale", () => {
    it("returns false for fresh snapshot", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(tracker.isStale(snapshot)).toBe(false);
    });

    it("returns true after device invalidation", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      tracker.invalidate({ deviceId: "device-1" });
      expect(tracker.isStale(snapshot)).toBe(true);
    });

    it("returns true after role-specific invalidation", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      tracker.invalidate({ deviceId: "device-1", role: "operator" });
      expect(tracker.isStale(snapshot)).toBe(true);
    });

    it("returns false for null snapshot", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.isStale(null)).toBe(false);
    });

    it("returns false for undefined snapshot", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.isStale(undefined)).toBe(false);
    });

    it("does not stale other devices", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      tracker.invalidate({ deviceId: "device-2" });
      expect(tracker.isStale(snapshot)).toBe(false);
    });

    it("does not stale other roles on same device", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      tracker.invalidate({ deviceId: "device-1", role: "admin" });
      expect(tracker.isStale(snapshot)).toBe(false);
    });

    it("wildcard invalidation stales all roles", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const opSnapshot = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      const adminSnapshot = tracker.createSnapshot({ deviceId: "device-1", role: "admin" });
      tracker.invalidate({ deviceId: "device-1" });
      expect(tracker.isStale(opSnapshot)).toBe(true);
      expect(tracker.isStale(adminSnapshot)).toBe(true);
    });
  });

  describe("generations cap", () => {
    it("evicts the oldest entry when the cap is exceeded by a new key", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      // Seed dev-0 so it has a tracked generation, then capture a snapshot.
      tracker.invalidate({ deviceId: "dev-0" });
      const victimSnapshot = tracker.createSnapshot({ deviceId: "dev-0", role: "operator" });
      expect(victimSnapshot?.deviceGeneration).toBe(1);

      // Fill the remaining 4095 slots with one key per device.
      for (let i = 1; i < 4096; i++) {
        tracker.invalidate({ deviceId: `dev-${i}` });
      }
      // 4097th new key triggers eviction of the oldest ("dev-0").
      tracker.invalidate({ deviceId: "dev-4096" });

      expect(tracker.isStale(victimSnapshot)).toBe(true);
      const freshSnapshot = tracker.createSnapshot({ deviceId: "dev-4096", role: "operator" });
      expect(tracker.isStale(freshSnapshot)).toBe(false);
    });

    it("never grows past the cap even under heavy repeated invalidation", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      for (let i = 0; i < 10_000; i++) {
        tracker.invalidate({ deviceId: "dev-1" });
      }
      const snapshot = tracker.createSnapshot({ deviceId: "dev-1", role: "operator" });
      expect(tracker.isStale(snapshot)).toBe(false);
    });

    it("forgets a stale snapshot after a long-running eviction cycle", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      tracker.invalidate({ deviceId: "dev-victim" });
      const snapshot = tracker.createSnapshot({ deviceId: "dev-victim", role: "operator" });
      expect(snapshot?.deviceGeneration).toBe(1);

      // 4095 more devices bring the map to the cap (dev-victim still in).
      for (let i = 0; i < 4095; i++) {
        tracker.invalidate({ deviceId: `dev-other-${i}` });
      }
      expect(tracker.isStale(snapshot)).toBe(false);

      // 4096th new device triggers eviction of dev-victim.
      tracker.invalidate({ deviceId: "dev-other-4095" });
      expect(tracker.isStale(snapshot)).toBe(true);
    });
  });

  describe("dispose", () => {
    it("clears all generations", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      tracker.invalidate({ deviceId: "dev-1" });
      const snapshot = tracker.createSnapshot({ deviceId: "dev-1", role: "operator" });
      expect(snapshot?.deviceGeneration).toBe(1);

      tracker.dispose();
      const afterDispose = tracker.createSnapshot({ deviceId: "dev-1", role: "operator" });
      expect(afterDispose?.deviceGeneration).toBe(0);
    });
  });
});
