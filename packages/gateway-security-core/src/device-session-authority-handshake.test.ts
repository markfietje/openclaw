import { describe, expect, it } from "vitest";
import { DeviceSessionAuthorityTracker } from "./device-session-authority.js";

/**
 * Handshake snapshot semantics tests.
 *
 * These tests document the interaction between createSnapshot failure
 * (returning null) and the isStale check at dispatch time.
 *
 * The key behavioral contract:
 * - createSnapshot returns null when deviceId or role is missing/blank.
 * - isStale(null) returns false — the staleness check short-circuits.
 * - This means a device-token session that failed to capture a snapshot
 *   at handshake time proceeds to business logic instead of being rejected.
 *
 * This is Gap G1 described in the security post "01-when-the-bug-is-real-but-the-fix-isnt-ready.md":
 * the fail-closed default applies only when a snapshot exists and is stale,
 * not when no snapshot was captured at all.
 *
 * Whether this is correct depends on operational expectations: if device-token
 * sessions without snapshots are an expected operational case (e.g., certain
 * degraded-auth scenarios), the current behavior is a deliberate availability
 * tradeoff. If they are always a misconfiguration, the handshake should enforce
 * snapshot capture as a precondition.
 */
describe("DeviceSessionAuthorityTracker handshake semantics", () => {
  describe("createSnapshot failure modes", () => {
    it("returns null when deviceId is null", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: undefined, role: "operator" })).toBeNull();
    });

    it("returns null when role is null", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: "device-1", role: undefined })).toBeNull();
    });

    it("returns null when both are null", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: undefined, role: undefined })).toBeNull();
    });

    it("returns null for undefined inputs", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: undefined, role: undefined })).toBeNull();
    });

    it("returns null for empty strings", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: "", role: "" })).toBeNull();
    });

    it("returns null for whitespace-only strings", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.createSnapshot({ deviceId: "   ", role: "  " })).toBeNull();
    });

    it("returns a valid snapshot for trimmed non-empty inputs", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snap = tracker.createSnapshot({ deviceId: " device-1 ", role: " operator " });
      expect(snap).not.toBeNull();
      expect(snap?.deviceId).toBe("device-1");
      expect(snap?.role).toBe("operator");
    });
  });

  describe("isStale with null/undefined snapshot (dispatch behavior)", () => {
    it("returns false for null snapshot", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.isStale(null)).toBe(false);
    });

    it("returns false for undefined snapshot", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      expect(tracker.isStale(undefined)).toBe(false);
    });

    /**
     * This test documents Gap G1: a device-token session without a snapshot
     * will pass the staleness check (isStale returns false) and proceed to
     * business logic. The optional chaining in the message handler means
     * the check short-circuits when client.deviceSessionAuthority is undefined.
     *
     * This is the current fail-open behavior for handshake snapshot failures.
     */
    it("a null snapshot is never stale — dispatch will not reject it", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      // Simulate a device-token session where createSnapshot returned null
      const nullSnapshot = null;
      // The dispatch staleness check: tracker.isStale(nullSnapshot) → false
      // Optional chaining: deviceSessionAuthorityTracker?.isStale(nullSnapshot)
      // Result: check short-circuits, request is allowed through
      expect(tracker.isStale(nullSnapshot)).toBe(false);
    });

    it("a null snapshot remains not-stale even after invalidation", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const nullSnapshot = null;
      // Invalidation does not affect the null case
      tracker.invalidate({ deviceId: "device-1" });
      expect(tracker.isStale(nullSnapshot)).toBe(false);
    });
  });

  describe("valid snapshot staleness after invalidation", () => {
    it("fresh snapshot is not stale", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snap = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      expect(tracker.isStale(snap)).toBe(false);
    });

    it("snapshot becomes stale after device-wide invalidation", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snap = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      tracker.invalidate({ deviceId: "device-1" });
      expect(tracker.isStale(snap)).toBe(true);
    });

    it("snapshot becomes stale after role-specific invalidation", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snap = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      tracker.invalidate({ deviceId: "device-1", role: "operator" });
      expect(tracker.isStale(snap)).toBe(true);
    });

    it("role-specific invalidation does not stale other roles", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const opSnap = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      const adminSnap = tracker.createSnapshot({ deviceId: "device-1", role: "admin" });
      tracker.invalidate({ deviceId: "device-1", role: "operator" });
      expect(tracker.isStale(opSnap)).toBe(true);
      expect(tracker.isStale(adminSnap)).toBe(false);
    });

    it("device-wide invalidation stales all role snapshots", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const opSnap = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      const adminSnap = tracker.createSnapshot({ deviceId: "device-1", role: "admin" });
      tracker.invalidate({ deviceId: "device-1" }); // no role → device-scoped bump
      expect(tracker.isStale(opSnap)).toBe(true);
      expect(tracker.isStale(adminSnap)).toBe(true);
    });
  });

  describe("invalidation does not affect other devices", () => {
    it("invalidating device-1 does not stale device-2 snapshots", () => {
      const tracker = new DeviceSessionAuthorityTracker();
      const snap1 = tracker.createSnapshot({ deviceId: "device-1", role: "operator" });
      const snap2 = tracker.createSnapshot({ deviceId: "device-2", role: "operator" });
      tracker.invalidate({ deviceId: "device-1" });
      expect(tracker.isStale(snap1)).toBe(true);
      expect(tracker.isStale(snap2)).toBe(false);
    });
  });
});
