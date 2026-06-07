import { DeviceSessionAuthorityTracker } from "@openclaw/gateway-security-core/device-session-authority";
// Device credential mutation: when a method like device.pair.remove,
// device.token.rotate, or device.token.revoke completes successfully, the
// session authority for the targeted device must be invalidated so other
// connections that hold an authority snapshot cannot keep acting on the
// stale session. The barrier in message-handler.ts uses a `dispatchSucceeded`
// closure flag to skip invalidation on error responses, so an attacker
// without operator.pairing scope cannot bump the generation by sending
// invalid params.
//
// These tests exercise the barrier's invalidation logic via the exported
// `testing.shouldInvalidateDeviceAuthority` hook. The full connect path has
// pre-existing auth/device-pairing flakiness on this branch; the barrier is
// the right unit of behavior for this gate.
import { describe, expect, it } from "vitest";
import { __testing } from "./message-handler.js";

const { shouldInvalidateDeviceAuthority } = __testing;

function newTracker() {
  return new DeviceSessionAuthorityTracker();
}

describe("shouldInvalidateDeviceAuthority", () => {
  it("invalidates when dispatch succeeded and deviceId is a non-empty string", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: true,
        deviceSessionAuthorityTracker: newTracker(),
        params: { deviceId: "device-1" },
      }),
    ).toBe(true);
  });

  it("does not invalidate when dispatch failed", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: false,
        deviceSessionAuthorityTracker: newTracker(),
        params: { deviceId: "device-1" },
      }),
    ).toBe(false);
  });

  it("does not invalidate when tracker is missing", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: true,
        deviceSessionAuthorityTracker: undefined,
        params: { deviceId: "device-1" },
      }),
    ).toBe(false);
  });

  it("does not invalidate when params are missing", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: true,
        deviceSessionAuthorityTracker: newTracker(),
        params: undefined,
      }),
    ).toBe(false);
  });

  it("does not invalidate when deviceId is missing from params", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: true,
        deviceSessionAuthorityTracker: newTracker(),
        params: {},
      }),
    ).toBe(false);
  });

  it("does not invalidate when deviceId is not a string", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: true,
        deviceSessionAuthorityTracker: newTracker(),
        params: { deviceId: 42 },
      }),
    ).toBe(false);
  });

  it("does not invalidate when deviceId is empty string", () => {
    expect(
      shouldInvalidateDeviceAuthority({
        dispatchSucceeded: true,
        deviceSessionAuthorityTracker: newTracker(),
        params: { deviceId: "" },
      }),
    ).toBe(false);
  });
});
