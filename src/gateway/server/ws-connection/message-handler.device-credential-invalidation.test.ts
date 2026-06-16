// Device credential mutation gating: only device.pair.remove,
// device.token.rotate, and device.token.revoke may bump the device-session
// authority generation. server-methods.ts invokes onBeforeRespond for ANY
// successful method whose params carry a non-empty deviceId, so the method
// gate lives at onBeforeRespond construction time in message-handler.ts.
// These tests pin that contract via the exported isDeviceCredentialInvalidatingMethod
// helper, which is the single source of truth used by both the onBeforeRespond
// construction and the per-connection mutation barrier.
import { describe, expect, it } from "vitest";
import { __testing } from "./message-handler.js";

const { isDeviceCredentialInvalidatingMethod } = __testing;

describe("isDeviceCredentialInvalidatingMethod", () => {
  it("returns true for the three device-credential mutating methods", () => {
    expect(isDeviceCredentialInvalidatingMethod("device.pair.remove")).toBe(true);
    expect(isDeviceCredentialInvalidatingMethod("device.token.rotate")).toBe(true);
    expect(isDeviceCredentialInvalidatingMethod("device.token.revoke")).toBe(true);
  });

  it("returns false for non-mutating methods that may carry a deviceId in params", () => {
    // Regression guard: a read/list method that happens to include deviceId
    // must NOT trigger authority invalidation (would force spurious reconnects).
    expect(isDeviceCredentialInvalidatingMethod("device.list")).toBe(false);
    expect(isDeviceCredentialInvalidatingMethod("device.get")).toBe(false);
    expect(isDeviceCredentialInvalidatingMethod("device.pair.status")).toBe(false);
    expect(isDeviceCredentialInvalidatingMethod("chat.send")).toBe(false);
    expect(isDeviceCredentialInvalidatingMethod("ping")).toBe(false);
  });

  it("returns false for unknown methods", () => {
    expect(isDeviceCredentialInvalidatingMethod("device.token.refresh")).toBe(false);
    expect(isDeviceCredentialInvalidatingMethod("device.pair")).toBe(false);
    expect(isDeviceCredentialInvalidatingMethod("")).toBe(false);
  });
});
