// Per-connection mutation barrier gating: only the three device-credential
// mutating methods (device.pair.remove, device.token.rotate, device.token.revoke)
// take the per-connection serialization barrier in message-handler.ts, so
// concurrent requests on the same connection wait for the mutation to settle.
// The barrier is an ordering fix; the universal staleness check is the
// generation-based authority check (line 2387), which runs on every RPC
// regardless of method. Authority invalidation itself is handler-driven
// via context.invalidateDeviceAuthority(...), so the set of methods that
// bump the generation is no longer enumerated here.
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
    // The barrier is an ordering fix for known-mutating methods; a read/list
    // method that happens to include deviceId does not need to take it.
    // Authority invalidation is now driven by handler opt-in via
    // context.invalidateDeviceAuthority(...), not by this enumeration.
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
