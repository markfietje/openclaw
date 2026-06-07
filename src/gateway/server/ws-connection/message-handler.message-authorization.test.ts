// Message authorization gate tests: when the per-request authorization block
// runs, an unmapped RPC method (no authorization decision in the registry)
// must fail closed with INVALID_REQUEST / method-not-authorized, unless
// security.dangerouslyAllowUnmappedMethods === true. The gate itself is
// gated by security.enableMessageAuthorization (or the legacy
// security.messageAuth.enabled).
import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../../../config/types.js";
import { __testing } from "./message-handler.js";

const { isMessageAuthorizationEnabled, isUnmappedMethodAllowed } = __testing;

function configWith(security: OpenClawConfig["gateway"]["security"]): OpenClawConfig {
  return { gateway: { security } } as OpenClawConfig;
}

describe("isMessageAuthorizationEnabled", () => {
  it("returns true when security is missing (default)", () => {
    expect(isMessageAuthorizationEnabled(undefined)).toBe(true);
    expect(isMessageAuthorizationEnabled({ gateway: {} } as OpenClawConfig)).toBe(true);
  });

  it("returns true when neither field is set (default)", () => {
    expect(isMessageAuthorizationEnabled(configWith({}))).toBe(true);
  });

  it("returns true when enableMessageAuthorization is true", () => {
    expect(isMessageAuthorizationEnabled(configWith({ enableMessageAuthorization: true }))).toBe(
      true,
    );
  });

  it("returns false when enableMessageAuthorization is false", () => {
    expect(isMessageAuthorizationEnabled(configWith({ enableMessageAuthorization: false }))).toBe(
      false,
    );
  });

  it("returns false when the legacy messageAuth.enabled is false", () => {
    expect(isMessageAuthorizationEnabled(configWith({ messageAuth: { enabled: false } }))).toBe(
      false,
    );
  });

  it("returns true when both fields are true (no conflict)", () => {
    expect(
      isMessageAuthorizationEnabled(
        configWith({ enableMessageAuthorization: true, messageAuth: { enabled: true } }),
      ),
    ).toBe(true);
  });
});

describe("isUnmappedMethodAllowed", () => {
  it("returns false when security is missing (default: fail closed)", () => {
    expect(isUnmappedMethodAllowed(undefined)).toBe(false);
    expect(isUnmappedMethodAllowed({ gateway: {} } as OpenClawConfig)).toBe(false);
  });

  it("returns false when the flag is unset", () => {
    expect(isUnmappedMethodAllowed(configWith({}))).toBe(false);
  });

  it("returns false when the flag is explicitly false", () => {
    expect(isUnmappedMethodAllowed(configWith({ dangerouslyAllowUnmappedMethods: false }))).toBe(
      false,
    );
  });

  it("returns true only when the flag is explicitly true", () => {
    expect(isUnmappedMethodAllowed(configWith({ dangerouslyAllowUnmappedMethods: true }))).toBe(
      true,
    );
  });
});
