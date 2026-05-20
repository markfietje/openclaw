import { describe, expect, it } from "vitest";
import { validateCredentialStrength } from "./auth.js";

// Build a minimal ResolvedGatewayAuth for testing
function makeAuth(
  overrides: Record<string, unknown>,
): ReturnType<typeof import("./auth.js").resolveGatewayAuth> {
  // We just need the shape for the function, not a real resolve
  return {
    mode: "token",
    allowTailscale: false,
    ...overrides,
  } as ReturnType<typeof import("./auth.js").resolveGatewayAuth>;
}

describe("validateCredentialStrength", () => {
  it("returns ok when not network-exposed", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "token", token: "short" }),
      isNetworkExposed: false,
    });
    expect(result.ok).toBe(true);
    expect(result.errors).toHaveLength(0);
    expect(result.warnings).toHaveLength(0);
  });

  it("errors on short token when network-exposed", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "token", token: "tooshort" }),
      isNetworkExposed: true,
    });
    expect(result.ok).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain("minimum 32");
  });

  it("accepts long token", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "token", token: "a".repeat(64) }),
      isNetworkExposed: true,
    });
    expect(result.ok).toBe(true);
  });

  it("errors on short password when network-exposed", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "password", password: "abc123" }),
      isNetworkExposed: true,
    });
    expect(result.ok).toBe(false);
    expect(result.errors.some((w) => w.includes("minimum 15"))).toBe(true);
  });

  it("warns on all-digit password", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "password", password: "123456789012" }),
      isNetworkExposed: true,
    });
    expect(result.ok).toBe(false);
    expect(result.warnings.some((w) => w.includes("only digits"))).toBe(true);
  });

  it("warns on all-lowercase password", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "password", password: "abcdefghijkl" }),
      isNetworkExposed: true,
    });
    expect(result.ok).toBe(false);
    expect(result.warnings.some((w) => w.includes("only lowercase"))).toBe(true);
  });

  it("accepts strong password", () => {
    const result = validateCredentialStrength({
      auth: makeAuth({ mode: "password", password: "Str0ng!P@ssw0rd" }),
      isNetworkExposed: true,
    });
    expect(result.ok).toBe(true);
  });
});
