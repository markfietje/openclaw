/**
 * Tests for the protected config path guard.
 *
 * The protected paths in {@link PROTECTED_CONFIG_PATHS} require the
 * `admin:config` capability to modify. The prefix-matching helpers in this
 * module are the building block that the config.set / config.patch handlers
 * use to reject modifications to those paths when the caller lacks the
 * capability.
 */
import { describe, expect, it } from "vitest";
import {
  PROTECTED_CONFIG_PATHS,
  assertNoProtectedPaths,
  filterProtectedPaths,
  hasProtectedConfigPath,
  isProtectedConfigPath,
} from "./config-guard.js";

describe("config-guard: isProtectedConfigPath", () => {
  it("recognises each of the 6 protected top-level paths", () => {
    for (const path of PROTECTED_CONFIG_PATHS) {
      expect(isProtectedConfigPath(path)).toBe(true);
    }
  });

  it("recognises nested paths underneath a protected prefix", () => {
    expect(isProtectedConfigPath("gateway.auth.mode")).toBe(true);
    expect(isProtectedConfigPath("gateway.security.strictHeaderValidation")).toBe(true);
    expect(isProtectedConfigPath("gateway.trustedProxies.0")).toBe(true);
    expect(isProtectedConfigPath("gateway.bind")).toBe(true);
    expect(isProtectedConfigPath("gateway.port")).toBe(true);
  });

  it("does not match unrelated top-level paths", () => {
    expect(isProtectedConfigPath("agents.defaults.model")).toBe(false);
    expect(isProtectedConfigPath("agents.defaults.provider")).toBe(false);
    expect(isProtectedConfigPath("gateway.handshakeTimeoutMs")).toBe(false);
    expect(isProtectedConfigPath("")).toBe(false);
  });

  it("does not match paths that merely share a string prefix without a dot separator", () => {
    // "gateway.authenticator" is a different path; the dot is the separator.
    expect(isProtectedConfigPath("gateway.authenticator")).toBe(false);
    expect(isProtectedConfigPath("gateway.tailscaleXYZ")).toBe(false);
  });

  it("trims whitespace and trailing dots before matching", () => {
    expect(isProtectedConfigPath("  gateway.auth  ")).toBe(true);
    expect(isProtectedConfigPath("gateway.auth.")).toBe(true);
    expect(isProtectedConfigPath("gateway.auth...")).toBe(true);
  });
});

describe("config-guard: hasProtectedConfigPath", () => {
  it("returns true if any path in the input is protected", () => {
    expect(hasProtectedConfigPath(["agents.defaults.model", "gateway.auth"])).toBe(true);
    expect(hasProtectedConfigPath(["gateway.port"])).toBe(true);
  });

  it("returns false if no path in the input is protected", () => {
    expect(hasProtectedConfigPath(["agents.defaults.model", "agents.providers"])).toBe(false);
    expect(hasProtectedConfigPath([])).toBe(false);
  });
});

describe("config-guard: filterProtectedPaths", () => {
  it("returns only the protected subset", () => {
    const result = filterProtectedPaths([
      "agents.defaults.model",
      "gateway.auth",
      "gateway.bind",
      "agents.defaults.provider",
    ]);
    expect(result).toEqual(["gateway.auth", "gateway.bind"]);
  });

  it("returns an empty array when nothing is protected", () => {
    expect(filterProtectedPaths(["agents.defaults.model"])).toEqual([]);
  });

  it("includes nested protected paths in the filtered output", () => {
    const result = filterProtectedPaths([
      "agents.defaults.model",
      "gateway.security.strictHeaderValidation",
    ]);
    expect(result).toEqual(["gateway.security.strictHeaderValidation"]);
  });
});

describe("config-guard: assertNoProtectedPaths", () => {
  it("returns null when no protected paths are present", () => {
    expect(assertNoProtectedPaths(["agents.defaults.model"])).toBeNull();
    expect(assertNoProtectedPaths([])).toBeNull();
  });

  it("returns a human-readable error naming the protected paths when present", () => {
    const message = assertNoProtectedPaths(["gateway.auth", "agents.defaults.model"]);
    expect(message).not.toBeNull();
    expect(message).toContain("admin:config");
    expect(message).toContain("gateway.auth");
    // benign path is intentionally NOT in the rejection message
    expect(message).not.toContain("agents.defaults.model");
  });

  it("the rejection message lists every protected path, comma-separated", () => {
    const message = assertNoProtectedPaths(["gateway.auth", "gateway.bind", "gateway.port"]);
    expect(message).toContain("gateway.auth");
    expect(message).toContain("gateway.bind");
    expect(message).toContain("gateway.port");
  });
});

describe("config-guard: invariant", () => {
  it("PROTECTED_CONFIG_PATHS has exactly 6 entries covering the documented surfaces", () => {
    // If a new path is added or removed intentionally, this test must be
    // updated alongside the change. The set is the security contract.
    expect(PROTECTED_CONFIG_PATHS).toEqual([
      "gateway.auth",
      "gateway.tailscale",
      "gateway.security",
      "gateway.trustedProxies",
      "gateway.bind",
      "gateway.port",
    ]);
  });
});
