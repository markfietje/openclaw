import { describe, expect, it } from "vitest";
import {
  assertStartupSecurityFindingsAllowed,
  DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE_ENV,
  runStartupSecurityChecks,
} from "./startup-security-checks.js";

const safeLoopback = {
  isNetworkExposed: false,
  hasTls: false,
  terminatedUpstream: false,
  authMode: "token",
  bindAddress: "127.0.0.1",
  tokenLength: 64,
};

const safeNetworkExposed = {
  isNetworkExposed: true,
  hasTls: true,
  terminatedUpstream: false,
  authMode: "token",
  bindAddress: "192.168.1.1",
  tokenLength: 64,
};

describe("runStartupSecurityChecks", () => {
  it("returns empty when loopback-only (safe default)", () => {
    expect(runStartupSecurityChecks(safeLoopback)).toEqual([]);
  });

  it("returns empty when network-exposed with TLS and strong auth", () => {
    expect(runStartupSecurityChecks(safeNetworkExposed)).toEqual([]);
  });

  // Gap 7: TLS enforcement
  it("returns critical when network-exposed without TLS", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      hasTls: false,
      terminatedUpstream: false,
    });
    expect(results.some((r) => r.id === "gateway.no_tls_network_exposed")).toBe(true);
    expect(results.find((r) => r.id === "gateway.no_tls_network_exposed")!.severity).toBe(
      "critical",
    );
  });

  it("does not warn when network-exposed without TLS but terminated upstream", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      hasTls: false,
      terminatedUpstream: true,
    });
    expect(results.some((r) => r.id === "gateway.no_tls_network_exposed")).toBe(false);
  });

  // Token strength
  it("returns critical for short token when network-exposed", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      authMode: "token",
      tokenLength: 16,
    });
    expect(results.some((r) => r.id === "gateway.token_too_short")).toBe(true);
  });

  it("does not warn for short token when loopback-only", () => {
    const results = runStartupSecurityChecks({
      ...safeLoopback,
      tokenLength: 8,
    });
    expect(results.some((r) => r.id === "gateway.token_too_short")).toBe(false);
  });

  // Password strength
  it("returns critical for short password when network-exposed", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      authMode: "password",
      passwordLength: 8,
    });
    expect(results.some((r) => r.id === "gateway.password_too_short")).toBe(true);
  });

  // No auth
  it("returns critical when network-exposed with no auth", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      authMode: "none",
    });
    expect(results.some((r) => r.id === "gateway.no_auth_network_exposed")).toBe(true);
    expect(results.find((r) => r.id === "gateway.no_auth_network_exposed")!.severity).toBe(
      "critical",
    );
  });

  // Gap 9: Bind address
  it("returns warn when bound to 0.0.0.0", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      bindAddress: "0.0.0.0",
    });
    expect(results.some((r) => r.id === "gateway.bind_all_interfaces")).toBe(true);
    expect(results.find((r) => r.id === "gateway.bind_all_interfaces")!.severity).toBe("warn");
  });

  it("returns warn when bound to ::", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      bindAddress: "::",
    });
    expect(results.some((r) => r.id === "gateway.bind_all_interfaces")).toBe(true);
  });

  it("does not warn when bound to specific address", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      bindAddress: "192.168.1.100",
    });
    expect(results.some((r) => r.id === "gateway.bind_all_interfaces")).toBe(false);
  });

  it("sorts critical before warn", () => {
    const results = runStartupSecurityChecks({
      isNetworkExposed: true,
      hasTls: false,
      terminatedUpstream: false,
      authMode: "none",
      bindAddress: "0.0.0.0",
    });
    const severities = results.map((r) => r.severity);
    const firstWarn = severities.indexOf("warn");
    const lastCritical = severities.lastIndexOf("critical");
    if (firstWarn !== -1 && lastCritical !== -1) {
      expect(lastCritical).toBeLessThan(firstWarn);
    }
  });

  it("fails closed for critical startup findings without the dangerous override", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      hasTls: false,
      terminatedUpstream: false,
    });

    expect(() => assertStartupSecurityFindingsAllowed(results, {})).toThrow(
      "Refusing to start network-exposed gateway with critical security findings.",
    );
  });

  it("allows critical startup findings only with the explicit dangerous override", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      hasTls: false,
      terminatedUpstream: false,
    });

    expect(() =>
      assertStartupSecurityFindingsAllowed(results, {
        [DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE_ENV]: "1",
      }),
    ).not.toThrow();
  });

  it("does not require the dangerous override for warnings only", () => {
    const results = runStartupSecurityChecks({
      ...safeNetworkExposed,
      bindAddress: "0.0.0.0",
    });

    expect(() => assertStartupSecurityFindingsAllowed(results, {})).not.toThrow();
  });
});
