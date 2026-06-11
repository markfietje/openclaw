/**
 * WebSocket authentication message regression tests.
 */
import { describe, expect, it } from "vitest";
import { formatGatewayAuthFailureMessage } from "./auth-messages.js";

describe("formatGatewayAuthFailureMessage", () => {
  it("keeps device-token scope mismatches distinct from token mismatches", () => {
    expect(
      formatGatewayAuthFailureMessage({
        authMode: "token",
        authProvided: "device-token",
        reason: "scope_mismatch",
        client: { id: "openclaw-control-ui", mode: "ui" },
      }),
    ).toBe("unauthorized: device token scope mismatch (re-pair or approve scope upgrade)");
  });

  // Fix 3.3: unknown clients get generic message, not auth-config-leaking details
  it("returns generic message for unknown clients", () => {
    expect(
      formatGatewayAuthFailureMessage({
        authMode: "token",
        authProvided: "none",
        client: { id: "unknown", mode: "unknown" },
      }),
    ).toBe("unauthorized: authentication failed");
  });

  it("returns generic message when client is undefined", () => {
    expect(
      formatGatewayAuthFailureMessage({
        authMode: "token",
        authProvided: "none",
      }),
    ).toBe("unauthorized: authentication failed");
  });

  it("returns specific message for CLI clients (known)", () => {
    expect(
      formatGatewayAuthFailureMessage({
        authMode: "token",
        authProvided: "none",
        client: { id: "cli", mode: "cli" },
      }),
    ).toContain("gateway token missing");
  });

  it("returns specific message for Control UI clients (known)", () => {
    expect(
      formatGatewayAuthFailureMessage({
        authMode: "token",
        authProvided: "none",
        client: { id: "openclaw-control-ui", mode: "ui" },
      }),
    ).toContain("gateway token missing");
  });

  it("returns specific message for webchat clients (known)", () => {
    expect(
      formatGatewayAuthFailureMessage({
        authMode: "password",
        authProvided: "none",
        client: { id: "webchat-ui", mode: "webchat" },
      }),
    ).toContain("gateway password missing");
  });
});
