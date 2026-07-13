// Endpoint capability gate tests for the WS message handler.
//
// We test the gate via the exported `matchesEndpointCapabilities` helper
// rather than driving `attachGatewayWsMessageHandler` end-to-end. The full
// connect flow has pre-existing auth/device-pairing flakiness on this
// branch; the helper is the right unit of behavior for this gate.
import { describe, expect, it } from "vitest";
import { createMessageAuthContext } from "../../message-auth.js";
import { __testing } from "./message-handler.js";

const { matchesEndpointCapabilities } = __testing;

describe("matchesEndpointCapabilities", () => {
  it("treats undefined allowed list as no gate (back-compat)", () => {
    const ctx = createMessageAuthContext({ clientId: "c1", scopes: [], endpoint: "test" });
    expect(matchesEndpointCapabilities(ctx, undefined)).toBe(true);
  });

  it("treats empty allowed list as no gate (back-compat)", () => {
    const ctx = createMessageAuthContext({ clientId: "c1", scopes: [], endpoint: "test" });
    expect(matchesEndpointCapabilities(ctx, [])).toBe(true);
  });

  it("matches when operator.read resolves to admin:read", () => {
    const ctx = createMessageAuthContext({
      clientId: "c1",
      scopes: ["operator.read"],
      endpoint: "test",
    });
    expect(matchesEndpointCapabilities(ctx, ["admin:read", "admin:write"])).toBe(true);
  });

  it("matches when operator.admin resolves to admin:read + admin:write", () => {
    const ctx = createMessageAuthContext({
      clientId: "c1",
      scopes: ["operator.admin"],
      endpoint: "test",
    });
    expect(matchesEndpointCapabilities(ctx, ["admin:read", "admin:write"])).toBe(true);
  });

  it("matches when admin:* namespace wildcard is in the resolved caps", () => {
    const ctx = createMessageAuthContext({ clientId: "c1", scopes: ["admin:*"], endpoint: "test" });
    expect(matchesEndpointCapabilities(ctx, ["admin:read"])).toBe(true);
    expect(matchesEndpointCapabilities(ctx, ["admin:write"])).toBe(true);
  });

  it("matches when global * is in the resolved caps", () => {
    const ctx = createMessageAuthContext({ clientId: "c1", scopes: ["*"], endpoint: "test" });
    expect(matchesEndpointCapabilities(ctx, ["admin:read"])).toBe(true);
  });

  it("rejects when no resolved cap matches the allowed list", () => {
    const ctx = createMessageAuthContext({
      clientId: "c1",
      scopes: ["agent.read"],
      endpoint: "test",
    });
    expect(matchesEndpointCapabilities(ctx, ["admin:read", "admin:write"])).toBe(false);
  });

  it("rejects when scopes are empty", () => {
    const ctx = createMessageAuthContext({ clientId: "c1", scopes: [], endpoint: "test" });
    expect(matchesEndpointCapabilities(ctx, ["admin:read"])).toBe(false);
  });

  it("allows node-role connections through the endpoint gate (role-based auth)", () => {
    const ctx = createMessageAuthContext({
      clientId: "c1",
      role: "node",
      scopes: ["node.invoke"],
      endpoint: "test",
    });
    expect(matchesEndpointCapabilities(ctx, ["admin:read", "admin:write"])).toBe(true);
  });

  it("allows node-role connections with empty scopes through the endpoint gate", () => {
    const ctx = createMessageAuthContext({
      clientId: "c1",
      role: "node",
      scopes: [],
      endpoint: "test",
    });
    expect(matchesEndpointCapabilities(ctx, ["agent:read", "agent:execute"])).toBe(true);
  });
});
