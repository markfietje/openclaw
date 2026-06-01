import { describe, expect, it } from "vitest";
import { CORE_GATEWAY_METHOD_SPECS } from "../../../src/gateway/methods/core-descriptors.js";
import {
  authorizeMessage,
  createMessageAuthContext,
  resolveMessageAuthorizationDecision,
} from "./message-auth.js";

function createCtx(params: { role?: string; scopes?: string[] }) {
  return createMessageAuthContext({
    clientId: "message-auth-test",
    endpoint: "gateway",
    ...(params.role ? { role: params.role } : {}),
    ...(params.scopes ? { scopes: params.scopes } : {}),
  });
}

describe("gateway message authorization", () => {
  it("resolves every core gateway descriptor to a message authorization decision", () => {
    const missing = CORE_GATEWAY_METHOD_SPECS.filter((spec) => {
      const decision = resolveMessageAuthorizationDecision(`gateway.method.${spec.name}`);
      return decision === undefined;
    }).map((spec) => spec.name);

    expect(missing).toEqual([]);
  });

  it("uses descriptor scopes instead of stale static capability coverage", () => {
    const readCtx = createCtx({ role: "operator", scopes: ["admin:read"] });
    const readResult = authorizeMessage(readCtx, "gateway.method.diagnostics.stability", {
      requireCapabilityForAll: true,
      logDenied: false,
    });
    expect(readResult).toMatchObject({ ok: true, capability: "admin:read" });

    const writeCtx = createCtx({ role: "operator", scopes: ["admin:write"] });
    const writeResult = authorizeMessage(writeCtx, "gateway.method.tasks.cancel", {
      requireCapabilityForAll: true,
      logDenied: false,
    });
    expect(writeResult).toMatchObject({ ok: true, capability: "admin:write" });
  });

  it("keeps node-role descriptors behind node role authorization", () => {
    const nodeCtx = createCtx({ role: "node", scopes: [] });
    const allowed = authorizeMessage(nodeCtx, "gateway.method.node.pluginSurface.refresh", {
      requireCapabilityForAll: true,
      logDenied: false,
    });
    expect(allowed).toMatchObject({ ok: true, capability: "role:node" });

    const operatorCtx = createCtx({ role: "operator", scopes: ["admin:write"] });
    const denied = authorizeMessage(operatorCtx, "gateway.method.node.pluginSurface.refresh", {
      requireCapabilityForAll: true,
      logDenied: false,
    });
    expect(denied.ok).toBe(false);
    if (!denied.ok) {
      expect(denied.missingCapability).toBe("role:node");
    }
  });

  it("honors the live method registry when supplied", () => {
    const registry = {
      getScope: (name: string) => (name === "plugin.example.read" ? "operator.read" : undefined),
    };
    const ctx = createCtx({ role: "operator", scopes: ["admin:read"] });

    const result = authorizeMessage(ctx, "gateway.method.plugin.example.read", {
      methodRegistry: registry,
      requireCapabilityForAll: true,
      logDenied: false,
    });

    expect(result).toMatchObject({ ok: true, capability: "admin:read" });
  });
});
