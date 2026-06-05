import { describe, expect, it } from "vitest";
import {
  authorizeMessage,
  createMessageAuthContext,
  resolveMessageAuthorizationDecision,
} from "./message-auth.js";
import { CORE_GATEWAY_METHOD_SPECS } from "./methods/core-descriptors.js";

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

  it("denies when scopes are empty against a capability-gated method", () => {
    const ctx = createCtx({ role: "operator", scopes: [] });
    const result = authorizeMessage(ctx, "gateway.method.diagnostics.stability", {
      requireCapabilityForAll: true,
      logDenied: false,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.missingCapability).toBeDefined();
    }
  });

  it("allows unknown methods when no decision is resolved", () => {
    const decision = resolveMessageAuthorizationDecision("gateway.method.nonexistent");
    expect(decision).toBeUndefined();
  });

  it("denies subset scope against a write-gated method", () => {
    const ctx = createCtx({ role: "operator", scopes: ["admin:read"] });
    const result = authorizeMessage(ctx, "gateway.method.tasks.cancel", {
      requireCapabilityForAll: true,
      logDenied: false,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.missingCapability).toContain("admin:write");
    }
  });

  it("denies when scopes are empty even with requireCapabilityForAll false", () => {
    const ctx = createCtx({ role: "operator", scopes: [] });
    const result = authorizeMessage(ctx, "gateway.method.diagnostics.stability", {
      requireCapabilityForAll: false,
      logDenied: false,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.missingCapability).toBeDefined();
    }
  });

  it("denies when role is missing against a role-gated method", () => {
    const ctx = createCtx({ scopes: ["admin:write"] });
    const decision = resolveMessageAuthorizationDecision(
      "gateway.method.node.pluginSurface.refresh",
    );
    if (decision?.kind === "role") {
      const result = authorizeMessage(ctx, "gateway.method.node.pluginSurface.refresh", {
        requireCapabilityForAll: true,
        logDenied: false,
      });
      expect(result.ok).toBe(false);
    }
  });
});
