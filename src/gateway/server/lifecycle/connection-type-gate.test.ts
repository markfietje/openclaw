// Connection-type capability gate tests.
// Covers node-only method restriction and pass-through for other methods.

import { describe, expect, it } from "vitest";
import {
  isMethodAllowedForConnectionType,
  resolveConnectionType,
  type ConnectionType,
} from "./connection-type-gate.js";

describe("isMethodAllowedForConnectionType", () => {
  it("allows methods not in the matrix for any connection type", () => {
    expect(isMethodAllowedForConnectionType("health", "cli")).toBe(true);
    expect(isMethodAllowedForConnectionType("health", "webchat")).toBe(true);
    expect(isMethodAllowedForConnectionType("health", "node")).toBe(true);
    expect(isMethodAllowedForConnectionType("chat.send", "ui")).toBe(true);
  });

  it("allows node-only methods for node connections", () => {
    expect(isMethodAllowedForConnectionType("node.pluginSurface.refresh", "node")).toBe(true);
    expect(isMethodAllowedForConnectionType("node.pending.drain", "node")).toBe(true);
    expect(isMethodAllowedForConnectionType("node.pending.pull", "node")).toBe(true);
    expect(isMethodAllowedForConnectionType("node.pending.ack", "node")).toBe(true);
    expect(isMethodAllowedForConnectionType("node.invoke.result", "node")).toBe(true);
    expect(isMethodAllowedForConnectionType("node.event", "node")).toBe(true);
  });

  it("rejects node-only methods for non-node connection types", () => {
    const nonNodeTypes: ConnectionType[] = [
      "cli",
      "webchat",
      "ui",
      "backend",
      "probe",
      "test",
      "mcp-loopback",
    ];
    for (const connType of nonNodeTypes) {
      expect(isMethodAllowedForConnectionType("node.pluginSurface.refresh", connType)).toBe(false);
      expect(isMethodAllowedForConnectionType("node.pending.drain", connType)).toBe(false);
      expect(isMethodAllowedForConnectionType("node.pending.pull", connType)).toBe(false);
      expect(isMethodAllowedForConnectionType("node.pending.ack", connType)).toBe(false);
      expect(isMethodAllowedForConnectionType("node.invoke.result", connType)).toBe(false);
      expect(isMethodAllowedForConnectionType("node.event", connType)).toBe(false);
    }
  });

  it("allows tools.invoke for all connection types", () => {
    // tools.invoke is called via chat.send tool flows, not just MCP loopback.
    const allTypes: ConnectionType[] = [
      "cli",
      "webchat",
      "ui",
      "backend",
      "node",
      "probe",
      "test",
      "mcp-loopback",
    ];
    for (const connType of allTypes) {
      expect(isMethodAllowedForConnectionType("tools.invoke", connType)).toBe(true);
    }
  });
});

describe("resolveConnectionType", () => {
  it("returns cli when no clientMode is provided", () => {
    expect(resolveConnectionType({})).toBe("cli");
  });

  it("returns cli for unknown clientMode", () => {
    expect(resolveConnectionType({ clientMode: "unknown" })).toBe("cli");
  });

  it("is case-insensitive", () => {
    expect(resolveConnectionType({ clientMode: "NODE" })).toBe("node");
    expect(resolveConnectionType({ clientMode: "CLI" })).toBe("cli");
  });

  it("trims whitespace", () => {
    expect(resolveConnectionType({ clientMode: "  webchat  " })).toBe("webchat");
  });

  it("resolves known client modes", () => {
    expect(resolveConnectionType({ clientMode: "webchat" })).toBe("webchat");
    expect(resolveConnectionType({ clientMode: "cli" })).toBe("cli");
    expect(resolveConnectionType({ clientMode: "ui" })).toBe("ui");
    expect(resolveConnectionType({ clientMode: "backend" })).toBe("backend");
    expect(resolveConnectionType({ clientMode: "node" })).toBe("node");
    expect(resolveConnectionType({ clientMode: "probe" })).toBe("probe");
    expect(resolveConnectionType({ clientMode: "test" })).toBe("test");
    expect(resolveConnectionType({ clientMode: "mcp-loopback" })).toBe("mcp-loopback");
  });
});
