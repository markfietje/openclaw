import { describe, expect, it } from "vitest";
import {
  WS_ENDPOINT,
  classifyWsEndpoint,
  isKnownWsEndpoint,
  getEndpointSecurity,
} from "./ws-endpoint.js";

describe("ws-endpoint", () => {
  describe("WS_ENDPOINT constants", () => {
    it("defines all four endpoints", () => {
      expect(WS_ENDPOINT.AGENT).toBe("/gateway/ws-agent");
      expect(WS_ENDPOINT.ADMIN).toBe("/gateway/ws-admin");
      expect(WS_ENDPOINT.INTERNAL).toBe("/gateway/ws-internal");
      expect(WS_ENDPOINT.LEGACY).toBe("/gateway");
    });
  });

  describe("classifyWsEndpoint", () => {
    it.each([
      { path: "/gateway/ws-agent", expected: WS_ENDPOINT.AGENT },
      { path: "/gateway/ws-admin", expected: WS_ENDPOINT.ADMIN },
      { path: "/gateway/ws-internal", expected: WS_ENDPOINT.INTERNAL },
      { path: "/gateway", expected: WS_ENDPOINT.LEGACY },
    ])("classifies $path", ({ path, expected }) => {
      expect(classifyWsEndpoint(path)).toBe(expected);
    });

    it("normalizes trailing slash", () => {
      expect(classifyWsEndpoint("/gateway/")).toBe(WS_ENDPOINT.LEGACY);
      expect(classifyWsEndpoint("/gateway/ws-agent/")).toBe(WS_ENDPOINT.AGENT);
    });

    it("falls back to LEGACY for unknown paths", () => {
      expect(classifyWsEndpoint("/gateway/ws-unknown")).toBe(WS_ENDPOINT.LEGACY);
      expect(classifyWsEndpoint("/unknown")).toBe(WS_ENDPOINT.LEGACY);
    });
  });

  describe("isKnownWsEndpoint", () => {
    it("returns true for all known endpoints", () => {
      expect(isKnownWsEndpoint("/gateway/ws-agent")).toBe(true);
      expect(isKnownWsEndpoint("/gateway/ws-admin")).toBe(true);
      expect(isKnownWsEndpoint("/gateway/ws-internal")).toBe(true);
      expect(isKnownWsEndpoint("/gateway")).toBe(true);
    });

    it("returns false for unknown paths", () => {
      expect(isKnownWsEndpoint("/gateway/ws-unknown")).toBe(false);
      expect(isKnownWsEndpoint("/unknown")).toBe(false);
      expect(isKnownWsEndpoint("/gateway/")).toBe(true);
    });
  });

  describe("getEndpointSecurity", () => {
    it("returns security config for each endpoint", () => {
      const agent = getEndpointSecurity(WS_ENDPOINT.AGENT);
      expect(agent.requireOrigin).toBe(true);
      expect(agent.requireAuth).toBe(true);
      expect(agent.allowedCapabilities).toContain("agent:read");

      const admin = getEndpointSecurity(WS_ENDPOINT.ADMIN);
      expect(admin.requireOrigin).toBe(true);
      expect(admin.allowedCapabilities).toContain("admin:config");

      const internal = getEndpointSecurity(WS_ENDPOINT.INTERNAL);
      expect(internal.requireOrigin).toBe(false);
      expect(internal.allowedCapabilities).toContain("internal:*");

      const legacy = getEndpointSecurity(WS_ENDPOINT.LEGACY);
      expect(legacy.requireOrigin).toBe(true);
      expect(legacy.allowedCapabilities).toEqual(["agent:read", "agent:write", "agent:execute"]);
    });
  });
});
