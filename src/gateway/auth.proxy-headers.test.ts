/**
 * Proxy header enforcement tests for the HTTP auth layer.
 *
 * IMPORTANT ARCHITECTURE NOTE:
 * As of the clean-rebase from upstream, proxy header rejection for untrusted
 * sources moved from `auth.ts` (this layer) to `verify-client.ts` (pre-handshake
 * WebSocket callback) and `ws-connection.ts` (L2 defense-in-depth).
 *
 * This means `authorizeHttpGatewayConnect()` no longer rejects requests with
 * proxy headers from untrusted IPs. That rejection now happens BEFORE the auth
 * layer is reached. The tests below verify that:
 *   1. Trusted proxy requests with headers are allowed (unchanged)
 *   2. Untrusted proxy requests with headers are allowed HERE (no longer rejected
 *      at this layer — see verify-client.test.ts for the actual rejection)
 *   3. Requests without proxy headers are allowed from any IP (unchanged)
 *
 * The same proxy header scenarios ARE tested at the verify-client layer in:
 *   src/gateway/server/verify-client.test.ts ("rejects untrusted proxy headers")
 */
import type { IncomingMessage } from "node:http";
import { describe, it, expect } from "vitest";
import { authorizeHttpGatewayConnect, type ResolvedGatewayAuth } from "./auth.js";

function createMockRequest(options: {
  remoteAddress?: string;
  headers?: Record<string, string | undefined>;
}): IncomingMessage {
  return {
    socket: {
      remoteAddress: options.remoteAddress,
    } as unknown as IncomingMessage["socket"],
    headers: options.headers || {},
  } as unknown as IncomingMessage;
}

describe("Proxy Header Enforcement", () => {
  const trustedProxyIP = "10.0.0.5";
  const untrustedIP = "1.2.3.4";
  const trustedProxies = [trustedProxyIP];

  const authNone: ResolvedGatewayAuth = {
    mode: "none",
    allowTailscale: false,
    dangerouslyAllowNoAuth: true,
  };

  describe("requests without proxy headers", () => {
    it("should allow requests without any proxy headers from any IP", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests with empty proxy headers", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-for": "",
          "x-real-ip": "  ",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(true);
    });
  });

  describe("requests with X-Forwarded-For header", () => {
    it("should allow requests from trusted proxy with X-Forwarded-For", async () => {
      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          "x-forwarded-for": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests from untrusted IP with X-Forwarded-For (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-for": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      // Proxy header rejection for untrusted sources is now handled at the
      // verify-client pre-handshake layer, not here in auth.ts.
      expect(result.ok).toBe(true);
    });

    it("should allow requests from untrusted IP with chained X-Forwarded-For", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-for": "192.168.1.100, 10.0.0.1",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      // Rejection moved to verify-client layer
      expect(result.ok).toBe(true);
    });
  });

  describe("requests with X-Real-IP header", () => {
    it("should allow requests from trusted proxy with X-Real-IP", async () => {
      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          "x-real-ip": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
        allowRealIpFallback: true,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests from untrusted IP with X-Real-IP (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-real-ip": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
        allowRealIpFallback: true,
      });

      // Rejection moved to verify-client layer
      expect(result.ok).toBe(true);
    });
  });

  describe("requests with X-Forwarded-Host header", () => {
    it("should allow requests from trusted proxy with X-Forwarded-Host", async () => {
      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          "x-forwarded-host": "example.com",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests from untrusted IP with X-Forwarded-Host (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-host": "example.com",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      // Rejection moved to verify-client layer
      expect(result.ok).toBe(true);
    });
  });

  describe("requests with X-Forwarded-Proto header", () => {
    it("should allow requests from trusted proxy with X-Forwarded-Proto", async () => {
      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          "x-forwarded-proto": "https",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests from untrusted IP with X-Forwarded-Proto (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-proto": "https",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      // Rejection moved to verify-client layer
      expect(result.ok).toBe(true);
    });
  });

  describe("requests with Forwarded header (RFC 7239)", () => {
    it("should allow requests from trusted proxy with Forwarded header", async () => {
      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          forwarded: "for=192.168.1.100;by=10.0.0.5",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests from untrusted IP with Forwarded header (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          forwarded: "for=192.168.1.100;by=10.0.0.5",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
      });

      // Rejection moved to verify-client layer
      expect(result.ok).toBe(true);
    });
  });

  describe("security scenarios", () => {
    it("should allow requests with multiple proxy headers from trusted proxy", async () => {
      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          "x-forwarded-for": "192.168.1.100",
          "x-forwarded-host": "example.com",
          "x-forwarded-proto": "https",
          "x-real-ip": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
        allowRealIpFallback: true,
      });

      expect(result.ok).toBe(true);
    });

    it("should allow requests with multiple proxy headers from untrusted IP (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-for": "192.168.1.100",
          "x-forwarded-host": "example.com",
          "x-forwarded-proto": "https",
          "x-real-ip": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
        allowRealIpFallback: true,
      });

      // Rejection moved to verify-client layer
      expect(result.ok).toBe(true);
    });

    it("should allow bypass attempts with mixed headers (rejection moved to verify-client)", async () => {
      const req = createMockRequest({
        remoteAddress: untrustedIP,
        headers: {
          "x-forwarded-for": "10.0.0.1", // Spoofed trusted IP
          "x-real-ip": "10.0.0.1",
          "x-forwarded-host": "trusted.internal",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authNone,
        req,
        trustedProxies,
        allowRealIpFallback: true,
      });

      // Rejection moved to verify-client layer — the spoofed headers would be
      // rejected at the pre-handshake verify-client check before reaching auth.
      expect(result.ok).toBe(true);
    });

    it("should still reject auth when mode requires token even from trusted proxy", async () => {
      const authToken: ResolvedGatewayAuth = {
        mode: "token",
        token: "secret-token",
        allowTailscale: false,
      };

      const req = createMockRequest({
        remoteAddress: trustedProxyIP,
        headers: {
          "x-forwarded-for": "192.168.1.100",
        },
      });

      const result = await authorizeHttpGatewayConnect({
        auth: authToken,
        req,
        trustedProxies,
      });

      expect(result.ok).toBe(false);
    });
  });
});
