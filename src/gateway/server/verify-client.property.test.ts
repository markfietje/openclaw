/**
 * Property-based tests for the verify-client pipeline.
 *
 * These tests verify invariants that hold across all possible inputs,
 * complementing the step-by-step unit tests in verify-client.test.ts.
 *
 * Uses pure Vitest with generated inputs (no fast-check dependency).
 */
import type { IncomingMessage } from "node:http";
import net from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../../config/config.js";
import { clearRuntimeConfigSnapshot, setRuntimeConfigSnapshot } from "../../config/io.js";
import { createGatewayVerifyClient } from "./verify-client.js";

// ---------------------------------------------------------------------------
// Shared helpers (same patterns as verify-client.test.ts)
// ---------------------------------------------------------------------------

function createMockReq(
  opts: {
    headers?: Record<string, string | string[] | undefined>;
    remoteAddress?: string;
  } = {},
): IncomingMessage {
  return {
    headers: opts.headers ?? {},
    socket: { remoteAddress: opts.remoteAddress } as net.Socket,
  } as unknown as IncomingMessage;
}

function makeConfig(gateway: OpenClawConfig["gateway"] = {}): OpenClawConfig {
  return { gateway } as OpenClawConfig;
}

function createVerifyClient() {
  const log = { info: vi.fn(), warn: vi.fn() };
  const verify = createGatewayVerifyClient({ log });
  return { verify, log };
}

async function runVerify(
  verify: ReturnType<typeof createVerifyClient>["verify"],
  req: IncomingMessage,
): Promise<{ allowed: boolean; code?: number; message?: string }> {
  let result!: { allowed: boolean; code?: number; message?: string };
  await new Promise<void>((resolve) => {
    verify({ origin: "", secure: false, req }, (allowed, code, message) => {
      result = { allowed, code, message };
      resolve();
    });
  });
  return result;
}

// ---------------------------------------------------------------------------
// Test data generators
// ---------------------------------------------------------------------------

const PROXY_HEADER_COMBOS: Array<Record<string, string>> = [
  { "x-forwarded-for": "1.2.3.4" },
  { "x-forwarded-host": "evil.com" },
  { "x-forwarded-proto": "https" },
  { "x-real-ip": "1.2.3.4" },
  { forwarded: "for=1.2.3.4" },
  // Combinations of multiple proxy headers
  { "x-forwarded-for": "1.2.3.4", "x-forwarded-host": "evil.com" },
  { "x-forwarded-for": "1.2.3.4", "x-forwarded-proto": "https", "x-real-ip": "5.6.7.8" },
  { forwarded: "for=1.2.3.4;host=evil.com;proto=https" },
  // All proxy headers at once
  {
    "x-forwarded-for": "1.2.3.4",
    "x-forwarded-host": "evil.com",
    "x-forwarded-proto": "https",
    "x-real-ip": "5.6.7.8",
    forwarded: "for=5.6.7.8",
  },
];

const LOOPBACK_IPS = ["127.0.0.1", "::1", "::ffff:127.0.0.1"];
const NON_LOOPBACK_IPS = [
  "192.168.1.1",
  "10.0.0.1",
  "172.16.0.1",
  "203.0.113.1",
  "198.51.100.1",
  "8.8.8.8",
];

const LOOPBACK_ORIGINS = [
  undefined,
  "",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://[::1]:3000",
];

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

describe("verify-client property tests", () => {
  beforeEach(() => {
    setRuntimeConfigSnapshot(makeConfig());
  });

  afterEach(() => {
    clearRuntimeConfigSnapshot();
  });

  // Property 1: Any proxy header from a non-trusted IP is ALWAYS rejected (403)
  // regardless of which proxy header(s) are present.
  it("always rejects proxy headers from non-trusted IPs", async () => {
    const { verify } = createVerifyClient();

    for (const headers of PROXY_HEADER_COMBOS) {
      for (const remoteIp of NON_LOOPBACK_IPS) {
        const result = await runVerify(
          verify,
          createMockReq({
            remoteAddress: remoteIp,
            headers: { ...headers, "sec-websocket-protocol": "openclaw-gateway-v1" },
          }),
        );
        expect(result.allowed).toBe(false);
        expect(result.code).toBe(403);
        expect(result.message).toBe("proxy headers from untrusted source");
      }
    }
  });

  // Property 2: Valid loopback connections with subprotocol are always allowed
  // across all loopback IPs and loopback-compatible origins.
  it("always allows valid loopback connections with subprotocol", async () => {
    const { verify } = createVerifyClient();

    for (const ip of LOOPBACK_IPS) {
      for (const origin of LOOPBACK_ORIGINS) {
        const headers: Record<string, string> = {
          "sec-websocket-protocol": "openclaw-gateway-v1",
        };
        if (origin) {
          headers["origin"] = origin;
        }

        const result = await runVerify(verify, createMockReq({ remoteAddress: ip, headers }));
        expect(result.allowed).toBe(true);
      }
    }
  });

  // Property 3: Pipeline ordering — strict header validation (step 1) runs
  // before proxy header rejection (step 2). If both issues are present, the
  // strict header error (400) should be returned, not the proxy error (403).
  it("strict header validation runs before proxy header rejection", async () => {
    const { verify, log } = createVerifyClient();

    // Combine duplicate sensitive header with proxy header from non-trusted IP
    const result = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "192.168.1.100",
        headers: {
          host: ["a.com", "b.com"], // duplicate — strict validation failure
          "x-forwarded-for": "1.2.3.4", // proxy header from non-trusted
          "sec-websocket-protocol": "openclaw-gateway-v1",
        },
      }),
    );

    expect(result.allowed).toBe(false);
    // Step 1 (strict headers) produces 400, step 2 (proxy) produces 403
    expect(result.code).toBe(400);
    expect(result.message).toBe("invalid headers");
    // Only one warn call — pipeline exited early at step 1
    expect(log.warn).toHaveBeenCalledTimes(1);
  });

  // Property 4: Proxy rejection (step 2) runs before IP restriction (step 4).
  // A connection with proxy headers from a non-trusted IP and a blocked client
  // IP should be rejected with 403 (proxy), not the IP restriction code.
  it("proxy rejection runs before IP restriction", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        trustedProxies: [],
        security: { ipBlocklist: ["192.168.1.100"] },
      }),
    );
    const { verify, log } = createVerifyClient();

    const result = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "192.168.1.100",
        headers: {
          "x-forwarded-for": "1.2.3.4",
          "sec-websocket-protocol": "openclaw-gateway-v1",
        },
      }),
    );

    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("proxy headers from untrusted source");
    // Only one warn call — pipeline exited at step 2, never reached IP check
    expect(log.warn).toHaveBeenCalledTimes(1);
  });

  // Property 5: Subprotocol check is the final step (step 5). A connection
  // that passes all earlier checks but lacks the required subprotocol is
  // rejected with 400 at the last gate.
  it("rejects missing subprotocol after passing all other checks", async () => {
    const { verify } = createVerifyClient();

    // Loopback, no proxy headers, no origin header — passes steps 0-4.
    // Missing subprotocol — fails at step 5.
    const result = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "127.0.0.1",
        headers: {},
      }),
    );

    expect(result.allowed).toBe(false);
    expect(result.code).toBe(400);
    expect(result.message).toBe("Missing required subprotocol");
  });

  // Property 6: Crash safety — the pipeline never throws for any combination
  // of inputs. Every path returns a well-formed result object.
  it("never throws for any combination of headers and IPs", async () => {
    const { verify } = createVerifyClient();

    const headerCombos: Array<Record<string, string | string[] | undefined>> = [
      {},
      { "sec-websocket-protocol": "openclaw-gateway-v1" },
      { "sec-websocket-protocol": "openclaw-gateway-v1, other" },
      { "sec-websocket-protocol": "other-protocol" },
      { origin: "https://example.com", "sec-websocket-protocol": "openclaw-gateway-v1" },
      { "x-forwarded-for": "1.2.3.4" },
      { "x-forwarded-host": "evil.com", origin: "https://evil.com" },
      {
        host: "example.com",
        origin: "https://example.com",
        "sec-websocket-protocol": "openclaw-gateway-v1",
      },
      { forwarded: "for=1.2.3.4;host=evil.com;proto=https" },
      { host: ["a.com", "b.com"] }, // duplicate headers
      { "sec-websocket-protocol": "" },
      { "sec-websocket-version": "8" },
      { "sec-fetch-site": "cross-site" },
      { "x-forwarded-for": "1.2.3.4, 10.0.0.1" }, // chained
      { origin: "null" },
    ];

    const allIps = [
      ...LOOPBACK_IPS,
      ...NON_LOOPBACK_IPS,
      "unknown",
      "",
      undefined as unknown as string,
    ];

    for (const headers of headerCombos) {
      for (const ip of allIps) {
        const result = await runVerify(verify, createMockReq({ remoteAddress: ip, headers }));
        expect(typeof result.allowed).toBe("boolean");
        if (!result.allowed) {
          expect(typeof result.code).toBe("number");
          expect(typeof result.message).toBe("string");
        }
      }
    }
  });

  // Property 7: When rejectUntrustedProxyHeaders is explicitly disabled,
  // proxy headers from non-trusted IPs are allowed through (but still logged).
  it("allows proxy headers from non-trusted IPs when disabled", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        trustedProxies: [],
        security: { rejectUntrustedProxyHeaders: false },
      }),
    );
    const { verify, log } = createVerifyClient();

    for (const headers of PROXY_HEADER_COMBOS) {
      log.warn.mockClear();

      const result = await runVerify(
        verify,
        createMockReq({
          remoteAddress: "192.168.1.100",
          headers: { ...headers, "sec-websocket-protocol": "openclaw-gateway-v1" },
        }),
      );

      // Should be allowed (proxy rejection disabled) but logged as warning
      expect(result.allowed).toBe(true);
      expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("allowed by config"));
    }
  });

  // Property 8: Blocklisted IPs are always rejected regardless of other factors.
  // Tests CIDR range matching covers the entire block.
  it("always rejects blocklisted IPs", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { ipBlocklist: ["10.0.0.0/8"] },
      }),
    );
    const { verify } = createVerifyClient();

    const blockedIps = ["10.0.0.1", "10.1.2.3", "10.255.255.255", "10.128.0.1"];
    for (const ip of blockedIps) {
      const result = await runVerify(
        verify,
        createMockReq({
          remoteAddress: ip,
          headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
        }),
      );
      expect(result.allowed).toBe(false);
      expect(result.code).toBe(403);
      expect(result.message).toBe("ip not allowed");
    }
  });

  // Property 9: Allowlist-only mode — unknown IPs fail closed.
  // Only IPs within the allowlist CIDR range are accepted.
  it("rejects IPs not in allowlist when allowlist is set", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { ipAllowlist: ["192.168.1.0/24"] },
      }),
    );
    const { verify } = createVerifyClient();

    // IPs in range — should be allowed
    const allowedIps = ["192.168.1.1", "192.168.1.50", "192.168.1.254"];
    for (const ip of allowedIps) {
      const result = await runVerify(
        verify,
        createMockReq({
          remoteAddress: ip,
          headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
        }),
      );
      expect(result.allowed).toBe(true);
    }

    // IPs outside range — should be rejected
    const rejectedIps = ["192.168.2.1", "192.168.0.1", "10.0.0.1", "172.16.0.1", "8.8.8.8"];
    for (const ip of rejectedIps) {
      const result = await runVerify(
        verify,
        createMockReq({
          remoteAddress: ip,
          headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
        }),
      );
      expect(result.allowed).toBe(false);
      expect(result.code).toBe(403);
    }
  });

  // Property 10: Blocklist takes precedence over allowlist.
  // An IP present in both lists must be blocked.
  it("blocklist takes precedence over allowlist", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: {
          ipAllowlist: ["10.0.0.0/8"],
          ipBlocklist: ["10.0.0.1"],
        },
      }),
    );
    const { verify } = createVerifyClient();

    // IP is in both allowlist and blocklist → blocklist wins
    const result = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "10.0.0.1",
        headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
      }),
    );
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("ip not allowed");

    // Another IP in the allowlist range but NOT in the blocklist → allowed
    const allowed = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "10.0.0.2",
        headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
      }),
    );
    expect(allowed.allowed).toBe(true);
  });

  // Property 11: maxConnections gate rejects before all other checks.
  // Regardless of headers, IP, or subprotocol, 503 is returned immediately.
  it("max connection limit rejects before all other checks", async () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const activeConnectionCount = vi.fn().mockReturnValue(5);
    const verify = createGatewayVerifyClient({
      log,
      maxConnections: 5,
      activeConnectionCount,
    });

    // Even a valid loopback connection with subprotocol should be rejected
    const result = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "127.0.0.1",
        headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
      }),
    );
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(503);
    expect(result.message).toBe("max connections reached");
  });

  // Property 12: Rate limiting rejects before all checks after connection count.
  // A rate-limited IP gets 429 regardless of other headers.
  it("rate limiting rejects before security checks", async () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const connectionRateLimiter = {
      check: vi.fn().mockReturnValue({ allowed: false, retryAfterMs: 5000 }),
      recordAttempt: vi.fn(),
      size: vi.fn().mockReturnValue(1),
      prune: vi.fn(),
      dispose: vi.fn(),
    };
    const verify = createGatewayVerifyClient({ log, connectionRateLimiter });

    const result = await runVerify(
      verify,
      createMockReq({
        remoteAddress: "127.0.0.1",
        headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
      }),
    );
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(429);
    expect(result.message).toBe("too many connections");
    // recordAttempt must NOT be called when rate-limited
    expect(connectionRateLimiter.recordAttempt).not.toHaveBeenCalled();
  });

  // Property 13: Every rejection produces a non-empty message.
  // The error message is sent in the HTTP response body — it must be informative.
  it("every rejection has a non-empty message", async () => {
    const { verify } = createVerifyClient();

    const rejectionCases: Array<{
      desc: string;
      remoteAddress: string;
      headers: Record<string, string | string[] | undefined>;
      config?: OpenClawConfig["gateway"];
    }> = [
      {
        desc: "missing subprotocol",
        remoteAddress: "127.0.0.1",
        headers: {},
      },
      {
        desc: "wrong subprotocol",
        remoteAddress: "127.0.0.1",
        headers: { "sec-websocket-protocol": "wrong" },
      },
      {
        desc: "proxy headers from untrusted",
        remoteAddress: "192.168.1.1",
        headers: { "x-forwarded-for": "1.2.3.4", "sec-websocket-protocol": "openclaw-gateway-v1" },
      },
      {
        desc: "duplicate host header",
        remoteAddress: "127.0.0.1",
        headers: { host: ["a.com", "b.com"] },
      },
      {
        desc: "blocklisted IP",
        remoteAddress: "10.0.0.1",
        headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
        config: { security: { ipBlocklist: ["10.0.0.1"] } },
      },
      {
        desc: "chained x-forwarded-for",
        remoteAddress: "127.0.0.1",
        headers: { "x-forwarded-for": "1.2.3.4, 5.6.7.8" },
      },
    ];

    for (const { desc: _desc, remoteAddress, headers, config } of rejectionCases) {
      if (config) {
        setRuntimeConfigSnapshot(makeConfig(config));
      }

      const result = await runVerify(verify, createMockReq({ remoteAddress, headers }));

      expect(result.allowed).toBe(false);
      expect(result.code).toBeGreaterThanOrEqual(400);
      expect(result.message).toBeTruthy();
      expect(result.message!.length).toBeGreaterThan(0);

      if (config) {
        setRuntimeConfigSnapshot(makeConfig());
      }
    }
  });

  // Property 14: Rejection codes form a closed set matching pipeline steps.
  // The pipeline only produces: 400 (bad request), 403 (forbidden),
  // 429 (rate limit), 503 (max connections).
  it("rejection codes belong to the known set {400, 403, 429, 503}", async () => {
    const { verify } = createVerifyClient();

    const allHeaders: Array<Record<string, string | string[] | undefined>> = [
      {},
      { "sec-websocket-protocol": "openclaw-gateway-v1" },
      { "x-forwarded-for": "1.2.3.4" },
      { host: ["a", "b"] },
      { "sec-websocket-protocol": "wrong" },
      { origin: "https://evil.com" },
      { forwarded: "for=1.2.3.4" },
    ];
    const ips = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "unknown"];
    const validCodes = new Set([400, 403, 429, 503]);

    for (const headers of allHeaders) {
      for (const ip of ips) {
        const result = await runVerify(verify, createMockReq({ remoteAddress: ip, headers }));
        if (!result.allowed) {
          expect(validCodes.has(result.code!)).toBe(true);
        }
      }
    }
  });

  // Property 15: Trusted proxies with proxy headers are allowed through.
  // Connections from IPs in the trustedProxies CIDR range can send proxy
  // headers without being rejected at step 2.
  it("trusted proxies can send proxy headers without rejection", async () => {
    setRuntimeConfigSnapshot(makeConfig({ trustedProxies: ["192.168.1.0/24"] }));
    const { verify, log } = createVerifyClient();

    for (const headers of PROXY_HEADER_COMBOS) {
      log.warn.mockClear();

      const result = await runVerify(
        verify,
        createMockReq({
          remoteAddress: "192.168.1.1",
          headers: { ...headers, "sec-websocket-protocol": "openclaw-gateway-v1" },
        }),
      );

      // Trusted proxy — should not be rejected for proxy headers
      // (may still fail at origin check depending on headers, but not 403 proxy)
      if (result.allowed) {
        // All good — trusted proxy path succeeded
      } else if (result.code === 403 && result.message === "proxy headers from untrusted source") {
        // This should NOT happen for trusted proxies
        expect.unreachable("trusted proxy should not be rejected for proxy headers");
      }
      // Other rejections (origin, etc.) are acceptable
    }
  });
});
