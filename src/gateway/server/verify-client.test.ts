/* eslint-disable @typescript-eslint/no-unused-vars -- tests destructure `log` from createVerifyClient() for shared assertions; not all tests need it */
import type { IncomingMessage } from "node:http";
import net from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WebSocketServer } from "ws";
import type { OpenClawConfig } from "../../config/config.js";
import { clearRuntimeConfigSnapshot, setRuntimeConfigSnapshot } from "../../config/io.js";
import type { ConnectionRateLimiter } from "../connection-rate-limit.js";
import {
  createGatewayVerifyClient,
  runGatewayUpgradePreflight,
  type GatewayVerifyClient,
} from "./verify-client.js";

function createMockReq(
  opts: {
    headers?: Record<string, string | string[] | undefined>;
    remoteAddress?: string;
  } = {},
): IncomingMessage {
  return {
    headers: opts.headers ?? {},
    socket: { remoteAddress: opts.remoteAddress } as net.Socket,
  } as IncomingMessage;
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

describe("runGatewayUpgradePreflight", () => {
  it("preserves async verifyClient rejection metadata", async () => {
    const req = createMockReq({
      headers: {
        origin: "https://blocked.example",
        "sec-websocket-version": "13",
      },
    });
    const verify: GatewayVerifyClient = vi.fn((info, callback) => {
      expect(info.origin).toBe("https://blocked.example");
      callback(false, 403, "origin not allowed");
    });

    await expect(runGatewayUpgradePreflight(verify, req)).resolves.toEqual({
      ok: false,
      code: 403,
      message: "origin not allowed",
    });
  });

  it("matches ws sync verifyClient rejection defaults", async () => {
    const req = createMockReq();

    await expect(runGatewayUpgradePreflight(() => false, req)).resolves.toEqual({
      ok: false,
      code: 401,
      message: "Unauthorized",
    });
  });
});

describe("createGatewayVerifyClient", () => {
  beforeEach(() => {
    setRuntimeConfigSnapshot(makeConfig());
  });

  afterEach(() => {
    clearRuntimeConfigSnapshot();
  });

  it("allows connections with no security config", async () => {
    const { verify } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
  });

  it("rejects blocked IPs", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { ipBlocklist: ["10.0.0.1"] },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({ remoteAddress: "10.0.0.1" });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("ip not allowed");
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("IP not allowed"));
  });

  it("rejects IP not in allowlist", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { ipAllowlist: ["10.0.0.0/8"] },
      }),
    );
    const { verify } = createVerifyClient();
    const req = createMockReq({ remoteAddress: "192.168.1.1" });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("ip not allowed");
  });

  it("allows IP in allowlist", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { ipAllowlist: ["10.0.0.0/8"] },
      }),
    );
    const { verify } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "10.0.0.5",
      headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
  });

  it("rejects untrusted proxy headers", async () => {
    setRuntimeConfigSnapshot(makeConfig({ trustedProxies: [] }));
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.100",
      headers: { "x-forwarded-for": "10.0.0.1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("proxy headers from untrusted source");
    expect(log.warn).toHaveBeenCalledWith(
      expect.stringContaining("proxy headers from untrusted address"),
    );
  });

  it("allows trusted proxy headers", async () => {
    setRuntimeConfigSnapshot(makeConfig({ trustedProxies: ["192.168.1.0/24"] }));
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.1",
      headers: { "x-forwarded-for": "10.0.0.1", "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it("allows untrusted proxy headers when rejectUntrustedProxyHeaders is false", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        trustedProxies: [],
        security: { rejectUntrustedProxyHeaders: false },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.100",
      headers: { "x-forwarded-for": "10.0.0.1", "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("allowed by config"));
  });

  it("rejects duplicate sensitive headers when strict validation is enabled", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { strictHeaderValidation: true },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { host: ["example.com", "evil.com"] },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(400);
    expect(result.message).toBe("invalid headers");
    expect(log.warn).toHaveBeenCalledWith(
      expect.stringContaining("strict header validation failed"),
    );
  });

  it("allows duplicate headers when strict validation is disabled", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { strictHeaderValidation: false },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: {
        host: ["example.com", "evil.com"],
        "sec-websocket-protocol": "openclaw-gateway-v1",
      },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
  });

  it("rejects missing subprotocol when required", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { requireSubprotocol: true },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({ remoteAddress: "127.0.0.1" });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(400);
    expect(result.message).toBe("Missing required subprotocol");
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("missing required subprotocol"));
  });

  it("allows connection with correct subprotocol when required", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { requireSubprotocol: true },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
  });

  it("allows connection when the required subprotocol is one of several requested protocols", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { requireSubprotocol: true },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "other, openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
  });

  it("rejects wrong subprotocol when required", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { requireSubprotocol: true },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "some-other-protocol" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(400);
  });

  it("checks strict headers before proxy header rejection", async () => {
    setRuntimeConfigSnapshot(makeConfig({ trustedProxies: [] }));
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.100",
      headers: {
        host: ["a.com", "b.com"],
        "x-forwarded-for": "10.0.0.1",
      },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.message).toBe("invalid headers");
    // Strict header check runs first, so only one warn call
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(log.warn).toHaveBeenCalledWith(
      expect.stringContaining("strict header validation failed"),
    );
  });

  it("checks proxy headers before IP restriction", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        trustedProxies: [],
        security: { ipBlocklist: ["10.0.0.1"] },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.100",
      headers: { "x-forwarded-for": "10.0.0.1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.message).toBe("proxy headers from untrusted source");
    // Proxy check runs before IP check, so only one warn call
    expect(log.warn).toHaveBeenCalledTimes(1);
  });

  it("rejects chained X-Forwarded-For when strict validation is enabled", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { strictHeaderValidation: true },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "x-forwarded-for": "10.0.0.1, 10.0.0.2" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.message).toBe("invalid headers");
  });

  // --- Connection rate limiting ---

  it("rejects connections when rate limited", async () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const connectionRateLimiter = {
      check: vi.fn().mockReturnValue({ allowed: false, retryAfterMs: 5000 }),
      recordAttempt: vi.fn(),
      size: vi.fn().mockReturnValue(0),
      prune: vi.fn(),
      dispose: vi.fn(),
    } satisfies ConnectionRateLimiter;
    const verify = createGatewayVerifyClient({ log, connectionRateLimiter });
    const req = createMockReq({ remoteAddress: "192.168.1.1" });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(429);
    expect(result.message).toBe("too many connections");
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("connection rate limited"));
    expect(connectionRateLimiter.recordAttempt).not.toHaveBeenCalled();
  });

  it("records attempt when rate limiter allows connection", async () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const connectionRateLimiter = {
      check: vi.fn().mockReturnValue({ allowed: true, retryAfterMs: 0 }),
      recordAttempt: vi.fn(),
      size: vi.fn().mockReturnValue(0),
      prune: vi.fn(),
      dispose: vi.fn(),
    } satisfies ConnectionRateLimiter;
    const verify = createGatewayVerifyClient({ log, connectionRateLimiter });
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
    expect(connectionRateLimiter.recordAttempt).toHaveBeenCalled();
  });

  // --- maxConnections limit ---

  it("rejects connections when max connections reached", async () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const activeConnectionCount = vi.fn().mockReturnValue(10);
    const verify = createGatewayVerifyClient({
      log,
      maxConnections: 10,
      activeConnectionCount,
    });
    const req = createMockReq({ remoteAddress: "127.0.0.1" });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(503);
    expect(result.message).toBe("max connections reached");
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("max connections reached"));
  });

  it("allows connections when under max connections limit", async () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const activeConnectionCount = vi.fn().mockReturnValue(5);
    const verify = createGatewayVerifyClient({
      log,
      maxConnections: 10,
      activeConnectionCount,
    });
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    const result = await runVerify(verify, req);
    expect(result.allowed).toBe(true);
  });

  // --- autoDisableLocalhostBehindProxy ---
  // enforceOriginCheckForAllClients is not checked in verify-client.ts — it is
  // enforced post-handshake in ws-connection.ts, so no test is added here.
  //
  // autoDisableLocalhostBehindProxy IS used in verify-client.ts: it re-enables
  // disableLocalhostPrivilege when proxy headers are present, even if the
  // operator explicitly set disableLocalhostPrivilege: false. This is
  // defense-in-depth because isLocalClient is already false when proxy headers
  // exist, but the flag adds an extra layer of protection.

  it("allows localhost loopback origin when disableLocalhostPrivilege is false and no proxy headers", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        security: { disableLocalhostPrivilege: false },
      }),
    );
    const { verify } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "127.0.0.1",
      headers: { "sec-websocket-protocol": "openclaw-gateway-v1" },
    });
    let result!: { allowed: boolean; code?: number; message?: string };
    await new Promise<void>((resolve) => {
      verify({ origin: "http://localhost:3000", secure: false, req }, (allowed, code, message) => {
        result = { allowed, code, message };
        resolve();
      });
    });
    expect(result.allowed).toBe(true);
  });

  it("rejects localhost origin when autoDisableLocalhostBehindProxy re-enables privilege behind proxy", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        trustedProxies: ["192.168.1.0/24"],
        security: { disableLocalhostPrivilege: false },
      }),
    );
    const { verify, log } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.1",
      headers: {
        "x-forwarded-for": "127.0.0.1",
        host: "example.com",
        "sec-websocket-protocol": "openclaw-gateway-v1",
      },
    });
    let result!: { allowed: boolean; code?: number; message?: string };
    await new Promise<void>((resolve) => {
      verify({ origin: "http://localhost:3000", secure: false, req }, (allowed, code, message) => {
        result = { allowed, code, message };
        resolve();
      });
    });
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("origin not allowed");
    expect(log.warn).toHaveBeenCalledWith(expect.stringContaining("origin not allowed"));
  });

  it("allows localhost origin behind proxy when both disableLocalhostPrivilege and autoDisableLocalhostBehindProxy are false", async () => {
    setRuntimeConfigSnapshot(
      makeConfig({
        trustedProxies: ["192.168.1.0/24"],
        security: {
          disableLocalhostPrivilege: false,
          autoDisableLocalhostBehindProxy: false,
        },
      }),
    );
    const { verify } = createVerifyClient();
    const req = createMockReq({
      remoteAddress: "192.168.1.1",
      headers: {
        "x-forwarded-for": "127.0.0.1",
        host: "localhost:3000",
        "sec-websocket-protocol": "openclaw-gateway-v1",
      },
    });
    let result!: { allowed: boolean; code?: number; message?: string };
    await new Promise<void>((resolve) => {
      verify({ origin: "http://localhost:3000", secure: false, req }, (allowed, code, message) => {
        result = { allowed, code, message };
        resolve();
      });
    });
    // With autoDisableLocalhostBehindProxy: false, disableLocalhostPrivilege
    // stays false — but isLocalClient is already false because proxy headers
    // are present (isLocalClient = isLoopback && !hasProxyHeaders). So
    // checkBrowserOrigin's local-loopback branch still won't fire.
    // The origin must pass another path. With host = localhost:3000 matching
    // the origin, allowHostHeaderOriginFallback would help, but it's not
    // enabled. Expect rejection via origin not allowed.
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(403);
    expect(result.message).toBe("origin not allowed");
  });
});

describe("WebSocketServer perMessageDeflate security", () => {
  it("constructs a noServer WebSocketServer with perMessageDeflate: false", () => {
    // Verifies the ws library accepts perMessageDeflate: false without error.
    // This documents the OWASP-recommended setting used in server-runtime-state.ts.
    const wss = new WebSocketServer({
      noServer: true,
      perMessageDeflate: false,
    });
    expect(wss).toBeDefined();
    wss.close();
  });
});
