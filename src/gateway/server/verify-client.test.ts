import { describe, it, expect } from "vitest";
import type { OpenClawConfig } from "../../config/config.js";
import { createGatewayVerifyClient } from "./verify-client.js";

function makeReq(opts: {
  remoteAddress?: string;
  headers?: Record<string, string>;
  origin?: string;
}): Parameters<ReturnType<typeof createGatewayVerifyClient>>[0] {
  return {
    req: { socket: { remoteAddress: opts.remoteAddress }, headers: opts.headers ?? {} },
    origin: opts.origin,
  } as never;
}

function verifyOk(opts: Parameters<typeof makeReq>[0]): Promise<boolean> {
  const verifyClient = createGatewayVerifyClient({
    log: { info: () => {}, warn: () => {} },
    getConfigSnapshot: () => baseCfg,
  });
  return new Promise((resolve) => {
    verifyClient(makeReq(opts), (ok: boolean) => resolve(ok));
  });
}

const baseCfg = {
  gateway: {
    trustedProxies: ["127.0.0.1/32"],
    security: {},
    controlUi: { allowedOrigins: ["https://app.example.com"] },
  },
} as unknown as OpenClawConfig;

describe("gateway verifyClient", () => {
  // Regression for rejected PR #35109: the trusted-proxy flag was never wired at
  // the call site, so every X-Forwarded request from a trusted proxy was rejected.
  // These two cases prove gateway.trustedProxies is actually read from config.
  it("accepts a plaintext request from a trusted proxy presenting X-Forwarded-Proto", async () => {
    expect(
      await verifyOk({
        remoteAddress: "127.0.0.1",
        origin: "https://app.example.com",
        headers: {
          host: "gateway.internal",
          "x-forwarded-host": "app.example.com",
          "x-forwarded-proto": "https",
        },
      }),
    ).toBe(true);
  });

  it("rejects the identical request from an untrusted peer", async () => {
    expect(
      await verifyOk({
        remoteAddress: "198.51.100.7",
        origin: "https://app.example.com",
        headers: {
          host: "gateway.internal",
          "x-forwarded-host": "app.example.com",
          "x-forwarded-proto": "https",
        },
      }),
    ).toBe(false);
  });

  it("rejects cross-site websocket initiations from a browser", async () => {
    expect(
      await verifyOk({
        remoteAddress: "192.0.2.10",
        origin: "https://evil.example.com",
        headers: { host: "gateway.internal", "sec-fetch-site": "cross-site" },
      }),
    ).toBe(false);
  });

  it("passes non-browser clients that send no Origin header", async () => {
    expect(
      await verifyOk({ remoteAddress: "192.0.2.10", headers: { host: "gateway.internal" } }),
    ).toBe(true);
  });

  it("rejects a literal 'null' browser origin instead of skipping the gate", async () => {
    expect(
      await verifyOk({
        remoteAddress: "192.0.2.10",
        origin: "null",
        headers: { host: "gateway.internal", "sec-fetch-site": "cross-site" },
      }),
    ).toBe(false);
  });
});
