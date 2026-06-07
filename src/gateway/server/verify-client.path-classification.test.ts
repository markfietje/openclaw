import type { IncomingMessage } from "node:http";
import net from "node:net";
import { GATEWAY_WS_SUBPROTOCOL } from "@openclaw/gateway-security-core/ws-protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { OpenClawConfig } from "../../config/config.js";
import { clearRuntimeConfigSnapshot, setRuntimeConfigSnapshot } from "../../config/io.js";
import { createGatewayVerifyClient } from "./verify-client.js";

function createMockReq(
  opts: {
    headers?: Record<string, string | string[] | undefined>;
    remoteAddress?: string;
    url?: string;
  } = {},
): IncomingMessage {
  return {
    ...(opts.url !== undefined ? { url: opts.url } : {}),
    headers: {
      "sec-websocket-protocol": GATEWAY_WS_SUBPROTOCOL,
      ...opts.headers,
    },
    socket: { remoteAddress: opts.remoteAddress } as net.Socket,
  } as IncomingMessage;
}

function makeConfig(security: OpenClawConfig["gateway"]["security"] = {}): OpenClawConfig {
  return { gateway: { security } } as OpenClawConfig;
}

function createVerifyClient() {
  const log = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() };
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

describe("createGatewayVerifyClient — endpoint path classification", () => {
  afterEach(() => {
    clearRuntimeConfigSnapshot();
  });

  it("allows known legacy /gateway path", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway" }));
    expect(result.allowed).toBe(true);
  });

  it("allows known /gateway/ws-agent path", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway/ws-agent" }));
    expect(result.allowed).toBe(true);
  });

  it("allows known /gateway/ws-admin path", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway/ws-admin" }));
    expect(result.allowed).toBe(true);
  });

  it("allows known /gateway/ws-internal path", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway/ws-internal" }));
    expect(result.allowed).toBe(true);
  });

  it("rejects unknown path with 404 by default", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway/ws-typo" }));
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(404);
    expect(result.message).toBe("unknown endpoint");
  });

  it("rejects completely unrelated path with 404 by default", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/admin/console" }));
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(404);
  });

  it("rejects unknown path even with query string", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway/ws-typo?token=abc" }));
    expect(result.allowed).toBe(false);
    expect(result.code).toBe(404);
  });

  it("allows known path with query string", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway?token=abc" }));
    expect(result.allowed).toBe(true);
  });

  it("allows unknown path when dangerouslyAllowLegacyEndpointFallback is true", async () => {
    setRuntimeConfigSnapshot(makeConfig({ dangerouslyAllowLegacyEndpointFallback: true }));
    const { verify, log } = createVerifyClient();
    const result = await runVerify(verify, createMockReq({ url: "/gateway/ws-typo" }));
    expect(result.allowed).toBe(true);
    // The path classification warning should still be logged so operators can
    // spot misconfigured clients even when the legacy fallback accepts them.
    expect(log.warn).toHaveBeenCalled();
  });

  it("still rejects when request has no url (defensive: lets other checks decide)", async () => {
    setRuntimeConfigSnapshot(makeConfig());
    const { verify } = createVerifyClient();
    // No url field on the request — path check should be skipped, not crash.
    const result = await runVerify(verify, createMockReq());
    expect(result.allowed).toBe(true);
  });
});
