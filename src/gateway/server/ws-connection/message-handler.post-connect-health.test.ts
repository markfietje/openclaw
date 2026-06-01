import type { IncomingMessage } from "node:http";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { WebSocket } from "ws";
import { PROTOCOL_VERSION } from "../../../../packages/gateway-protocol/src/index.js";
import type { HealthSummary } from "../../../commands/health.types.js";
import type { ResolvedGatewayAuth } from "../../auth.js";
import { getOperatorApprovalRuntimeToken } from "../../operator-approval-runtime-token.js";
import type { GatewayRequestContext } from "../../server-methods/types.js";

const {
  buildGatewaySnapshotMock,
  getHealthCacheMock,
  getHealthVersionMock,
  incrementPresenceVersionMock,
  loadConfigMock,
  upsertPresenceMock,
} = vi.hoisted(() => ({
  buildGatewaySnapshotMock: vi.fn(() => ({
    presence: [],
    health: {},
    stateVersion: { presence: 1, health: 1 },
    uptimeMs: 1,
    sessionDefaults: {
      defaultAgentId: "main",
      mainKey: "main",
      mainSessionKey: "main",
      scope: "per-sender",
    },
  })),
  getHealthCacheMock: vi.fn(() => null),
  getHealthVersionMock: vi.fn(() => 1),
  incrementPresenceVersionMock: vi.fn(() => 2),
  loadConfigMock: vi.fn(() => ({
    gateway: {
      auth: { mode: "none" },
      controlUi: {
        allowedOrigins: ["http://127.0.0.1:19001"],
        dangerouslyDisableDeviceAuth: true,
      },
    },
  })),
  upsertPresenceMock: vi.fn(),
}));

vi.mock("../../../config/config.js", () => ({
  getRuntimeConfig: loadConfigMock,
  loadConfig: loadConfigMock,
}));

vi.mock("../../../config/io.js", () => ({
  getRuntimeConfig: loadConfigMock,
}));
vi.mock("../../../infra/system-presence.js", () => ({
  upsertPresence: upsertPresenceMock,
}));

vi.mock("../../server-methods.js", () => ({
  handleGatewayRequest: vi.fn(),
}));

vi.mock("../health-state.js", () => ({
  buildGatewaySnapshot: buildGatewaySnapshotMock,
  getHealthCache: getHealthCacheMock,
  getHealthVersion: getHealthVersionMock,
  incrementPresenceVersion: incrementPresenceVersionMock,
}));

import { handleGatewayRequest } from "../../server-methods.js";
import { __testing, attachGatewayWsMessageHandler } from "./message-handler.js";

function createLogger() {
  return {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  };
}

function createHealthSummary(): HealthSummary {
  return {
    ok: true,
    ts: 1,
    durationMs: 1,
    channels: {},
    channelOrder: [],
    channelLabels: {},
    heartbeatSeconds: 0,
    defaultAgentId: "main",
    agents: [],
    sessions: {
      path: "",
      count: 0,
      recent: [],
    },
  };
}

function attachGatewayHarness(options: {
  connId: string;
  connectNonce: string;
  refreshHealthSnapshot: GatewayRequestContext["refreshHealthSnapshot"];
  requestOrigin?: string;
  isClosed?: () => boolean;
}) {
  const socketSend = vi.fn((_payload: string, cb?: (err?: Error) => void) => {
    cb?.();
  });
  let onMessage: ((data: string) => void) | undefined;
  const socket = {
    _receiver: {},
    send: socketSend,
    on: vi.fn((event: string, handler: (data: string) => void) => {
      if (event === "message") {
        onMessage = handler;
      }
      return socket;
    }),
  } as unknown as WebSocket;
  const send = vi.fn();
  const close = vi.fn();
  const setCloseCause = vi.fn();
  let client: unknown = null;
  const resolvedAuth: ResolvedGatewayAuth = {
    mode: "none",
    allowTailscale: false,
  };
  attachGatewayWsMessageHandler({
    socket,
    upgradeReq: {
      url: "/gateway",
      headers: {
        host: "127.0.0.1:19001",
        ...(options.requestOrigin ? { origin: options.requestOrigin } : {}),
      },
      socket: { localAddress: "127.0.0.1", remoteAddress: "127.0.0.1" },
    } as unknown as IncomingMessage,
    connId: options.connId,
    remoteAddr: "127.0.0.1",
    localAddr: "127.0.0.1",
    requestHost: "127.0.0.1:19001",
    requestOrigin: options.requestOrigin,
    connectNonce: options.connectNonce,
    getResolvedAuth: () => resolvedAuth,
    gatewayMethods: [],
    events: [],
    extraHandlers: {},
    buildRequestContext: () => ({}) as GatewayRequestContext,
    refreshHealthSnapshot: options.refreshHealthSnapshot,
    send,
    close,
    isClosed: options.isClosed ?? vi.fn(() => false),
    clearHandshakeTimer: vi.fn(),
    getClient: () => client as never,
    setClient: (next) => {
      client = next;
      return true;
    },
    setHandshakeState: vi.fn(),
    setCloseCause,
    setLastFrameMeta: vi.fn(),
    originCheckMetrics: { hostHeaderFallbackAccepted: 0 },
    logGateway: createLogger() as never,
    logHealth: createLogger() as never,
    logWsControl: createLogger() as never,
  });
  if (onMessage === undefined) {
    throw new Error("expected websocket message handler");
  }
  const sendMessage = onMessage;
  return {
    socketSend,
    close,
    setCloseCause,
    sendRaw: sendMessage,
    sendConnect: (id: string, params: Record<string, unknown>) => {
      sendMessage(
        JSON.stringify({
          type: "req",
          id,
          method: "connect",
          params,
        }),
      );
    },
    get client() {
      return client;
    },
  };
}

describe("attachGatewayWsMessageHandler post-connect health refresh", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("closes invalidated clients before dispatching queued requests", async () => {
    const harness = attachGatewayHarness({
      connId: "conn-invalidated",
      connectNonce: "nonce-invalidated",
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
    });

    harness.sendConnect("connect-invalidated", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-tui",
        version: "dev",
        platform: "test",
        mode: "cli",
      },
      role: "operator",
      scopes: ["operator.read"],
      caps: [],
    });

    await vi.waitFor(() => {
      expect(harness.client).not.toBeNull();
    });
    const client = harness.client as { invalidated?: boolean; invalidatedReason?: string };
    client.invalidated = true;
    client.invalidatedReason = "device-token-revoked";

    harness.sendRaw(
      JSON.stringify({
        type: "req",
        id: "queued-1",
        method: "status.summary",
        params: {},
      }),
    );

    expect(harness.setCloseCause).toHaveBeenCalledWith("client-invalidated", {
      reason: "device-token-revoked",
      method: "status.summary",
    });
    expect(harness.close).toHaveBeenCalledWith(4001, "client invalidated: device-token-revoked");
    expect(handleGatewayRequest).not.toHaveBeenCalled();
  });

  it("waits for authority mutations before dispatching later queued requests", async () => {
    let releaseMutation: (() => void) | undefined;
    let connectedClient: { invalidated?: boolean; invalidatedReason?: string } | null = null;
    vi.mocked(handleGatewayRequest).mockImplementation(async (opts) => {
      expect(opts.req.method).toBe("device.token.revoke");
      await new Promise<void>((resolve) => {
        releaseMutation = resolve;
      });
      if (!connectedClient) {
        throw new Error("expected connected client");
      }
      connectedClient.invalidated = true;
      connectedClient.invalidatedReason = "device-token-revoked";
    });

    const harness = attachGatewayHarness({
      connId: "conn-invalidating",
      connectNonce: "nonce-invalidating",
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
    });

    harness.sendConnect("connect-invalidating", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-tui",
        version: "dev",
        platform: "test",
        mode: "cli",
      },
      role: "operator",
      scopes: ["operator.pairing"],
      caps: [],
    });

    await vi.waitFor(() => {
      expect(harness.client).not.toBeNull();
    });
    connectedClient = harness.client as typeof connectedClient;

    harness.sendRaw(
      JSON.stringify({
        type: "req",
        id: "revoke-1",
        method: "device.token.revoke",
        params: { deviceId: "device-1", role: "operator" },
      }),
    );
    harness.sendRaw(
      JSON.stringify({
        type: "req",
        id: "queued-1",
        method: "status.summary",
        params: {},
      }),
    );

    await vi.waitFor(() => {
      expect(handleGatewayRequest).toHaveBeenCalledTimes(1);
      expect(releaseMutation).toBeTypeOf("function");
    });
    expect(harness.close).not.toHaveBeenCalled();

    releaseMutation?.();

    await vi.waitFor(() => {
      expect(harness.close).toHaveBeenCalledWith(4001, "client invalidated: device-token-revoked");
    });
    expect(handleGatewayRequest).toHaveBeenCalledTimes(1);
    expect(harness.setCloseCause).toHaveBeenCalledWith("client-invalidated", {
      reason: "device-token-revoked",
      method: "status.summary",
    });
  });

  it("uses the injected runtime-aware health refresh after hello", async () => {
    let resolveRefresh: (() => void) | undefined;
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(
      () =>
        new Promise((resolve) => {
          resolveRefresh = () => resolve(createHealthSummary());
        }),
    );
    const isClosed = vi.fn(() => false);
    const harness = attachGatewayHarness({
      connId: "conn-1",
      requestOrigin: "http://127.0.0.1:19001",
      connectNonce: "nonce-1",
      refreshHealthSnapshot,
      isClosed,
    });

    harness.sendConnect("connect-1", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-control-ui",
        version: "dev",
        platform: "test",
        mode: "ui",
      },
      role: "operator",
      caps: [],
    });

    await vi.waitFor(() => {
      expect(harness.socketSend).toHaveBeenCalled();
    });
    const hello = JSON.parse(harness.socketSend.mock.calls.at(0)?.[0] ?? "{}") as { ok?: boolean };
    expect(hello.ok).toBe(true);

    await vi.waitFor(() => {
      expect(refreshHealthSnapshot).toHaveBeenCalledWith({ probe: false });
    });
    resolveRefresh?.();
  });

  it("closes post-auth clients after repeated malformed frames", async () => {
    const harness = attachGatewayHarness({
      connId: "conn-invalid",
      connectNonce: "nonce-invalid",
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
    });

    harness.sendConnect("connect-invalid", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-tui",
        version: "dev",
        platform: "test",
        mode: "cli",
      },
      role: "operator",
      scopes: ["operator.read"],
      caps: [],
    });

    await vi.waitFor(() => {
      expect(harness.client).not.toBeNull();
    });

    harness.sendRaw("{");
    harness.sendRaw("{");
    expect(harness.close).not.toHaveBeenCalled();

    harness.sendRaw("{");
    expect(harness.close).toHaveBeenCalledWith(1008, "too many invalid frames");
  });

  it("does not mark local backend self-pairing clients as approval runtimes", async () => {
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(async () =>
      createHealthSummary(),
    );
    const harness = attachGatewayHarness({
      connId: "conn-approval-runtime-spoof",
      connectNonce: "nonce-approval-runtime-spoof",
      refreshHealthSnapshot,
    });

    harness.sendConnect("connect-approval-runtime-spoof", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        version: "dev",
        platform: "test",
        mode: "backend",
      },
      role: "operator",
      scopes: ["operator.approvals"],
      caps: [],
    });

    await vi.waitFor(() => {
      expect(harness.socketSend).toHaveBeenCalled();
    });
    const connectedClient = harness.client as {
      connect?: { scopes?: string[] };
      internal?: { approvalRuntime?: boolean };
    } | null;
    expect(connectedClient?.connect?.scopes).toEqual(["operator.approvals"]);
    expect(connectedClient?.internal?.approvalRuntime).not.toBe(true);
  });

  it("marks operator approval clients with the server runtime token", async () => {
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(async () =>
      createHealthSummary(),
    );
    const harness = attachGatewayHarness({
      connId: "conn-approval-runtime-token",
      connectNonce: "nonce-approval-runtime-token",
      refreshHealthSnapshot,
    });

    harness.sendConnect("connect-approval-runtime-token", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        version: "dev",
        platform: "test",
        mode: "backend",
      },
      role: "operator",
      scopes: ["operator.approvals"],
      caps: [],
      auth: {
        approvalRuntimeToken: getOperatorApprovalRuntimeToken(),
      },
    });

    await vi.waitFor(() => {
      expect(harness.socketSend).toHaveBeenCalled();
    });
    const connectedClient = harness.client as {
      internal?: { approvalRuntime?: boolean };
    } | null;
    expect(connectedClient?.internal?.approvalRuntime).toBe(true);
  });

  it("returns a generic unavailable response when the top-level request handler throws", async () => {
    const thrown = new Error(
      "ENOENT: open '/Users/mark/.openclaw/credentials/provider-token.json'",
    );
    thrown.stack =
      "Error: ENOENT: open '/Users/mark/.openclaw/credentials/provider-token.json'\n" +
      "    at readFile (/Users/mark/Sites/openclaw/src/gateway/secrets.ts:12:3)";
    vi.mocked(handleGatewayRequest).mockRejectedValueOnce(thrown);

    const socketSend = vi.fn((_payload: string, cb?: (err?: Error) => void) => {
      cb?.();
    });
    let onMessage: ((data: string) => void) | undefined;
    const socket = {
      _receiver: {},
      send: socketSend,
      on: vi.fn((event: string, handler: (data: string) => void) => {
        if (event === "message") {
          onMessage = handler;
        }
        return socket;
      }),
    } as unknown as WebSocket;
    const send = vi.fn();
    const isClosed = vi.fn(() => false);
    let client: unknown = null;
    const resolvedAuth: ResolvedGatewayAuth = {
      mode: "none",
      allowTailscale: false,
    };
    const logGateway = createLogger();

    attachGatewayWsMessageHandler({
      socket,
      upgradeReq: {
        url: "/gateway",
        headers: { host: "127.0.0.1:19001" },
        socket: { localAddress: "127.0.0.1", remoteAddress: "127.0.0.1" },
      } as unknown as IncomingMessage,
      connId: "conn-1",
      remoteAddr: "127.0.0.1",
      localAddr: "127.0.0.1",
      requestHost: "127.0.0.1:19001",
      connectNonce: "nonce-1",
      getResolvedAuth: () => resolvedAuth,
      gatewayMethods: [],
      events: [],
      extraHandlers: {},
      buildRequestContext: () => ({}) as GatewayRequestContext,
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
      send,
      close: vi.fn(),
      isClosed,
      clearHandshakeTimer: vi.fn(),
      getClient: () => client as never,
      setClient: (next) => {
        client = next;
        return true;
      },
      setHandshakeState: vi.fn(),
      setCloseCause: vi.fn(),
      setLastFrameMeta: vi.fn(),
      originCheckMetrics: { hostHeaderFallbackAccepted: 0 },
      logGateway: logGateway as never,
      logHealth: createLogger() as never,
      logWsControl: createLogger() as never,
    });

    expect(onMessage).toBeDefined();

    onMessage?.(
      JSON.stringify({
        type: "req",
        id: "connect-1",
        method: "connect",
        params: {
          minProtocol: PROTOCOL_VERSION,
          maxProtocol: PROTOCOL_VERSION,
          client: {
            id: "openclaw-tui",
            version: "dev",
            platform: "test",
            mode: "cli",
          },
          role: "operator",
          scopes: ["operator.read"],
          caps: [],
        },
      }),
    );

    await vi.waitFor(() => {
      expect(socketSend).toHaveBeenCalled();
    });

    onMessage?.(
      JSON.stringify({
        type: "req",
        id: "req-1",
        method: "health",
      }),
    );

    await vi.waitFor(() => {
      expect(send).toHaveBeenCalledWith({
        type: "res",
        id: "req-1",
        ok: false,
        payload: undefined,
        error: {
          code: "UNAVAILABLE",
          message: "gateway request unavailable",
        },
      });
    });

    expect(send.mock.calls.at(-1)?.[0]).not.toEqual(
      expect.objectContaining({
        error: expect.objectContaining({
          message: expect.stringContaining("/Users/mark/.openclaw"),
        }),
      }),
    );
    expect(logGateway.error).toHaveBeenCalledWith(
      expect.stringContaining("/Users/mark/.openclaw/credentials/provider-token.json"),
    );
  });
});

describe("resolvePinnedClientMetadata", () => {
  it.each([
    ["darwin", "macos"],
    ["win32", "windows"],
  ])(
    "pins legacy node-host platform alias %s to paired canonical %s",
    (claimedPlatform, pairedPlatform) => {
      expect(
        __testing.resolvePinnedClientMetadata({
          clientId: "node-host",
          clientMode: "node",
          claimedPlatform,
          claimedDeviceFamily: pairedPlatform === "macos" ? "Mac" : "Windows",
          pairedPlatform,
          pairedDeviceFamily: pairedPlatform === "macos" ? "Mac" : "Windows",
        }),
      ).toEqual({
        platformMismatch: false,
        deviceFamilyMismatch: false,
        pinnedPlatform: pairedPlatform,
        pinnedDeviceFamily: pairedPlatform === "macos" ? "Mac" : "Windows",
      });
    },
  );

  it.each([
    ["macos", "darwin", "Mac"],
    ["windows", "win32", "Windows"],
  ])(
    "pins canonical node-host platform %s over paired legacy alias %s",
    (claimedPlatform, pairedPlatform, deviceFamily) => {
      expect(
        __testing.resolvePinnedClientMetadata({
          clientId: "node-host",
          clientMode: "node",
          claimedPlatform,
          claimedDeviceFamily: deviceFamily,
          pairedPlatform,
          pairedDeviceFamily: deviceFamily,
        }),
      ).toEqual({
        platformMismatch: false,
        deviceFamilyMismatch: false,
        pinnedPlatform: claimedPlatform,
        pinnedDeviceFamily: deviceFamily,
      });
    },
  );

  it.each([
    ["openclaw-ios", "iOS 26.5.0", "iOS 26.4.2", "iPhone"],
    ["openclaw-ios", "iPadOS 26.5.0", "iPadOS 26.4.2", "iPad"],
    ["openclaw-ios", "iPadOS 26.5.0", "iOS 26.4.2", "iPad"],
    ["openclaw-android", "Android 16", "Android 15", "Android"],
  ])(
    "allows %s platform version refresh without metadata-upgrade approval",
    (clientId, claimedPlatform, pairedPlatform, deviceFamily) => {
      expect(
        __testing.resolvePinnedClientMetadata({
          clientId,
          clientMode: "node",
          claimedPlatform,
          claimedDeviceFamily: deviceFamily,
          pairedPlatform,
          pairedDeviceFamily: deviceFamily,
        }),
      ).toEqual({
        platformMismatch: false,
        deviceFamilyMismatch: false,
        pinnedPlatform: claimedPlatform,
        pinnedDeviceFamily: deviceFamily,
        refreshPairedPlatform: claimedPlatform,
      });
    },
  );

  it("still requires approval when an iOS device family changes", () => {
    expect(
      __testing.resolvePinnedClientMetadata({
        clientId: "openclaw-ios",
        clientMode: "node",
        claimedPlatform: "iOS 26.5.0",
        claimedDeviceFamily: "iPad",
        pairedPlatform: "iOS 26.4.2",
        pairedDeviceFamily: "iPhone",
      }),
    ).toEqual({
      platformMismatch: false,
      deviceFamilyMismatch: true,
      pinnedPlatform: "iOS 26.5.0",
      pinnedDeviceFamily: "iPhone",
      refreshPairedPlatform: "iOS 26.5.0",
    });
  });

  it("keeps non-mobile platform version changes approval-bound", () => {
    expect(
      __testing.resolvePinnedClientMetadata({
        clientId: "node-host",
        clientMode: "node",
        claimedPlatform: "linux 6.9",
        claimedDeviceFamily: "Linux",
        pairedPlatform: "linux 6.8",
        pairedDeviceFamily: "Linux",
      }),
    ).toEqual({
      platformMismatch: true,
      deviceFamilyMismatch: false,
      pinnedPlatform: undefined,
      pinnedDeviceFamily: "Linux",
    });
  });
});
