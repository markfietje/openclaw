// WebSocket message-handler health tests cover post-connect startup-unavailable and health-gated dispatch.
import type { IncomingMessage } from "node:http";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { WebSocket } from "ws";
import { PROTOCOL_VERSION } from "../../../../packages/gateway-protocol/src/index.js";
import type { HealthSummary } from "../../../commands/health.types.js";
import {
  onInternalDiagnosticEvent,
  resetDiagnosticEventsForTest,
  type DiagnosticSecurityEvent,
} from "../../../infra/diagnostic-events.js";
import { mintAgentRuntimeIdentityToken } from "../../agent-runtime-identity-token.js";
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

const DEVICE_TOKEN_MUTATION_PARAMS = {
  deviceId: "device-1",
  role: "operator",
} as const satisfies Record<string, unknown>;
const NODE_PAIR_REMOVE_PARAMS = {
  nodeId: "device-1",
} as const satisfies Record<string, unknown>;

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

type ConnectedTestClient = {
  invalidated: boolean;
  invalidatedReason?: string;
  connect: {
    client: {
      id: string;
      version: string;
      platform: string;
      mode: string;
    };
    role: "operator";
    scopes: string[];
  };
  connId: string;
  usesSharedGatewayAuth: false;
};

type CloseGatewayConnection = (code?: number, reason?: string) => void;

function createConnectedTestClient(params: {
  connId: string;
  invalidated?: boolean;
  invalidatedReason?: string;
}): ConnectedTestClient {
  return {
    invalidated: params.invalidated ?? false,
    ...(params.invalidatedReason ? { invalidatedReason: params.invalidatedReason } : {}),
    connect: {
      client: {
        id: "openclaw-control-ui",
        version: "dev",
        platform: "test",
        mode: "ui",
      },
      role: "operator",
      scopes: [],
    },
    connId: params.connId,
    usesSharedGatewayAuth: false,
  };
}

function createCloseMock() {
  return vi.fn<CloseGatewayConnection>();
}

function captureSecurityEvents(): {
  events: DiagnosticSecurityEvent[];
  stop: () => void;
} {
  const events: DiagnosticSecurityEvent[] = [];
  const stop = onInternalDiagnosticEvent((event, metadata) => {
    if (metadata.trusted && event.type === "security.event") {
      events.push(event);
    }
  });
  return { events, stop };
}

function attachGatewayHarness(options: {
  connId: string;
  connectNonce: string;
  refreshHealthSnapshot: GatewayRequestContext["refreshHealthSnapshot"];
  requestOrigin?: string;
  requestHost?: string;
  remoteAddr?: string;
  localAddr?: string;
  resolvedAuth?: ResolvedGatewayAuth;
  client?: unknown;
  isClosed?: () => boolean;
  close?: CloseGatewayConnection;
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
  let client: unknown = options.client ?? null;
  const requestHost = options.requestHost ?? "127.0.0.1:19001";
  const remoteAddr = options.remoteAddr ?? "127.0.0.1";
  const localAddr = options.localAddr ?? "127.0.0.1";
  const resolvedAuth: ResolvedGatewayAuth = options.resolvedAuth ?? {
    mode: "none",
    allowTailscale: false,
    allowLocalDirectNoAuth: true,
    toolsInvokeMaxBodyBytes: 262144,
  };
  const advanceHandshakePhase = vi.fn();
  const close = options.close ?? vi.fn();
  const setCloseCause = vi.fn();
  attachGatewayWsMessageHandler({
    socket,
    upgradeReq: {
      url: "/gateway",
      headers: {
        host: requestHost,
        ...(options.requestOrigin ? { origin: options.requestOrigin } : {}),
      },
      socket: { localAddress: localAddr, remoteAddress: remoteAddr },
    } as unknown as IncomingMessage,
    connId: options.connId,
    remoteAddr,
    localAddr,
    requestHost,
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
    advanceHandshakePhase,
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
    advanceHandshakePhase,
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
    resetDiagnosticEventsForTest();
    vi.clearAllMocks();
  });

  it("closes invalidated clients before dispatching queued requests", async () => {
    const harness = attachGatewayHarness({
      connId: "conn-invalidated",
      connectNonce: "nonce-invalidated",
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
      requestOrigin: "http://127.0.0.1:19001",
    });

    harness.sendConnect("connect-invalidated", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-control-ui",
        version: "dev",
        platform: "test",
        mode: "ui",
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
      requestOrigin: "http://127.0.0.1:19001",
    });

    harness.sendConnect("connect-invalidating", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-control-ui",
        version: "dev",
        platform: "test",
        mode: "ui",
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

  it("waits for device-backed node removal before dispatching later queued requests", async () => {
    let releaseMutation: (() => void) | undefined;
    const close = createCloseMock();
    const client = createConnectedTestClient({ connId: "conn-node-invalidating" });
    vi.mocked(handleGatewayRequest).mockImplementation(async (opts) => {
      expect(opts.req.method).toBe("node.pair.remove");
      await new Promise<void>((resolve) => {
        releaseMutation = resolve;
      });
      client.invalidated = true;
      client.invalidatedReason = "device-pair-removed";
    });

    const harness = attachGatewayHarness({
      connId: "conn-node-invalidating",
      connectNonce: "nonce-node-invalidating",
      client,
      close,
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
    });

    harness.sendRaw(
      JSON.stringify({
        type: "req",
        id: "remove-node-1",
        method: "node.pair.remove",
        params: NODE_PAIR_REMOVE_PARAMS,
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

    releaseMutation?.();

    await vi.waitFor(() => {
      expect(close).toHaveBeenCalledWith(4001, "client invalidated: device-pair-removed");
    });
    expect(handleGatewayRequest).toHaveBeenCalledTimes(1);
    expect(harness.setCloseCause).toHaveBeenCalledWith("client-invalidated", {
      reason: "device-pair-removed",
      method: "status.summary",
    });
  });

  it("drains credential mutation barriers installed by earlier queued requests", async () => {
    let releaseFirstMutation: (() => void) | undefined;
    let releaseSecondMutation: (() => void) | undefined;
    const close = createCloseMock();
    const client = createConnectedTestClient({ connId: "conn-chained-invalidating" });
    vi.mocked(handleGatewayRequest).mockImplementation(async (opts) => {
      if (opts.req.method === "device.token.rotate") {
        await new Promise<void>((resolve) => {
          releaseFirstMutation = resolve;
        });
        return;
      }
      expect(opts.req.method).toBe("device.token.revoke");
      await new Promise<void>((resolve) => {
        releaseSecondMutation = resolve;
      });
      client.invalidated = true;
      client.invalidatedReason = "device-token-revoked";
    });

    const harness = attachGatewayHarness({
      connId: "conn-chained-invalidating",
      connectNonce: "nonce-chained-invalidating",
      client,
      close,
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
    });

    harness.sendRaw(
      JSON.stringify({
        type: "req",
        id: "rotate-1",
        method: "device.token.rotate",
        params: DEVICE_TOKEN_MUTATION_PARAMS,
      }),
    );
    harness.sendRaw(
      JSON.stringify({
        type: "req",
        id: "revoke-1",
        method: "device.token.revoke",
        params: DEVICE_TOKEN_MUTATION_PARAMS,
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
      expect(releaseFirstMutation).toBeTypeOf("function");
    });

    releaseFirstMutation?.();
    await vi.waitFor(() => {
      expect(handleGatewayRequest).toHaveBeenCalledTimes(2);
      expect(releaseSecondMutation).toBeTypeOf("function");
    });
    await new Promise((resolve) => {
      setTimeout(resolve, 0);
    });
    expect(handleGatewayRequest).toHaveBeenCalledTimes(2);

    releaseSecondMutation?.();
    await vi.waitFor(() => {
      expect(close).toHaveBeenCalledWith(4001, "client invalidated: device-token-revoked");
    });
    expect(handleGatewayRequest).toHaveBeenCalledTimes(2);
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
    const captured = captureSecurityEvents();

    try {
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
    } finally {
      captured.stop();
    }
    const hello = JSON.parse(harness.socketSend.mock.calls.at(0)?.[0] ?? "{}") as { ok?: boolean };
    expect(hello.ok).toBe(true);
    expect(captured.events).toHaveLength(1);
    expect(captured.events[0]).toMatchObject({
      action: "gateway.auth.succeeded",
      outcome: "success",
      severity: "low",
      actor: { kind: "operator", role: "operator" },
      target: { kind: "gateway", name: "websocket" },
      policy: { id: "gateway.websocket-auth", decision: "allow" },
      control: { id: "gateway.ws.connect", family: "auth" },
      attributes: {
        auth_mode: "none",
        auth_method: "none",
        auth_provided: "none",
        client_mode: "ui",
        has_device_identity: false,
        scope_count: 0,
      },
    });

    await vi.waitFor(() => {
      expect(refreshHealthSnapshot).toHaveBeenCalledWith({ probe: false });
    });
    resolveRefresh?.();
  });

  it("emits a security event for rejected gateway auth", async () => {
    const close = createCloseMock();
    const harness = attachGatewayHarness({
      connId: "conn-auth-failed",
      connectNonce: "nonce-auth-failed",
      requestHost: "gateway.example.com:18789",
      remoteAddr: "203.0.113.50",
      resolvedAuth: {
        mode: "token",
        token: "gateway-token",
        allowTailscale: false,
      },
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
      close,
    });
    const captured = captureSecurityEvents();

    try {
      harness.sendConnect("connect-auth-failed", {
        minProtocol: PROTOCOL_VERSION,
        maxProtocol: PROTOCOL_VERSION,
        client: {
          id: "gateway-client",
          version: "dev",
          platform: "test",
          mode: "backend",
        },
        role: "operator",
        scopes: ["operator.admin"],
        caps: [],
        auth: { token: "wrong-token" },
      });

      await vi.waitFor(() => {
        expect(close).toHaveBeenCalledWith(1008, expect.stringContaining("unauthorized"));
      });
    } finally {
      captured.stop();
    }

    expect(captured.events).toHaveLength(1);
    expect(captured.events[0]).toMatchObject({
      action: "gateway.auth.failed",
      outcome: "denied",
      severity: "medium",
      reason: "token_mismatch",
      actor: { kind: "operator", role: "operator" },
      target: { kind: "gateway", name: "websocket" },
      policy: {
        id: "gateway.websocket-auth",
        decision: "deny",
        reason: "token_mismatch",
      },
      control: { id: "gateway.ws.connect", family: "auth" },
      attributes: {
        auth_mode: "token",
        auth_method: "token",
        auth_provided: "token",
        client_mode: "backend",
        has_device_identity: false,
        scope_count: 0,
        rate_limited: false,
      },
    });
    expect(JSON.stringify(captured.events)).not.toContain("wrong-token");
    expect(JSON.stringify(captured.events)).not.toContain("gateway-token");
  });

  it("records credential and hello preparation phases during connect", async () => {
    const harness = attachGatewayHarness({
      connId: "conn-phases",
      connectNonce: "nonce-phases",
      resolvedAuth: {
        mode: "token",
        token: "gateway-token",
        allowTailscale: false,
      },
    });

    harness.sendConnect("connect-phases", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        version: "dev",
        platform: "test",
        mode: "backend",
      },
      role: "operator",
      scopes: [],
      caps: [],
      auth: {
        token: "gateway-token",
      },
    });

    await vi.waitFor(() => {
      expect(harness.socketSend).toHaveBeenCalled();
    });
    expect(harness.advanceHandshakePhase.mock.calls.map(([phase]) => phase)).toEqual([
      "auth_credentials_received",
      "auth_validated",
      "session_attached",
      "hello_payload_prepared",
      "ready",
    ]);
    expect(upsertPresenceMock).not.toHaveBeenCalled();
  });

  it("closes post-auth clients after repeated malformed frames", async () => {
    const harness = attachGatewayHarness({
      connId: "conn-invalid",
      connectNonce: "nonce-invalid",
      refreshHealthSnapshot: vi.fn(async () => createHealthSummary()),
      requestOrigin: "http://127.0.0.1:19001",
    });

    harness.sendConnect("connect-invalid", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "openclaw-control-ui",
        version: "dev",
        platform: "test",
        mode: "ui",
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

  it("does not trust approval runtime tokens from remote clients", async () => {
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(async () =>
      createHealthSummary(),
    );
    const harness = attachGatewayHarness({
      connId: "conn-remote-approval-runtime-token",
      connectNonce: "nonce-remote-approval-runtime-token",
      requestHost: "gateway.example.com:18789",
      remoteAddr: "203.0.113.50",
      resolvedAuth: {
        mode: "token",
        token: "gateway-token",
        allowTailscale: false,
        allowLocalDirectNoAuth: true,
        toolsInvokeMaxBodyBytes: 262144,
      },
      refreshHealthSnapshot,
    });

    harness.sendConnect("connect-remote-approval-runtime-token", {
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
        token: "gateway-token",
        approvalRuntimeToken: getOperatorApprovalRuntimeToken(),
      },
    });

    await vi.waitFor(() => {
      expect(harness.socketSend).toHaveBeenCalled();
    });
    const connectedClient = harness.client as {
      internal?: { approvalRuntime?: boolean };
    } | null;
    expect(connectedClient?.internal?.approvalRuntime).not.toBe(true);
  });

  it("marks local backend clients with a valid agent runtime identity token", async () => {
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(async () =>
      createHealthSummary(),
    );
    const harness = attachGatewayHarness({
      connId: "conn-agent-runtime-token",
      connectNonce: "nonce-agent-runtime-token",
      refreshHealthSnapshot,
    });

    harness.sendConnect("connect-agent-runtime-token", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        version: "dev",
        platform: "test",
        mode: "backend",
      },
      role: "operator",
      scopes: ["operator.write"],
      caps: [],
      auth: {
        agentRuntimeIdentityToken: await mintAgentRuntimeIdentityToken({
          agentId: "ops",
          sessionKey: "agent:ops:telegram:direct:alice",
        }),
      },
    });

    await vi.waitFor(() => {
      expect(harness.socketSend).toHaveBeenCalled();
    });
    const connectedClient = harness.client as {
      internal?: {
        agentRuntimeIdentity?: { agentId?: string; sessionKey?: string };
      };
    } | null;
    expect(connectedClient?.internal?.agentRuntimeIdentity).toMatchObject({
      agentId: "ops",
      sessionKey: "agent:ops:telegram:direct:alice",
    });
  });

  it("rejects agent runtime identity tokens from remote clients", async () => {
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(async () =>
      createHealthSummary(),
    );
    const close = createCloseMock();
    const harness = attachGatewayHarness({
      connId: "conn-remote-agent-runtime-token",
      connectNonce: "nonce-remote-agent-runtime-token",
      requestHost: "gateway.example.com:18789",
      remoteAddr: "203.0.113.50",
      resolvedAuth: {
        mode: "token",
        token: "gateway-token",
        allowTailscale: false,
        allowLocalDirectNoAuth: false,
        toolsInvokeMaxBodyBytes: 262144,
      },
      refreshHealthSnapshot,
      close,
    });

    harness.sendConnect("connect-remote-agent-runtime-token", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        version: "dev",
        platform: "test",
        mode: "backend",
      },
      role: "operator",
      scopes: ["operator.write"],
      caps: [],
      auth: {
        token: "gateway-token",
        agentRuntimeIdentityToken: await mintAgentRuntimeIdentityToken({
          agentId: "ops",
          sessionKey: "agent:ops:telegram:direct:alice",
        }),
      },
    });

    await vi.waitFor(() => {
      expect(close).toHaveBeenCalledWith(
        1008,
        "agent runtime identity token is only accepted from local backend gateway clients",
      );
    });
    expect(harness.client).toBeNull();
  });

  it("rejects invalid local agent runtime identity tokens", async () => {
    const refreshHealthSnapshot = vi.fn<GatewayRequestContext["refreshHealthSnapshot"]>(async () =>
      createHealthSummary(),
    );
    const close = createCloseMock();
    const harness = attachGatewayHarness({
      connId: "conn-invalid-agent-runtime-token",
      connectNonce: "nonce-invalid-agent-runtime-token",
      refreshHealthSnapshot,
      close,
    });

    harness.sendConnect("connect-invalid-agent-runtime-token", {
      minProtocol: PROTOCOL_VERSION,
      maxProtocol: PROTOCOL_VERSION,
      client: {
        id: "gateway-client",
        version: "dev",
        platform: "test",
        mode: "backend",
      },
      role: "operator",
      scopes: ["operator.write"],
      caps: [],
      auth: {
        agentRuntimeIdentityToken: "not-a-valid-token",
      },
    });

    await vi.waitFor(() => {
      expect(close).toHaveBeenCalledWith(1008, "invalid agent runtime identity token");
    });
    expect(harness.client).toBeNull();
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
      allowLocalDirectNoAuth: true,
      toolsInvokeMaxBodyBytes: 262144,
    };
    const logGateway = createLogger();

    attachGatewayWsMessageHandler({
      socket,
      upgradeReq: {
        url: "/gateway",
        headers: { host: "127.0.0.1:19001", origin: "http://127.0.0.1:19001" },
        socket: { localAddress: "127.0.0.1", remoteAddress: "127.0.0.1" },
      } as unknown as IncomingMessage,
      connId: "conn-1",
      remoteAddr: "127.0.0.1",
      localAddr: "127.0.0.1",
      requestHost: "127.0.0.1:19001",
      requestOrigin: "http://127.0.0.1:19001",
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
            id: "openclaw-control-ui",
            version: "dev",
            platform: "test",
            mode: "ui",
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
    ["openclaw-macos", "macOS 26.5.1", "macOS 26.5.0", "Mac"],
    ["openclaw-macos", "macOS 27.0.0", "macOS 26.5.1", "Mac"],
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

  it.each(["node", "ui"])("allows a macOS platform version refresh in %s mode", (clientMode) => {
    expect(
      testing.resolvePinnedClientMetadata({
        clientId: "openclaw-macos",
        clientMode,
        claimedPlatform: "macOS 26.5.2",
        claimedDeviceFamily: "Mac",
        pairedPlatform: "macOS 26.5.1",
        pairedDeviceFamily: "Mac",
      }),
    ).toEqual({
      platformMismatch: false,
      deviceFamilyMismatch: false,
      pinnedPlatform: "macOS 26.5.2",
      pinnedDeviceFamily: "Mac",
      refreshPairedPlatform: "macOS 26.5.2",
    });
  });

  it("accepts a node-host macOS alias against the shared Mac app platform pin", () => {
    expect(
      testing.resolvePinnedClientMetadata({
        clientId: "node-host",
        clientMode: "node",
        claimedPlatform: "macos",
        claimedDeviceFamily: "Mac",
        pairedPlatform: "macOS 26.5.2",
        pairedDeviceFamily: "Mac",
      }),
    ).toEqual({
      platformMismatch: false,
      deviceFamilyMismatch: false,
      pinnedPlatform: "macOS 26.5.2",
      pinnedDeviceFamily: "Mac",
    });
  });

  it("refreshes a shared node-host macOS pin from the native Mac app", () => {
    expect(
      testing.resolvePinnedClientMetadata({
        clientId: "openclaw-macos",
        clientMode: "ui",
        claimedPlatform: "macOS 26.5.2",
        claimedDeviceFamily: "Mac",
        pairedPlatform: "macos",
        pairedDeviceFamily: "Mac",
      }),
    ).toEqual({
      platformMismatch: false,
      deviceFamilyMismatch: false,
      pinnedPlatform: "macOS 26.5.2",
      pinnedDeviceFamily: "Mac",
      refreshPairedPlatform: "macOS 26.5.2",
    });
  });

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

  it("still requires approval when a macOS device family changes", () => {
    expect(
      testing.resolvePinnedClientMetadata({
        clientId: "openclaw-macos",
        clientMode: "node",
        claimedPlatform: "macOS 26.5.2",
        claimedDeviceFamily: "VirtualMac",
        pairedPlatform: "macOS 26.5.1",
        pairedDeviceFamily: "Mac",
      }),
    ).toEqual({
      platformMismatch: false,
      deviceFamilyMismatch: true,
      pinnedPlatform: "macOS 26.5.2",
      pinnedDeviceFamily: "Mac",
      refreshPairedPlatform: "macOS 26.5.2",
    });
  });

  it.each([
    ["node-host", "macOS 26.5.2", "macOS 26.5.1"],
    ["openclaw-macos", "macOS anything", "macOS previous"],
    ["openclaw-macos", "macOS", "macOS 26.5.1"],
  ])(
    "keeps non-version macOS platform changes approval-bound for %s",
    (clientId, claimed, paired) => {
      expect(
        testing.resolvePinnedClientMetadata({
          clientId,
          clientMode: "node",
          claimedPlatform: claimed,
          claimedDeviceFamily: "Mac",
          pairedPlatform: paired,
          pairedDeviceFamily: "Mac",
        }),
      ).toMatchObject({
        platformMismatch: true,
        deviceFamilyMismatch: false,
        pinnedPlatform: undefined,
      });
    },
  );

  it("keeps non-native-app platform version changes approval-bound", () => {
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
