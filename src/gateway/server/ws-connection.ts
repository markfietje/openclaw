import { randomUUID } from "node:crypto";
import type { Socket } from "node:net";
import type { RawData, WebSocket, WebSocketServer } from "ws";
import { getRuntimeConfig, loadConfig } from "../../config/io.js";
import { resolveCanvasHostUrl } from "../../infra/canvas-host-url.js";
import { removeRemoteNodeInfo } from "../../infra/skills-remote.js";
import { upsertPresence } from "../../infra/system-presence.js";
import { logRejectedLargePayload } from "../../logging/diagnostic-payload.js";
import type { createSubsystemLogger } from "../../logging/subsystem.js";
import { normalizeLowercaseStringOrEmpty } from "../../shared/string-coerce.js";
import { truncateUtf16Safe } from "../../utils.js";
import { isWebchatClient } from "../../utils/message-channel.js";
import type { AuthRateLimiter } from "../auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "../auth.js";
import { resolvePreauthHandshakeTimeoutMs } from "../handshake-timeouts.js";
import { resolveHostedPluginSurfaceUrl } from "../hosted-plugin-surface-url.js";
import { isIpAllowed, type IpRestrictionConfig } from "../ip-restriction-policy.js";
import type { GatewayMethodRegistry } from "../methods/registry.js";
import {
  isLoopbackAddress,
  isTrustedProxyAddress,
  resolveClientIp,
  validateForwardedHeaderConsistency,
  validateSensitiveHeaders,
} from "../net.js";
import { checkBrowserOrigin } from "../origin-check.js";
import type { PluginNodeCapabilitySurface } from "../plugin-node-capability.js";
import {
  GATEWAY_STARTUP_CLOSE_CODE,
  GATEWAY_STARTUP_PENDING_CLOSE_CAUSE,
} from "../protocol/startup-unavailable.js";
import { MAX_PAYLOAD_BYTES, MAX_PREAUTH_PAYLOAD_BYTES } from "../server-constants.js";
import { clearNodeWakeState } from "../server-methods/nodes.js";
import type { ToolAuditLogger } from "../tool-audit.js";
import { GATEWAY_WS_SUBPROTOCOL } from "../ws-protocol.js";

// Protocol-level ping/pong defaults for reverse proxy dead-connection detection.
// Complements the application-level tick (30s) by using WebSocket control frames
// that proxies (nginx, Caddy, HAProxy, AWS ALB, Tailscale Serve) understand natively.
const DEFAULT_PING_INTERVAL_MS = 25_000;
const DEFAULT_PONG_TIMEOUT_MS = 10_000;
const PONG_TIMEOUT_CLOSE_CODE = 4001;
import type { GatewayRequestContext, GatewayRequestHandlers } from "../server-methods/types.js";
import { formatError } from "../server-utils.js";
import { logWs } from "../ws-log.js";
import { getHealthVersion, incrementPresenceVersion } from "./health-state.js";
import type { PreauthConnectionBudget } from "./preauth-connection-budget.js";
import { broadcastPresenceSnapshot } from "./presence-events.js";
import type {
  GatewayWsMessageHandlerParams,
  WsOriginCheckMetrics,
} from "./ws-connection/message-handler.js";
import { resolveSharedGatewaySessionGeneration } from "./ws-shared-generation.js";
import type { GatewayWsClient } from "./ws-types.js";

type SubsystemLogger = ReturnType<typeof createSubsystemLogger>;

const LOG_HEADER_MAX_LEN = 300;
const LOG_HEADER_FORMAT_REGEX = /\p{Cf}/gu;
const MAX_QUEUED_MESSAGE_HANDLER_FRAMES = 16;

function replaceControlChars(value: string): string {
  let cleaned = "";
  for (const char of value) {
    const codePoint = char.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      cleaned += " ";
      continue;
    }
    cleaned += char;
  }
  return cleaned;
}
const sanitizeLogValue = (value: string | undefined): string | undefined => {
  if (!value) {
    return undefined;
  }
  const cleaned = replaceControlChars(value)
    .replace(LOG_HEADER_FORMAT_REGEX, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) {
    return undefined;
  }
  if (cleaned.length <= LOG_HEADER_MAX_LEN) {
    return cleaned;
  }
  return truncateUtf16Safe(cleaned, LOG_HEADER_MAX_LEN);
};

function formatSocketEndpoint(
  address: string | undefined,
  port: number | undefined,
): string | undefined {
  if (!address) {
    return undefined;
  }
  if (port === undefined) {
    return address;
  }
  return address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`;
}

function resolveSocketAddress(socket: WebSocket): {
  remoteAddr?: string;
  remotePort?: number;
  localAddr?: string;
  localPort?: number;
  endpoint?: string;
} {
  const rawSocket = (socket as WebSocket & { _socket?: Socket })["_socket"];
  const remoteAddr = rawSocket?.remoteAddress;
  const remotePort = rawSocket?.remotePort;
  const localAddr = rawSocket?.localAddress;
  const localPort = rawSocket?.localPort;
  const remoteEndpoint = formatSocketEndpoint(remoteAddr, remotePort);
  const localEndpoint = formatSocketEndpoint(localAddr, localPort);
  return {
    remoteAddr,
    remotePort,
    localAddr,
    localPort,
    endpoint:
      remoteEndpoint && localEndpoint
        ? `${remoteEndpoint}->${localEndpoint}`
        : (remoteEndpoint ?? localEndpoint),
  };
}

function isWsPayloadLimitError(err: unknown): boolean {
  if (!err || typeof err !== "object") {
    return false;
  }
  const code = (err as { code?: unknown }).code;
  if (code === "WS_ERR_UNSUPPORTED_MESSAGE_LENGTH") {
    return true;
  }
  const message = (err as { message?: unknown }).message;
  return typeof message === "string" && /max payload size exceeded/i.test(message);
}

export type GatewayWsSharedHandlerParams = {
  wss: WebSocketServer;
  clients: Set<GatewayWsClient>;
  preauthConnectionBudget: PreauthConnectionBudget;
  authenticatedConnectionBudget: import("./authenticated-connection-budget.js").AuthenticatedConnectionBudget;
  port: number;
  gatewayHost?: string;
  pluginSurfaceScheme?: "http" | "https";
  getPluginNodeCapabilities?: () => PluginNodeCapabilitySurface[];
  resolvedAuth: ResolvedGatewayAuth;
  getResolvedAuth?: () => ResolvedGatewayAuth;
  getRequiredSharedGatewaySessionGeneration?: () => string | undefined;
  /** Optional rate limiter for auth brute-force protection. */
  rateLimiter?: AuthRateLimiter;
  /** Browser-origin fallback limiter (loopback is never exempt). */
  browserRateLimiter?: AuthRateLimiter;
  preauthHandshakeTimeoutMs?: number;
  isStartupPending?: () => boolean;
  gatewayMethods: string[];
  events: string[];
  refreshHealthSnapshot: GatewayRequestContext["refreshHealthSnapshot"];
};

export type AttachGatewayWsConnectionHandlerParams = GatewayWsSharedHandlerParams & {
  logGateway: SubsystemLogger;
  logHealth: SubsystemLogger;
  logWsControl: SubsystemLogger;
  extraHandlers: GatewayRequestHandlers;
  getMethodRegistry?: () => GatewayMethodRegistry;
  broadcast: (
    event: string,
    payload: unknown,
    opts?: {
      dropIfSlow?: boolean;
      stateVersion?: { presence?: number; health?: number };
    },
  ) => void;
  buildRequestContext: () => GatewayRequestContext;
  /** Optional tool audit logger for structured tool call forensics. */
  toolAuditLogger?: ToolAuditLogger;
};

function attachGatewayWsMessageHandlerOnDemand(params: GatewayWsMessageHandlerParams): void {
  const queued: RawData[] = [];
  const queueMessage = (data: RawData) => {
    if (queued.length >= MAX_QUEUED_MESSAGE_HANDLER_FRAMES) {
      params.setCloseCause("message-handler-loading-overflow", {
        queuedFrames: queued.length,
      });
      params.close(1008, "gateway message handler loading");
      return;
    }
    queued.push(data);
  };
  params.socket.on("message", queueMessage);
  void import("./ws-connection/message-handler.js")
    .then(({ attachGatewayWsMessageHandler }) => {
      params.socket.off("message", queueMessage);
      if (params.isClosed()) {
        return;
      }
      attachGatewayWsMessageHandler(params);
      for (const data of queued) {
        params.socket.emit("message", data);
      }
    })
    .catch((error: unknown) => {
      params.socket.off("message", queueMessage);
      params.setCloseCause("message-handler-load-failed", {
        error: formatError(error),
      });
      params.logWsControl.warn(
        `failed to load ws message handler conn=${params.connId}: ${formatError(error)}`,
      );
      params.close(1011, "gateway message handler unavailable");
    });
}

export function attachGatewayWsConnectionHandler(params: AttachGatewayWsConnectionHandlerParams) {
  const {
    wss,
    clients,
    preauthConnectionBudget,
    authenticatedConnectionBudget,
    port,
    pluginSurfaceScheme,
    getPluginNodeCapabilities,
    resolvedAuth,
    getResolvedAuth = () => resolvedAuth,
    getRequiredSharedGatewaySessionGeneration = () =>
      resolveSharedGatewaySessionGeneration(
        getResolvedAuth(),
        getRuntimeConfig().gateway?.trustedProxies,
      ),
    rateLimiter,
    browserRateLimiter,
    isStartupPending,
    gatewayMethods,
    events,
    refreshHealthSnapshot,
    logGateway,
    logHealth,
    logWsControl,
    extraHandlers,
    getMethodRegistry,
    broadcast,
    buildRequestContext,
    toolAuditLogger,
  } = params;
  const originCheckMetrics: WsOriginCheckMetrics = { hostHeaderFallbackAccepted: 0 };

  wss.on("connection", (socket, upgradeReq) => {
    const configSnapshot = loadConfig();
    // Resolve ping/pong config once — disabled by default only if explicitly set false
    const pingConfig =
      configSnapshot.gateway?.security?.enablePingPong === false
        ? null
        : {
            pingIntervalMs:
              configSnapshot.gateway?.security?.pingIntervalMs ?? DEFAULT_PING_INTERVAL_MS,
            pongTimeoutMs:
              configSnapshot.gateway?.security?.pongTimeoutMs ?? DEFAULT_PONG_TIMEOUT_MS,
          };
    const securityConfig = configSnapshot.gateway?.security ?? {};
    const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];
    const allowRealIpFallback = configSnapshot.gateway?.allowRealIpFallback !== false;
    const controlUiConfig = configSnapshot.gateway?.controlUi;

    let client: GatewayWsClient | null = null;
    let closed = false;
    const openedAt = Date.now();
    const connId = randomUUID();
    const { remoteAddr, remotePort, localAddr, localPort, endpoint } = resolveSocketAddress(socket);
    const preauthBudgetKey = (
      socket as WebSocket & {
        __openclawPreauthBudgetClaimed?: boolean;
        __openclawPreauthBudgetKey?: string;
      }
    )["__openclawPreauthBudgetKey"];
    (
      socket as WebSocket & {
        __openclawPreauthBudgetClaimed?: boolean;
      }
    )["__openclawPreauthBudgetClaimed"] = true;
    const headerValue = (value: string | string[] | undefined) =>
      Array.isArray(value) ? value[0] : value;
    const requestHost = headerValue(upgradeReq.headers.host);
    const forwardedHost = headerValue(upgradeReq.headers["x-forwarded-host"]);
    const requestOrigin = headerValue(upgradeReq.headers.origin);
    const requestUserAgent = headerValue(upgradeReq.headers["user-agent"]);
    const forwardedFor = headerValue(upgradeReq.headers["x-forwarded-for"]);
    const realIp = headerValue(upgradeReq.headers["x-real-ip"]);
    const xForwardedProto = headerValue(upgradeReq.headers["x-forwarded-proto"]);
    const forwarded = headerValue(upgradeReq.headers.forwarded);
    const secFetchSite = headerValue(upgradeReq.headers["sec-fetch-site"]);

    const pluginNodeCapabilities = getPluginNodeCapabilities?.() ?? [];
    const pluginSurfaceBaseUrl =
      pluginNodeCapabilities.length > 0
        ? resolveHostedPluginSurfaceUrl({
            port,
            forwardedHost: upgradeReq.headers["x-forwarded-host"],
            requestHost: upgradeReq.headers.host,
            forwardedProto: upgradeReq.headers["x-forwarded-proto"],
            localAddress: upgradeReq.socket?.localAddress,
            scheme: pluginSurfaceScheme,
          })
        : undefined;

    logWs("in", "open", { connId, remoteAddr, remotePort, localAddr, localPort, endpoint });
    let handshakeState: "pending" | "connected" | "failed" = "pending";
    let holdsPreauthBudget = true;
    let holdsAuthenticatedBudget = false;
    let authenticatedBudgetDeviceId: string | undefined;
    let closeCause: string | undefined;
    let closeMeta: Record<string, unknown> = {};
    let lastFrameType: string | undefined;
    let lastFrameMethod: string | undefined;
    let lastFrameId: string | undefined;

    // Protocol-level ping/pong state for dead-connection detection
    let pingTimer: ReturnType<typeof setInterval> | null = null;
    let pongTimer: ReturnType<typeof setTimeout> | null = null;
    let pongReceived = true;

    const setCloseCause = (cause: string, meta?: Record<string, unknown>) => {
      if (!closeCause) {
        closeCause = cause;
      }
      if (meta && Object.keys(meta).length > 0) {
        closeMeta = { ...closeMeta, ...meta };
      }
    };

    const releasePreauthBudget = () => {
      if (!holdsPreauthBudget) {
        return;
      }
      holdsPreauthBudget = false;
      preauthConnectionBudget.release(preauthBudgetKey);
    };

    const releaseAuthenticatedBudget = () => {
      if (!holdsAuthenticatedBudget) {
        return;
      }
      holdsAuthenticatedBudget = false;
      authenticatedConnectionBudget.release(authenticatedBudgetDeviceId, connId);
    };

    const setLastFrameMeta = (meta: { type?: string; method?: string; id?: string }) => {
      if (meta.type || meta.method || meta.id) {
        lastFrameType = meta.type ?? lastFrameType;
        lastFrameMethod = meta.method ?? lastFrameMethod;
        lastFrameId = meta.id ?? lastFrameId;
      }
    };

    const send = (obj: unknown) => {
      try {
        socket.send(JSON.stringify(obj));
      } catch {
        /* ignore */
      }
    };

    // Security (defense-in-depth): Reject invalid headers, untrusted proxy
    // headers, unauthorized origins, and unauthorized IPs BEFORE sending
    // the nonce challenge. These checks mirror the pre-handshake verifyClient
    // callback in verify-client.ts (L1). If an attacker somehow bypasses
    // verifyClient, these L2 checks still protect the connection.
    // Check order matches L1:
    //   1. Strict header validation
    //   2. Untrusted proxy header rejection
    //   3. Origin validation
    //   4. IP restriction
    //   5. Subprotocol enforcement
    if (securityConfig.strictHeaderValidation !== false) {
      const headerValidation = validateSensitiveHeaders(upgradeReq.headers);
      if (!headerValidation.ok) {
        logWsControl.warn("Strict header validation failed: duplicate or chained header detected", {
          connId,
          header: headerValidation.header,
          reason: headerValidation.reason,
        });
        socket.close(1008, "invalid headers");
        return;
      }
    }
    // Cross-header consistency: reject if X-Forwarded-For and Forwarded
    // disagree on the resolved client IP (prevents header contradiction attacks).
    const headerConsistency = validateForwardedHeaderConsistency(
      upgradeReq.headers,
      trustedProxies,
    );
    if (!headerConsistency.ok) {
      logWsControl.warn(`Forwarded header inconsistency: ${headerConsistency.reason}`, {
        connId,
      });
      socket.close(1008, "invalid headers");
      return;
    }
    const hasProxyHeaders = Boolean(
      forwardedFor || realIp || forwardedHost || xForwardedProto || forwarded,
    );
    const remoteIsTrustedProxy = isTrustedProxyAddress(remoteAddr, trustedProxies);
    if (hasProxyHeaders && !remoteIsTrustedProxy) {
      if (securityConfig.rejectUntrustedProxyHeaders !== false) {
        logWsControl.warn("Rejecting connection: proxy headers from untrusted address", {
          connId,
          remoteAddr,
        });
        socket.close(1008, "proxy headers from untrusted source");
        return;
      }
      logWsControl.warn("Proxy headers detected from untrusted address (allowed by config)", {
        connId,
        remoteAddr,
      });
    }

    // 3. Origin validation — mirrors verifyClient step 3.
    //    Re-checks origin after handshake in case config reload changed
    //    allowedOrigins between L1 and L2.
    const hasBrowserOriginHeader = Boolean(requestOrigin && requestOrigin !== "null");
    if (hasBrowserOriginHeader) {
      const isLocalClient = isLoopbackAddress(remoteAddr) && !hasProxyHeaders;
      const hostHeaderOriginFallbackEnabled =
        controlUiConfig?.dangerouslyAllowHostHeaderOriginFallback === true ||
        securityConfig.dangerouslyAllowHostHeaderOriginFallback === true;
      const originCheck = checkBrowserOrigin({
        requestHost,
        requestForwardedHost: forwardedHost,
        requestForwardedProto: xForwardedProto,
        origin: requestOrigin,
        allowedOrigins: controlUiConfig?.allowedOrigins,
        allowHostHeaderOriginFallback: hostHeaderOriginFallbackEnabled,
        isLocalClient,
        isTrustedProxy: remoteIsTrustedProxy,
        forwardedHeader: forwarded,
        disableLocalhostPrivilege:
          securityConfig.disableLocalhostPrivilege !== false ||
          (securityConfig.autoDisableLocalhostBehindProxy !== false && hasProxyHeaders),
        validateHostHeader: securityConfig.validateHostHeader !== false,
        secFetchSite,
        strictProtoValidation: securityConfig.strictProtoValidation,
      });
      if (!originCheck.ok) {
        logWsControl.warn(`Origin not allowed: ${originCheck.reason}`, {
          connId,
          origin: requestOrigin,
        });
        socket.close(1008, "origin not allowed");
        return;
      }
    }

    // Security (defense-in-depth): IP restriction check — also enforced by
    // verifyClient (L1). This second check uses the same resolved clientIp
    // and catches any config reload drift between handshake and first message.
    const clientIp = resolveClientIp({
      remoteAddr,
      forwardedFor,
      forwarded: upgradeReq.headers.forwarded,
      realIp,
      trustedProxies,
      allowRealIpFallback,
    });
    const ipRestriction: IpRestrictionConfig = {
      ipAllowlist: securityConfig.ipAllowlist,
      ipBlocklist: securityConfig.ipBlocklist,
    };
    if (
      (ipRestriction.ipAllowlist?.length || ipRestriction.ipBlocklist?.length) &&
      !isIpAllowed(clientIp, ipRestriction)
    ) {
      logWsControl.warn("Connection rejected: IP not allowed", {
        connId,
        remoteAddr,
        clientIp,
      });
      socket.close(1008, "ip not allowed");
      return;
    }

    // Subprotocol enforcement — mirrors verifyClient step 5.
    if (securityConfig.requireSubprotocol !== false) {
      if (socket.protocol !== GATEWAY_WS_SUBPROTOCOL) {
        logWsControl.warn("Missing required subprotocol", { connId });
        socket.close(1002, "Missing required subprotocol");
        return;
      }
    }

    const connectNonce = randomUUID();

    let handshakeTimer: ReturnType<typeof setTimeout> | null = null;
    const clearHandshakeTimer = () => {
      if (handshakeTimer) {
        clearTimeout(handshakeTimer);
        handshakeTimer = null;
      }
    };

    const close = (code = 1000, reason?: string) => {
      if (closed) {
        return;
      }
      closed = true;
      clearHandshakeTimer();
      if (pingTimer) {
        clearInterval(pingTimer);
        pingTimer = null;
      }
      if (pongTimer) {
        clearTimeout(pongTimer);
        pongTimer = null;
      }
      releasePreauthBudget();
      releaseAuthenticatedBudget();
      if (client) {
        clients.delete(client);
      }
      try {
        socket.close(code, reason);
      } catch {
        /* ignore */
      }
    };

    socket.once("error", (err) => {
      if (isWsPayloadLimitError(err)) {
        logRejectedLargePayload({
          surface: client ? "gateway.ws.frame" : "gateway.ws.preauth",
          limitBytes: client ? MAX_PAYLOAD_BYTES : MAX_PREAUTH_PAYLOAD_BYTES,
          reason: client ? "ws_frame_limit" : "preauth_frame_limit",
        });
      }
      logWsControl.warn(`error conn=${connId} remote=${remoteAddr ?? "?"}: ${formatError(err)}`);
      close();
    });

    const isNoisySwiftPmHelperClose = (userAgent: string | undefined, remote: string | undefined) =>
      normalizeLowercaseStringOrEmpty(userAgent).includes("swiftpm-testing-helper") &&
      isLoopbackAddress(remote);

    socket.once("close", (code, reason) => {
      const durationMs = Date.now() - openedAt;
      const logForwardedFor = sanitizeLogValue(forwardedFor);
      const logOrigin = sanitizeLogValue(requestOrigin);
      const logHost = sanitizeLogValue(requestHost);
      const logUserAgent = sanitizeLogValue(requestUserAgent);
      const logReason = sanitizeLogValue(reason?.toString());
      const closeContext = {
        cause: closeCause,
        handshake: handshakeState,
        durationMs,
        lastFrameType,
        lastFrameMethod,
        lastFrameId,
        host: logHost,
        origin: logOrigin,
        userAgent: logUserAgent,
        forwardedFor: logForwardedFor,
        remoteAddr,
        remotePort,
        localAddr,
        localPort,
        endpoint,
        ...closeMeta,
      };
      if (!client) {
        const isExpectedStartupRetryClose =
          closeCause === GATEWAY_STARTUP_PENDING_CLOSE_CAUSE && code === GATEWAY_STARTUP_CLOSE_CODE;
        const logFn =
          isNoisySwiftPmHelperClose(requestUserAgent, remoteAddr) || isExpectedStartupRetryClose
            ? logWsControl.debug
            : logWsControl.warn;
        logFn(
          `closed before connect conn=${connId} peer=${endpoint ?? "n/a"} remote=${remoteAddr ?? "?"} fwd=${logForwardedFor || "n/a"} origin=${logOrigin || "n/a"} host=${logHost || "n/a"} ua=${logUserAgent || "n/a"} code=${code ?? "n/a"} reason=${logReason || "n/a"}`,
          closeContext,
        );
      }
      if (client && isWebchatClient(client.connect.client)) {
        logWsControl.info(
          `webchat disconnected code=${code} reason=${logReason || "n/a"} conn=${connId}`,
        );
      }
      const context = buildRequestContext();
      context.unsubscribeAllSessionEvents(connId);
      let currentDisconnectedNodeId: string | null = null;
      if (client?.connect?.role === "node") {
        currentDisconnectedNodeId = context.nodeRegistry.unregister(connId);
      }
      if (
        client?.presenceKey &&
        (client.connect.role !== "node" || currentDisconnectedNodeId !== null)
      ) {
        upsertPresence(client.presenceKey, { reason: "disconnect" });
        broadcastPresenceSnapshot({ broadcast, incrementPresenceVersion, getHealthVersion });
      }
      if (currentDisconnectedNodeId) {
        removeRemoteNodeInfo(currentDisconnectedNodeId);
        context.nodeUnsubscribeAll(currentDisconnectedNodeId);
        clearNodeWakeState(currentDisconnectedNodeId);
      }
      logWs("out", "close", {
        connId,
        code,
        reason: logReason,
        durationMs,
        cause: closeCause,
        handshake: handshakeState,
        lastFrameType,
        lastFrameMethod,
        lastFrameId,
        endpoint,
      });
      close();
    });

    const handshakeTimeoutMs = resolvePreauthHandshakeTimeoutMs({
      configuredTimeoutMs: params.preauthHandshakeTimeoutMs,
    });
    handshakeTimer = setTimeout(() => {
      if (!client) {
        handshakeState = "failed";
        setCloseCause("handshake-timeout", {
          handshakeMs: Date.now() - openedAt,
          endpoint,
        });
        logWsControl.warn(
          `handshake timeout conn=${connId} peer=${endpoint ?? "n/a"} remote=${remoteAddr ?? "?"}`,
        );
        close();
      }
    }, handshakeTimeoutMs);

    attachGatewayWsMessageHandlerOnDemand({
      socket,
      upgradeReq,
      connId,
      remoteAddr,
      remotePort,
      localAddr,
      localPort,
      endpoint,
      forwardedFor,
      realIp,
      requestHost: forwardedHost || requestHost,
      requestOrigin,
      requestUserAgent,
      pluginSurfaceBaseUrl,
      pluginNodeCapabilities,
      connectNonce,
      getResolvedAuth,
      getRequiredSharedGatewaySessionGeneration,
      rateLimiter,
      browserRateLimiter,
      isStartupPending,
      gatewayMethods,
      events,
      extraHandlers,
      getMethodRegistry,
      buildRequestContext,
      refreshHealthSnapshot,
      send,
      close,
      isClosed: () => closed,
      clearHandshakeTimer,
      getClient: () => client,
      setClient: (next) => {
        if (closed) {
          return false;
        }
        releasePreauthBudget();
        // Acquire authenticated connection budget after successful handshake.
        const deviceId = next.connect?.device?.id;
        if (!holdsAuthenticatedBudget && authenticatedConnectionBudget.acquire(deviceId, connId)) {
          holdsAuthenticatedBudget = true;
          authenticatedBudgetDeviceId = deviceId;
        }
        client = next;
        clients.add(next);
        return true;
      },
      setHandshakeState: (next) => {
        handshakeState = next;
      },
      setCloseCause,
      setLastFrameMeta,
      onHandshakeComplete: pingConfig
        ? () => {
            if (pingTimer) {
              return;
            }
            // Start protocol-level ping/pong after successful handshake.
            // Proxies forward WebSocket ping/pong frames natively, so this
            // detects TCP half-open connections that application-level ticks miss.
            socket.on("pong", () => {
              pongReceived = true;
              if (pongTimer) {
                clearTimeout(pongTimer);
                pongTimer = null;
              }
            });
            pingTimer = setInterval(() => {
              if (closed) {
                return;
              }
              pongReceived = false;
              try {
                socket.ping();
              } catch {
                close(PONG_TIMEOUT_CLOSE_CODE, "ping failed");
              }
              pongTimer = setTimeout(() => {
                if (!closed && !pongReceived) {
                  logWsControl.warn(`pong timeout conn=${connId} remote=${remoteAddr ?? "?"}`);
                  close(PONG_TIMEOUT_CLOSE_CODE, "pong timeout");
                }
              }, pingConfig.pongTimeoutMs);
            }, pingConfig.pingIntervalMs);
          }
        : undefined,
      originCheckMetrics,
      logGateway,
      logHealth,
      logWsControl,
      toolAuditLogger,
    });

    try {
      socket.send(
        JSON.stringify({
          type: "event",
          event: "connect.challenge",
          payload: { nonce: connectNonce },
        }),
      );
    } catch (err) {
      logWsControl.warn(`failed to send nonce challenge conn=${connId}: ${String(err)}`);
      close(1011, "failed to send nonce challenge");
    }
  });
}
