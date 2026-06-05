// WebSocket message handler validates frames, dispatches gateway RPCs, manages pairing, and reports responses.
import type { RawData } from "ws";
import type {
  DeviceSessionAuthoritySnapshot,
  DeviceSessionAuthorityTracker,
} from "@openclaw/gateway-security-core/device-session-authority";
import { validateInboundFrame } from "@openclaw/gateway-security-core/ws-frame-validator";
import {
  checkRateLimit,
  createRateLimiterState,
  DEFAULT_FRAME_LIMITS,
  type RateLimiterState,
} from "@openclaw/gateway-security-core/ws-protocol";
import {
  GATEWAY_CLIENT_IDS,
  GATEWAY_CLIENT_MODES,
} from "../../../../packages/gateway-protocol/src/client-info.js";
import {
  type ConnectParams,
  ErrorCodes,
  errorShape,
  formatValidationErrors,
  type RequestFrame,
  validateConnectParams,
  validateRequestFrame,
} from "../../../../packages/gateway-protocol/src/index.js";
import { getRuntimeConfig } from "../../../config/io.js";
import {
  createDiagnosticTraceContext,
  runWithDiagnosticTraceContext,
} from "../../../infra/diagnostic-trace-context.js";
import {
  releaseNodePairingCleanupClaim,
  type NodePairingCleanupClaim,
  type RequestNodePairingResult,
} from "../../../infra/node-pairing.js";
import { rawDataByteLength, rawDataToString } from "../../../infra/ws.js";
import { logRejectedLargePayload } from "../../../logging/diagnostic-payload.js";
import {
  getGatewaySuspendAdmissionPhase,
  isGatewayRestartDraining,
  runWithGatewayIndependentRootWorkAdmission,
  tryBeginGatewayRootWorkAdmission,
} from "../../../process/gateway-work-admission.js";
import { isWebchatClient } from "../../../utils/message-channel.js";
import { hasForwardedRequestHeaders, isLocalDirectRequest } from "../../auth.js";
import {
  authorizeMessage,
  createMessageAuthContext,
  resolveMessageAuthorizationDecision,
  type MessageAuthorizationContext,
} from "../../message-auth.js";
import {
  isLocalishHost,
  isLoopbackAddress,
  isTrustedProxyAddress,
  resolveClientIp,
} from "../../net.js";
import { resolveNodePairingClientIpSource } from "../../node-pairing-auto-approve.js";
import { MAX_PREAUTH_PAYLOAD_BYTES } from "../../server-constants.js";
import { formatForLog, logWs } from "../../ws-log.js";
import { truncateCloseReason } from "../close-reason.js";
import { createGatewayAuthenticatedRequestDispatcher } from "./authenticated-request-dispatch.js";
import { authenticateGatewayConnect } from "./connect-auth.js";
import { resolvePinnedClientMetadata } from "./connect-device-metadata.js";
import { authorizeGatewayConnectDevice } from "./connect-device-pairing.js";
import { attachAuthenticatedGatewayConnect } from "./connect-session.js";
import { resolveHandshakeBrowserSecurityContext } from "./handshake-auth-helpers.js";
import type { GatewayConnectPhaseContext } from "./message-handler-types.js";
export type {
  GatewayWsMessageHandlerParams,
  WsOriginCheckMetrics,
} from "./message-handler-types.js";
import type { GatewayWsMessageHandlerParams } from "./message-handler-types.js";

const GATEWAY_WORK_ADMISSION_RETRY_AFTER_MS = 1_000;
const GATEWAY_WORK_ADMISSION_CLOSE_CODE = 1013;
function claimsWorkerConnectionIdentity(value: unknown): boolean {
  if (!value || typeof value !== "object") {
    return false;
  }
  const connect = value as { role?: unknown; client?: unknown };
  if (connect.role === "worker") {
    return true;
  }
  if (!connect.client || typeof connect.client !== "object") {
    return false;
  }
  const client = connect.client as { id?: unknown; mode?: unknown };
  return client.id === GATEWAY_CLIENT_IDS.WORKER || client.mode === GATEWAY_CLIENT_MODES.WORKER;
}

export function attachGatewayWsMessageHandler(params: GatewayWsMessageHandlerParams) {
  const {
    socket,
    upgradeReq,
    connId,
    remoteAddr,
    endpoint,
    forwardedFor,
    realIp,
    requestHost,
    requestOrigin,
    requestUserAgent,
    rateLimiter,
    browserRateLimiter,
    deviceSessionAuthorityTracker,
    buildRequestContext,
    send,
    close,
    isClosed,
    getClient,
    setHandshakeState,
    setCloseCause,
    setLastFrameMeta,
    logGateway,
    logWsControl,
  } = params;

  const sendFrame = async (obj: unknown): Promise<void> =>
    await new Promise<void>((resolve, reject) => {
      socket.send(JSON.stringify(obj), (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });

  const configSnapshot = getRuntimeConfig();
  const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];
  const allowRealIpFallback = configSnapshot.gateway?.allowRealIpFallback === true;
  const clientIp = resolveClientIp({
    remoteAddr,
    forwardedFor,
    realIp,
    trustedProxies,
    allowRealIpFallback,
  });
  const peerLabel = endpoint ?? remoteAddr ?? "n/a";

  // If proxy headers are present but the remote address isn't trusted, don't treat
  // the connection as local. This prevents auth bypass when running behind a reverse
  // proxy without proper configuration - the proxy's loopback connection would otherwise
  // cause all external requests to be treated as trusted local clients.
  const hasProxyHeaders = hasForwardedRequestHeaders(upgradeReq);
  const remoteIsTrustedProxy = isTrustedProxyAddress(remoteAddr, trustedProxies);
  const hasUntrustedProxyHeaders = hasProxyHeaders && !remoteIsTrustedProxy;
  const hostIsLocalish = isLocalishHost(requestHost);
  const isLocalClient = isLocalDirectRequest(upgradeReq, trustedProxies, allowRealIpFallback);
  const reportedClientIp =
    isLocalClient || hasUntrustedProxyHeaders
      ? undefined
      : clientIp && !isLoopbackAddress(clientIp)
        ? clientIp
        : undefined;
  const reportedClientIpSource = resolveNodePairingClientIpSource({
    reportedClientIp,
    hasProxyHeaders,
    remoteIsTrustedProxy,
    remoteIsLoopback: isLoopbackAddress(remoteAddr),
  });

  if (hasUntrustedProxyHeaders) {
    logWsControl.warn(
      "Proxy headers detected from untrusted address. " +
        "Connection will not be treated as local. " +
        "Configure gateway.trustedProxies to restore local client detection behind your proxy.",
    );
  }
  if (!hostIsLocalish && isLoopbackAddress(remoteAddr) && !hasProxyHeaders) {
    logWsControl.warn(
      "Loopback connection with non-local Host header. " +
        "Treating it as remote. If you're behind a reverse proxy, " +
        "set gateway.trustedProxies and forward X-Forwarded-For/X-Real-IP.",
    );
  }

  const isWebchatConnect = (p: ConnectParams | null | undefined) => isWebchatClient(p?.client);
  const authenticatedRequestDispatcher = createGatewayAuthenticatedRequestDispatcher({
    handler: params,
    isWebchatConnect,
  });
  const MAX_MALFORMED_FRAMES_BEFORE_CLOSE = 3;
  let malformedFrameCount = 0;
  const browserSecurity = resolveHandshakeBrowserSecurityContext({
    requestOrigin,
    clientIp,
    rateLimiter,
    browserRateLimiter,
  });
  const {
    hasBrowserOriginHeader,
    enforceOriginCheckForAnyClient,
    rateLimitClientIp: browserRateLimitClientIp,
    authRateLimiter,
  } = browserSecurity;
  const runDetachedConnectWork = (run: () => Promise<void>, onError: (error: unknown) => void) => {
    // Connect-triggered mutations outlive hello-ok. Give each tail its own
    // root lease so suspension cannot report ready while one is still active.
    void runWithGatewayIndependentRootWorkAdmission(run).catch(onError);
  };

  let messageAuthContext: MessageAuthorizationContext | undefined;
  let deviceSessionAuthority: DeviceSessionAuthoritySnapshot | null = null;

  // Per-connection rate limiter state for frame/message/byte budget enforcement.
  const rateLimiterState: RateLimiterState = createRateLimiterState();

  const handleMessage = async (data: RawData) => {
    if (isClosed()) {
      return;
    }
    // Per-connection rate limiting: frame/message/byte budget.
    const payloadBytes = rawDataByteLength(data);
    const rateResult = checkRateLimit(rateLimiterState, DEFAULT_FRAME_LIMITS, payloadBytes);
    if (!rateResult.ok) {
      setCloseCause("rate-limit-exceeded", { reason: rateResult.reason });
      logWsControl.warn(
        `rate limit exceeded conn=${connId} reason=${rateResult.reason} remote=${remoteAddr ?? "?"}`,
      );
      close(1008, rateResult.reason);
      return;
    }

    const preauthPayloadBytes = !getClient() ? payloadBytes : undefined;
    if (preauthPayloadBytes !== undefined && preauthPayloadBytes > MAX_PREAUTH_PAYLOAD_BYTES) {
      logRejectedLargePayload({
        surface: "gateway.ws.preauth",
        bytes: preauthPayloadBytes,
        limitBytes: MAX_PREAUTH_PAYLOAD_BYTES,
        reason: "preauth_frame_limit",
      });
      setHandshakeState("failed");
      setCloseCause("preauth-payload-too-large", {
        payloadBytes: preauthPayloadBytes,
        limitBytes: MAX_PREAUTH_PAYLOAD_BYTES,
      });
      close(1009, "preauth payload too large");
      return;
    }

    const text = rawDataToString(data);
    // Connect phases share cleanup ownership; the outer catch must release
    // any claim installed before a later phase fails.
    const pendingNodePairingCleanup: { value?: NodePairingCleanupClaim } = {};
    let parsed: unknown;
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      malformedFrameCount += 1;
      if (malformedFrameCount >= MAX_MALFORMED_FRAMES_BEFORE_CLOSE) {
        setCloseCause("too-many-malformed-frames", {
          count: malformedFrameCount,
        });
        logWsControl.warn(
          `too many invalid frames conn=${connId} count=${malformedFrameCount} remote=${remoteAddr ?? "?"}`,
        );
        close(1008, "too many invalid frames");
      }
      return;
    }
    const broadcastNodePairingResult = (result: RequestNodePairingResult) => {
      const context = buildRequestContext();
      const resolvedAt = Date.now();
      for (const superseded of result.created ? (result.superseded ?? []) : []) {
        context.broadcast(
          "node.pair.resolved",
          {
            requestId: superseded.requestId,
            nodeId: superseded.nodeId,
            decision: "rejected",
            ts: resolvedAt,
          },
          { dropIfSlow: true },
        );
      }
      if (result.created) {
        context.broadcast("node.pair.requested", result.request, {
          dropIfSlow: true,
        });
      }
    };
    const releasePendingNodePairingCleanup = async () => {
      const claim = pendingNodePairingCleanup.value;
      pendingNodePairingCleanup.value = undefined;
      if (!claim) {
        return;
      }
      try {
        await releaseNodePairingCleanupClaim(claim);
      } catch (error) {
        logGateway.warn(
          `failed to release pending pairing cleanup for ${claim.nodeId}: ${formatForLog(error)}`,
        );
      }
    };

    // Defense-in-depth: validate frame structure against Zod schema.
    const frameValidation = validateInboundFrame(parsed);
    if (!frameValidation.ok) {
      malformedFrameCount += 1;
      if (malformedFrameCount >= MAX_MALFORMED_FRAMES_BEFORE_CLOSE) {
        setCloseCause("too-many-malformed-frames", {
          count: malformedFrameCount,
        });
        close(1008, "too many invalid frames");
      }
      return;
    }
    try {
      const client = getClient();
      if (
        !client &&
        parsed !== null &&
        typeof parsed === "object" &&
        "params" in parsed &&
        claimsWorkerConnectionIdentity(parsed.params)
      ) {
        setHandshakeState("failed");
        setCloseCause("invalid-handshake", { handshakeError: "invalid worker handshake" });
        logWsControl.warn("worker admission rejected reason=invalid-handshake");
        close(1008, "invalid-handshake");
        return;
      }
      const frameType =
        parsed && typeof parsed === "object" && "type" in parsed
          ? typeof (parsed as { type?: unknown }).type === "string"
            ? String((parsed as { type?: unknown }).type)
            : undefined
          : undefined;
      const frameMethod =
        parsed && typeof parsed === "object" && "method" in parsed
          ? typeof (parsed as { method?: unknown }).method === "string"
            ? String((parsed as { method?: unknown }).method)
            : undefined
          : undefined;
      const frameId =
        parsed && typeof parsed === "object" && "id" in parsed
          ? typeof (parsed as { id?: unknown }).id === "string"
            ? String((parsed as { id?: unknown }).id)
            : undefined
          : undefined;
      if (frameType || frameMethod || frameId) {
        setLastFrameMeta({ type: frameType, method: frameMethod, id: frameId });
      }

      if (!client) {
        // Handshake must be a normal request:
        // { type:"req", method:"connect", params: ConnectParams }.
        const isRequestFrame = validateRequestFrame(parsed);
        const preAuthParsed = parsed as RequestFrame;
        if (
          !isRequestFrame ||
          preAuthParsed.method !== "connect" ||
          !validateConnectParams(preAuthParsed.params)
        ) {
          const handshakeError = isRequestFrame
            ? preAuthParsed.method === "connect"
              ? `invalid connect params: ${formatValidationErrors(validateConnectParams.errors)}`
              : "invalid handshake: first request must be connect"
            : "invalid request frame";
          setHandshakeState("failed");
          setCloseCause("invalid-handshake", {
            frameType,
            frameMethod,
            frameId,
            handshakeError,
          });
          if (isRequestFrame) {
            const req = parsed as RequestFrame;
            send({
              type: "res",
              id: req.id,
              ok: false,
              error: errorShape(ErrorCodes.INVALID_REQUEST, handshakeError),
            });
          } else {
            logWsControl.warn(
              `invalid handshake conn=${connId} peer=${formatForLog(peerLabel)} remote=${remoteAddr ?? "?"} fwd=${formatForLog(forwardedFor ?? "n/a")} origin=${formatForLog(requestOrigin ?? "n/a")} host=${formatForLog(requestHost ?? "n/a")} ua=${formatForLog(requestUserAgent ?? "n/a")}`,
            );
          }
          const closeReason = truncateCloseReason(handshakeError || "invalid handshake");
          if (isRequestFrame) {
            queueMicrotask(() => close(1008, closeReason));
          } else {
            close(1008, closeReason);
          }
          return;
        }

        const frame = parsed as RequestFrame;
        const connectParams = frame.params as ConnectParams;
        const clientLabel = connectParams.client.displayName ?? connectParams.client.id;
        const clientMeta = {
          client: connectParams.client.id,
          clientDisplayName: connectParams.client.displayName,
          mode: connectParams.client.mode,
          version: connectParams.client.version,
          platform: connectParams.client.platform,
          deviceFamily: connectParams.client.deviceFamily,
          modelIdentifier: connectParams.client.modelIdentifier,
          instanceId: connectParams.client.instanceId,
        };
        const markHandshakeFailure = (cause: string, meta?: Record<string, unknown>) => {
          setHandshakeState("failed");
          setCloseCause(cause, { ...meta, ...clientMeta });
        };
        const sendHandshakeErrorResponse = (
          code: Parameters<typeof errorShape>[0],
          message: string,
          options?: Parameters<typeof errorShape>[2],
        ) => {
          send({
            type: "res",
            id: frame.id,
            ok: false,
            error: errorShape(code, message, options),
          });
        };

        const phaseContext = {
          handler: params,
          frame,
          connectParams,
          configSnapshot,

          trustedProxies,
          allowRealIpFallback,
          peerLabel,
          hasProxyHeaders,
          isLocalClient,
          reportedClientIp,
          reportedClientIpSource,
          hasBrowserOriginHeader,
          enforceOriginCheckForAnyClient,
          browserRateLimitClientIp,
          authRateLimiter,
          clientLabel,
          clientMeta,
          markHandshakeFailure,
          sendHandshakeErrorResponse,
          sendFrame,
          isWebchatConnect,
          runDetachedConnectWork,
          pendingNodePairingCleanup,
          broadcastNodePairingResult,
          releasePendingNodePairingCleanup,
        } satisfies GatewayConnectPhaseContext;
        const authenticated = await authenticateGatewayConnect(phaseContext);
        if (!authenticated) {
          return;
        }
        const deviceAuthorized = await authorizeGatewayConnectDevice(phaseContext, authenticated);
        if (!deviceAuthorized) {
          return;
        }
        messageAuthContext = createMessageAuthContext({
          clientId: connectParams.client.id,
          role: authenticated.role,
          scopes: authenticated.scopes,
          endpoint: "ws-message",
        });
        const deviceId = connectParams.device?.id;
        const sessionRole = connectParams.client?.mode;
        if (deviceId && sessionRole) {
          deviceSessionAuthority = deviceSessionAuthorityTracker?.createSnapshot({
            deviceId,
            role: sessionRole,
          });
        }
        await attachAuthenticatedGatewayConnect(phaseContext, deviceAuthorized);
        return;
      }
      if (deviceSessionAuthorityTracker?.isStale(deviceSessionAuthority)) {
        setCloseCause("session-authority-stale", {
          deviceId: connectParams.device?.id,
        });
        close(4001, "session authority changed");
        return;
      }
      if (
        messageAuthContext !== undefined &&
        configSnapshot.gateway?.security?.messageAuth?.enabled !== false
      ) {
        const req = parsed as RequestFrame;
        const messageType = `gateway.method.${req.method}`;
        const decision = resolveMessageAuthorizationDecision(messageType, {});
        if (decision !== undefined) {
          let requiresExtraCheck = false;
          if (decision.kind === "role" && decision.role === "node") {
            requiresExtraCheck = true;
          } else if (
            decision.kind === "capability" &&
            (decision.capability === "secrets:read" ||
              decision.capability === "secrets:manage" ||
              decision.capability === "admin:config")
          ) {
            requiresExtraCheck = true;
          }
          if (requiresExtraCheck) {
            const authDecision = authorizeMessage(messageAuthContext, messageType, {});
            if (!authDecision.ok) {
              const isNodeRole = decision.kind === "role" && decision.role === "node";
              const errorMessage = isNodeRole
                ? `unauthorized role: ${messageAuthContext.role ?? "operator"} for method ${req.method}`
                : `missing scope: ${authDecision.missingCapability} for method ${req.method}`;
              send({
                type: "res",
                id: req.id,
                ok: false,
                error: errorShape(ErrorCodes.INVALID_REQUEST, errorMessage, {
                  details: {
                    code: "method-not-authorized",
                    method: req.method,
                    ...(isNodeRole
                      ? { requiredRole: "node" }
                      : { missingScope: authDecision.missingCapability }),
                  },
                }),
              });
              return;
            }
          }
        }
      }
      await authenticatedRequestDispatcher.dispatch(parsed, client);
    } catch (err) {
      await releasePendingNodePairingCleanup();
      logGateway.error(`parse/handle error: ${String(err)}`);
      logWs("out", "parse-error", { connId, error: formatForLog(err) });
      if (!getClient()) {
        close();
      }
    }
  };

  const rejectConnectForClosedAdmission = async (data: RawData): Promise<boolean> => {
    if (isClosed() || rawDataByteLength(data) > MAX_PREAUTH_PAYLOAD_BYTES) {
      return false;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawDataToString(data));
    } catch {
      return false;
    }
    if (
      !validateRequestFrame(parsed) ||
      parsed.method !== "connect" ||
      !validateConnectParams(parsed.params)
    ) {
      return false;
    }

    const restartDraining = isGatewayRestartDraining();
    const reason = restartDraining ? "gateway-restarting" : "gateway-suspending";
    const operation = restartDraining ? "restart" : "suspension";
    const phase = getGatewaySuspendAdmissionPhase();
    setLastFrameMeta({ type: "req", method: "connect", id: parsed.id });
    setHandshakeState("failed");
    setCloseCause(reason, {
      method: "connect",
      phase,
    });
    await sendFrame({
      type: "res",
      id: parsed.id,
      ok: false,
      error: errorShape(ErrorCodes.UNAVAILABLE, `connect unavailable during gateway ${operation}`, {
        retryable: true,
        retryAfterMs: GATEWAY_WORK_ADMISSION_RETRY_AFTER_MS,
        details: {
          method: "connect",
          reason,
          phase,
        },
      }),
    }).catch(() => {});
    queueMicrotask(() =>
      close(GATEWAY_WORK_ADMISSION_CLOSE_CODE, `gateway ${operation} in progress`),
    );
    return true;
  };

  const handleIncomingMessage = async (data: RawData) => {
    if (getClient()) {
      await handleMessage(data);
      return;
    }
    const admission = tryBeginGatewayRootWorkAdmission();
    if (!admission) {
      if (await rejectConnectForClosedAdmission(data)) {
        return;
      }
      // Malformed pre-auth frames still use the established validation and
      // close path; only a validated connect can cross into mutable work.
      await handleMessage(data);
      return;
    }
    try {
      await admission.run(() => handleMessage(data));
    } finally {
      admission.release();
    }
  };

  socket.on("message", (data) => {
    void runWithDiagnosticTraceContext(createDiagnosticTraceContext(), () =>
      handleIncomingMessage(data),
    );
  });
}

export const testing = {
  resolvePinnedClientMetadata,
};
export { testing as __testing };
