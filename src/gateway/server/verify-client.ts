import type { IncomingMessage, OutgoingHttpHeaders } from "node:http";
import { loadConfig } from "../../config/io.js";
import type { OpenClawConfig } from "../../config/types.js";
import {
  SENSITIVE_HEADERS,
  validateForwardedHeaderConsistency,
  validateProtoMismatch,
  validateSensitiveHeaders,
} from "../forwarded-headers.js";
import { isLoopbackAddress, isTrustedProxyAddress } from "../net.js";
import { checkBrowserOrigin } from "../origin-check.js";

const HTTP_BAD_REQUEST = 400;
const HTTP_FORBIDDEN = 403;

type GatewayVerifyClientInfo = { origin: string; secure: boolean; req: IncomingMessage };
type GatewayVerifyClientCallback = (
  result: boolean,
  code?: number,
  message?: string,
  headers?: OutgoingHttpHeaders,
) => void;

export type GatewayVerifyClient = (
  info: GatewayVerifyClientInfo,
  callback: GatewayVerifyClientCallback,
) => void;

export type GatewayVerifyClientParams = {
  log: { info: (msg: string) => void; warn: (msg: string) => void };
  /** Cached config snapshot getter. Falls back to loadConfig() when not provided. */
  getConfigSnapshot?: () => OpenClawConfig;
};

function headerValue(value: string | string[] | undefined): string {
  if (Array.isArray(value)) {
    return value[0] ?? "";
  }
  return value ?? "";
}

function hasSocketTlsFlags(
  socket: object,
): socket is { authorized?: unknown; encrypted?: unknown } {
  return "authorized" in socket || "encrypted" in socket;
}

function isSecureUpgradeRequest(req: IncomingMessage): boolean {
  const socket = req.socket;
  return hasSocketTlsFlags(socket) && (socket.authorized === true || socket.encrypted === true);
}

/**
 * Pre-handshake WebSocket validation for the gateway. Runs before the HTTP 101
 * response so unauthenticated clients never complete the upgrade.
 *
 * Design is additive and safe for existing deployments:
 * - Non-browser clients (CLI, native apps) send no Origin header and pass through;
 *   they are authenticated post-handshake as upstream does today.
 * - Only browser-origin requests are origin-checked, and only when an Origin is present.
 * - Protocol/header contradiction checks only reject genuine mismatches; they never
 *   reject a well-formed request from a trusted proxy.
 *
 * Checks (defense-in-depth):
 * 1. Proto mismatch — reject when X-Forwarded-Proto / Forwarded proto disagrees with
 *    the socket transport, but only when the peer is NOT a trusted proxy (a trusted
 *    TLS-terminating proxy legitimately presents plaintext to the gateway).
 * 2. Forwarded-header consistency — reject when X-Forwarded-For and Forwarded disagree
 *    on the resolved client IP (header contradiction / smuggling attack).
 * 3. Strict header validation (opt-in) — reject duplicate or comma-chained sensitive
 *    proxy headers.
 * 4. Untrusted proxy headers (opt-in) — reject proxy headers from a non-trusted peer.
 * 5. Origin + Sec-Fetch-Site — reject unauthorized browser origins and cross-site
 *    WebSocket initiations (CSRF / DNS-rebinding class defenses).
 */
export function createGatewayVerifyClient(params: GatewayVerifyClientParams): GatewayVerifyClient {
  const { log, getConfigSnapshot } = params;

  return (info, callback) => {
    const { req } = info;
    const configSnapshot = getConfigSnapshot?.() ?? loadConfig();
    const gateway = configSnapshot.gateway as unknown as Record<string, unknown> | undefined;
    const security = (gateway?.security ?? {}) as Record<string, unknown>;
    const controlUi = configSnapshot.gateway?.controlUi;
    const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];

    const firstHeader = (value: string | string[] | undefined) =>
      Array.isArray(value) ? value[0] : value;

    const remoteAddr = req.socket?.remoteAddress;
    const MAX_FORWARDED_HEADER_LENGTH = 4096;
    const forwardedFor =
      firstHeader(req.headers["x-forwarded-for"])?.slice(0, MAX_FORWARDED_HEADER_LENGTH) ??
      undefined;
    const forwardedHost =
      firstHeader(req.headers["x-forwarded-host"])?.slice(0, MAX_FORWARDED_HEADER_LENGTH) ??
      undefined;
    const xForwardedProto = firstHeader(req.headers["x-forwarded-proto"]);
    const forwarded =
      firstHeader(req.headers.forwarded)?.slice(0, MAX_FORWARDED_HEADER_LENGTH) ?? undefined;
    const hasProxyHeaders = Boolean(
      forwardedFor || req.headers["x-real-ip"] || forwardedHost || xForwardedProto || forwarded,
    );
    const remoteIsTrustedProxy = isTrustedProxyAddress(remoteAddr, trustedProxies);

    // 1. Proto mismatch — only enforce when the peer is not a trusted proxy.
    if (!remoteIsTrustedProxy) {
      const originProto = isSecureUpgradeRequest(req) ? "https" : "http";
      const protoCheck = validateProtoMismatch({
        originProto,
        forwardedProto: forwarded
          ? firstHeader(req.headers.forwarded)?.match(/proto=([^;,]+)/i)?.[1]
          : undefined,
        xForwardedProto: xForwardedProto ? [xForwardedProto] : undefined,
      });
      if (!protoCheck.ok) {
        log.warn(`verifyClient: ${protoCheck.reason}`);
        callback(false, HTTP_BAD_REQUEST, "invalid protocol");
        return;
      }
    }

    // 2. Forwarded-header consistency.
    const consistency = validateForwardedHeaderConsistency(req.headers, trustedProxies);
    if (!consistency.ok) {
      log.warn(`verifyClient: ${consistency.reason}`);
      callback(false, HTTP_BAD_REQUEST, "invalid headers");
      return;
    }

    // 3. Strict header validation (opt-in). Comma-chained X-Forwarded-For is common
    //    behind real proxies, so this is OFF by default to avoid breaking deployments.
    if (security.strictHeaderValidation === true) {
      const headerValidation = validateSensitiveHeaders(req.headers);
      if (!headerValidation.ok) {
        log.warn(`verifyClient: strict header validation failed: ${headerValidation.header}`);
        callback(false, HTTP_BAD_REQUEST, "invalid headers");
        return;
      }
    }

    // 4. Untrusted proxy headers (opt-in).
    if (hasProxyHeaders && !remoteIsTrustedProxy && security.rejectUntrustedProxyHeaders === true) {
      log.warn(`verifyClient: proxy headers from untrusted address (remote=${remoteAddr ?? "?"})`);
      callback(false, HTTP_FORBIDDEN, "proxy headers from untrusted source");
      return;
    }

    // 5. Origin + Sec-Fetch-Site (browser clients only).
    const MAX_ORIGIN_LENGTH = 256;
    const requestOrigin = info.origin?.slice(0, MAX_ORIGIN_LENGTH) ?? undefined;
    const hasBrowserOriginHeader = Boolean(requestOrigin && requestOrigin !== "null");
    if (!hasBrowserOriginHeader) {
      callback(true);
      return;
    }

    const isLocalClient = isLoopbackAddress(remoteAddr) && !hasProxyHeaders;
    const hostHeaderOriginFallbackEnabled =
      controlUi?.dangerouslyAllowHostHeaderOriginFallback === true ||
      security.dangerouslyAllowHostHeaderOriginFallback === true;
    const originCheck = checkBrowserOrigin({
      requestHost: headerValue(req.headers.host)?.slice(0, 256),
      origin: requestOrigin,
      allowedOrigins: controlUi?.allowedOrigins,
      allowHostHeaderOriginFallback: hostHeaderOriginFallbackEnabled,
      isLocalClient,
    });
    if (!originCheck.ok) {
      log.warn(`verifyClient: origin not allowed (${originCheck.reason})`);
      callback(false, HTTP_FORBIDDEN, "origin not allowed");
      return;
    }

    // Sec-Fetch-Site cross-site rejection (CSRF class defense). Only browsers send
    // this header; same-origin Control UI connections pass. Opt-out via config.
    const secFetchSite = headerValue(req.headers["sec-fetch-site"]).toLowerCase();
    if (
      security.rejectCrossSiteWebSocketRequests !== false &&
      (secFetchSite === "cross-site" || secFetchSite === "cross-origin")
    ) {
      log.warn(
        `verifyClient: cross-site websocket request rejected (sec-fetch-site=${secFetchSite})`,
      );
      callback(false, HTTP_FORBIDDEN, "cross-site request rejected");
      return;
    }

    callback(true);
  };
}

export type GatewayVerifyClientFactoryParams = GatewayVerifyClientParams;

export function createRuntimeVerifyClient(
  params: GatewayVerifyClientFactoryParams,
): GatewayVerifyClient {
  return createGatewayVerifyClient(params);
}

export { SENSITIVE_HEADERS };
