import type { IncomingMessage, OutgoingHttpHeaders } from "node:http";
import type { ConnectionRateLimiter } from "@openclaw/gateway-security-core/connection-rate-limit";
import {
  isIpAllowed,
  type IpRestrictionConfig,
} from "@openclaw/gateway-security-core/ip-restriction-policy";
import { hasGatewayWsSubprotocol } from "@openclaw/gateway-security-core/ws-protocol";
import { loadConfig } from "../../config/io.js";
import {
  isLoopbackAddress,
  isTrustedProxyAddress,
  resolveClientIp,
  validateForwardedHeaderConsistency,
  validateSensitiveHeaders,
} from "../net.js";
import { checkBrowserOrigin } from "../origin-check.js";

const HTTP_BAD_REQUEST = 400;
const HTTP_FORBIDDEN = 403;
const HTTP_TOO_MANY_REQUESTS = 429;
const HTTP_SERVICE_UNAVAILABLE = 503;

export type GatewayVerifyClientParams = {
  log: { info: (msg: string) => void; warn: (msg: string) => void };
  /** Pre-handshake connection rate limiter for DoS protection. */
  connectionRateLimiter?: ConnectionRateLimiter;
  /** Maximum concurrent WebSocket connections. Rejects new connections when reached. */
  maxConnections?: number;
  /** Current connection count accessor — called on each verifyClient invocation. */
  activeConnectionCount?: () => number;
};

type GatewayVerifyClientInfo = { origin: string; secure: boolean; req: IncomingMessage };
type GatewayVerifyClientCallback = (
  result: boolean,
  code?: number,
  message?: string,
  headers?: OutgoingHttpHeaders,
) => void;
type GatewayVerifyClientSync = (info: GatewayVerifyClientInfo) => boolean;
type GatewayVerifyClientAsync = (
  info: GatewayVerifyClientInfo,
  callback: GatewayVerifyClientCallback,
) => void;

export type GatewayVerifyClient = GatewayVerifyClientSync | GatewayVerifyClientAsync;

export type GatewayUpgradePreflightResult =
  | { ok: true }
  | { ok: false; code: number; message: string; headers?: OutgoingHttpHeaders };

function isSyncGatewayVerifyClient(
  verifyClient: GatewayVerifyClient,
): verifyClient is GatewayVerifyClientSync {
  return verifyClient.length < 2;
}

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

function createVerifyClientInfo(req: IncomingMessage): GatewayVerifyClientInfo {
  const version = Number(headerValue(req.headers["sec-websocket-version"]));
  const originHeader = version === 8 ? "sec-websocket-origin" : "origin";
  return {
    origin: headerValue(req.headers[originHeader]),
    secure: isSecureUpgradeRequest(req),
    req,
  };
}

export async function runGatewayUpgradePreflight(
  verifyClient: GatewayVerifyClient,
  req: IncomingMessage,
): Promise<GatewayUpgradePreflightResult> {
  const info = createVerifyClientInfo(req);
  if (isSyncGatewayVerifyClient(verifyClient)) {
    return verifyClient(info) ? { ok: true } : { ok: false, code: 401, message: "Unauthorized" };
  }

  return await new Promise<GatewayUpgradePreflightResult>((resolve) => {
    verifyClient(info, (verified, code, message, headers) => {
      if (verified) {
        resolve({ ok: true });
        return;
      }
      resolve({
        ok: false,
        code: code ?? 401,
        message: message ?? "Unauthorized",
        ...(headers ? { headers } : {}),
      });
    });
  });
}

/**
 * Creates a `verifyClient` callback for the `ws` WebSocketServer that performs
 * pre-handshake security validation per OWASP guidelines.
 *
 * All checks run before the HTTP 101 response is sent, preventing unauthenticated
 * clients from completing the WebSocket handshake. Uses the two-argument callback
 * form so rejected connections receive valid HTTP status codes and human-readable messages
 * (the synchronous boolean form in `ws` always returns 401 with no reason).
 *
 * Check order (defense-in-depth):
 * 0. Connection limits — reject when max connections reached or rate limited
 * 1. Strict header validation — rejects duplicate/chained sensitive headers
 * 2. Untrusted proxy header rejection — blocks spoofed X-Forwarded-* from non-proxies
 * 3. Origin validation — rejects unauthorized browser origins per OWASP CSRF guidance
 * 4. IP allowlist/blocklist — network-level access control
 * 5. Subprotocol enforcement — protocol compliance when configured
 */
export function createGatewayVerifyClient(
  params: GatewayVerifyClientParams,
): (
  info: { origin: string; secure: boolean; req: IncomingMessage },
  callback: (result: boolean, code?: number, message?: string) => void,
) => void {
  const { log, connectionRateLimiter, maxConnections, activeConnectionCount } = params;

  return (info, callback) => {
    const { req } = info;
    const configSnapshot = loadConfig();
    const securityConfig = configSnapshot.gateway?.security ?? {};
    const controlUiConfig = configSnapshot.gateway?.controlUi;
    const trustedProxies = configSnapshot.gateway?.trustedProxies ?? [];
    const allowRealIpFallback = configSnapshot.gateway?.allowRealIpFallback === true;

    const firstHeader = (value: string | string[] | undefined) =>
      Array.isArray(value) ? value[0] : value;

    const remoteAddr = req.socket?.remoteAddress;
    const forwardedFor = firstHeader(req.headers["x-forwarded-for"]);
    const realIp = firstHeader(req.headers["x-real-ip"]);
    const forwardedHost = firstHeader(req.headers["x-forwarded-host"]);
    const xForwardedProto = firstHeader(req.headers["x-forwarded-proto"]);
    const forwarded = firstHeader(req.headers.forwarded);

    // 0. Connection limits — prevent resource exhaustion before any auth work
    if (maxConnections !== undefined && maxConnections > 0 && activeConnectionCount) {
      const currentCount = activeConnectionCount();
      if (currentCount >= maxConnections) {
        log.warn(`verifyClient: max connections reached (${currentCount}/${maxConnections})`);
        callback(false, HTTP_SERVICE_UNAVAILABLE, "max connections reached");
        return;
      }
    }

    // 0b. Connection rate limiting — coarse per-IP throttle before handshake
    if (connectionRateLimiter) {
      const clientIpForRateLimit = resolveClientIp({
        remoteAddr,
        forwardedFor,
        forwarded,
        realIp,
        trustedProxies: configSnapshot.gateway?.trustedProxies ?? [],
        allowRealIpFallback,
      });
      const rateCheck = connectionRateLimiter.check(clientIpForRateLimit);
      if (!rateCheck.allowed) {
        log.warn(
          `verifyClient: connection rate limited (remote=${remoteAddr ?? "?"}, retryAfterMs=${rateCheck.retryAfterMs})`,
        );
        callback(false, HTTP_TOO_MANY_REQUESTS, "too many connections");
        return;
      }
      connectionRateLimiter.recordAttempt(clientIpForRateLimit);
    }

    // 1. Strict header validation — reject duplicate/chained sensitive headers
    if (securityConfig.strictHeaderValidation !== false) {
      const headerValidation = validateSensitiveHeaders(req.headers);
      if (!headerValidation.ok) {
        log.warn(
          `verifyClient: strict header validation failed: ${headerValidation.header} (${headerValidation.reason})`,
        );
        callback(false, HTTP_BAD_REQUEST, "invalid headers");
        return;
      }
    }

    // 1b. Cross-header consistency — reject if X-Forwarded-For and Forwarded
    //     disagree on the resolved client IP (prevents header contradiction attacks).
    const headerConsistency = validateForwardedHeaderConsistency(req.headers, trustedProxies);
    if (!headerConsistency.ok) {
      log.warn(`verifyClient: forwarded header inconsistency: ${headerConsistency.reason}`);
      callback(false, HTTP_BAD_REQUEST, "invalid headers");
      return;
    }

    // 2. Untrusted proxy header rejection
    //    Rejects proxy headers (X-Forwarded-For/Host/Proto/Real-IP, Forwarded)
    //    from IPs not in trustedProxies.
    //    Must run before origin and IP restriction so we don't trust spoofed
    //    headers for those decisions.
    const hasProxyHeaders = Boolean(
      forwardedFor || realIp || forwardedHost || xForwardedProto || forwarded,
    );
    const remoteIsTrustedProxy = isTrustedProxyAddress(remoteAddr, trustedProxies);
    if (hasProxyHeaders && !remoteIsTrustedProxy) {
      if (securityConfig.rejectUntrustedProxyHeaders !== false) {
        log.warn(
          `verifyClient: proxy headers from untrusted address (remote=${remoteAddr ?? "?"})`,
        );
        callback(false, HTTP_FORBIDDEN, "proxy headers from untrusted source");
        return;
      }
      log.warn(
        `verifyClient: proxy headers from untrusted address (allowed by config, remote=${remoteAddr ?? "?"})`,
      );
    }

    // 3. Origin validation — reject unauthorized browser origins per OWASP
    //    Browsers always send the Origin header for WebSocket connections.
    //    Non-browser clients (CLI, native apps) may omit it and are allowed
    //    through here; they are authenticated post-handshake.
    const requestOrigin = info.origin;
    const hasBrowserOriginHeader = Boolean(requestOrigin && requestOrigin !== "null");
    if (hasBrowserOriginHeader) {
      const isLocalClient = isLoopbackAddress(remoteAddr) && !hasProxyHeaders;
      const hostHeaderOriginFallbackEnabled =
        controlUiConfig?.dangerouslyAllowHostHeaderOriginFallback === true ||
        securityConfig.dangerouslyAllowHostHeaderOriginFallback === true;
      const originCheck = checkBrowserOrigin({
        requestHost: headerValue(req.headers.host),
        requestForwardedHost: forwardedHost,
        requestForwardedProto: headerValue(req.headers["x-forwarded-proto"]),
        origin: requestOrigin,
        allowedOrigins: controlUiConfig?.allowedOrigins,
        allowHostHeaderOriginFallback: hostHeaderOriginFallbackEnabled,
        isLocalClient,
        isTrustedProxy: remoteIsTrustedProxy,
        forwardedHeader: req.headers.forwarded,
        disableLocalhostPrivilege:
          securityConfig.disableLocalhostPrivilege !== false ||
          (securityConfig.autoDisableLocalhostBehindProxy !== false && hasProxyHeaders),
        validateHostHeader: securityConfig.validateHostHeader !== false,
        secFetchSite: headerValue(req.headers["sec-fetch-site"]),
        strictProtoValidation: securityConfig.strictProtoValidation,
      });

      if (!originCheck.ok) {
        log.warn(`verifyClient: origin not allowed (${originCheck.reason})`);
        callback(false, HTTP_FORBIDDEN, "origin not allowed");
        return;
      }
    }

    // 4. IP restriction — blocklist takes precedence over allowlist
    const ipRestriction: IpRestrictionConfig = {
      ipAllowlist: securityConfig.ipAllowlist,
      ipBlocklist: securityConfig.ipBlocklist,
    };
    if (ipRestriction.ipAllowlist?.length || ipRestriction.ipBlocklist?.length) {
      const clientIp = resolveClientIp({
        remoteAddr,
        forwardedFor,
        forwarded,
        realIp,
        trustedProxies,
        allowRealIpFallback,
      });
      if (!isIpAllowed(clientIp, ipRestriction)) {
        log.warn(
          `verifyClient: IP not allowed (remote=${remoteAddr ?? "?"}, clientIp=${clientIp ?? "?"})`,
        );
        callback(false, HTTP_FORBIDDEN, "ip not allowed");
        return;
      }
    }

    // 5. Subprotocol enforcement — clients must negotiate openclaw-gateway-v1
    if (securityConfig.requireSubprotocol !== false) {
      if (!hasGatewayWsSubprotocol(req.headers["sec-websocket-protocol"])) {
        log.warn("verifyClient: missing required subprotocol");
        callback(false, HTTP_BAD_REQUEST, "Missing required subprotocol");
        return;
      }
    }

    callback(true);
  };
}
