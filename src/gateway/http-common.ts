// Shared Gateway HTTP helpers handle small JSON/text responses, SSE headers,
// body-size errors, and client disconnect aborts.
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  logRejectedLargePayload,
  parseContentLengthHeader,
} from "../logging/diagnostic-payload.js";
import type { GatewayAuthResult } from "./auth.js";
import { readJsonBody } from "./hooks.js";

/**
 * Apply baseline security headers that are safe for all response types (API JSON,
 * HTML pages, static assets, SSE streams). Headers that restrict framing or set a
 * Content-Security-Policy are intentionally omitted here because some handlers
 * (canvas host, A2UI) serve content that may be loaded inside frames.
 */
export function setDefaultSecurityHeaders(
  res: ServerResponse,
  opts?: { strictTransportSecurity?: string },
) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(self), geolocation=()");
  const strictTransportSecurity = opts?.strictTransportSecurity;
  if (typeof strictTransportSecurity === "string" && strictTransportSecurity.length > 0) {
    res.setHeader("Strict-Transport-Security", strictTransportSecurity);
  }
}

/**
 * Apply strict security headers for API-only responses (JSON, SSE).
 * Includes X-Frame-Options: DENY since API responses should never be framed.
 * Use this for non-HTML responses. For Control UI / canvas responses, use
 * setDefaultSecurityHeaders() or setControlUiSecurityHeaders() instead.
 */
export function setApiSecurityHeaders(
  res: ServerResponse,
  opts?: { strictTransportSecurity?: string },
) {
  setDefaultSecurityHeaders(res, opts);
  res.setHeader("X-Frame-Options", "DENY");
}

/**
 * Apply security headers for Control UI HTML responses.
 * Includes a strict Content-Security-Policy that only allows resources
 * from the same origin. Canvas embedding via frame-ancestors is allowed
 * for the specific canvas host use case.
 *
 * Note: the Control UI module (control-ui.ts) builds its own CSP via
 * buildControlUiCspHeader() which is richer and includes inline script
 * hashes. This function is a general-purpose alternative for simpler
 * HTML-serving handlers.
 */
export function setControlUiSecurityHeaders(
  res: ServerResponse,
  opts?: { strictTransportSecurity?: string; canvasAllowedOrigins?: string[] },
) {
  setDefaultSecurityHeaders(res, opts);

  const frameAncestors = opts?.canvasAllowedOrigins?.length
    ? `'self' ${opts.canvasAllowedOrigins.join(" ")}`
    : "'self'";

  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self'",
      "img-src 'self' data: blob:",
      "font-src 'self'",
      "connect-src 'self'",
      "frame-ancestors " + frameAncestors,
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join("; "),
  );
}

export function sendJson(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function sendText(res: ServerResponse, status: number, body: string) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.end(body);
}

export function sendMethodNotAllowed(res: ServerResponse, allow = "POST") {
  res.setHeader("Allow", allow);
  sendText(res, 405, "Method Not Allowed");
}

export function sendUnauthorized(res: ServerResponse) {
  sendJson(res, 401, {
    error: { message: "Unauthorized", type: "unauthorized" },
  });
}

export function sendRateLimited(res: ServerResponse, retryAfterMs?: number) {
  if (retryAfterMs && retryAfterMs > 0) {
    res.setHeader("Retry-After", String(Math.ceil(retryAfterMs / 1000)));
  }
  sendJson(res, 429, {
    error: {
      message: "Too many failed authentication attempts. Please try again later.",
      type: "rate_limited",
    },
  });
}

export function sendGatewayAuthFailure(res: ServerResponse, authResult: GatewayAuthResult) {
  if (authResult.rateLimited) {
    sendRateLimited(res, authResult.retryAfterMs);
    return;
  }
  sendUnauthorized(res);
}

export function sendInvalidRequest(res: ServerResponse, message: string) {
  sendJson(res, 400, {
    error: { message, type: "invalid_request_error" },
  });
}

export function buildMissingScopeForbiddenBody(missingScope: string | undefined) {
  return {
    ok: false,
    error: {
      type: "forbidden",
      message: missingScope ? `missing scope: ${missingScope}` : "Insufficient permissions",
    },
  };
}

export function sendMissingScopeForbidden(res: ServerResponse, missingScope: string | undefined) {
  sendJson(res, 403, buildMissingScopeForbiddenBody(missingScope));
}

export async function readJsonBodyOrError(
  req: IncomingMessage,
  res: ServerResponse,
  maxBytes: number,
): Promise<unknown> {
  // Enforce JSON Content-Type for non-empty bodies. Missing body is fine
  // (some callers allow empty POSTs); wrong media type returns 415.
  const contentLengthRaw = req.headers?.["content-length"];
  const contentLength = parseContentLengthHeader(contentLengthRaw) ?? 0;
  if (contentLength > 0) {
    const contentTypeRaw = req.headers?.["content-type"];
    const contentType = (Array.isArray(contentTypeRaw) ? contentTypeRaw[0] : contentTypeRaw)
      ?.split(";")[0]
      ?.trim()
      .toLowerCase();
    if (contentType !== "application/json") {
      sendJson(res, 415, {
        error: {
          message: "Content-Type must be application/json",
          type: "invalid_request_error",
        },
      });
      return undefined;
    }
  }
  const body = await readJsonBody(req, maxBytes);
  if (!body.ok) {
    if (body.error === "payload too large") {
      const announcedLength = parseContentLengthHeader(req.headers?.["content-length"]);
      logRejectedLargePayload({
        surface: "gateway.http.json",
        limitBytes: maxBytes,
        reason: "json_body_limit",
        ...(announcedLength !== undefined ? { bytes: announcedLength } : {}),
      });
      sendJson(res, 413, {
        error: { message: "Payload too large", type: "invalid_request_error" },
      });
      return undefined;
    }
    if (body.error === "request body timeout") {
      sendJson(res, 408, {
        error: { message: "Request body timeout", type: "invalid_request_error" },
      });
      return undefined;
    }
    sendInvalidRequest(res, body.error);
    return undefined;
  }
  return body.value;
}

export function writeDone(res: ServerResponse) {
  res.write("data: [DONE]\n\n");
}

export function setSseHeaders(res: ServerResponse) {
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();
}

/** Abort reason used when the HTTP client disconnects before delivery. */
class ClientDisconnectError extends Error {
  constructor(message = "HTTP client disconnected") {
    super(message);
    this.name = "ClientDisconnectError";
  }
}

export function watchClientDisconnect(
  req: IncomingMessage,
  res: ServerResponse,
  abortController: AbortController,
  onDisconnect?: () => void,
) {
  const sockets = Array.from(
    new Set(
      [req.socket, res.socket].filter(
        (socket): socket is NonNullable<typeof socket> => socket !== null,
      ),
    ),
  );
  if (sockets.length === 0) {
    return () => {};
  }
  const handleClose = () => {
    onDisconnect?.();
    if (!abortController.signal.aborted) {
      abortController.abort(new ClientDisconnectError());
    }
  };
  for (const socket of sockets) {
    socket.on("close", handleClose);
  }
  return () => {
    for (const socket of sockets) {
      socket.off("close", handleClose);
    }
  };
}
