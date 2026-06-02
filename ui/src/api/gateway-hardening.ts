/**
 * Gateway browser client hardening configuration.
 *
 * Provides timeout defaults, tick watchdog settings, and secure-context
 * enforcement for the browser Control UI WebSocket client.
 */

import { GATEWAY_WS_SUBPROTOCOL } from "../../../packages/gateway-security-core/src/ws-protocol.js";

// ---------------------------------------------------------------------------
// Subprotocol
// ---------------------------------------------------------------------------

export { GATEWAY_WS_SUBPROTOCOL };

// ---------------------------------------------------------------------------
// Timing defaults
// ---------------------------------------------------------------------------

export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
export const DEFAULT_TICK_WATCH_MIN_INTERVAL_MS = 15_000;
export const DEFAULT_TICK_WATCH_TIMEOUT_MS = 45_000;
export const MAX_TICK_WATCH_TIMEOUT_MS = 120_000;

// ---------------------------------------------------------------------------
// Hardening options (extends GatewayBrowserClientOptions)
// ---------------------------------------------------------------------------

export type GatewayHardeningOptions = {
  requestTimeoutMs?: number;
  tickWatchMinIntervalMs?: number;
  tickWatchTimeoutMs?: number;
};

// ---------------------------------------------------------------------------
// Secure context enforcement
// ---------------------------------------------------------------------------

export function assertSecureContext(url: string): void {
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "ws:" && isSecurePage()) {
      throw new Error(
        "Browser refused the Gateway WebSocket for security reasons. " +
          "Use wss:// when the Control UI is served over HTTPS/Tailscale Serve, " +
          "or open the loopback dashboard at http://127.0.0.1:18789.",
      );
    }
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("Browser refused")) {
      throw err;
    }
    // Let malformed URLs through to the WebSocket constructor error handler.
  }
}

function isSecurePage(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  return (
    window.location.protocol === "https:" ||
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1" ||
    window.location.hostname === "[::1]"
  );
}

// ---------------------------------------------------------------------------
// Resolved hardening config
// ---------------------------------------------------------------------------

export type ResolvedHardeningConfig = {
  requestTimeoutMs: number;
  tickWatchMinIntervalMs: number;
  tickWatchTimeoutMs: number;
};

export function resolveHardeningConfig(opts: GatewayHardeningOptions): ResolvedHardeningConfig {
  return {
    requestTimeoutMs:
      typeof opts.requestTimeoutMs === "number" && opts.requestTimeoutMs > 0
        ? Math.min(opts.requestTimeoutMs, 300_000)
        : DEFAULT_REQUEST_TIMEOUT_MS,
    tickWatchMinIntervalMs:
      typeof opts.tickWatchMinIntervalMs === "number" && opts.tickWatchMinIntervalMs > 0
        ? Math.min(opts.tickWatchMinIntervalMs, MAX_TICK_WATCH_TIMEOUT_MS)
        : DEFAULT_TICK_WATCH_MIN_INTERVAL_MS,
    tickWatchTimeoutMs:
      typeof opts.tickWatchTimeoutMs === "number" && opts.tickWatchTimeoutMs > 0
        ? Math.min(opts.tickWatchTimeoutMs, MAX_TICK_WATCH_TIMEOUT_MS)
        : DEFAULT_TICK_WATCH_TIMEOUT_MS,
  };
}
