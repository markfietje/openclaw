// Keep server maxPayload aligned with gateway client maxPayload so high-res canvas snapshots
// don't get disconnected mid-invoke with "Max payload size exceeded".
export const MAX_PAYLOAD_BYTES = 25 * 1024 * 1024;
export const MAX_BUFFERED_BYTES = 50 * 1024 * 1024; // per-connection send buffer limit (2x max payload)
export const MAX_PREAUTH_PAYLOAD_BYTES = 64 * 1024;

/** Default per-IP WebSocket connection cap. Override via gateway.security.maxWebSocketConnections. */
export const DEFAULT_MAX_WEBSOCKET_CONNECTIONS = 64;
/** Default minimum TLS version for gateway HTTPS listeners. Override via gateway.security.tlsMinVersion. */
export const DEFAULT_TLS_MIN_VERSION: "TLSv1.2" | "TLSv1.3" = "TLSv1.2";

/**
 * Resolve the WebSocket max payload size from config with a safe fallback.
 * Used by the runtime-state WebSocketServer; bounded so a single misconfigured
 * config value cannot exhaust process memory.
 */
export function resolveMaxPayloadBytes(value: number | undefined): number {
  if (typeof value === "number" && Number.isFinite(value) && value > 0) {
    return Math.min(value, MAX_PAYLOAD_BYTES);
  }
  return MAX_PAYLOAD_BYTES;
}

const DEFAULT_MAX_CHAT_HISTORY_MESSAGES_BYTES = 6 * 1024 * 1024; // keep history responses comfortably under client WS limits
let maxChatHistoryMessagesBytes = DEFAULT_MAX_CHAT_HISTORY_MESSAGES_BYTES;

export const getMaxChatHistoryMessagesBytes = () => maxChatHistoryMessagesBytes;

export const setMaxChatHistoryMessagesBytesForTest = (value?: number) => {
  if (!process.env.VITEST && process.env.NODE_ENV !== "test") {
    return;
  }
  if (value === undefined) {
    maxChatHistoryMessagesBytes = DEFAULT_MAX_CHAT_HISTORY_MESSAGES_BYTES;
    return;
  }
  if (Number.isFinite(value) && value > 0) {
    maxChatHistoryMessagesBytes = value;
  }
};
export const TICK_INTERVAL_MS = 30_000;
export const HEALTH_REFRESH_INTERVAL_MS = 60_000;
export const DEDUPE_TTL_MS = 5 * 60_000;
export const DEDUPE_MAX = 1000;
