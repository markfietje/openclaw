// Keep server maxPayload aligned with gateway client maxPayload so high-res canvas snapshots
// don't get disconnected mid-invoke with "Max payload size exceeded".

/** Default maximum WebSocket message payload size in bytes after authentication (25 MB). */
export const DEFAULT_MAX_PAYLOAD_BYTES = 25 * 1024 * 1024;

/**
 * Absolute maximum allowed payload size.
 * Prevents accidental misconfiguration that could cause OOM.
 */
const ABSOLUTE_MAX_PAYLOAD_BYTES = 100 * 1024 * 1024; // 100 MB

/**
 * Minimum meaningful payload size.
 * Anything below this would break the protocol (connect messages, etc.).
 */
const MIN_PAYLOAD_BYTES = 64 * 1024; // 64 KB

/** @deprecated Use DEFAULT_MAX_PAYLOAD_BYTES instead. Kept for backward compatibility. */
export const MAX_PAYLOAD_BYTES = DEFAULT_MAX_PAYLOAD_BYTES;

/**
 * Resolve the effective max payload size from config.
 * Clamps to [MIN_PAYLOAD_BYTES, ABSOLUTE_MAX_PAYLOAD_BYTES].
 */
export function resolveMaxPayloadBytes(configValue?: number): number {
  if (configValue === undefined) {
    return DEFAULT_MAX_PAYLOAD_BYTES;
  }
  if (!Number.isFinite(configValue) || configValue <= 0) {
    return DEFAULT_MAX_PAYLOAD_BYTES;
  }
  if (configValue < MIN_PAYLOAD_BYTES) {
    return MIN_PAYLOAD_BYTES;
  }
  if (configValue > ABSOLUTE_MAX_PAYLOAD_BYTES) {
    return ABSOLUTE_MAX_PAYLOAD_BYTES;
  }
  return configValue;
}
/** Default maximum concurrent WebSocket connections when not configured. */
export const DEFAULT_MAX_WEBSOCKET_CONNECTIONS = 100;

/** Default minimum TLS version for gateway HTTPS connections. */
export const DEFAULT_TLS_MIN_VERSION = "TLSv1.2" as const;

export const MAX_BUFFERED_BYTES = 50 * 1024 * 1024; // per-connection send buffer limit (2x max payload)
export const MAX_PREAUTH_PAYLOAD_BYTES = 64 * 1024;

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
