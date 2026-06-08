export interface FrameLimits {
  maxFrameSize: number;
  maxMessageSize: number;
  maxQueueSize: number;
  maxFramesPerSecond: number;
  maxMessagesPerSecond: number;
  /** Max cumulative bytes per connection per minute. OWASP: prevents slow-loris-style resource exhaustion. */
  maxBytesPerMinute: number;
}

export const GATEWAY_WS_SUBPROTOCOL = "openclaw-gateway-v1";

function parseGatewayWsSubprotocolHeader(header: string | string[] | undefined): string[] {
  const values = Array.isArray(header) ? header : header === undefined ? [] : [header];
  return values
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

export function hasGatewayWsSubprotocol(header: string | string[] | undefined): boolean {
  return parseGatewayWsSubprotocolHeader(header).includes(GATEWAY_WS_SUBPROTOCOL);
}

export const DEFAULT_FRAME_LIMITS: FrameLimits = {
  maxFrameSize: 16 * 1024,
  maxMessageSize: 1024 * 1024,
  maxQueueSize: 100,
  maxFramesPerSecond: 1000,
  maxMessagesPerSecond: 500,
  maxBytesPerMinute: 50 * 1024 * 1024,
};

export interface RateLimiterState {
  frameTimestamps: number[];
  messageTimestamps: number[];
  byteTimestamps: { ts: number; bytes: number }[];
}

export function createRateLimiterState(): RateLimiterState {
  return {
    frameTimestamps: [],
    messageTimestamps: [],
    byteTimestamps: [],
  };
}

export function checkRateLimit(
  state: RateLimiterState,
  limits: FrameLimits,
  payloadBytes?: number,
): { ok: true } | { ok: false; reason: string } {
  const now = Date.now();
  const windowMs = 1000;
  const windowStart = now - windowMs;

  while (state.frameTimestamps.length > 0 && state.frameTimestamps[0] < windowStart) {
    state.frameTimestamps.shift();
  }
  while (state.messageTimestamps.length > 0 && state.messageTimestamps[0] < windowStart) {
    state.messageTimestamps.shift();
  }

  if (state.frameTimestamps.length >= limits.maxFramesPerSecond) {
    return { ok: false, reason: "frame rate limit exceeded" };
  }

  if (state.messageTimestamps.length >= limits.maxMessagesPerSecond) {
    return { ok: false, reason: "message rate limit exceeded" };
  }

  state.frameTimestamps.push(now);
  state.messageTimestamps.push(now);

  // Byte budget tracking
  if (payloadBytes !== undefined && payloadBytes > 0) {
    const byteWindowMs = 60_000;
    const byteWindowStart = now - byteWindowMs;
    state.byteTimestamps = state.byteTimestamps.filter((e) => e.ts > byteWindowStart);
    const totalBytes = state.byteTimestamps.reduce((sum, e) => sum + e.bytes, 0) + payloadBytes;
    if (totalBytes > limits.maxBytesPerMinute) {
      // Roll back both entries added above (1 frame + 1 message).
      state.frameTimestamps.pop();
      state.messageTimestamps.pop();
      return { ok: false, reason: "byte budget exceeded" };
    }
    state.byteTimestamps.push({ ts: now, bytes: payloadBytes });
  }

  return { ok: true };
}
