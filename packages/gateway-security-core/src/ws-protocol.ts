export interface FrameLimits {
  maxFrameSize: number;
  maxMessageSize: number;
  maxQueueSize: number;
  maxFramesPerSecond: number;
  maxMessagesPerSecond: number;
}

export const GATEWAY_WS_SUBPROTOCOL = "openclaw-gateway-v1";

export function parseGatewayWsSubprotocolHeader(header: string | string[] | undefined): string[] {
  const values = Array.isArray(header) ? header : header === undefined ? [] : [header];
  return values
    .flatMap((value) => value.split(","))
    .map((value) => value.trim())
    .filter((value) => value.length > 0);
}

export function hasGatewayWsSubprotocol(header: string | string[] | undefined): boolean {
  return parseGatewayWsSubprotocolHeader(header).includes(GATEWAY_WS_SUBPROTOCOL);
}

export function selectGatewayWsSubprotocol(protocols: Iterable<string>): string | false {
  for (const protocol of protocols) {
    if (protocol === GATEWAY_WS_SUBPROTOCOL) {
      return GATEWAY_WS_SUBPROTOCOL;
    }
  }
  return false;
}

export const DEFAULT_FRAME_LIMITS: FrameLimits = {
  maxFrameSize: 16 * 1024,
  maxMessageSize: 1024 * 1024,
  maxQueueSize: 100,
  maxFramesPerSecond: 1000,
  maxMessagesPerSecond: 500,
};

export interface RateLimiterState {
  frameTimestamps: number[];
  messageTimestamps: number[];
}

export function createRateLimiterState(): RateLimiterState {
  return {
    frameTimestamps: [],
    messageTimestamps: [],
  };
}

export function checkRateLimit(
  state: RateLimiterState,
  limits: FrameLimits,
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

  return { ok: true };
}
