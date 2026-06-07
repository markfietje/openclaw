import { describe, expect, it } from "vitest";
import {
  hasGatewayWsSubprotocol,
  createRateLimiterState,
  checkRateLimit,
  DEFAULT_FRAME_LIMITS,
} from "./ws-protocol.js";

describe("ws-protocol", () => {
  describe("hasGatewayWsSubprotocol", () => {
    it("returns true when subprotocol is present", () => {
      expect(hasGatewayWsSubprotocol("openclaw-gateway-v1")).toBe(true);
      expect(hasGatewayWsSubprotocol("other, openclaw-gateway-v1")).toBe(true);
    });

    it("returns false when subprotocol is absent", () => {
      expect(hasGatewayWsSubprotocol("other")).toBe(false);
      expect(hasGatewayWsSubprotocol(undefined)).toBe(false);
    });
  });

  describe("checkRateLimit", () => {
    it("allows under frame and message limits", () => {
      const state = createRateLimiterState();
      const result = checkRateLimit(state, DEFAULT_FRAME_LIMITS);
      expect(result.ok).toBe(true);
    });

    it("rejects when frame limit exceeded", () => {
      const state = createRateLimiterState();
      const limits = { ...DEFAULT_FRAME_LIMITS, maxFramesPerSecond: 2, maxMessagesPerSecond: 100 };
      checkRateLimit(state, limits);
      checkRateLimit(state, limits);
      const result = checkRateLimit(state, limits);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toContain("frame rate limit");
      }
    });

    it("rejects when message limit exceeded", () => {
      const state = createRateLimiterState();
      const limits = { ...DEFAULT_FRAME_LIMITS, maxFramesPerSecond: 100, maxMessagesPerSecond: 2 };
      checkRateLimit(state, limits);
      checkRateLimit(state, limits);
      const result = checkRateLimit(state, limits);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toContain("message rate limit");
      }
    });

    it("prunes expired timestamps on each check", () => {
      const state = createRateLimiterState();
      const limits = { ...DEFAULT_FRAME_LIMITS, maxFramesPerSecond: 1, maxMessagesPerSecond: 1 };

      const result1 = checkRateLimit(state, limits);
      expect(result1.ok).toBe(true);

      const result2 = checkRateLimit(state, limits);
      expect(result2.ok).toBe(false);
    });
  });
});
