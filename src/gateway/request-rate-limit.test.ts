import { describe, expect, it, vi } from "vitest";
import { createRequestRateLimiter } from "./request-rate-limit.js";

describe("createRequestRateLimiter", () => {
  it("allows requests within the limit", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 5, windowMs: 60_000 });
    for (let i = 0; i < 5; i++) {
      const result = limiter.check("1.2.3.4");
      expect(result.allowed).toBe(true);
      limiter.recordRequest("1.2.3.4");
    }
  });

  it("blocks requests over the limit", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 3, windowMs: 60_000 });
    for (let i = 0; i < 3; i++) {
      limiter.recordRequest("1.2.3.4");
    }
    const result = limiter.check("1.2.3.4");
    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
  });

  it("tracks different IPs independently", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 2, windowMs: 60_000 });
    limiter.recordRequest("1.2.3.4");
    limiter.recordRequest("1.2.3.4");
    expect(limiter.check("1.2.3.4").allowed).toBe(false);
    expect(limiter.check("5.6.7.8").allowed).toBe(true);
  });

  it("exempts loopback by default", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 1, windowMs: 60_000 });
    limiter.recordRequest("127.0.0.1");
    limiter.recordRequest("127.0.0.1");
    limiter.recordRequest("127.0.0.1");
    expect(limiter.check("127.0.0.1").allowed).toBe(true);
  });

  it("does not exempt loopback when configured false", () => {
    const limiter = createRequestRateLimiter({
      maxRequests: 1,
      windowMs: 60_000,
      exemptLoopback: false,
    });
    limiter.recordRequest("127.0.0.1");
    expect(limiter.check("127.0.0.1").allowed).toBe(false);
  });

  it("prunes expired entries", () => {
    vi.useFakeTimers();
    try {
      const limiter = createRequestRateLimiter({
        maxRequests: 10,
        windowMs: 1_000,
        pruneIntervalMs: -1,
      });
      limiter.recordRequest("1.2.3.4");
      expect(limiter.size()).toBe(1);
      vi.advanceTimersByTime(2_000);
      limiter.prune();
      expect(limiter.size()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it("dispose clears all state", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 10, windowMs: 60_000 });
    limiter.recordRequest("1.2.3.4");
    limiter.dispose();
    expect(limiter.size()).toBe(0);
  });

  it("returns remaining count correctly", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 10, windowMs: 60_000 });
    expect(limiter.check("1.2.3.4").remaining).toBe(10);
    limiter.recordRequest("1.2.3.4");
    expect(limiter.check("1.2.3.4").remaining).toBe(9);
  });
});
