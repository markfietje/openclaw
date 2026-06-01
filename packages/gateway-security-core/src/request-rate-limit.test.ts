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

  it("blocks requests over the limit with retry metadata", () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(1_000);
      const limiter = createRequestRateLimiter({ maxRequests: 3, windowMs: 60_000 });
      for (let i = 0; i < 3; i++) {
        limiter.recordRequest("1.2.3.4");
      }
      vi.advanceTimersByTime(10_000);

      const result = limiter.check("1.2.3.4");
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfterMs).toBe(50_000);
    } finally {
      vi.useRealTimers();
    }
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

  it("supports check-before-record request flow without blocking the final allowed request", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 3, windowMs: 60_000 });
    for (let i = 0; i < 3; i++) {
      const result = limiter.check("1.2.3.4");
      expect(result.allowed).toBe(true);
      limiter.recordRequest("1.2.3.4");
    }

    expect(limiter.check("1.2.3.4")).toMatchObject({ allowed: false, remaining: 0 });
  });

  it("fails closed for new IPs when the tracked IP cap is full", () => {
    vi.useFakeTimers();
    try {
      vi.setSystemTime(1_000);
      const limiter = createRequestRateLimiter({
        maxRequests: 10,
        windowMs: 60_000,
        maxEntries: 1,
        pruneIntervalMs: -1,
      });
      limiter.recordRequest("1.2.3.4");

      const blocked = limiter.check("5.6.7.8");
      expect(blocked.allowed).toBe(false);
      expect(blocked.retryAfterMs).toBe(60_000);
      expect(limiter.size()).toBe(1);

      vi.advanceTimersByTime(60_001);
      expect(limiter.check("5.6.7.8").allowed).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("caps per-IP timestamps when recordRequest is called without a prior check", () => {
    const limiter = createRequestRateLimiter({ maxRequests: 2, windowMs: 60_000 });
    limiter.recordRequest("1.2.3.4");
    limiter.recordRequest("1.2.3.4");
    limiter.recordRequest("1.2.3.4");

    expect(limiter.check("1.2.3.4")).toMatchObject({ allowed: false, remaining: 0 });
  });
});
