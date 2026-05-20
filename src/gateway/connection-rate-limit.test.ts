import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createConnectionRateLimiter } from "./connection-rate-limit.js";

describe("connection-rate-limit", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("default configuration", () => {
    it("allows connections under the limit (30 per 10s window)", () => {
      const limiter = createConnectionRateLimiter();
      for (let i = 0; i < 29; i++) {
        const result = limiter.check("10.0.0.1");
        expect(result.allowed).toBe(true);
        limiter.recordAttempt("10.0.0.1");
      }
      // 30th attempt should still be allowed (maxAttempts=30 means 30 is ok)
      const result = limiter.check("10.0.0.1");
      expect(result.allowed).toBe(true);
      limiter.recordAttempt("10.0.0.1");

      // 31st should be blocked
      const blocked = limiter.check("10.0.0.1");
      expect(blocked.allowed).toBe(false);
      expect(blocked.retryAfterMs).toBeGreaterThan(0);

      limiter.dispose();
    });

    it("returns retryAfterMs reflecting remaining lockout time", () => {
      const limiter = createConnectionRateLimiter();
      // Fill up 30 attempts
      for (let i = 0; i < 30; i++) {
        limiter.check("10.0.0.1");
        limiter.recordAttempt("10.0.0.1");
      }

      const blocked = limiter.check("10.0.0.1");
      expect(blocked.allowed).toBe(false);
      // Default lockout is 60_000ms, check should be near that
      expect(blocked.retryAfterMs).toBeCloseTo(60_000, -2);

      // Advance 30 seconds
      vi.advanceTimersByTime(30_000);
      const stillBlocked = limiter.check("10.0.0.1");
      expect(stillBlocked.allowed).toBe(false);
      expect(stillBlocked.retryAfterMs).toBeCloseTo(30_000, -2);

      limiter.dispose();
    });

    it("unlocks after lockout duration expires", () => {
      const limiter = createConnectionRateLimiter();
      for (let i = 0; i < 30; i++) {
        limiter.check("10.0.0.1");
        limiter.recordAttempt("10.0.0.1");
      }

      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      // Advance past lockout (60s default)
      vi.advanceTimersByTime(60_001);

      const afterLockout = limiter.check("10.0.0.1");
      expect(afterLockout.allowed).toBe(true);
      expect(afterLockout.retryAfterMs).toBe(0);

      limiter.dispose();
    });

    it("tracks separate IPs independently", () => {
      const limiter = createConnectionRateLimiter();
      // Exhaust IP A
      for (let i = 0; i < 30; i++) {
        limiter.check("10.0.0.1");
        limiter.recordAttempt("10.0.0.1");
      }
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      // IP B should still be allowed
      expect(limiter.check("10.0.0.2").allowed).toBe(true);

      limiter.dispose();
    });
  });

  describe("sliding window", () => {
    it("expires old attempts outside the window after lockout", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 5,
        windowMs: 10_000,
        lockoutMs: 5_000,
      });
      // Record 5 attempts (triggers lockout)
      for (let i = 0; i < 5; i++) {
        limiter.check("10.0.0.1");
        limiter.recordAttempt("10.0.0.1");
      }
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      // Advance past both the window and the lockout
      vi.advanceTimersByTime(10_001);

      // Should be allowed again with fresh window
      const result = limiter.check("10.0.0.1");
      expect(result.allowed).toBe(true);

      limiter.dispose();
    });

    it("partially expires attempts in sliding window", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 5,
        windowMs: 10_000,
        lockoutMs: 5_000,
      });
      // Record 3 attempts
      for (let i = 0; i < 3; i++) {
        limiter.check("10.0.0.1");
        limiter.recordAttempt("10.0.0.1");
      }

      // Advance 6 seconds (first 3 attempts still in window)
      vi.advanceTimersByTime(6_000);

      // Should allow 2 more (5 - 3 remaining = 2)
      expect(limiter.check("10.0.0.1").allowed).toBe(true);
      limiter.recordAttempt("10.0.0.1");
      expect(limiter.check("10.0.0.1").allowed).toBe(true);
      limiter.recordAttempt("10.0.0.1");

      // Now all 5 slots used
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      limiter.dispose();
    });

    it("does not count check() without recordAttempt()", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 3,
        windowMs: 10_000,
      });
      // Check 3 times but don't record
      limiter.check("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.check("10.0.0.1");

      // Should still be allowed — only recordAttempt increments the counter
      expect(limiter.check("10.0.0.1").allowed).toBe(true);

      limiter.dispose();
    });
  });

  describe("loopback exemption", () => {
    it("exempts 127.0.0.1 by default", () => {
      const limiter = createConnectionRateLimiter({ maxAttempts: 2 });
      for (let i = 0; i < 100; i++) {
        const result = limiter.check("127.0.0.1");
        expect(result.allowed).toBe(true);
        expect(result.retryAfterMs).toBe(0);
        limiter.recordAttempt("127.0.0.1");
      }
      limiter.dispose();
    });

    it("exempts ::1 by default", () => {
      const limiter = createConnectionRateLimiter({ maxAttempts: 2 });
      for (let i = 0; i < 100; i++) {
        expect(limiter.check("::1").allowed).toBe(true);
        limiter.recordAttempt("::1");
      }
      limiter.dispose();
    });

    it("can disable loopback exemption", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 2,
        exemptLoopback: false,
      });
      limiter.check("127.0.0.1");
      limiter.recordAttempt("127.0.0.1");
      limiter.check("127.0.0.1");
      limiter.recordAttempt("127.0.0.1");
      expect(limiter.check("127.0.0.1").allowed).toBe(false);
      limiter.dispose();
    });
  });

  describe("undefined / unknown IP handling", () => {
    it("normalizes undefined IP to 'unknown'", () => {
      const limiter = createConnectionRateLimiter({ maxAttempts: 3 });
      limiter.check(undefined);
      limiter.recordAttempt(undefined);
      limiter.check(undefined);
      limiter.recordAttempt(undefined);
      limiter.check(undefined);
      limiter.recordAttempt(undefined);
      // Should be blocked now
      expect(limiter.check(undefined).allowed).toBe(false);
      // Another undefined should also be blocked (same 'unknown' bucket)
      expect(limiter.check(undefined).allowed).toBe(false);
      limiter.dispose();
    });
  });

  describe("lockout behavior", () => {
    it("does not extend lockout when attempts are recorded while locked", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 2,
        lockoutMs: 30_000,
      });
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      // Record more attempts while locked — should not extend lockout
      limiter.recordAttempt("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      vi.advanceTimersByTime(29_999);
      // Should still be locked at 29.999s
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      vi.advanceTimersByTime(2);
      // Should be unlocked at 30.001s (original lockout, not extended)
      expect(limiter.check("10.0.0.1").allowed).toBe(true);

      limiter.dispose();
    });

    it("clears attempts after lockout expires (fresh start)", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 2,
        windowMs: 10_000,
        lockoutMs: 5_000,
      });
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      // Locked
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      // Wait for lockout to expire
      vi.advanceTimersByTime(5_001);

      // Should get a fresh window
      expect(limiter.check("10.0.0.1").allowed).toBe(true);
      limiter.recordAttempt("10.0.0.1");
      expect(limiter.check("10.0.0.1").allowed).toBe(true);
      limiter.recordAttempt("10.0.0.1");
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      limiter.dispose();
    });
  });

  describe("prune()", () => {
    it("removes entries whose attempts have expired outside the window", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 3,
        windowMs: 10_000,
        pruneIntervalMs: 0, // disable auto-prune for this test
      });

      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.2");
      limiter.recordAttempt("10.0.0.2");

      expect(limiter.size()).toBe(2);

      // Advance past window
      vi.advanceTimersByTime(10_001);

      limiter.prune();
      expect(limiter.size()).toBe(0);

      limiter.dispose();
    });

    it("keeps locked entries until lockout expires", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 2,
        windowMs: 5_000,
        lockoutMs: 60_000,
        pruneIntervalMs: 0,
      });

      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      expect(limiter.size()).toBe(1);

      // Advance past window but still within lockout
      vi.advanceTimersByTime(5_001);
      limiter.prune();
      // Should keep the entry because it's still locked
      expect(limiter.size()).toBe(1);

      // Advance past lockout
      vi.advanceTimersByTime(60_000);
      limiter.prune();
      expect(limiter.size()).toBe(0);

      limiter.dispose();
    });

    it("keeps entries with remaining attempts in the window", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 5,
        windowMs: 10_000,
        pruneIntervalMs: 0,
      });

      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      vi.advanceTimersByTime(5_000);
      limiter.prune();
      // Entry should still exist (1 attempt within 10s window)
      expect(limiter.size()).toBe(1);

      limiter.dispose();
    });
  });

  describe("dispose()", () => {
    it("clears all entries and stops the prune timer", () => {
      const limiter = createConnectionRateLimiter({ maxAttempts: 5 });
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.2");
      limiter.recordAttempt("10.0.0.2");

      expect(limiter.size()).toBe(2);

      limiter.dispose();
      expect(limiter.size()).toBe(0);

      // After dispose, check should work as if fresh
      const result = limiter.check("10.0.0.1");
      expect(result.allowed).toBe(true);
    });
  });

  describe("size()", () => {
    it("returns the number of tracked IPs", () => {
      const limiter = createConnectionRateLimiter({ pruneIntervalMs: 0 });
      expect(limiter.size()).toBe(0);

      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      expect(limiter.size()).toBe(1);

      limiter.check("10.0.0.2");
      limiter.recordAttempt("10.0.0.2");
      expect(limiter.size()).toBe(2);

      // Same IP doesn't increase size
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      expect(limiter.size()).toBe(2);

      limiter.dispose();
    });
  });

  describe("custom configuration", () => {
    it("respects custom maxAttempts", () => {
      const limiter = createConnectionRateLimiter({ maxAttempts: 5 });
      for (let i = 0; i < 5; i++) {
        limiter.check("10.0.0.1");
        limiter.recordAttempt("10.0.0.1");
      }
      expect(limiter.check("10.0.0.1").allowed).toBe(false);
      limiter.dispose();
    });

    it("respects custom windowMs", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 3,
        windowMs: 5_000,
        lockoutMs: 10_000,
      });
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      vi.advanceTimersByTime(5_001);
      // Window expired but still locked
      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      vi.advanceTimersByTime(10_000);
      // Lockout expired
      expect(limiter.check("10.0.0.1").allowed).toBe(true);

      limiter.dispose();
    });

    it("respects custom lockoutMs", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 2,
        lockoutMs: 120_000,
      });
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      const blocked = limiter.check("10.0.0.1");
      expect(blocked.allowed).toBe(false);
      expect(blocked.retryAfterMs).toBeCloseTo(120_000, -2);

      limiter.dispose();
    });

    it("handles edge case: maxAttempts of 1", () => {
      const limiter = createConnectionRateLimiter({ maxAttempts: 1 });
      expect(limiter.check("10.0.0.1").allowed).toBe(true);
      limiter.recordAttempt("10.0.0.1");
      expect(limiter.check("10.0.0.1").allowed).toBe(false);
      limiter.dispose();
    });

    it("handles edge case: very short window and lockout", () => {
      const limiter = createConnectionRateLimiter({
        maxAttempts: 2,
        windowMs: 100,
        lockoutMs: 200,
      });
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");
      limiter.check("10.0.0.1");
      limiter.recordAttempt("10.0.0.1");

      expect(limiter.check("10.0.0.1").allowed).toBe(false);

      vi.advanceTimersByTime(201);
      expect(limiter.check("10.0.0.1").allowed).toBe(true);

      limiter.dispose();
    });
  });
});
