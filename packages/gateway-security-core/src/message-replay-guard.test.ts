import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createMessageReplayGuard } from "./message-replay-guard.js";

describe("message-replay-guard", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("allows a new key and records it", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000 });
    expect(guard.checkAndRecord("req-1")).toEqual({ ok: true });
    expect(guard.size()).toBe(1);
    guard.dispose();
  });

  it("rejects a reused key within the TTL window", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000 });
    expect(guard.checkAndRecord("req-1")).toEqual({ ok: true });
    const reused = guard.checkAndRecord("req-1");
    expect(reused.ok).toBe(false);
    if (!reused.ok) {
      expect(reused.reason).toBe("reused");
    }
    // Re-check does not duplicate the entry.
    expect(guard.size()).toBe(1);
    guard.dispose();
  });

  it("allows a key again after the TTL expires", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000, pruneIntervalMs: 0 });
    expect(guard.checkAndRecord("req-1")).toEqual({ ok: true });
    vi.advanceTimersByTime(60_001);
    expect(guard.checkAndRecord("req-1")).toEqual({ ok: true });
    guard.dispose();
  });

  it("allows different keys independently", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000 });
    expect(guard.checkAndRecord("req-1")).toEqual({ ok: true });
    expect(guard.checkAndRecord("req-2")).toEqual({ ok: true });
    expect(guard.checkAndRecord("req-1").ok).toBe(false);
    expect(guard.checkAndRecord("req-2").ok).toBe(false);
    guard.dispose();
  });

  it("treats empty / non-string keys as allowed (no tracking)", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000 });
    expect(guard.checkAndRecord("")).toEqual({ ok: true });
    expect(guard.checkAndRecord("")).toEqual({ ok: true });
    expect(guard.size()).toBe(0);
    guard.dispose();
  });

  it("evicts the oldest entry when maxEntries is reached (LRU)", () => {
    // Cap of 2: fill a,b. A 3rd distinct key ("c") evicts "a" (oldest), so "a"
    // becomes acceptable again. With a 2-slot cache, re-adding "a" then evicts "b".
    const guard = createMessageReplayGuard({ ttlMs: 60_000, maxEntries: 2 });
    expect(guard.checkAndRecord("a")).toEqual({ ok: true });
    expect(guard.checkAndRecord("b")).toEqual({ ok: true });
    expect(guard.size()).toBe(2);
    // "c" forces eviction of "a" (oldest).
    expect(guard.checkAndRecord("c")).toEqual({ ok: true });
    expect(guard.size()).toBe(2);
    // "a" was evicted, so it is accepted again as if new.
    expect(guard.checkAndRecord("a")).toEqual({ ok: true });
    guard.dispose();
  });

  it("does not evict when below maxEntries", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000, maxEntries: 100 });
    for (let i = 0; i < 50; i++) {
      expect(guard.checkAndRecord(`k-${i}`)).toEqual({ ok: true });
    }
    expect(guard.size()).toBe(50);
    // All prior keys remain remembered.
    expect(guard.checkAndRecord("k-0").ok).toBe(false);
    expect(guard.checkAndRecord("k-49").ok).toBe(false);
    guard.dispose();
  });

  it("prune() drops only expired entries", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000, pruneIntervalMs: 0 });
    guard.checkAndRecord("a");
    vi.advanceTimersByTime(30_000);
    guard.checkAndRecord("b");
    expect(guard.size()).toBe(2);
    vi.advanceTimersByTime(31_000); // "a" (60s) expired, "b" (61s total observed) still has ~29s left
    guard.prune();
    expect(guard.size()).toBe(1);
    guard.dispose();
  });

  it("dispose() clears state and stops the timer", () => {
    const guard = createMessageReplayGuard({ ttlMs: 60_000 });
    guard.checkAndRecord("a");
    expect(guard.size()).toBe(1);
    guard.dispose();
    expect(guard.size()).toBe(0);
    // Re-check after dispose still functions (records fresh).
    expect(guard.checkAndRecord("a")).toEqual({ ok: true });
    guard.dispose();
  });

  it("throws on non-positive ttlMs", () => {
    expect(() => createMessageReplayGuard({ ttlMs: 0 })).toThrow();
    expect(() => createMessageReplayGuard({ ttlMs: -1 })).toThrow();
  });

  it("falls back to defaults when config is omitted", () => {
    const guard = createMessageReplayGuard();
    expect(guard.checkAndRecord("x")).toEqual({ ok: true });
    expect(guard.checkAndRecord("x").ok).toBe(false);
    guard.dispose();
  });
});
