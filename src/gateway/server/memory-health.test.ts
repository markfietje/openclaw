// Tests for gateway memory health monitor.
import { describe, expect, it, vi } from "vitest";
import { readMemoryHealth, createGatewayMemoryHealthMonitor } from "./memory-health.js";

describe("readMemoryHealth", () => {
  it("returns valid shape with normal pressure under default memory", () => {
    const health = readMemoryHealth();
    expect(health.rssBytes).toBeGreaterThan(0);
    expect(health.heapUsedBytes).toBeGreaterThan(0);
    expect(health.heapTotalBytes).toBeGreaterThan(0);
    expect(health.pressure).toBe("normal");
  });
});

describe("createGatewayMemoryHealthMonitor", () => {
  it("starts and stops without error", () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const monitor = createGatewayMemoryHealthMonitor(log as never);
    monitor.start();
    const snapshot = monitor.snapshot();
    expect(snapshot.rssBytes).toBeGreaterThan(0);
    monitor.stop();
  });

  it("returns last snapshot after stop", () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const monitor = createGatewayMemoryHealthMonitor(log as never);
    monitor.start();
    const before = monitor.snapshot();
    monitor.stop();
    const after = monitor.snapshot();
    expect(after).toEqual(before);
  });

  it("is idempotent on double start", () => {
    const log = { info: vi.fn(), warn: vi.fn() };
    const monitor = createGatewayMemoryHealthMonitor(log as never);
    monitor.start();
    monitor.start();
    monitor.stop();
  });
});
