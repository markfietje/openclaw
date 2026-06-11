// Gateway memory health monitor samples RSS and heap usage for readiness
// and diagnostic logging. OWASP DoS Cheat Sheet — resource exhaustion prevention.
import type { SubsystemLogger } from "../../logging/subsystem.js";

const RSS_WARN_BYTES = 512 * 1024 * 1024; // 512 MB
const RSS_CRITICAL_BYTES = 1024 * 1024 * 1024; // 1 GB
const CHECK_INTERVAL_MS = 30_000;

export type MemoryHealth = {
  rssBytes: number;
  heapUsedBytes: number;
  heapTotalBytes: number;
  pressure: "normal" | "warn" | "critical";
};

export function readMemoryHealth(): MemoryHealth {
  const usage = process.memoryUsage();
  const pressure =
    usage.rss >= RSS_CRITICAL_BYTES ? "critical" : usage.rss >= RSS_WARN_BYTES ? "warn" : "normal";
  return {
    rssBytes: usage.rss,
    heapUsedBytes: usage.heapUsed,
    heapTotalBytes: usage.heapTotal,
    pressure,
  };
}

export function createGatewayMemoryHealthMonitor(log: SubsystemLogger): {
  start: () => void;
  stop: () => void;
  snapshot: () => MemoryHealth;
} {
  let timer: ReturnType<typeof setInterval> | undefined;
  let last: MemoryHealth = readMemoryHealth();

  return {
    start: () => {
      if (timer) return;
      timer = setInterval(() => {
        last = readMemoryHealth();
        if (last.pressure === "critical") {
          log.warn(`memory pressure critical: rss=${Math.round(last.rssBytes / 1024 / 1024)}MB`);
          // Suggest GC if available (Node 22+ with --expose-gc)
          globalThis.gc?.();
        }
      }, CHECK_INTERVAL_MS);
    },
    stop: () => {
      if (timer) {
        clearInterval(timer);
        timer = undefined;
      }
    },
    snapshot: () => last,
  };
}
