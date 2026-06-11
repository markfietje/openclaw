// Periodic heap pressure check.
// Logs a warning and optionally triggers GC when heap approaches the container ceiling.

import { registerInterval } from "./timer-registry.js";

const HEAP_PRESSURE_RATIO = 0.8;
const CHECK_INTERVAL_MS = 60_000;

let stopped = false;

export function startHeapPressureMonitor(opts?: {
  maxHeapBytes?: number;
  log?: { warn: (msg: string) => void };
}): void {
  const maxHeapBytes = opts?.maxHeapBytes ?? parseMaxOldSpaceSize();
  const log = opts?.log ?? { warn: (msg: string) => console.warn(msg) };
  stopped = false;
  registerInterval(
    "heap-pressure-check",
    () => {
      if (stopped) return;
      const usage = process.memoryUsage();
      if (usage.heapUsed > HEAP_PRESSURE_RATIO * maxHeapBytes) {
        if (typeof globalThis.gc === "function") {
          globalThis.gc();
        }
        log.warn(
          `heap pressure: ${Math.round(usage.heapUsed / 1024 / 1024)}MB / ${Math.round(maxHeapBytes / 1024 / 1024)}MB`,
        );
      }
    },
    CHECK_INTERVAL_MS,
  );
}

export function stopHeapPressureMonitor(): void {
  stopped = true;
}

function parseMaxOldSpaceSize(): number {
  const arg = process.execArgv.find((a) => a.startsWith("--max-old-space-size="));
  if (arg) {
    const value = parseInt(arg.split("=")[1] ?? "", 10);
    if (Number.isFinite(value) && value > 0) {
      return value * 1024 * 1024;
    }
  }
  return 1.5 * 1024 * 1024 * 1024; // Node default ~1.5GB
}
