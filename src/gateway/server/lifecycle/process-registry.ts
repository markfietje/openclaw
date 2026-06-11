// Process registry for MCP child process orphan reaping.
// Records child PIDs in the shared state DB on spawn and removes them on clean shutdown.
// On startup, stale PIDs from a previous run are reaped.

import { createSubsystemLogger } from "../../../logging/subsystem.js";

const procLog = createSubsystemLogger("gateway/process-registry");

const TABLE_DDL = `
CREATE TABLE IF NOT EXISTS child_processes (
  pid INTEGER NOT NULL PRIMARY KEY,
  label TEXT NOT NULL,
  started_at INTEGER NOT NULL
);
`;

const ORPHAN_SIGTERM_TIMEOUT_MS = 5_000;
const ORPHAN_SIGKILL_WAIT_MS = 500;

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function sendSignal(pid: number, signal: "SIGTERM" | "SIGKILL"): void {
  try {
    process.kill(pid, signal);
  } catch {
    // Process already exited
  }
}

type ChildProcessRow = {
  pid: number;
  label: string;
  started_at: number;
};

/**
 * Ensure the child_processes table exists in the shared state DB.
 * Safe to call multiple times (IF NOT EXISTS).
 */
export function ensureChildProcessTable(db: { exec: (sql: string) => void }): void {
  db.exec(TABLE_DDL);
}

/**
 * Record a child process PID for orphan detection.
 */
export function registerChildProcess(
  db: { prepare: (sql: string) => { run: (...args: unknown[]) => void } },
  pid: number,
  label: string,
): void {
  const stmt = db.prepare(
    "INSERT OR REPLACE INTO child_processes (pid, label, started_at) VALUES (?, ?, ?)",
  );
  stmt.run(pid, label, Date.now());
}

/**
 * Remove a child process PID from the registry.
 */
export function unregisterChildProcess(
  db: { prepare: (sql: string) => { run: (...args: unknown[]) => void } },
  pid: number,
): void {
  const stmt = db.prepare("DELETE FROM child_processes WHERE pid = ?");
  stmt.run(pid);
}

/**
 * Remove all recorded child process PIDs (for clean shutdown).
 */
export function clearAllChildProcesses(db: { exec: (sql: string) => void }): void {
  db.exec("DELETE FROM child_processes");
}

/**
 * Query the table for stale PIDs and reap them. Sends SIGTERM, waits,
 * then SIGKILL. Deletes stale rows regardless of reap success.
 * Call on startup before initializing new MCP runtimes.
 */
export async function reapOrphanChildProcesses(db: {
  prepare: (sql: string) => { all: () => unknown[] };
  exec: (sql: string) => void;
}): Promise<{ reaped: number; skipped: number }> {
  let rows: ChildProcessRow[];
  try {
    const stmt = db.prepare("SELECT pid, label, started_at FROM child_processes");
    rows = stmt.all() as ChildProcessRow[];
  } catch {
    return { reaped: 0, skipped: 0 };
  }

  if (rows.length === 0) {
    return { reaped: 0, skipped: 0 };
  }

  procLog.info(`found ${rows.length} stale child process record(s) from previous run`);

  let reaped = 0;
  let skipped = 0;

  for (const row of rows) {
    if (!isProcessRunning(row.pid)) {
      skipped++;
      continue;
    }

    procLog.info(`sending SIGTERM to orphan pid=${row.pid} label=${row.label}`);
    sendSignal(row.pid, "SIGTERM");

    // Wait up to 5s for graceful exit
    const deadline = Date.now() + ORPHAN_SIGTERM_TIMEOUT_MS;
    while (Date.now() < deadline) {
      if (!isProcessRunning(row.pid)) {
        break;
      }
      await new Promise((resolve) => {
        setTimeout(resolve, 200).unref();
      });
    }

    if (isProcessRunning(row.pid)) {
      procLog.info(`sending SIGKILL to orphan pid=${row.pid} label=${row.label}`);
      sendSignal(row.pid, "SIGKILL");
      await new Promise((resolve) => {
        setTimeout(resolve, ORPHAN_SIGKILL_WAIT_MS).unref();
      });
    }

    if (!isProcessRunning(row.pid)) {
      reaped++;
    } else {
      procLog.warn(`failed to reap orphan pid=${row.pid} label=${row.label}`);
    }
  }

  // Clear all rows regardless of reap success
  db.exec("DELETE FROM child_processes");

  return { reaped, skipped };
}
