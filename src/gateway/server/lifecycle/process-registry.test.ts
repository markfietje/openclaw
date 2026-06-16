// Process registry orphan reaper tests.
// Covers the PID-reuse safety gate: rows whose recorded started_at is older
// than the reap window are skipped (not signaled) and the table is cleared
// regardless. Between restarts the OS may recycle a PID to an unrelated
// process, so reaping stale rows risks killing the wrong process.
import { describe, expect, it } from "vitest";
import { reapOrphanChildProcesses } from "./process-registry.js";

type Row = { pid: number; label: string; started_at: number };

// Matches the Statement.all() return shape reapOrphanChildProcesses expects
// (StmtAll). Production code casts these rows to ChildProcessRow before
// reading started_at, so the exact column values here only need to survive
// that cast.
type SqlValue = string | number | bigint | Uint8Array | null;
type DbRow = Record<string, SqlValue | SqlValue[]>;

function makeDb(rows: Row[]) {
  return {
    prepare(_sql: string) {
      return {
        all(): DbRow[] {
          return rows as unknown as DbRow[];
        },
      };
    },
    exec(_sql: string) {
      // Track that the clear-all DELETE ran by emptying the rows buffer.
      rows.length = 0;
    },
  };
}

describe("reapOrphanChildProcesses", () => {
  it("returns zero counts when the table is empty", async () => {
    const db = makeDb([]);
    const result = await reapOrphanChildProcesses(db);
    expect(result).toEqual({ reaped: 0, skipped: 0 });
  });

  it("skips rows whose started_at exceeds the reap window (PID-reuse safety)", async () => {
    // 5 minutes old — well past the 60s window. Use a PID that is not running
    // so the skip is attributable solely to the age gate, not isProcessRunning.
    const stalePid = 999_999_999;
    const rows: Row[] = [
      {
        pid: stalePid,
        label: "old-mcp",
        started_at: Date.now() - 5 * 60_000,
      },
    ];
    const db = makeDb(rows);
    const result = await reapOrphanChildProcesses(db);
    expect(result).toEqual({ reaped: 0, skipped: 1 });
    // Table is cleared regardless of reap outcome.
    expect(rows).toHaveLength(0);
  });

  it("skips rows with a non-numeric started_at (defensive)", async () => {
    const rows: Row[] = [
      // Simulate a malformed/legacy row by coercing the type at the boundary.
      { pid: 999_999_998, label: "bad-row", started_at: Number.NaN },
    ];
    const db = makeDb(rows);
    const result = await reapOrphanChildProcesses(db);
    expect(result).toEqual({ reaped: 0, skipped: 1 });
    expect(rows).toHaveLength(0);
  });

  it("clears the table even when all rows are skipped", async () => {
    const rows: Row[] = [
      { pid: 999_999_997, label: "old-1", started_at: Date.now() - 120_000 },
      { pid: 999_999_996, label: "old-2", started_at: Date.now() - 90_000 },
    ];
    const db = makeDb(rows);
    const result = await reapOrphanChildProcesses(db);
    expect(result.reaped).toBe(0);
    expect(result.skipped).toBe(2);
    expect(rows).toHaveLength(0);
  });
});
