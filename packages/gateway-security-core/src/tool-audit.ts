import crypto from "node:crypto";
import { appendFile, chmod, mkdir, rename, stat } from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "./paths.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ToolAuditEventType = "tool.call" | "tool.result" | "tool.error";

export type ToolAuditEntry = {
  ts: string;
  source: "gateway";
  event: ToolAuditEventType;
  /** Originating surface: "tools-invoke", "openresponses", "chat", etc. */
  surface: string;
  /** Tool name — e.g. "exec", "file_read". Sensitive args are NEVER logged. */
  tool: string;
  actorId?: string;
  session?: string;
  channel?: string;
  model?: string;
  runId?: string;
  toolCallId?: string;
  resultStatus?: "success" | "failure" | "denied";
  durationMs?: number;
};

export interface ToolAuditLogger {
  /** Fire-and-forget write. Errors are swallowed. */
  log(entry: Omit<ToolAuditEntry, "ts" | "source">): void;
  /** Await all pending writes. */
  flush(): Promise<void>;
}

export type ToolAuditLogConfig = {
  maxBytes?: number;
  maxFiles?: number;
  logDir?: string;
  /** HMAC signing token. When non-empty, each line includes an `hmac` field. */
  token?: string;
};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_MAX_BYTES = 10 * 1024 * 1024; // 10 MB
const DEFAULT_MAX_FILES = 3;
const AUDIT_DIR_MODE = 0o700;
const AUDIT_FILE_MODE = 0o600;
const BASE_FILENAME = "gateway-tool-audit";
const EXT = "jsonl";

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------

function computeHmac(jsonWithoutHmac: string, token: string): string {
  return crypto.createHmac("sha256", token).update(jsonWithoutHmac).digest("hex");
}

/**
 * Verify a tool-audit log line against a signing token.
 *
 * Returns `{ valid: true, entry }` when the HMAC matches (or when the line
 * has no `hmac` field and `token` is empty — backward-compatible mode).
 * Returns `{ valid: false }` otherwise.
 */
export function verifyToolAuditLine(
  line: string,
  token: string,
): { valid: boolean; entry?: ToolAuditEntry } {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return { valid: false };
  }

  const hasHmac = "hmac" in parsed && typeof parsed.hmac === "string";

  // No token configured — backward-compatible: accept lines without hmac.
  if (!token) {
    if (hasHmac) {
      // Signed line but no token to verify — treat as invalid.
      return { valid: false };
    }
    return { valid: true, entry: parsed as unknown as ToolAuditEntry };
  }

  // Token is configured but line has no hmac field.
  if (!hasHmac) {
    return { valid: false };
  }

  const claimedHmac = parsed.hmac as string;

  // Reconstruct the JSON without the hmac field, preserving field order.
  const { hmac: _hmac, ...rest } = parsed;
  const reconstructed = JSON.stringify(rest);

  const expectedHmac = computeHmac(reconstructed, token);

  // Timing-safe comparison.
  if (
    claimedHmac.length !== expectedHmac.length ||
    !crypto.timingSafeEqual(Buffer.from(claimedHmac, "hex"), Buffer.from(expectedHmac, "hex"))
  ) {
    return { valid: false };
  }

  return { valid: true, entry: rest as unknown as ToolAuditEntry };
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

export function createToolAuditLogger(config?: ToolAuditLogConfig): ToolAuditLogger {
  const maxBytes = config?.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxFiles = config?.maxFiles ?? DEFAULT_MAX_FILES;
  const logDir = config?.logDir ?? path.join(resolveStateDir(), "logs");
  const hmacToken = config?.token ?? "";
  const activeFile = path.join(logDir, `${BASE_FILENAME}.${EXT}`);

  // Promise chain serialises concurrent writes without blocking callers.
  let pending: Promise<void> = Promise.resolve();

  function log(entry: Omit<ToolAuditEntry, "ts" | "source">): void {
    pending = pending
      .then(() => writeEntry(entry))
      .catch(() => {
        /* swallow — audit logging must never crash the gateway */
      });
  }

  function flush(): Promise<void> {
    return pending;
  }

  // ---- internal helpers ---------------------------------------------------

  async function ensureDir(): Promise<void> {
    await mkdir(logDir, { recursive: true, mode: AUDIT_DIR_MODE });
    await chmod(logDir, AUDIT_DIR_MODE);
  }

  async function secureFile(filePath: string): Promise<void> {
    await chmod(filePath, AUDIT_FILE_MODE);
  }

  async function writeEntry(entry: Omit<ToolAuditEntry, "ts" | "source">): Promise<void> {
    const line: ToolAuditEntry = {
      ts: new Date().toISOString(),
      source: "gateway",
      ...entry,
    };

    let data: string;

    if (hmacToken) {
      // Build JSON without hmac, compute HMAC, then inject hmac as the last field.
      const jsonWithoutHmac = JSON.stringify(line);
      const hmacHex = computeHmac(jsonWithoutHmac, hmacToken);
      // hmacHex is a hex string (only [0-9a-f]) — safe to inject into JSON.
      data = `${jsonWithoutHmac.slice(0, -1)},"hmac":"${hmacHex}"}\n`;
    } else {
      data = JSON.stringify(line) + "\n";
    }

    await ensureDir();
    await appendFile(activeFile, data, { encoding: "utf8", mode: AUDIT_FILE_MODE });
    await secureFile(activeFile);
    await rotateIfNeeded();
  }

  async function rotateIfNeeded(): Promise<void> {
    let fileSize: number;
    try {
      const info = await stat(activeFile);
      fileSize = info.size;
    } catch {
      // File doesn't exist yet or is inaccessible — nothing to rotate.
      return;
    }

    if (fileSize < maxBytes) {
      return;
    }

    // Shift rotated files: .N → .N+1, then current → .1, delete oldest.
    for (let i = maxFiles - 1; i >= 1; i--) {
      const older = rotatedPath(i);
      const newer = i === 1 ? activeFile : rotatedPath(i - 1);
      try {
        await rename(newer, older);
        await secureFile(older);
      } catch {
        // File may not exist yet — that is fine.
      }
    }
  }

  function rotatedPath(index: number): string {
    return path.join(logDir, `${BASE_FILENAME}.${index}.${EXT}`);
  }

  return { log, flush };
}
