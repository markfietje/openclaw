import crypto from "node:crypto";
import { appendFile, chmod, mkdir, rename, stat } from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "../../../src/config/paths.js";

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

export type AuditLogFormat = "jsonl" | "json";

export type AuditLogConfig = {
  maxBytes?: number;
  maxFiles?: number;
  logDir?: string;
  token?: string;
  /** Output format. "jsonl" (default) writes one JSON object per line. "json" is reserved for future structured output modes. */
  format?: AuditLogFormat;
};

export type AuditLogEntry = Record<string, unknown>;

export interface AuditLogger<T extends AuditLogEntry> {
  log(entry: Omit<T, "ts">): void;
  flush(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Shared defaults
// ---------------------------------------------------------------------------

export const DEFAULT_MAX_BYTES = 10 * 1024 * 1024;
export const DEFAULT_MAX_FILES = 3;
export const AUDIT_DIR_MODE = 0o700;
export const AUDIT_FILE_MODE = 0o600;
export const EXT = "jsonl";

// Bound upstream-supplied audit-log string fields (user, clientId, etc.) so a
// hostile trusted-proxy header or misconfigured identity provider cannot
// inflate log lines or consume memory on disk. Appending an ellipsis keeps
// it obvious to an analyst that the value was clipped.
export const MAX_AUDIT_STRING_LENGTH = 256;

export function truncateAuditField(value: string | undefined): string | undefined {
  if (value === undefined || value.length === 0) {
    return value;
  }
  return value.length > MAX_AUDIT_STRING_LENGTH
    ? `${value.slice(0, MAX_AUDIT_STRING_LENGTH)}\u2026`
    : value;
}

// ---------------------------------------------------------------------------
// Shared HMAC helpers
// ---------------------------------------------------------------------------

export function computeHmac(jsonWithoutHmac: string, token: string): string {
  return crypto.createHmac("sha256", token).update(jsonWithoutHmac).digest("hex");
}

// `T` is intentionally return-position only: callers supply the narrowed
// entry type (e.g. `verifyAuditLine<AuthAuditEntry>(...)`) so the returned
// `entry` is typed for the audit log domain rather than the generic base.
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- Caller-controlled entry narrowing is part of the public API contract.
export function verifyAuditLine<T extends AuditLogEntry>(
  line: string,
  token: string,
): { valid: boolean; entry?: T } {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return { valid: false };
  }

  const hasHmac = "hmac" in parsed && typeof parsed.hmac === "string";

  if (!token) {
    if (hasHmac) {
      return { valid: false };
    }
    return { valid: true, entry: parsed as unknown as T };
  }

  if (!hasHmac) {
    return { valid: false };
  }

  const claimedHmac = parsed.hmac as string;
  const { hmac: _hmac, ...rest } = parsed;
  const reconstructed = JSON.stringify(rest);
  const expectedHmac = computeHmac(reconstructed, token);

  // OWASP A05:2021 — Cryptographic Failures. Use constant-time comparison
  // to prevent timing side-channel attacks that could leak HMAC validity.
  // The length check is safe here because sha256 hex is always 64 characters;
  // we validate the hex charset first to ensure the claimedHmac is well-formed.
  if (!/^[0-9a-f]{64}$/i.test(claimedHmac)) {
    return { valid: false };
  }
  const claimedBuf = Buffer.from(claimedHmac, "hex");
  const expectedBuf = Buffer.from(expectedHmac, "hex");
  if (
    claimedBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(claimedBuf, expectedBuf)
  ) {
    return { valid: false };
  }

  return { valid: true, entry: rest as unknown as T };
}

// ---------------------------------------------------------------------------
// Shared implementation
// ---------------------------------------------------------------------------

export type AuditLogBaseParams = {
  config?: AuditLogConfig;
  baseFilename: string;
  stampEntry: (entry: AuditLogEntry) => AuditLogEntry;
};

export function createAuditLogBase<T extends AuditLogEntry>(
  params: AuditLogBaseParams,
): AuditLogger<T> {
  const maxBytes = params.config?.maxBytes ?? DEFAULT_MAX_BYTES;
  const maxFiles = params.config?.maxFiles ?? DEFAULT_MAX_FILES;
  const logDir = params.config?.logDir ?? path.join(resolveStateDir(), "logs");
  // Auto-generate a per-process HMAC token when none is configured so audit
  // logs are always integrity-protected. The token is ephemeral — rotated on
  // gateway restart — which is acceptable for local single-process deployments.
  const hmacToken = params.config?.token ?? crypto.randomBytes(32).toString("hex");

  // JSONL is required for HMAC-signed append-only logs — a JSON array cannot be
  // appended to without parsing and rewriting the entire file. Reserved for future
  // structured output modes (e.g., a separate rotated JSON index file).
  const _format: AuditLogFormat = params.config?.format ?? "jsonl";
  void _format;

  const activeFile = path.join(logDir, `${params.baseFilename}.${EXT}`);

  const MAX_PENDING_DEPTH = 1000;
  let pendingDepth = 0;
  let pending: Promise<void> = Promise.resolve();

  function log(entry: Omit<T, "ts">): void {
    if (pendingDepth >= MAX_PENDING_DEPTH) {
      // Drop entry to avoid unbounded promise chain growth on I/O failures.
      // Warn to alert operators without flooding logs.
      console.warn(
        `[audit-log] dropped entry (pending depth ${pendingDepth} >= ${MAX_PENDING_DEPTH}); ` +
          "I/O may be blocked or disk full. Check disk space and audit log directory.",
      );
      return;
    }
    pendingDepth++;
    pending = pending
      .then(() => writeEntry(entry as AuditLogEntry))
      .catch(() => {})
      .finally(() => {
        pendingDepth--;
      });
  }

  function flush(): Promise<void> {
    return pending;
  }

  async function ensureDir(): Promise<void> {
    await mkdir(logDir, { recursive: true, mode: AUDIT_DIR_MODE });
    await chmod(logDir, AUDIT_DIR_MODE);
  }

  async function secureFile(filePath: string): Promise<void> {
    await chmod(filePath, AUDIT_FILE_MODE);
  }

  async function writeEntry(entry: AuditLogEntry): Promise<void> {
    const stamped = params.stampEntry({ ...entry, ts: new Date().toISOString() });

    let data: string;

    if (hmacToken) {
      const jsonWithoutHmac = JSON.stringify(stamped);
      const hmacHex = computeHmac(jsonWithoutHmac, hmacToken);
      data = `${jsonWithoutHmac.slice(0, -1)},"hmac":"${hmacHex}"}\n`;
    } else {
      data = JSON.stringify(stamped) + "\n";
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
      return;
    }

    if (fileSize < maxBytes) {
      return;
    }

    for (let i = maxFiles - 1; i >= 1; i--) {
      const older = rotatedPath(i);
      const newer = i === 1 ? activeFile : rotatedPath(i - 1);
      try {
        await rename(newer, older);
        await secureFile(older);
      } catch (err) {
        // Rotation failure is non-fatal but operators should know about
        // disk/permission issues before the active log grows unbounded.
        console.warn("[audit-log] log rotation failed:", err);
      }
    }
  }

  function rotatedPath(index: number): string {
    return path.join(logDir, `${params.baseFilename}.${index}.${EXT}`);
  }

  return { log, flush };
}
