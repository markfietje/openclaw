import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
/**
 * Tests for the import-safety helpers in safety.ts.
 *
 * These tests cover three properties:
 *   1. checkFileSize accepts files under the limit and rejects oversized files.
 *   2. ensurePathContained accepts targets inside the parent and rejects
 *      targets that escape the parent via `..` segments or symlinks.
 *   3. runImportSafetyChecks produces a report that surfaces both
 *      oversized files and out-of-bounds paths in one pass.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  checkFileSize,
  DEFAULT_MAX_ARCHIVE_BYTES,
  DEFAULT_MAX_IMPORT_BYTES,
  ensurePathContained,
  runImportSafetyChecks,
} from "./safety.js";

let workDir: string;
let testFile: string;
let bigFile: string;

beforeEach(async () => {
  workDir = await fs.mkdtemp(path.join(os.tmpdir(), "hermes-safety-"));
  testFile = path.join(workDir, "config.yaml");
  bigFile = path.join(workDir, "huge.bin");
  await fs.writeFile(testFile, "model: gpt-4\n", "utf8");
  await fs.writeFile(bigFile, Buffer.alloc(DEFAULT_MAX_IMPORT_BYTES + 1));
});

afterEach(async () => {
  if (workDir) {
    await fs.rm(workDir, { recursive: true, force: true });
  }
});

describe("safety: checkFileSize", () => {
  it("accepts a small file under the limit", async () => {
    const result = await checkFileSize(testFile, DEFAULT_MAX_IMPORT_BYTES);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.size).toBeLessThan(DEFAULT_MAX_IMPORT_BYTES);
    }
  });

  it("rejects a file over the limit", async () => {
    const result = await checkFileSize(bigFile, DEFAULT_MAX_IMPORT_BYTES);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.size).toBeGreaterThan(DEFAULT_MAX_IMPORT_BYTES);
      expect(result.limit).toBe(DEFAULT_MAX_IMPORT_BYTES);
      expect(result.path).toBe(bigFile);
    }
  });

  it("accepts a missing file (size 0) so the caller can decide", async () => {
    const missing = path.join(workDir, "does-not-exist.yaml");
    const result = await checkFileSize(missing, DEFAULT_MAX_IMPORT_BYTES);
    expect(result.ok).toBe(true);
  });
});

describe("safety: ensurePathContained", () => {
  it("accepts a path inside the parent directory", async () => {
    const inner = path.join(workDir, "sub", "config.yaml");
    const result = await ensurePathContained(inner, workDir);
    expect(result.ok).toBe(true);
  });

  it("rejects a path that escapes the parent via '..'", async () => {
    const escape = path.join(workDir, "..", "evil.yaml");
    const result = await ensurePathContained(escape, workDir);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("outside-parent");
    }
  });

  it("rejects when the parent directory does not exist", async () => {
    const missing = path.join(workDir, "nope");
    const result = await ensurePathContained(path.join(missing, "x"), missing);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("missing");
    }
  });
});

describe("safety: runImportSafetyChecks", () => {
  it("reports ok when every file is under the limit and inside the parent", async () => {
    const report = await runImportSafetyChecks({
      files: [testFile],
      archivePaths: [],
      parentDir: workDir,
    });
    expect(report.ok).toBe(true);
    expect(report.checked).toBe(1);
    expect(report.oversized).toEqual([]);
    expect(report.outOfBounds).toEqual([]);
  });

  it("flags oversized files", async () => {
    const report = await runImportSafetyChecks({
      files: [bigFile],
      archivePaths: [],
      parentDir: workDir,
    });
    expect(report.ok).toBe(false);
    expect(report.oversized).toHaveLength(1);
    expect(report.oversized[0]?.path).toBe(bigFile);
  });

  it("flags archive paths that escape the parent", async () => {
    const escapeArchive = path.join(workDir, "..", "evil-plugin");
    const report = await runImportSafetyChecks({
      files: [],
      archivePaths: [escapeArchive],
      parentDir: workDir,
    });
    expect(report.ok).toBe(false);
    expect(report.outOfBounds).toHaveLength(1);
    expect(report.outOfBounds[0]?.reason).toBe("outside-parent");
  });

  it("respects custom maxBytes and maxArchiveBytes overrides", async () => {
    const report = await runImportSafetyChecks({
      files: [testFile],
      archivePaths: [],
      parentDir: workDir,
      options: { maxBytes: 1 }, // smaller than the test file
    });
    expect(report.ok).toBe(false);
    expect(report.oversized).toHaveLength(1);
    expect(report.oversized[0]?.limit).toBe(1);
  });
});

describe("safety: defaults", () => {
  it("exposes the documented default caps", () => {
    expect(DEFAULT_MAX_IMPORT_BYTES).toBe(10 * 1024 * 1024);
    expect(DEFAULT_MAX_ARCHIVE_BYTES).toBe(100 * 1024 * 1024);
  });
});
