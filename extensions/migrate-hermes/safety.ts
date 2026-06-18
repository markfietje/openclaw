// Migrate Hermes safety module enforces size caps and path containment on
// imported files. Without these guards, a malicious or accidentally huge
// Hermes source can either exhaust disk space during apply or escape the
// expected target directory through a path containing `..` segments.
//
// The defaults below are conservative for a configuration/auth import:
//   - 10 MB per file (config.yaml, auth.json, opencode auth, skills)
//   - 100 MB per archive item (state.db snapshots, plugin directories)
//
// Operators can override per-call with the `maxBytes` and `maxArchiveBytes`
// options on `withImportSafety`.

import fs from "node:fs/promises";
import path from "node:path";

/** Default size cap for non-archive imported files. */
export const DEFAULT_MAX_IMPORT_BYTES = 10 * 1024 * 1024;

/** Default size cap for archive items (state.db, plugin dirs, etc.). */
export const DEFAULT_MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;

export type SizeCheckResult =
  | { ok: true; size: number }
  | { ok: false; size: number; limit: number; path: string };

/**
 * Check that a file's size does not exceed the given limit. Returns the
 * observed size on success, or the observed size and the configured limit
 * on failure. The check is performed with `fs.stat` (not `lstat`) so a
 * symlink swap cannot bypass the cap.
 */
export async function checkFileSize(
  filePath: string,
  limitBytes: number,
): Promise<SizeCheckResult> {
  const resolved = path.resolve(filePath);
  const stat = await fs.stat(resolved).catch(() => undefined);
  if (!stat || !stat.isFile()) {
    // Missing or non-file: not a size violation, let the caller decide.
    return { ok: true, size: 0 };
  }
  if (stat.size > limitBytes) {
    return { ok: false, size: stat.size, limit: limitBytes, path: resolved };
  }
  return { ok: true, size: stat.size };
}

export type PathContainmentResult =
  | { ok: true; resolved: string }
  | {
      ok: false;
      resolved: string;
      parent: string;
      reason: "outside-parent" | "symlink" | "missing";
    };

/**
 * Confirm that `target` resolves to a path inside `parentDir` after symlink
 * resolution. The check uses `fs.realpath` on the parent directory so a
 * symlinked parent does not silently relocate the target.
 *
 * The check fails closed when the parent does not exist or the target
 * escapes the parent via `..` segments. The caller can choose how to
 * react (skip, error, etc.).
 */
export async function ensurePathContained(
  target: string,
  parentDir: string,
): Promise<PathContainmentResult> {
  const resolvedTarget = path.resolve(target);
  const resolvedParent = path.resolve(parentDir);
  const parentReal = await fs.realpath(resolvedParent).catch(() => undefined);
  if (!parentReal) {
    return {
      ok: false,
      resolved: resolvedTarget,
      parent: resolvedParent,
      reason: "missing",
    };
  }
  // Walk up the target path until we hit an existing ancestor, then
  // resolve that ancestor. This handles the common case where the target
  // itself does not exist yet (e.g. an archive path that will be created
  // by the apply step).
  let cursor = path.dirname(resolvedTarget);
  let cursorReal: string | undefined;
  while (cursor && cursor !== path.dirname(cursor)) {
    cursorReal = await fs.realpath(cursor).catch(() => undefined);
    if (cursorReal) {
      break;
    }
    cursor = path.dirname(cursor);
  }
  // Fall back to lexical containment if the target path has no existing
  // ancestor at all. The lexical check is a last resort and only fires
  // when the entire target tree is uncreated, which is rare in practice.
  // `relative === ""` means the reference is the parent itself, which is
  // contained (a target inside the parent walks up to the parent).
  const reference = cursorReal ?? resolvedTarget;
  const relative = path.relative(parentReal, reference);
  const insideParent = !relative.startsWith("..") && !path.isAbsolute(relative);
  if (!insideParent) {
    return {
      ok: false,
      resolved: resolvedTarget,
      parent: parentReal,
      reason: "outside-parent",
    };
  }
  return { ok: true, resolved: resolvedTarget };
}

export type SafetyCheckOptions = {
  maxBytes?: number;
  maxArchiveBytes?: number;
};

export type SafetyReport = {
  ok: boolean;
  checked: number;
  oversized: Array<{ path: string; size: number; limit: number }>;
  outOfBounds: Array<{ path: string; parent: string; reason: string }>;
};

/**
 * Run the standard import safety checks across a list of file paths and
 * archive paths. Each file is checked against `maxBytes`; each archive
 * path is checked against `maxArchiveBytes`. Returns a report describing
 * every violation found, so the caller can decide whether to fail the
 * plan, skip the offender, or prompt the operator.
 */
export async function runImportSafetyChecks(params: {
  files: string[];
  archivePaths: string[];
  parentDir: string;
  options?: SafetyCheckOptions;
}): Promise<SafetyReport> {
  const maxBytes = params.options?.maxBytes ?? DEFAULT_MAX_IMPORT_BYTES;
  const maxArchiveBytes = params.options?.maxArchiveBytes ?? DEFAULT_MAX_ARCHIVE_BYTES;

  const oversized: SafetyReport["oversized"] = [];
  const outOfBounds: SafetyReport["outOfBounds"] = [];

  for (const file of params.files) {
    const result = await checkFileSize(file, maxBytes);
    if (!result.ok) {
      oversized.push({ path: result.path, size: result.size, limit: result.limit });
    }
  }
  for (const archive of params.archivePaths) {
    const result = await checkFileSize(archive, maxArchiveBytes);
    if (!result.ok) {
      oversized.push({ path: result.path, size: result.size, limit: result.limit });
    }
    const contained = await ensurePathContained(archive, params.parentDir);
    if (!contained.ok) {
      outOfBounds.push({
        path: contained.resolved,
        parent: contained.parent,
        reason: contained.reason,
      });
    }
  }

  return {
    ok: oversized.length === 0 && outOfBounds.length === 0,
    checked: params.files.length + params.archivePaths.length,
    oversized,
    outOfBounds,
  };
}
