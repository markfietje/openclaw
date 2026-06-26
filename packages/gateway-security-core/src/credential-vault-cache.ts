/**
 * Process-lifetime KEK resolution for the credential vault.
 *
 * The credential store is read on every provider resolution, so re-reading the
 * KEK source (a file) on each call would be wasteful and would amplify the
 * observable surface (repeated file reads an attacker can race/observe). This
 * module memoizes the EXPENSIVE part — reading + decoding the key file — while
 * resolving the CHEAP part (reading two env vars) on every call.
 *
 * Concretely: each `getKek()` reads the live env to decide whether a KEK source
 * is configured. If so, and a key file is involved, the file is read at most
 * once per distinct path (memoized in a module-level map). If the env changes
 * (tests, or an operator editing the env of a running process), the next call
 * re-resolves lazily without serving a stale KEK.
 *
 * There is no mutable shared cache OBJECT, so concurrent test files in one
 * vitest worker cannot contaminate each other through a swapped singleton:
 * each call sees the env current at call time. Only the (path-keyed, idempotent)
 * file read is shared, which is safe.
 */
import type {
  CredentialVaultKekOptions,
  CredentialVaultKekResolution,
} from "./credential-keystore.js";
import { resolveCredentialVaultKek } from "./credential-keystore.js";

export interface CredentialVaultKekCache {
  /**
   * The resolved KEK (or `{ kind: "none" }` when unconfigured). Reads the env
   * live; memoizes the file read per distinct key-file path so the expensive
   * part happens at most once. Re-throws any resolution error.
   */
  getKek(): CredentialVaultKekResolution;
  /** Forget memoized key-file contents. Exposed for tests. */
  reset(): void;
}

// Module-level memo of key-file contents, keyed by file path. Bounded: the
// number of distinct key files in a process is 0 or 1 in practice. Safe to
// share across callers because a re-read returns identical bytes.
const keyFileMemo = new Map<string, string>();

function memoizedKeyFileReader(filePath: string): string {
  const cached = keyFileMemo.get(filePath);
  if (cached !== undefined) {
    return cached;
  }
  // Lazily required so the package stays importable in environments that stub
  // `node:fs` (the resolver injects its own reader for unit tests).
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { readFileSync } = require("node:fs") as {
    readFileSync: (p: string, enc: string) => string;
  };
  const value = readFileSync(filePath, "utf8");
  keyFileMemo.set(filePath, value);
  return value;
}

export function createCredentialVaultKekCache(
  options: CredentialVaultKekOptions = {},
): CredentialVaultKekCache {
  const env = options.env ?? process.env;
  // An injected reader (unit tests) bypasses the memo so tests control output.
  const readKeyFile = options.readKeyFile ?? memoizedKeyFileReader;
  return {
    getKek(): CredentialVaultKekResolution {
      // Fresh resolution each call: cheap env read + memoized file read.
      return resolveCredentialVaultKek({ env, readKeyFile });
    },
    reset(): void {
      keyFileMemo.clear();
    },
  };
}
