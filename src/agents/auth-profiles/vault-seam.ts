// Credential vault seam for the auth-profile store.
//
// All vault logic (envelope crypto, KEK resolution, fail-closed policy) lives
// in @openclaw/gateway-security-core so it stays fork-only and does not touch
// upstream-tracked code. This file is the thin re-export + the process-lifetime
// KEK cache that sqlite.ts uses at the store_json cell chokepoint.
//
// The cache reads `process.env` lazily and re-resolves when the KEK-source env
// tuple changes, so in production (stable env) it resolves exactly once and in
// tests it can be exercised without a process restart.
import {
  openCredentialStoreCell,
  sealCredentialStoreCell,
} from "@openclaw/gateway-security-core/credential-store-cell";
import {
  createCredentialVaultKekCache,
  type CredentialVaultKekCache,
} from "@openclaw/gateway-security-core/credential-vault-cache";

// Shared production cache. Lazily resolved; reads process.env on each call but
// memoizes the expensive file-read so the KEK file is read at most once per
// distinct KEK-source env tuple.
const productionCache: CredentialVaultKekCache = createCredentialVaultKekCache();
let activeCache: CredentialVaultKekCache = productionCache;

/** Encrypt a serialized store payload when a KEK is configured, else pass
 *  through as plaintext (the default). Used at the write chokepoint. */
export function sealAuthProfileStoreCell(plaintextJson: string): string {
  return sealCredentialStoreCell(plaintextJson, activeCache);
}

/** Decrypt or parse a store cell, failing closed on downgrade/tamper. Returns
 *  `null` when the cell is absent so callers keep their existing "no row" path.
 *  Used at the read chokepoint. */
export function openAuthProfileStoreCell(raw: string | null | undefined): unknown {
  const result = openCredentialStoreCell(raw, activeCache);
  if (result.kind === "missing") {
    return null;
  }
  return result.value;
}

/** Test-only: install a cache backed by a fully-controlled env, so integration
 *  tests can exercise the wire point without mutating the shared worker's
 *  `process.env` (which would leak to unrelated test files in the same worker).
 *  Returns a restore function. Not exported via the package barrel. */
export function setAuthProfileVaultCacheForTesting(
  env: Record<string, string | undefined>,
): () => void {
  const previous = activeCache;
  activeCache = createCredentialVaultKekCache({ env });
  return () => {
    activeCache = previous;
  };
}
