/**
 * Convenience wrappers that combine the vault envelope, KEK cache, and the
 * fail-closed tamper policy into the two operations the credential-store wire
 * point actually needs: "encrypt on write if a KEK is present" and "decrypt or
 * parse on read, failing closed on a downgrade".
 *
 * These are thin orchestration over `credential-vault` + `credential-vault-cache`
 * so the SQLite chokepoint stays a one-liner and the policy lives in one place.
 */
import type { CredentialVaultKekCache } from "./credential-vault-cache.js";
import {
  isCredentialVaultEnvelope,
  openFromCredentialVault,
  sealWithCredentialVault,
} from "./credential-vault.js";
import { CredentialVaultTamperError } from "./credential-vault.js";

/**
 * Encrypt `plaintext` (already-serialized JSON) when a KEK is configured,
 * otherwise return it unchanged so the store cell stays plaintext (default).
 * Never throws for a "no KEK" condition — that is the documented default, not
 * an error. Does throw if the KEK is misconfigured (wrong length), because that
 * is a provisioning bug the operator must fix.
 */
export function sealCredentialStoreCell(plaintext: string, cache: CredentialVaultKekCache): string {
  const resolution = cache.getKek();
  if (resolution.kind === "none") {
    return plaintext;
  }
  return sealWithCredentialVault(plaintext, resolution.kek);
}

export type OpenCredentialStoreCellResult =
  | { readonly kind: "json"; readonly value: unknown }
  | { readonly kind: "missing" };

/**
 * Inverse of `sealCredentialStoreCell`. Policy:
 *   - cell is a sealed envelope → decrypt with the cached KEK and parse.
 *     Requires a KEK; throws `CredentialVaultKeyError`-style if none is cached
 *     (a sealed cell cannot exist without one having written it).
 *   - cell is plaintext and NO KEK is configured → parse as JSON (default).
 *   - cell is plaintext but a KEK IS configured → fail closed with
 *     `CredentialVaultTamperError`. This is the downgrade signal: someone
 *     replaced a sealed cell with plaintext hoping the loader would read it
 *     without the KEK. Reading it would silently disable encryption, which is
 *     exactly the failure mode the KEK is meant to prevent.
 *
 * `raw` is the cell value (string) or null/undefined when the row/cell is
 * absent, mirroring how the SQLite reader yields store payloads.
 */
export function openCredentialStoreCell(
  raw: string | null | undefined,
  cache: CredentialVaultKekCache,
): OpenCredentialStoreCellResult {
  if (raw === null || raw === undefined || raw === "") {
    return { kind: "missing" };
  }

  const resolution = cache.getKek();

  if (isCredentialVaultEnvelope(raw)) {
    if (resolution.kind === "none") {
      // A sealed cell exists but no KEK is configured. This is either a
      // misconfigured deployment (KEK file removed) or a stolen-disk scenario.
      // Either way we cannot decrypt; fail with a clear message rather than
      // silently treating it as empty.
      throw new CredentialVaultTamperError(
        "credential-vault: store cell is sealed but no KEK is configured. " +
          "Set OPENCLAW_CREDENTIAL_VAULT_KEY_FILE to the operator-managed key file.",
      );
    }
    const plaintext = openFromCredentialVault(raw, resolution.kek);
    return { kind: "json", value: JSON.parse(plaintext) as unknown };
  }

  // Plaintext cell.
  if (resolution.kind !== "none") {
    // KEK is configured but the cell is plaintext → downgrade/tamper signal.
    throw new CredentialVaultTamperError(
      "credential-vault: a KEK is configured but the credential store cell is " +
        "plaintext. This is either a pending migration (run the vault migration " +
        "after provisioning the KEK) or a tamper/downgrade attempt. The loader " +
        "refuses to read plaintext while encryption is configured.",
    );
  }

  return { kind: "json", value: JSON.parse(raw) as unknown };
}
