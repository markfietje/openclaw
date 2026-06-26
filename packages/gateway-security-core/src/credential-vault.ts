/**
 * Credential vault envelope encryption (AES-256-GCM).
 *
 * Encrypts a UTF-8 string (typically `JSON.stringify(storePayload)`) with a
 * caller-supplied 32-byte Key Encryption Key (KEK). The KEK is never stored or
 * derived here — the caller resolves it via `credential-keystore` (env, file,
 * or a future OS-keychain backend). Keeping this module KEK-agnostic and free
 * of `fs`/`env` access lets the package stay pure-logic and testable.
 *
 * Envelope v3 (prefix `openclaw-credential-vault-v3:`):
 *   { v:3, alg:"aes-256-gcm", iv, tag, ciphertext }  // all binary fields base64
 *
 * The envelope version and algorithm are bound into the GCM authentication tag
 * as Additional Authenticated Data (`3:aes-256-gcm`). This prevents a silent
 * downgrade or algorithm swap: any tamper that rewrites `v` or `alg` fails the
 * GCM tag check at `decipher.final()` rather than producing corrupted output.
 *
 * OWASP A02:2021 — Cryptographic Failures: authenticated encryption (AEAD) is
 * used so confidentiality and integrity come from one operation; a separate
 * HMAC step (the classic CBC mistake) is not needed and cannot be forgotten.
 * OWASP A04:2021 — Insecure Design: the loader fails closed when a KEK is
 * configured but the cell is plaintext (downgrade/tamper signal).
 *
 * @see docs/gateway/security/security-posts/03-encrypted-credentials-at-rest.md
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const VAULT_PREFIX = "openclaw-credential-vault-v3:";
const VAULT_ALG = "aes-256-gcm";
const VAULT_VERSION = 3 as const;
const KEK_LENGTH_BYTES = 32;
const IV_LENGTH_BYTES = 12;

type CredentialVaultEnvelope = {
  readonly v: typeof VAULT_VERSION;
  readonly alg: typeof VAULT_ALG;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
};

/** Bind the envelope version + algorithm into the GCM auth tag so the
 *  ciphertext cannot be replayed under a different v/alg (OWASP A02). */
function envelopeAad(): Buffer {
  return Buffer.from(`${VAULT_VERSION}:${VAULT_ALG}`, "utf8");
}

export class CredentialVaultKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialVaultKeyError";
  }
}

export class CredentialVaultTamperError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CredentialVaultTamperError";
  }
}

/** True when `value` begins with the v3 vault prefix — i.e. it is a sealed
 *  envelope rather than plaintext. Used by the loader to branch without
 *  attempting (and failing) `JSON.parse` on a sealed cell. */
export function isCredentialVaultEnvelope(value: string | null | undefined): value is string {
  return typeof value === "string" && value.startsWith(VAULT_PREFIX);
}

/**
 * Encrypt `plaintext` with `kek` and return the prefixed envelope string.
 * Throws `CredentialVaultKeyError` if the KEK is not exactly 32 bytes — a KEK
 * of the wrong length is a provisioning bug, not a runtime condition to paper
 * over with padding.
 */
export function sealWithCredentialVault(plaintext: string, kek: Buffer): string {
  if (!Buffer.isBuffer(kek) || kek.length !== KEK_LENGTH_BYTES) {
    throw new CredentialVaultKeyError(
      `credential-vault: KEK must be ${KEK_LENGTH_BYTES} bytes (got ${kek?.length ?? 0})`,
    );
  }
  const iv = randomBytes(IV_LENGTH_BYTES);
  const cipher = createCipheriv(VAULT_ALG, kek, iv);
  cipher.setAAD(envelopeAad());
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  const envelope: CredentialVaultEnvelope = {
    v: VAULT_VERSION,
    alg: VAULT_ALG,
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };
  return VAULT_PREFIX + Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
}

/**
 * Decrypt a prefixed envelope string produced by `sealWithCredentialVault`.
 * Verifies the GCM auth tag (via `decipher.final()`) so any tamper — modified
 * ciphertext, wrong KEK, or a rewritten `v`/`alg` — throws rather than
 * returning corrupted data.
 */
export function openFromCredentialVault(envelopeString: string, kek: Buffer): string {
  if (!Buffer.isBuffer(kek) || kek.length !== KEK_LENGTH_BYTES) {
    throw new CredentialVaultKeyError(
      `credential-vault: KEK must be ${KEK_LENGTH_BYTES} bytes (got ${kek?.length ?? 0})`,
    );
  }
  if (!isCredentialVaultEnvelope(envelopeString)) {
    throw new CredentialVaultTamperError(
      "credential-vault: value is not a sealed envelope (expected v3 prefix)",
    );
  }
  let envelope: CredentialVaultEnvelope;
  try {
    const json = Buffer.from(envelopeString.slice(VAULT_PREFIX.length), "base64").toString("utf8");
    envelope = JSON.parse(json) as CredentialVaultEnvelope;
  } catch {
    throw new CredentialVaultTamperError("credential-vault: envelope is not valid base64/JSON");
  }
  if (
    envelope.v !== VAULT_VERSION ||
    envelope.alg !== VAULT_ALG ||
    typeof envelope.iv !== "string" ||
    typeof envelope.tag !== "string" ||
    typeof envelope.ciphertext !== "string"
  ) {
    throw new CredentialVaultTamperError(
      "credential-vault: envelope fields missing or version/algorithm mismatch",
    );
  }

  const decipher = createDecipheriv(VAULT_ALG, kek, Buffer.from(envelope.iv, "base64"));
  decipher.setAAD(envelopeAad());
  decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
  // `final()` is where GCM verifies the auth tag. A tag mismatch (ciphertext
  // tamper, wrong KEK, or AAD rewrite) throws here — never returns garbage.
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(envelope.ciphertext, "base64")),
    decipher.final(),
  ]);
  return plaintext.toString("utf8");
}

/** Constant-time-ish check that a candidate string looks like a vault envelope.
 *  Exposed for callers that want to log/branch without keeping the prefix. */
export const CREDENTIAL_VAULT_PREFIX = VAULT_PREFIX;
export const CREDENTIAL_VAULT_KEK_LENGTH = KEK_LENGTH_BYTES;
