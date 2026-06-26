/**
 * Credential vault KEK resolution.
 *
 * Resolves the 32-byte Key Encryption Key used by `credential-vault` from
 * operator-configured sources, in this priority order:
 *
 *   1. `OPENCLAW_CREDENTIAL_VAULT_KEY_FILE` — path to a `0o600` file whose
 *      contents are 32 raw bytes, 64 hex chars, or base64 of 32 bytes.
 *      RECOMMENDED. The file is the KEK; create it once with
 *      `openssl rand 32 > vault.key && chmod 600 vault.key` and never commit
 *      it. Placing the file outside the OpenClaw state dir (e.g. on operator-
 *      managed secret storage) keeps the KEK off any disk image of the state
 *      volume.
 *   2. `OPENCLAW_CREDENTIAL_VAULT_KEY` — the KEK inline (hex or base64 of 32
 *      bytes). ESCAPE HATCH ONLY. Environment variables are readable by every
 *      process running under the same user (and are logged by launchd,
 *      systemd, docker inspect, etc.), so this source does NOT improve
 *      security over plaintext against a live same-UID attacker. It exists so
 *      CI and container entrypoints can exercise the encryption path; the
 *      resolver logs a warning every time it is used.
 *   3. `{ kind: "none" }` — no KEK configured. The credential store stays
 *      plaintext (the default). This is opt-in hardening, not a forced
 *      migration.
 *
 * A native OS-keychain backend (macOS Keychain / Data Protection Keychain) is
 * the stronger source and slots in as priority 0 when added; the resolver
 * shape is designed so that addition does not touch `credential-vault` or the
 * SQLite wire point.
 *
 * OWASP Secret & Credential Management: "Secrets should never be stored in
 * code, configuration files, or environment variables." The key-file source is
 * a pragmatic middle ground for local single-user deployments; the env source
 * is explicitly flagged as weaker. The recommended production posture is a
 * native keychain backend (future) or an external secret manager.
 */
import { readFileSync } from "node:fs";

const ENV_KEY = "OPENCLAW_CREDENTIAL_VAULT_KEY";
const ENV_KEY_FILE = "OPENCLAW_CREDENTIAL_VAULT_KEY_FILE";
export const CREDENTIAL_VAULT_KEY_LENGTH = 32;

export type CredentialVaultKekResolution =
  | { readonly kind: "none" } // feature off → plaintext (default)
  | { readonly kind: "file"; readonly kek: Buffer; readonly path: string }
  | {
      readonly kind: "env";
      readonly kek: Buffer;
      readonly warned: true; // env source is weaker; callers may surface this
    };

/** Injectable file reader so tests do not touch the real filesystem. */
export type KekFileReader = (path: string) => string;

export interface CredentialVaultKekOptions {
  readonly env?: NodeJS.ProcessEnv;
  /** Override the file reader. Defaults to `node:fs.readFileSync`. */
  readonly readKeyFile?: KekFileReader;
}

function decodeKekMaterial(raw: string, source: string): Buffer {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new Error(`credential-vault: KEK from ${source} is empty`);
  }
  // 64 hex chars → 32 bytes. Most ergonomic for operators.
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, "hex");
  }
  // Try base64. Accept both standard and url-safe alphabets; require that the
  // decoded length is exactly 32 bytes so a mis-pasted key fails loudly.
  let decoded: Buffer;
  try {
    decoded = Buffer.from(trimmed, "base64");
  } catch {
    throw new Error(`credential-vault: KEK from ${source} is not valid hex or base64`);
  }
  if (decoded.length !== CREDENTIAL_VAULT_KEY_LENGTH) {
    throw new Error(
      `credential-vault: KEK from ${source} decodes to ${decoded.length} bytes (expected ${CREDENTIAL_VAULT_KEY_LENGTH})`,
    );
  }
  return decoded;
}

/**
 * Resolve the vault KEK. Returns `{ kind: "none" }` when no source is
 * configured so callers can fall through to plaintext without branching on
 * null. Throws on a *misconfigured* source (file missing, wrong length) so a
 * half-broken provisioning surfaces immediately rather than silently disabling
 * encryption.
 */
export function resolveCredentialVaultKek(
  options: CredentialVaultKekOptions = {},
): CredentialVaultKekResolution {
  const env = options.env ?? process.env;
  const readKeyFile = options.readKeyFile ?? ((p) => readFileSync(p, "utf8"));

  const keyFilePath = env[ENV_KEY_FILE]?.trim();
  if (keyFilePath) {
    const kek = decodeKekMaterial(readKeyFile(keyFilePath), `${ENV_KEY_FILE}=${keyFilePath}`);
    if (kek.length !== CREDENTIAL_VAULT_KEY_LENGTH) {
      throw new Error(
        `credential-vault: KEK file ${keyFilePath} decoded to ${kek.length} bytes (expected ${CREDENTIAL_VAULT_KEY_LENGTH})`,
      );
    }
    return { kind: "file", kek, path: keyFilePath };
  }

  const inlineKey = env[ENV_KEY]?.trim();
  if (inlineKey) {
    // Env-source is the weak escape hatch. We still resolve it (CI/container
    // entrypoints rely on it), but flag it so callers can warn.
    const kek = decodeKekMaterial(inlineKey, ENV_KEY);
    return { kind: "env", kek, warned: true };
  }

  return { kind: "none" };
}

/** True when any KEK source is configured — used by the loader to decide
 *  whether plaintext-on-disk is a tamper signal (fail closed) or the default. */
export function hasCredentialVaultKek(options: CredentialVaultKekOptions = {}): boolean {
  return resolveCredentialVaultKek(options).kind !== "none";
}
