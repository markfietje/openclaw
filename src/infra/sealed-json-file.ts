import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SEALED_PREFIX = "openclaw-sealed-json-v1:";
const FILE_MODE = 0o600;

const ENV_KEY = "OPENCLAW_PASSPHRASE";

// Envelope version this code writes. v2 binds `v`+`alg` as AES-GCM AAD so the
// ciphertext is cryptographically tied to the envelope shape. v1 envelopes
// (written by older code, no AAD) are still accepted on read for compatibility.
const CURRENT_SEALED_VERSION = 2 as const;

// ── Envelope types ──────────────────────────────────────────────────────────

type SealedEnvelope = {
  readonly v: 1 | 2;
  readonly alg: "aes-256-gcm";
  readonly salt: string;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
};

/** Build the AES-GCM AAD that binds the envelope version + algorithm to the
 *  ciphertext, preventing silent downgrade or alg swaps (OWASP A02). */
function envelopeAad(v: number, alg: string): Buffer {
  return Buffer.from(`${v}:${alg}`, "utf8");
}

// ── Error ───────────────────────────────────────────────────────────────────

export class SealedJsonPassphraseRequiredError extends Error {
  public readonly filePath: string;

  constructor(filePath: string) {
    super(
      `File ${filePath} is sealed but ${ENV_KEY} is not set. ` +
        "Set the passphrase environment variable to decrypt.",
    );
    this.name = "SealedJsonPassphraseRequiredError";
    this.filePath = filePath;
  }
}

export class SealedJsonTamperError extends Error {
  public readonly filePath: string;

  constructor(filePath: string) {
    super(
      `File ${filePath} is not sealed but ${ENV_KEY} is configured. ` +
        "The file may have been tampered with or replaced with plaintext.",
    );
    this.name = "SealedJsonTamperError";
    this.filePath = filePath;
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function getPassphrase(env: NodeJS.ProcessEnv): string | undefined {
  return env[ENV_KEY]?.trim() || undefined;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, { N: 131072, maxmem: 128 * 131072 * 8 * 2 });
}

function encryptJson(data: unknown, passphrase: string): string {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");

  const alg = "aes-256-gcm";
  const cipher = createCipheriv(alg, key, iv);
  // v2 binds the envelope version + algorithm into the GCM auth tag so the
  // ciphertext cannot be replayed under a different v/alg.
  cipher.setAAD(envelopeAad(CURRENT_SEALED_VERSION, alg));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope: SealedEnvelope = {
    v: CURRENT_SEALED_VERSION,
    alg,
    salt: salt.toString("base64"),
    iv: iv.toString("base64"),
    tag: tag.toString("base64"),
    ciphertext: ciphertext.toString("base64"),
  };

  return SEALED_PREFIX + Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
}

function parseEnvelope(raw: string): SealedEnvelope | null {
  if (!raw.startsWith(SEALED_PREFIX)) {
    return null;
  }

  const b64 = raw.slice(SEALED_PREFIX.length);
  let json: unknown;
  try {
    json = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  } catch {
    return null;
  }

  if (
    typeof json !== "object" ||
    json === null ||
    !("v" in json) ||
    !("alg" in json) ||
    !("salt" in json) ||
    !("iv" in json) ||
    !("tag" in json) ||
    !("ciphertext" in json)
  ) {
    return null;
  }

  const obj = json as Record<string, unknown>;
  if ((obj.v !== 1 && obj.v !== 2) || obj.alg !== "aes-256-gcm") {
    return null;
  }

  if (
    typeof obj.salt !== "string" ||
    typeof obj.iv !== "string" ||
    typeof obj.tag !== "string" ||
    typeof obj.ciphertext !== "string"
  ) {
    return null;
  }

  return {
    v: obj.v,
    alg: "aes-256-gcm",
    salt: obj.salt,
    iv: obj.iv,
    tag: obj.tag,
    ciphertext: obj.ciphertext,
  };
}

function decryptEnvelope(envelope: SealedEnvelope, passphrase: string): unknown {
  const salt = Buffer.from(envelope.salt, "base64");
  const iv = Buffer.from(envelope.iv, "base64");
  const tag = Buffer.from(envelope.tag, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const key = deriveKey(passphrase, salt);

  const decipher = createDecipheriv(envelope.alg, key, iv);
  decipher.setAuthTag(tag);
  // v1 predates AAD binding and must decrypt without it; v2+ reproduces the
  // same `v:alg` AAD used at seal time or the GCM auth tag check fails.
  if (envelope.v >= 2) {
    decipher.setAAD(envelopeAad(envelope.v, envelope.alg));
  }
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

  return JSON.parse(plaintext.toString("utf8")) as unknown;
}

function trySetSecureMode(filePath: string): void {
  try {
    fs.chmodSync(filePath, FILE_MODE);
  } catch {
    // best-effort on platforms without chmod support
  }
}

function ensureParentDir(filePath: string): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
}

function isMissingFileError(err: unknown): boolean {
  return (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    (err as { code?: unknown }).code === "ENOENT"
  );
}
// ── Public API ──────────────────────────────────────────────────────────────

export type SealedJsonFileOptions = {
  readonly env?: NodeJS.ProcessEnv;
};

export function saveSealedJsonFile(
  filePath: string,
  data: unknown,
  options?: SealedJsonFileOptions,
): void {
  const env = options?.env ?? process.env;
  const passphrase = getPassphrase(env);

  const payload = passphrase ? encryptJson(data, passphrase) : `${JSON.stringify(data, null, 2)}\n`;

  ensureParentDir(filePath);
  fs.writeFileSync(filePath, payload, "utf8");
  trySetSecureMode(filePath);
}

export function loadSealedJsonFile(filePath: string, options?: SealedJsonFileOptions): unknown {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (err) {
    if (isMissingFileError(err)) {
      return undefined;
    }
    throw err;
  }
  const envelope = parseEnvelope(raw);
  const env = options?.env ?? process.env;
  const passphrase = getPassphrase(env);

  if (envelope === null) {
    // No passphrase configured — plaintext is the expected format.
    if (!passphrase) {
      return JSON.parse(raw) as unknown;
    }
    // Passphrase IS configured but file is plaintext — tamper or downgrade.
    // OWASP A04:2025 — Cryptographic Failures.
    throw new SealedJsonTamperError(filePath);
  }

  if (!passphrase) {
    throw new SealedJsonPassphraseRequiredError(filePath);
  }

  return decryptEnvelope(envelope, passphrase);
}
