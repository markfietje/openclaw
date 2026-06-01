import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const SEALED_PREFIX = "openclaw-sealed-json-v1:";
const FILE_MODE = 0o600;

const ENV_KEY = "OPENCLAW_PASSPHRASE";

// ── Envelope types ──────────────────────────────────────────────────────────

type SealedEnvelope = {
  readonly v: 1;
  readonly alg: "aes-256-gcm";
  readonly salt: string;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
};

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

// ── Helpers ─────────────────────────────────────────────────────────────────

function getPassphrase(env: NodeJS.ProcessEnv): string | undefined {
  return env[ENV_KEY]?.trim() || undefined;
}

function deriveKey(passphrase: string, salt: Buffer): Buffer {
  return scryptSync(passphrase, salt, 32, { N: 16384 });
}

function encryptJson(data: unknown, passphrase: string): string {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(passphrase, salt);
  const plaintext = Buffer.from(JSON.stringify(data), "utf8");

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  const envelope: SealedEnvelope = {
    v: 1,
    alg: "aes-256-gcm",
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
  if (obj.v !== 1 || obj.alg !== "aes-256-gcm") {
    return null;
  }

  return {
    v: 1,
    alg: "aes-256-gcm",
    salt: obj.salt as string,
    iv: obj.iv as string,
    tag: obj.tag as string,
    ciphertext: obj.ciphertext as string,
  };
}

function decryptEnvelope(envelope: SealedEnvelope, passphrase: string): unknown {
  const salt = Buffer.from(envelope.salt, "base64");
  const iv = Buffer.from(envelope.iv, "base64");
  const tag = Buffer.from(envelope.tag, "base64");
  const ciphertext = Buffer.from(envelope.ciphertext, "base64");
  const key = deriveKey(passphrase, salt);

  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
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

  if (envelope === null) {
    return JSON.parse(raw) as unknown;
  }

  const env = options?.env ?? process.env;
  const passphrase = getPassphrase(env);

  if (!passphrase) {
    throw new SealedJsonPassphraseRequiredError(filePath);
  }

  return decryptEnvelope(envelope, passphrase);
}
