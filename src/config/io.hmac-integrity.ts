import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync, statSync } from "node:fs";
import { readFile, writeFile, stat } from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "./paths.js";

const GATEWAY_TOKEN_FILENAME = "gateway.token";

/**
 * Read the gateway token from disk (~/.openclaw/gateway.token),
 * falling back to the OPENCLAW_GATEWAY_TOKEN env var.
 *
 * Intentionally uncached — fresh read on every call so token rotation
 * takes effect without a process restart.
 */
export function readGatewayToken(env: NodeJS.ProcessEnv = process.env): string | null {
  try {
    const stateDir = resolveStateDir(env);
    const tokenPath = path.join(stateDir, GATEWAY_TOKEN_FILENAME);
    const raw = readFileSync(tokenPath, "utf-8").trim();
    if (raw.length > 0) {
      return raw;
    }
  } catch {
    // File missing or unreadable — fall through to env var.
  }

  const envToken = env.OPENCLAW_GATEWAY_TOKEN?.trim();
  if (envToken && envToken.length > 0) {
    return envToken;
  }

  return null;
}

/** Compute an HMAC-SHA256 hex digest of `content` using `token` as the key. */
export function computeConfigHmac(content: string, token: string): string {
  return createHmac("sha256", token).update(content).digest("hex");
}

/** Async: write the HMAC signature to `${configPath}.sig`. */
export async function writeConfigHmacSig(
  configPath: string,
  content: string,
  token: string,
): Promise<void> {
  const sig = computeConfigHmac(content, token);
  await writeFile(`${configPath}.sig`, sig, "utf-8");
}

/** Sync: write the HMAC signature to `${configPath}.sig`. */
export function writeConfigHmacSigSync(configPath: string, content: string, token: string): void {
  const sig = computeConfigHmac(content, token);
  writeFileSync(`${configPath}.sig`, sig, "utf-8");
}

export type HmacVerifyResult =
  | { ok: true }
  | { ok: false; kind: "no_token" }
  | { ok: false; kind: "no_sig"; suspicious: boolean }
  | { ok: false; kind: "mismatch" }
  | { ok: false; kind: "error"; error: Error };

const SUSPICIOUS_SIZE_THRESHOLD = 100;

/**
 * Async: verify that the HMAC signature on disk matches the config content.
 *
 * - Returns `{ ok: false, kind: "no_token" }` when no gateway token is available.
 * - Returns `{ ok: false, kind: "no_sig", suspicious }` when the `.sig` file is
 *   missing. `suspicious` is `true` when the config file is > 100 bytes,
 *   suggesting a possible signature-deletion attack.
 * - Returns `{ ok: false, kind: "mismatch" }` when the HMAC does not match.
 * - Returns `{ ok: false, kind: "error", error }` on unexpected errors.
 */
export async function verifyConfigHmac(
  configPath: string,
  content: string,
): Promise<HmacVerifyResult> {
  try {
    const token = readGatewayToken();
    if (token === null) {
      return { ok: false, kind: "no_token" };
    }

    const expected = computeConfigHmac(content, token);

    let sigOnDisk: string;
    try {
      sigOnDisk = await readFile(`${configPath}.sig`, "utf-8");
    } catch {
      // Determine if the missing sig is suspicious by checking config file size.
      let suspicious = false;
      try {
        const fileStat = await stat(configPath);
        suspicious = fileStat.size > SUSPICIOUS_SIZE_THRESHOLD;
      } catch {
        // Config file itself missing — not suspicious, just uninitialized.
      }
      return { ok: false, kind: "no_sig", suspicious };
    }

    const expectedBuf = Buffer.from(expected, "utf-8");
    const actualBuf = Buffer.from(sigOnDisk.trim(), "utf-8");

    if (expectedBuf.length !== actualBuf.length) {
      return { ok: false, kind: "mismatch" };
    }

    if (!timingSafeEqual(expectedBuf, actualBuf)) {
      return { ok: false, kind: "mismatch" };
    }

    return { ok: true };
  } catch (err: unknown) {
    const error =
      err instanceof Error ? err : new Error(typeof err === "string" ? err : "Unknown error");
    return { ok: false, kind: "error", error };
  }
}

/** Sync: verify that the HMAC signature on disk matches the config content. */
export function verifyConfigHmacSync(configPath: string, content: string): HmacVerifyResult {
  try {
    const token = readGatewayToken();
    if (token === null) {
      return { ok: false, kind: "no_token" };
    }

    const expected = computeConfigHmac(content, token);

    let sigOnDisk: string;
    try {
      sigOnDisk = readFileSync(`${configPath}.sig`, "utf-8");
    } catch {
      // Determine if the missing sig is suspicious by checking config file size.
      let suspicious = false;
      try {
        suspicious = statSync(configPath).size > SUSPICIOUS_SIZE_THRESHOLD;
      } catch {
        // Config file itself missing — not suspicious, just uninitialized.
      }
      return { ok: false, kind: "no_sig", suspicious };
    }

    const expectedBuf = Buffer.from(expected, "utf-8");
    const actualBuf = Buffer.from(sigOnDisk.trim(), "utf-8");

    if (expectedBuf.length !== actualBuf.length) {
      return { ok: false, kind: "mismatch" };
    }

    if (!timingSafeEqual(expectedBuf, actualBuf)) {
      return { ok: false, kind: "mismatch" };
    }

    return { ok: true };
  } catch (err: unknown) {
    const error =
      err instanceof Error ? err : new Error(typeof err === "string" ? err : "Unknown error");
    return { ok: false, kind: "error", error };
  }
}
