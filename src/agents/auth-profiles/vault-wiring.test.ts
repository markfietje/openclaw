/**
 * Wiring tests: prove the credential vault is actually connected to the
 * auth-profile SQLite store chokepoint. These tests write/read a real store
 * through writePersistedAuthProfileStoreRaw / readPersistedAuthProfileStoreRaw
 * and assert the on-disk cell carries the v3 vault envelope when a KEK is
 * configured, that reads round-trip, and that the fail-closed tamper policy
 * holds at the integration boundary.
 *
 * To avoid leaking KEK state to unrelated test files in the same vitest worker,
 * these tests drive the seam through `setAuthProfileVaultCacheForTesting` with a
 * fully-controlled env rather than mutating `process.env`.
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { CREDENTIAL_VAULT_PREFIX } from "@openclaw/gateway-security-core/credential-vault";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  readPersistedAuthProfileStoreRaw,
  resolveAuthProfileDatabasePath,
  writePersistedAuthProfileStoreRaw,
} from "./sqlite.js";
import { setAuthProfileVaultCacheForTesting } from "./vault-seam.js";

const TEST_KEK_HEX = "0123456789abcdef".repeat(4); // 64 hex chars = 32 bytes

describe("auth-profile credential vault wiring", () => {
  let agentDir: string;
  let restoreCache: () => void;

  beforeEach(() => {
    agentDir = fs.mkdtempSync(path.join(os.tmpdir(), "openclaw-vault-wire-"));
    restoreCache = () => {};
  });

  afterEach(() => {
    restoreCache();
    fs.rmSync(agentDir, { recursive: true, force: true });
  });

  /** Install a vault cache backed by `env` for the duration of the test. */
  function withVaultEnv(env: Record<string, string | undefined>): void {
    restoreCache();
    restoreCache = setAuthProfileVaultCacheForTesting(env);
  }

  it("writes a sealed envelope to the store_json cell when a KEK is configured", () => {
    withVaultEnv({ OPENCLAW_CREDENTIAL_VAULT_KEY: TEST_KEK_HEX });
    const payload = { profiles: [{ id: "p1", provider: "openai", apiKey: "sk-test" }] };

    writePersistedAuthProfileStoreRaw(payload, agentDir);

    // Read the raw cell directly from SQLite to prove it is sealed on disk,
    // not just that the in-memory read round-trips.
    const cell = readRawStoreCell(agentDir);
    expect(cell.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(true);
    expect(cell).not.toContain("sk-test"); // plaintext credential must not appear on disk
  });

  it("reads a sealed store back as the original payload", () => {
    withVaultEnv({ OPENCLAW_CREDENTIAL_VAULT_KEY: TEST_KEK_HEX });
    const payload = {
      profiles: [
        { id: "openai-default", provider: "openai", apiKey: "sk-proj-abc" },
        {
          id: "anthropic-default",
          provider: "anthropic",
          oauth: { access: "ya29.x", refresh: "rt.y", expiresAt: 1764555200000 },
        },
      ],
    };

    writePersistedAuthProfileStoreRaw(payload, agentDir);
    const loaded = readPersistedAuthProfileStoreRaw(agentDir);

    expect(loaded).toEqual(payload);
  });

  it("writes plaintext JSON when no KEK is configured (default, opt-in)", () => {
    withVaultEnv({});
    const payload = { profiles: [{ id: "p1", provider: "openai", apiKey: "sk-plain" }] };

    writePersistedAuthProfileStoreRaw(payload, agentDir);

    const cell = readRawStoreCell(agentDir);
    expect(cell.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(false);
    expect(cell).toContain("sk-plain");
    expect(readPersistedAuthProfileStoreRaw(agentDir)).toEqual(payload);
  });

  it("fails closed when a KEK is configured but the cell is plaintext (downgrade)", () => {
    // First write plaintext (no KEK), then configure a KEK and attempt to read.
    withVaultEnv({});
    writePersistedAuthProfileStoreRaw(
      { profiles: [{ id: "p1", provider: "openai", apiKey: "sk-x" }] },
      agentDir,
    );

    withVaultEnv({ OPENCLAW_CREDENTIAL_VAULT_KEY: TEST_KEK_HEX });
    expect(() => readPersistedAuthProfileStoreRaw(agentDir)).toThrow();
  });

  it("produces a different on-disk ciphertext for identical payloads (random IV)", () => {
    withVaultEnv({ OPENCLAW_CREDENTIAL_VAULT_KEY: TEST_KEK_HEX });
    const payload = { profiles: [{ id: "p1", apiKey: "k" }] };

    writePersistedAuthProfileStoreRaw(payload, agentDir);
    const firstCell = readRawStoreCell(agentDir);

    writePersistedAuthProfileStoreRaw(payload, agentDir);
    const secondCell = readRawStoreCell(agentDir);

    expect(firstCell).not.toBe(secondCell);
    expect(firstCell.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(true);
    expect(secondCell.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(true);
    // Both still decrypt to the same payload.
    expect(readPersistedAuthProfileStoreRaw(agentDir)).toEqual(payload);
  });
});

/** Read the raw store_json cell straight from the SQLite file, bypassing the
 *  vault open path, so the test can inspect what is actually on disk. */
function readRawStoreCell(agentDir: string): string {
  const dbPath = resolveAuthProfileDatabasePath(agentDir);
  expect(fs.existsSync(dbPath)).toBe(true);
  return execFileSync(
    "sqlite3",
    [dbPath, "SELECT store_json FROM auth_profile_store WHERE store_key = 'primary';"],
    { encoding: "utf8" },
  );
}
