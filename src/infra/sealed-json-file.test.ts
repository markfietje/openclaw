import { mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  saveSealedJsonFile,
  loadSealedJsonFile,
  SealedJsonPassphraseRequiredError,
} from "./sealed-json-file.js";

describe("sealed-json-file", () => {
  let testDir: string;
  const PASSPHRASE = "test-passphrase-for-sealed-json";

  afterEach(() => {
    if (testDir) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  function makeTestDir(): string {
    testDir = path.join(
      tmpdir(),
      `sealed-json-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    mkdirSync(testDir, { recursive: true });
    return testDir;
  }

  it("round-trips JSON data with passphrase", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "test.json");
    const data = { key: "value", nested: { num: 42 } };

    saveSealedJsonFile(filePath, data, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });
    const loaded = loadSealedJsonFile(filePath, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });

    expect(loaded).toEqual(data);
  });

  it("round-trips without passphrase as plaintext JSON", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "test.json");
    const data = { plaintext: true };

    saveSealedJsonFile(filePath, data, { env: {} });
    const loaded = loadSealedJsonFile(filePath, { env: {} });

    expect(loaded).toEqual(data);
  });

  it("throws SealedJsonPassphraseRequiredError when passphrase missing", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "test.json");
    const data = { secret: "value" };

    saveSealedJsonFile(filePath, data, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });

    expect(() => loadSealedJsonFile(filePath, { env: {} })).toThrow(
      SealedJsonPassphraseRequiredError,
    );
  });

  it("returns undefined for missing file", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "nonexistent.json");

    expect(loadSealedJsonFile(filePath, { env: {} })).toBeUndefined();
  });

  it("fails decryption with wrong passphrase", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "test.json");
    const data = { sensitive: "data" };

    saveSealedJsonFile(filePath, data, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });

    expect(() =>
      loadSealedJsonFile(filePath, { env: { OPENCLAW_PASSPHRASE: "wrong-passphrase" } }),
    ).toThrow();
  });

  it("uses AES-256-GCM envelope format", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "test.json");

    saveSealedJsonFile(filePath, { test: true }, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });

    const raw = readFileSync(filePath, "utf-8");
    expect(raw).toMatch(/^openclaw-sealed-json-v1:/);

    const envelope = JSON.parse(
      Buffer.from(raw.slice("openclaw-sealed-json-v1:".length), "base64").toString("utf-8"),
    );
    expect(envelope.v).toBe(1);
    expect(envelope.alg).toBe("aes-256-gcm");
    expect(envelope.salt).toBeDefined();
    expect(envelope.iv).toBeDefined();
    expect(envelope.tag).toBeDefined();
    expect(envelope.ciphertext).toBeDefined();
  });
});
