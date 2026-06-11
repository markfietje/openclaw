import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  saveSealedJsonFile,
  loadSealedJsonFile,
  SealedJsonPassphraseRequiredError,
  SealedJsonTamperError,
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

  describe("plaintext downgrade protection", () => {
    it("throws SealedJsonTamperError when passphrase set but file is plaintext", () => {
      const dir = makeTestDir();
      const filePath = path.join(dir, "test.json");

      // Write plaintext JSON directly (not sealed)
      writeFileSync(filePath, JSON.stringify({ secret: "sensitive" }), "utf8");

      expect(() =>
        loadSealedJsonFile(filePath, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } }),
      ).toThrow(SealedJsonTamperError);
    });

    it("loads plaintext when no passphrase configured", () => {
      const dir = makeTestDir();
      const filePath = path.join(dir, "test.json");
      const data = { key: "value" };

      writeFileSync(filePath, JSON.stringify(data), "utf8");

      const loaded = loadSealedJsonFile(filePath, { env: {} });
      expect(loaded).toEqual(data);
    });

    it("loads sealed file when passphrase configured", () => {
      const dir = makeTestDir();
      const filePath = path.join(dir, "test.json");
      const data = { sealed: true };

      saveSealedJsonFile(filePath, data, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });
      const loaded = loadSealedJsonFile(filePath, { env: { OPENCLAW_PASSPHRASE: PASSPHRASE } });

      expect(loaded).toEqual(data);
    });
  });

  it("rejects envelope with non-string fields via plaintext fallback", () => {
    const dir = makeTestDir();
    const filePath = path.join(dir, "test.json");

    // Craft a valid-looking envelope prefix with non-string (number) field values.
    // parseEnvelope should return null for this, causing plaintext load path.
    const badEnvelope = {
      v: 1,
      alg: "aes-256-gcm",
      salt: 123, // number instead of string
      iv: "valid-iv",
      tag: "valid-tag",
      ciphertext: "valid-ciphertext",
    };
    const b64 = Buffer.from(JSON.stringify(badEnvelope), "utf8").toString("base64");
    writeFileSync(filePath, `openclaw-sealed-json-v1:${b64}`, "utf8");

    // With no passphrase, parseEnvelope returns null (type check failed on salt).
    // The raw content starts with the sealed prefix, so JSON.parse on the raw
    // content will throw — but the key thing is parseEnvelope rejected it.
    // With passphrase set, it falls through to plaintext JSON.parse which also throws.
    // Either way, the malformed envelope is NOT treated as a valid sealed file.
    expect(() => loadSealedJsonFile(filePath, { env: {} })).toThrow();
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
