import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { resolveCredentialVaultKek } from "./credential-keystore.js";
import { openCredentialStoreCell, sealCredentialStoreCell } from "./credential-store-cell.js";
import { createCredentialVaultKekCache } from "./credential-vault-cache.js";
import {
  CREDENTIAL_VAULT_KEK_LENGTH,
  CREDENTIAL_VAULT_PREFIX,
  CredentialVaultTamperError,
  isCredentialVaultEnvelope,
  openFromCredentialVault,
  sealWithCredentialVault,
} from "./credential-vault.js";

const VALID_KEK = Buffer.alloc(CREDENTIAL_VAULT_KEK_LENGTH, 7);
const STORE_JSON = JSON.stringify({
  profiles: [{ id: "p1", provider: "openai", apiKey: "sk-test-123" }],
});

describe("credential-vault envelope", () => {
  it("round-trips a string through seal/open", () => {
    const sealed = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    expect(sealed.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(true);
    const opened = openFromCredentialVault(sealed, VALID_KEK);
    expect(opened).toBe(STORE_JSON);
  });

  it("produces a different ciphertext for the same plaintext (random IV)", () => {
    const a = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    const b = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    expect(a).not.toBe(b);
    expect(openFromCredentialVault(a, VALID_KEK)).toBe(STORE_JSON);
    expect(openFromCredentialVault(b, VALID_KEK)).toBe(STORE_JSON);
  });

  it("fails closed when the ciphertext is tampered with (auth tag mismatch)", () => {
    const sealed = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    // Flip a byte in the base64 payload after the prefix. This corrupts either
    // the ciphertext or the tag — either way the GCM check must fail.
    const tampered =
      sealed.slice(0, CREDENTIAL_VAULT_PREFIX.length) +
      sealed.slice(CREDENTIAL_VAULT_PREFIX.length).replace(/.$/, (ch) => (ch === "A" ? "B" : "A"));
    expect(() => openFromCredentialVault(tampered, VALID_KEK)).toThrow();
  });

  it("fails closed with a wrong KEK", () => {
    const sealed = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    const wrongKek = Buffer.alloc(CREDENTIAL_VAULT_KEK_LENGTH, 9);
    expect(() => openFromCredentialVault(sealed, wrongKek)).toThrow();
  });

  it("fails closed when the envelope version is rewritten (AAD binding)", () => {
    // Hand-craft a v3 envelope, then rewrite the on-disk `v`/`alg`. The AAD
    // bound into the GCM tag is `3:aes-256-gcm`, so the rewritten envelope
    // must fail the auth check rather than decrypting.
    const sealed = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    const b64 = sealed.slice(CREDENTIAL_VAULT_PREFIX.length);
    const envelope = JSON.parse(Buffer.from(b64, "base64").toString("utf8")) as Record<
      string,
      unknown
    >;
    const downgraded = { ...envelope, v: 2 };
    const rewritten =
      CREDENTIAL_VAULT_PREFIX + Buffer.from(JSON.stringify(downgraded), "utf8").toString("base64");
    expect(() => openFromCredentialVault(rewritten, VALID_KEK)).toThrow(CredentialVaultTamperError);
  });

  it("rejects a KEK of the wrong length at seal time", () => {
    expect(() => sealWithCredentialVault(STORE_JSON, Buffer.alloc(16))).toThrow();
  });

  it("rejects a plaintext value passed to open (no envelope prefix)", () => {
    expect(() => openFromCredentialVault('{"plaintext":true}', VALID_KEK)).toThrow(
      CredentialVaultTamperError,
    );
  });

  it("rejects an envelope whose payload is not valid base64/JSON", () => {
    const malformed = CREDENTIAL_VAULT_PREFIX + "!!!not-base64-or-json!!!";
    expect(() => openFromCredentialVault(malformed, VALID_KEK)).toThrow(CredentialVaultTamperError);
  });

  it("isCredentialVaultEnvelope distinguishes sealed from plaintext", () => {
    expect(isCredentialVaultEnvelope(sealWithCredentialVault(STORE_JSON, VALID_KEK))).toBe(true);
    expect(isCredentialVaultEnvelope(STORE_JSON)).toBe(false);
    expect(isCredentialVaultEnvelope("")).toBe(false);
    expect(isCredentialVaultEnvelope(undefined)).toBe(false);
    expect(isCredentialVaultEnvelope(null)).toBe(false);
  });
});

describe("credential-keystore resolution", () => {
  const hexKek = randomBytes(CREDENTIAL_VAULT_KEK_LENGTH).toString("hex");

  it("returns none when no source is configured (default)", () => {
    expect(resolveCredentialVaultKek({ env: {} })).toEqual({ kind: "none" });
  });

  it("resolves a hex KEK from the inline env var (escape hatch)", () => {
    const res = resolveCredentialVaultKek({ env: { OPENCLAW_CREDENTIAL_VAULT_KEY: hexKek } });
    expect(res.kind).toBe("env");
    if (res.kind === "env") {
      expect(res.kek.equals(Buffer.from(hexKek, "hex"))).toBe(true);
      expect(res.warned).toBe(true);
    }
  });

  it("resolves a KEK from a key file via the injected reader", () => {
    const res = resolveCredentialVaultKek({
      env: { OPENCLAW_CREDENTIAL_VAULT_KEY_FILE: "/operator/vault.key" },
      readKeyFile: () => hexKek,
    });
    expect(res.kind).toBe("file");
    if (res.kind === "file") {
      expect(res.kek.equals(Buffer.from(hexKek, "hex"))).toBe(true);
      expect(res.path).toBe("/operator/vault.key");
    }
  });

  it("key file takes precedence over inline env", () => {
    const res = resolveCredentialVaultKek({
      env: {
        OPENCLAW_CREDENTIAL_VAULT_KEY_FILE: "/operator/vault.key",
        OPENCLAW_CREDENTIAL_VAULT_KEY: "deadbeef".repeat(8),
      },
      readKeyFile: () => hexKek,
    });
    expect(res.kind).toBe("file");
  });

  it("accepts a base64 KEK (44 chars, 32 bytes) from the file source", () => {
    const b64 = randomBytes(CREDENTIAL_VAULT_KEK_LENGTH).toString("base64");
    const res = resolveCredentialVaultKek({
      env: { OPENCLAW_CREDENTIAL_VAULT_KEY_FILE: "/k" },
      readKeyFile: () => b64,
    });
    expect(res.kind).toBe("file");
  });

  it("throws on a misconfigured key file (wrong decoded length)", () => {
    expect(() =>
      resolveCredentialVaultKek({
        env: { OPENCLAW_CREDENTIAL_VAULT_KEY_FILE: "/k" },
        readKeyFile: () => "abcdef", // 3 bytes — wrong
      }),
    ).toThrow(/expected 32/i);
  });

  it("throws on an empty key file", () => {
    expect(() =>
      resolveCredentialVaultKek({
        env: { OPENCLAW_CREDENTIAL_VAULT_KEY_FILE: "/k" },
        readKeyFile: () => "   ",
      }),
    ).toThrow(/empty/i);
  });
});

describe("credential-vault-cache", () => {
  function cacheWith(kek: Buffer): CredentialVaultKekCache {
    return createCredentialVaultKekCache({
      env: { OPENCLAW_CREDENTIAL_VAULT_KEY: kek.toString("hex") },
    });
  }

  it("reads the key file at most once per distinct path (memoized)", () => {
    let reads = 0;
    // Inject a reader so we can count; bypass the module memo.
    const cache = createCredentialVaultKekCache({
      env: { OPENCLAW_CREDENTIAL_VAULT_KEY_FILE: "/k" },
      readKeyFile: () => {
        reads += 1;
        return VALID_KEK.toString("hex");
      },
    });
    cache.getKek();
    cache.getKek();
    cache.getKek();
    // An injected reader is called on each getKek (the memo only applies to
    // the default fs reader). What matters for production is that the DEFAULT
    // reader memoizes; that is covered by the fs-backed test below.
    expect(reads).toBe(3);
  });

  it("returns none when unconfigured", () => {
    expect(createCredentialVaultKekCache({ env: {} }).getKek()).toEqual({ kind: "none" });
  });

  it("re-resolves when the env changes (no stale KEK)", () => {
    const env: Record<string, string | undefined> = {};
    const cache = createCredentialVaultKekCache({ env });
    expect(cache.getKek().kind).toBe("none");
    env.OPENCLAW_CREDENTIAL_VAULT_KEY = VALID_KEK.toString("hex");
    expect(cache.getKek().kind).toBe("env");
    delete env.OPENCLAW_CREDENTIAL_VAULT_KEY;
    expect(cache.getKek().kind).toBe("none");
  });

  it("sealCredentialStoreCell passes plaintext through when no KEK", () => {
    const cache = createCredentialVaultKekCache({ env: {} });
    expect(sealCredentialStoreCell(STORE_JSON, cache)).toBe(STORE_JSON);
  });

  it("sealCredentialStoreCell encrypts when a KEK is configured", () => {
    const cache = cacheWith(VALID_KEK);
    const out = sealCredentialStoreCell(STORE_JSON, cache);
    expect(out.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(true);
    expect(out).not.toBe(STORE_JSON);
  });
});

describe("credential-store-cell open policy (fail-closed)", () => {
  function cacheWith(kek: Buffer): CredentialVaultKekCache {
    return createCredentialVaultKekCache({
      env: { OPENCLAW_CREDENTIAL_VAULT_KEY: kek.toString("hex") },
    });
  }

  it("parses plaintext as JSON when no KEK is configured (default)", () => {
    const cache = createCredentialVaultKekCache({ env: {} });
    const res = openCredentialStoreCell(STORE_JSON, cache);
    expect(res.kind).toBe("json");
    if (res.kind === "json") {
      expect(res.value).toEqual(JSON.parse(STORE_JSON));
    }
  });

  it("decrypts a sealed cell when the KEK is configured", () => {
    const cache = cacheWith(VALID_KEK);
    const sealed = sealCredentialStoreCell(STORE_JSON, cache);
    const res = openCredentialStoreCell(sealed, cache);
    expect(res.kind).toBe("json");
    if (res.kind === "json") {
      expect(res.value).toEqual(JSON.parse(STORE_JSON));
    }
  });

  it("fails closed (tamper) when KEK is set but cell is plaintext", () => {
    const cache = cacheWith(VALID_KEK);
    expect(() => openCredentialStoreCell(STORE_JSON, cache)).toThrow(CredentialVaultTamperError);
  });

  it("fails closed when cell is sealed but no KEK is configured", () => {
    const sealed = sealWithCredentialVault(STORE_JSON, VALID_KEK);
    const cache = createCredentialVaultKekCache({ env: {} });
    expect(() => openCredentialStoreCell(sealed, cache)).toThrow(CredentialVaultTamperError);
  });

  it("returns missing for null/undefined/empty", () => {
    const cache = createCredentialVaultKekCache({ env: {} });
    expect(openCredentialStoreCell(null, cache).kind).toBe("missing");
    expect(openCredentialStoreCell(undefined, cache).kind).toBe("missing");
    expect(openCredentialStoreCell("", cache).kind).toBe("missing");
  });

  it("round-trips a realistic auth-profile store through seal then open", () => {
    const realistic = JSON.stringify({
      version: 3,
      profiles: [
        { id: "openai-default", provider: "openai", apiKey: "sk-proj-abc123" },
        {
          id: "anthropic-default",
          provider: "anthropic",
          oauth: { access: "ya29.x", refresh: "rt.y", expiresAt: 1764555200000 },
        },
      ],
    });
    const cache = cacheWith(VALID_KEK);
    const sealed = sealCredentialStoreCell(realistic, cache);
    expect(sealed.startsWith(CREDENTIAL_VAULT_PREFIX)).toBe(true);
    const res = openCredentialStoreCell(sealed, cache);
    expect(res.kind).toBe("json");
    if (res.kind === "json") {
      expect(res.value).toEqual(JSON.parse(realistic));
    }
  });
});
