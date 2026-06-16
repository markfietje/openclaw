import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  computeConfigHmac,
  verifyConfigHmacSync,
  writeConfigHmacSigSync,
} from "./io.hmac-integrity.js";

const TOKEN = "test-hmac-token-1234567890";
const CONTENT = '{"gateway":{"auth":{"mode":"token"}}}';

describe("config HMAC integrity", () => {
  let testDir: string;
  let originalEnvToken: string | undefined;

  beforeEach(() => {
    originalEnvToken = process.env.OPENCLAW_GATEWAY_TOKEN;
    process.env.OPENCLAW_GATEWAY_TOKEN = TOKEN;
  });

  afterEach(() => {
    if (originalEnvToken !== undefined) {
      process.env.OPENCLAW_GATEWAY_TOKEN = originalEnvToken;
    } else {
      delete process.env.OPENCLAW_GATEWAY_TOKEN;
    }
    if (testDir) {
      rmSync(testDir, { recursive: true, force: true });
    }
  });

  function makeTestDir(): string {
    testDir = path.join(tmpdir(), `hmac-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    mkdirSync(testDir, { recursive: true });
    return testDir;
  }

  describe("computeConfigHmac", () => {
    it("produces a deterministic hex digest", () => {
      const a = computeConfigHmac(CONTENT, TOKEN);
      const b = computeConfigHmac(CONTENT, TOKEN);
      expect(a).toBe(b);
      expect(a).toMatch(/^[0-9a-f]{64}$/);
    });

    it("produces different digests for different content", () => {
      expect(computeConfigHmac(CONTENT, TOKEN)).not.toBe(computeConfigHmac(CONTENT + "x", TOKEN));
    });

    it("produces different digests for different tokens", () => {
      expect(computeConfigHmac(CONTENT, TOKEN)).not.toBe(computeConfigHmac(CONTENT, "other-token"));
    });
  });

  describe("writeConfigHmacSigSync / verifyConfigHmacSync round-trip", () => {
    it("verifies a valid signature", () => {
      const dir = makeTestDir();
      const configPath = path.join(dir, "openclaw.json");
      writeFileSync(configPath, CONTENT, "utf-8");
      writeConfigHmacSigSync(configPath, CONTENT, TOKEN);

      const result = verifyConfigHmacSync(configPath, CONTENT);
      expect(result).toEqual({ ok: true });
    });

    it("detects tampered content", () => {
      const dir = makeTestDir();
      const configPath = path.join(dir, "openclaw.json");
      writeFileSync(configPath, CONTENT, "utf-8");
      writeConfigHmacSigSync(configPath, CONTENT, TOKEN);

      const result = verifyConfigHmacSync(configPath, CONTENT + "tampered");
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe("mismatch");
      }
    });

    // G2: a malformed (non-hex / wrong-length) signature must be rejected as a
    // mismatch without leaking length via timingSafeEqual, mirroring audit-log.
    it("rejects malformed signatures as mismatch", () => {
      const dir = makeTestDir();
      const configPath = path.join(dir, "openclaw.json");
      writeFileSync(configPath, CONTENT, "utf-8");
      writeFileSync(`${configPath}.sig`, "not-a-valid-hex-signature", "utf-8");

      const result = verifyConfigHmacSync(configPath, CONTENT);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe("mismatch");
      }
    });

    it("detects missing signature file as suspicious for large configs", () => {
      const dir = makeTestDir();
      const configPath = path.join(dir, "openclaw.json");
      const largeContent = JSON.stringify({
        gateway: { auth: { mode: "token", value: "x".repeat(200) } },
      });
      writeFileSync(configPath, largeContent, "utf-8");

      const result = verifyConfigHmacSync(configPath, largeContent);
      expect(result.ok).toBe(false);
      if (!result.ok && result.kind === "no_sig") {
        expect(result.suspicious).toBe(true);
      }
    });

    it("detects missing signature file as not suspicious for small configs", () => {
      const dir = makeTestDir();
      const configPath = path.join(dir, "openclaw.json");
      writeFileSync(configPath, CONTENT, "utf-8");

      const result = verifyConfigHmacSync(configPath, CONTENT);
      expect(result.ok).toBe(false);
      if (!result.ok && result.kind === "no_sig") {
        expect(result.suspicious).toBe(false);
      }
    });

    it("returns no_token when no gateway token available", () => {
      const dir = makeTestDir();
      const configPath = path.join(dir, "openclaw.json");
      writeFileSync(configPath, CONTENT, "utf-8");

      delete process.env.OPENCLAW_GATEWAY_TOKEN;

      const result = verifyConfigHmacSync(configPath, CONTENT);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.kind).toBe("no_token");
      }
    });
  });
});
