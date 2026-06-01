import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createAuthAuditLogger, verifyLine, type AuthAuditLogger } from "./auth-audit-log.js";

describe("auth audit log HMAC", () => {
  const TEST_TOKEN = "test-hmac-secret-key-1234567890";
  let testDir: string;
  let logger: AuthAuditLogger;

  afterEach(async () => {
    if (testDir) {
      await rm(testDir, { recursive: true, force: true });
    }
  });

  function makeTestDir(): string {
    testDir = path.join(
      tmpdir(),
      `auth-audit-hmac-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    return testDir;
  }

  // --- Lines written without token have no `hmac` field ---

  it("writes lines without hmac field when no token is configured", async () => {
    const dir = makeTestDir();
    logger = createAuthAuditLogger({ logDir: dir });
    logger.log({ event: "auth_failure", clientIp: "10.0.0.1", reason: "bad_token" });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-auth.jsonl"), "utf-8");
    const entry = JSON.parse(content.trim());
    expect(entry.event).toBe("auth_failure");
    expect(entry.hmac).toBeUndefined();
  });

  // --- Lines written with token have `hmac` field ---

  it("writes lines with hmac field when token is configured", async () => {
    const dir = makeTestDir();
    logger = createAuthAuditLogger({ logDir: dir, token: TEST_TOKEN });
    logger.log({ event: "auth_failure", clientIp: "10.0.0.1", reason: "bad_token" });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-auth.jsonl"), "utf-8");
    const entry = JSON.parse(content.trim());
    expect(entry.event).toBe("auth_failure");
    expect(entry.hmac).toBeDefined();
    expect(typeof entry.hmac).toBe("string");
    expect(entry.hmac).toHaveLength(64); // SHA-256 hex = 64 chars
  });

  // --- verifyLine returns valid for authentic lines ---

  it("verifies authentic lines as valid", async () => {
    const dir = makeTestDir();
    logger = createAuthAuditLogger({ logDir: dir, token: TEST_TOKEN });
    logger.log({ event: "auth_success", clientIp: "10.0.0.2", method: "token" });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-auth.jsonl"), "utf-8");
    const rawLine = content.trim();

    const result = verifyLine(rawLine, TEST_TOKEN);
    expect(result.valid).toBe(true);
    expect(result.entry).toBeDefined();
    expect(result.entry!.event).toBe("auth_success");
  });

  // --- verifyLine returns invalid for tampered lines ---

  it("rejects tampered lines", async () => {
    const dir = makeTestDir();
    logger = createAuthAuditLogger({ logDir: dir, token: TEST_TOKEN });
    logger.log({ event: "auth_failure", clientIp: "10.0.0.3", reason: "expired" });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-auth.jsonl"), "utf-8");
    const tampered = content.trim().replace("auth_failure", "auth_success");

    const result = verifyLine(tampered, TEST_TOKEN);
    expect(result.valid).toBe(false);
    expect(result.entry).toBeUndefined();
  });

  // --- verifyLine returns invalid for lines without hmac when token is expected ---

  it("rejects unsigned lines when token is expected", () => {
    const unsignedLine = JSON.stringify({
      ts: "2025-01-01T00:00:00.000Z",
      event: "auth_success",
      clientIp: "10.0.0.4",
    });

    const result = verifyLine(unsignedLine, TEST_TOKEN);
    expect(result.valid).toBe(false);
  });

  // --- Backward compat: entries without hmac are parsed when no token provided ---

  it("accepts unsigned lines when no token is provided", () => {
    const unsignedLine = JSON.stringify({
      ts: "2025-01-01T00:00:00.000Z",
      event: "auth_failure",
      clientIp: "10.0.0.5",
      reason: "invalid",
    });

    const result = verifyLine(unsignedLine, "");
    expect(result.valid).toBe(true);
    expect(result.entry).toBeDefined();
    expect(result.entry!.event).toBe("auth_failure");
  });

  // --- verifyLine rejects malformed JSON ---

  it("rejects malformed JSON lines", () => {
    const result = verifyLine("not valid json{}", TEST_TOKEN);
    expect(result.valid).toBe(false);
  });

  // --- actorId field is written through ---

  it("writes actorId field when provided", async () => {
    const dir = makeTestDir();
    logger = createAuthAuditLogger({ logDir: dir, token: TEST_TOKEN });
    logger.log({ event: "auth_success", clientIp: "10.0.0.6", actorId: "device-abc-123" });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-auth.jsonl"), "utf-8");
    const result = verifyLine(content.trim(), TEST_TOKEN);
    expect(result.valid).toBe(true);
    expect(result.entry!.actorId).toBe("device-abc-123");
  });

  // --- HMAC is the last field in the JSON line ---

  it("places hmac as the last field in the serialized line", async () => {
    const dir = makeTestDir();
    logger = createAuthAuditLogger({ logDir: dir, token: TEST_TOKEN });
    logger.log({ event: "auth_failure", reason: "test" });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-auth.jsonl"), "utf-8");
    const rawLine = content.trim();

    // The line should end with ,"hmac":"<hex>"}
    const suffixMatch = rawLine.match(/,"hmac":"[0-9a-f]+"}$/);
    expect(suffixMatch).not.toBeNull();
  });
});
