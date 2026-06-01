import { readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createToolAuditLogger, verifyLine, type ToolAuditLogger } from "./tool-audit.js";

describe("tool audit logger", () => {
  let testDir: string;
  let logger: ToolAuditLogger;

  afterEach(async () => {
    if (testDir) {
      await rm(testDir, { recursive: true, force: true });
    }
  });

  function makeTestDir(): string {
    testDir = path.join(
      tmpdir(),
      `tool-audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    return testDir;
  }

  it("logs a tool.call entry and verify it appears in JSONL output", async () => {
    const dir = makeTestDir();
    logger = createToolAuditLogger({ logDir: dir });
    logger.log({
      event: "tool.call",
      surface: "tools-invoke",
      tool: "exec",
      actorId: "user-123",
      session: "agent:main:main",
      channel: "discord",
      model: "sonnet-4.6",
      runId: "run-abc",
      toolCallId: "tc-001",
    });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-tool-audit.jsonl"), "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(1);

    const entry = JSON.parse(lines[0]);
    expect(entry.event).toBe("tool.call");
    expect(entry.source).toBe("gateway");
    expect(entry.surface).toBe("tools-invoke");
    expect(entry.tool).toBe("exec");
    expect(entry.actorId).toBe("user-123");
    expect(entry.session).toBe("agent:main:main");
    expect(entry.channel).toBe("discord");
    expect(entry.model).toBe("sonnet-4.6");
    expect(entry.runId).toBe("run-abc");
    expect(entry.toolCallId).toBe("tc-001");
    expect(entry.ts).toBeDefined();
    // No hmac when token is not configured
    expect(entry.hmac).toBeUndefined();
  });

  it.runIf(process.platform !== "win32")(
    "writes private log directory and file modes",
    async () => {
      const dir = makeTestDir();
      logger = createToolAuditLogger({ logDir: dir });
      logger.log({
        event: "tool.call",
        surface: "tools-invoke",
        tool: "exec",
      });
      await logger.flush();

      const dirMode = (await stat(dir)).mode & 0o777;
      const fileMode = (await stat(path.join(dir, "gateway-tool-audit.jsonl"))).mode & 0o777;
      expect(dirMode).toBe(0o700);
      expect(fileMode).toBe(0o600);
    },
  );

  it("logs a tool.result entry and verify structure", async () => {
    const dir = makeTestDir();
    logger = createToolAuditLogger({ logDir: dir });
    logger.log({
      event: "tool.result",
      surface: "openresponses",
      tool: "file_read",
      toolCallId: "tc-002",
      resultStatus: "success",
      durationMs: 42,
    });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-tool-audit.jsonl"), "utf-8");
    const entry = JSON.parse(content.trim());

    expect(entry.event).toBe("tool.result");
    expect(entry.source).toBe("gateway");
    expect(entry.surface).toBe("openresponses");
    expect(entry.tool).toBe("file_read");
    expect(entry.toolCallId).toBe("tc-002");
    expect(entry.resultStatus).toBe("success");
    expect(entry.durationMs).toBe(42);
    expect(entry.ts).toBeDefined();
  });

  it("logs a tool.error entry", async () => {
    const dir = makeTestDir();
    logger = createToolAuditLogger({ logDir: dir });
    logger.log({
      event: "tool.error",
      surface: "chat",
      tool: "web_search",
      toolCallId: "tc-003",
      resultStatus: "failure",
      durationMs: 1500,
    });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-tool-audit.jsonl"), "utf-8");
    const entry = JSON.parse(content.trim());

    expect(entry.event).toBe("tool.error");
    expect(entry.source).toBe("gateway");
    expect(entry.surface).toBe("chat");
    expect(entry.tool).toBe("web_search");
    expect(entry.resultStatus).toBe("failure");
    expect(entry.durationMs).toBe(1500);
  });

  it("HMAC signing works when token is provided", async () => {
    const dir = makeTestDir();
    const token = "test-hmac-secret";
    logger = createToolAuditLogger({ logDir: dir, token });
    logger.log({
      event: "tool.call",
      surface: "tools-invoke",
      tool: "exec",
      actorId: "user-456",
    });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-tool-audit.jsonl"), "utf-8");
    const line = content.trim();

    const parsed = JSON.parse(line);
    expect(parsed.hmac).toBeDefined();
    expect(typeof parsed.hmac).toBe("string");
    expect(parsed.hmac).toHaveLength(64); // sha256 hex digest

    // verifyLine should return valid
    const result = verifyLine(line, token);
    expect(result.valid).toBe(true);
    expect(result.entry).toBeDefined();
    expect(result.entry!.event).toBe("tool.call");
    expect(result.entry!.tool).toBe("exec");
    expect(result.entry!.actorId).toBe("user-456");
  });

  it("verifyLine detects tampering", async () => {
    const dir = makeTestDir();
    const token = "test-hmac-secret";
    logger = createToolAuditLogger({ logDir: dir, token });
    logger.log({
      event: "tool.call",
      surface: "tools-invoke",
      tool: "file_read",
    });
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-tool-audit.jsonl"), "utf-8");
    const originalLine = content.trim();

    // Verify original is valid
    expect(verifyLine(originalLine, token).valid).toBe(true);

    // Tamper with the tool name
    const tamperedLine = originalLine.replace('"file_read"', '"file_write"');
    expect(verifyLine(tamperedLine, token).valid).toBe(false);

    // Tamper with the hmac itself
    const parsed = JSON.parse(originalLine) as { hmac: string };
    const flippedHmac = parsed.hmac.slice(0, -2) + (parsed.hmac.endsWith("00") ? "01" : "00");
    const hmacTampered = originalLine.replace(parsed.hmac, flippedHmac);
    expect(verifyLine(hmacTampered, token).valid).toBe(false);

    // Wrong token should also fail
    expect(verifyLine(originalLine, "wrong-token").valid).toBe(false);

    // No token but signed line should fail
    expect(verifyLine(originalLine, "").valid).toBe(false);
  });

  it("rotation works when file exceeds maxBytes", async () => {
    const dir = makeTestDir();
    logger = createToolAuditLogger({ logDir: dir, maxBytes: 200, maxFiles: 3 });

    // Write enough entries to trigger rotation
    for (let i = 0; i < 20; i++) {
      logger.log({
        event: "tool.call",
        surface: "tools-invoke",
        tool: "exec",
        actorId: `user-${i}`,
      });
    }
    await logger.flush();

    // After rotation, at least one rotated file should exist
    const rotatedPath = path.join(dir, "gateway-tool-audit.1.jsonl");
    const rotatedStat = await stat(rotatedPath).catch(() => null);
    expect(rotatedStat).not.toBeNull();
    expect(rotatedStat!.size).toBeGreaterThan(0);

    // At least one rotated file has valid JSONL content
    const rotatedContent = await readFile(rotatedPath, "utf-8");
    const rotatedLines = rotatedContent.trim().split("\n");
    expect(rotatedLines.length).toBeGreaterThan(0);
    const entry = JSON.parse(rotatedLines[0]);
    expect(entry.event).toBe("tool.call");
    expect(entry.tool).toBe("exec");
  });

  it("multiple concurrent writes serialize correctly", async () => {
    const dir = makeTestDir();
    logger = createToolAuditLogger({ logDir: dir });

    // Fire 50 writes concurrently (all go into the promise chain)
    const count = 50;
    for (let i = 0; i < count; i++) {
      logger.log({
        event: i % 2 === 0 ? "tool.call" : "tool.result",
        surface: "tools-invoke",
        tool: `tool_${i}`,
        toolCallId: `tc-${i}`,
      });
    }
    await logger.flush();

    const content = await readFile(path.join(dir, "gateway-tool-audit.jsonl"), "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(count);

    // Each line should be valid JSON with correct structure
    for (let i = 0; i < lines.length; i++) {
      const entry = JSON.parse(lines[i]);
      expect(entry.source).toBe("gateway");
      expect(entry.ts).toBeDefined();
      expect(entry.tool).toMatch(/^tool_\d+$/);
      expect(entry.toolCallId).toMatch(/^tc-\d+$/);
    }
  });

  it("accepts unsigned lines when no token is configured", () => {
    const line = JSON.stringify({
      ts: "2025-01-01T00:00:00.000Z",
      source: "gateway",
      event: "tool.call",
      surface: "chat",
      tool: "exec",
    });

    const result = verifyLine(line, "");
    expect(result.valid).toBe(true);
    expect(result.entry).toBeDefined();
    expect(result.entry!.tool).toBe("exec");
  });

  it("rejects malformed JSON", () => {
    const result = verifyLine("not json at all", "");
    expect(result.valid).toBe(false);
  });

  it("rejects signed line when no token provided", () => {
    const line = JSON.stringify({
      ts: "2025-01-01T00:00:00.000Z",
      source: "gateway",
      event: "tool.call",
      surface: "chat",
      tool: "exec",
      hmac: "abc123",
    });

    const result = verifyLine(line, "");
    expect(result.valid).toBe(false);
  });

  it("rejects unsigned line when token is configured", () => {
    const line = JSON.stringify({
      ts: "2025-01-01T00:00:00.000Z",
      source: "gateway",
      event: "tool.call",
      surface: "chat",
      tool: "exec",
    });

    const result = verifyLine(line, "some-secret");
    expect(result.valid).toBe(false);
  });
});
