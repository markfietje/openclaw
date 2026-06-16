import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { resolveSecretEnvValue, isSecretEnvFileVar } from "./secret-env.js";

describe("resolveSecretEnvValue", () => {
  it("returns env value when set directly", () => {
    const result = resolveSecretEnvValue("OPENAI_API_KEY", { OPENAI_API_KEY: "sk-test-123" });
    expect(result).toEqual({ value: "sk-test-123", source: "env", envVar: "OPENAI_API_KEY" });
  });

  it("returns null when neither env nor file is set", () => {
    const result = resolveSecretEnvValue("MISSING_KEY", {});
    expect(result).toBeNull();
  });

  it("reads from _FILE path when env var is not set", () => {
    const homeDir = process.env.HOME ?? "/tmp";
    const dir = path.join(homeDir, ".openclaw", "credentials", `secret-env-test-${Date.now()}`);
    mkdirSync(dir, { recursive: true });
    const secretPath = path.join(dir, "openai-key");
    writeFileSync(secretPath, "sk-from-file\n", "utf8");
    try {
      const result = resolveSecretEnvValue("OPENAI_API_KEY", {
        OPENAI_API_KEY_FILE: secretPath,
      });
      expect(result).toEqual({ value: "sk-from-file", source: "file", envVar: "OPENAI_API_KEY" });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("prefers direct env over _FILE", () => {
    const result = resolveSecretEnvValue("OPENAI_API_KEY", {
      OPENAI_API_KEY: "sk-direct",
      OPENAI_API_KEY_FILE: "/nonexistent/path",
    });
    expect(result).toEqual({ value: "sk-direct", source: "env", envVar: "OPENAI_API_KEY" });
  });

  it("returns null when _FILE path does not exist", () => {
    const result = resolveSecretEnvValue("MY_KEY", { MY_KEY_FILE: "/nonexistent/secret" });
    expect(result).toBeNull();
  });

  it("rejects *_FILE paths outside allowed directories", () => {
    const result = resolveSecretEnvValue("MY_SECRET", { MY_SECRET_FILE: "/etc/shadow" });
    expect(result).toBeNull();
  });

  it("allows *_FILE paths under ~/.openclaw/credentials", () => {
    const homeDir = process.env.HOME ?? "/tmp";
    const credDir = path.join(homeDir, ".openclaw", "credentials");
    mkdirSync(credDir, { recursive: true });
    const secretPath = path.join(credDir, "test-key");
    try {
      writeFileSync(secretPath, "secret-value\n", "utf8");
      const result = resolveSecretEnvValue("MY_KEY", { MY_KEY_FILE: secretPath });
      expect(result).toEqual({ value: "secret-value", source: "file", envVar: "MY_KEY" });
    } finally {
      rmSync(secretPath, { force: true });
    }
  });

  // Symlink escape: a path that lexically lives inside an allowed dir but
  // resolves to a target outside it (e.g. /run/secrets/legit -> /etc/shadow)
  // must be rejected after canonicalizing the link via realpath.
  it("rejects *_FILE symlinks that escape an allowed directory", () => {
    const homeDir = process.env.HOME ?? "/tmp";
    const credDir = path.join(homeDir, ".openclaw", "credentials");
    mkdirSync(credDir, { recursive: true });
    // Target file OUTSIDE any allowed secret dir.
    const targetDir = mkdtempSync(path.join(tmpdir(), "secret-escape-"));
    const targetFile = path.join(targetDir, "shadow");
    writeFileSync(targetFile, "stolen-secret\n", "utf8");
    const linkPath = path.join(credDir, `escape-${Date.now()}`);
    try {
      symlinkSync(targetFile, linkPath);
      const result = resolveSecretEnvValue("MY_KEY", { MY_KEY_FILE: linkPath });
      expect(result).toBeNull();
    } finally {
      rmSync(linkPath, { force: true });
      rmSync(targetDir, { recursive: true, force: true });
    }
  });

  it("returns null for a dangling *_FILE symlink (fail closed)", () => {
    const homeDir = process.env.HOME ?? "/tmp";
    const credDir = path.join(homeDir, ".openclaw", "credentials");
    mkdirSync(credDir, { recursive: true });
    const linkPath = path.join(credDir, `dangling-${Date.now()}`);
    try {
      // Symlink to a nonexistent target — realpath throws.
      symlinkSync(path.join(tmpdir(), `no-such-target-${Date.now()}`), linkPath);
      const result = resolveSecretEnvValue("MY_KEY", { MY_KEY_FILE: linkPath });
      expect(result).toBeNull();
    } finally {
      rmSync(linkPath, { force: true });
    }
  });
});

describe("isSecretEnvFileVar", () => {
  it("returns true for keys ending with _FILE", () => {
    expect(isSecretEnvFileVar("OPENAI_API_KEY_FILE")).toBe(true);
  });

  it("returns false for regular env vars", () => {
    expect(isSecretEnvFileVar("OPENAI_API_KEY")).toBe(false);
  });
});
