import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
    const dir = mkdtempSync(path.join(tmpdir(), "secret-env-test-"));
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
});

describe("isSecretEnvFileVar", () => {
  it("returns true for keys ending with _FILE", () => {
    expect(isSecretEnvFileVar("OPENAI_API_KEY_FILE")).toBe(true);
  });

  it("returns false for regular env vars", () => {
    expect(isSecretEnvFileVar("OPENAI_API_KEY")).toBe(false);
  });
});
