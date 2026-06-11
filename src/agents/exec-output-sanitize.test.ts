// Tests for exec output sanitizer — credential path and secret value redaction.
import { describe, expect, it } from "vitest";
import { sanitizeExecOutput } from "./exec-output-sanitize.js";

describe("sanitizeExecOutput", () => {
  it("redacts credential paths", () => {
    expect(sanitizeExecOutput("key at /home/user/.openclaw/credentials/openai.json")).toContain(
      "[REDACTED]",
    );
    expect(sanitizeExecOutput("reading /etc/shadow")).toContain("[REDACTED]");
    expect(sanitizeExecOutput("reading /etc/passwd")).toContain("[REDACTED]");
    expect(sanitizeExecOutput("cat /proc/self/environ")).toContain("[REDACTED]");
  });

  it("redacts secret environment variable values", () => {
    expect(sanitizeExecOutput("API_KEY=sk-abc123")).toBe("API_KEY=[REDACTED]");
    expect(sanitizeExecOutput("SECRET=mysecret")).toBe("SECRET=[REDACTED]");
    expect(sanitizeExecOutput("TOKEN=abc123def")).toBe("TOKEN=[REDACTED]");
    expect(sanitizeExecOutput("PASSWORD=hunter2")).toBe("PASSWORD=[REDACTED]");
    expect(sanitizeExecOutput("PRIVATE_KEY=-----BEGIN")).toBe("PRIVATE_KEY=[REDACTED]");
  });

  it("preserves normal output unchanged", () => {
    expect(sanitizeExecOutput("hello world")).toBe("hello world");
    expect(sanitizeExecOutput("npm install")).toBe("npm install");
    expect(sanitizeExecOutput("")).toBe("");
  });

  it("redacts multiple patterns in one output", () => {
    const input = "API_KEY=sk-123 /home/user/.openclaw/credentials/openai.json done";
    const result = sanitizeExecOutput(input);
    expect(result).toContain("API_KEY=[REDACTED]");
    expect(result).toContain("[REDACTED]");
    expect(result).toContain("done");
  });
});
