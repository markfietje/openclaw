import { describe, expect, test } from "vitest";
import { createOutboundRedactor } from "./outbound-redact.js";

describe("createOutboundRedactor", () => {
  test("redacts OpenAI API keys", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("My key is sk-abc123def456ghi789jkl012mno345 and keep it safe");
    expect(result).toBe("My key is ***REDACTED*** and keep it safe");
  });

  test("redacts Slack tokens", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("slack: xoxb-1234-abcdef-xyzw and xoxp-5678-qrstuv");
    expect(result).toBe("slack: ***REDACTED*** and ***REDACTED***");
  });

  test("redacts GitHub PATs", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("export GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    expect(result).toBe("export GITHUB_TOKEN=***REDACTED***");
  });

  test("redacts GitHub OAuth tokens", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("token=gho_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    expect(result).toBe("token=***REDACTED***");
  });

  test("redacts GitHub app tokens", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("token=ghs_cccccccccccccccccccccccccccccccccccc");
    expect(result).toBe("token=***REDACTED***");
  });

  test("redacts Stripe live keys", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("key=sk_live_XXXXXXXXXXXXXXXXXXXXXXXXX");
    expect(result).toBe("key=***REDACTED***");
  });

  test("redacts Stripe test keys", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("key=sk_test_XXXXXXXXXXXXXXXXXXXXXXXXX");
    expect(result).toBe("key=***REDACTED***");
  });

  test("redacts private key blocks", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact(
      "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----",
    );
    expect(result).toBe("***REDACTED***\nMIIE...\n-----END RSA PRIVATE KEY-----");
  });

  test("redacts EC private key blocks", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact(
      "-----BEGIN EC PRIVATE KEY-----\nMHQ...\n-----END EC PRIVATE KEY-----",
    );
    expect(result).toBe("***REDACTED***\nMHQ...\n-----END EC PRIVATE KEY-----");
  });

  test("redacts generic API key params", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("url?api_key=abcdef12345678");
    expect(result).toBe("url?***REDACTED***");
  });

  test("redacts generic token params", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("config token=supersecret12345");
    expect(result).toBe("config ***REDACTED***");
  });

  test("redacts password params", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("login password=hunter2admin123");
    expect(result).toBe("login ***REDACTED***");
  });

  test("addSensitiveValue + redact works for exact match", () => {
    const redactor = createOutboundRedactor();
    redactor.addSensitiveValue("my-super-secret-gateway-token-2024");
    const result = redactor.redact("The token is my-super-secret-gateway-token-2024, ok?");
    expect(result).toBe("The token is ***REDACTED***, ok?");
  });

  test("short values (< 8 chars) from addSensitiveValue are NOT redacted", () => {
    const redactor = createOutboundRedactor();
    redactor.addSensitiveValue("short");
    const result = redactor.redact("This has the word short in it");
    expect(result).toBe("This has the word short in it");
  });

  test("multiple occurrences in same text are all redacted", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact(
      "key: sk-abc123def456ghi789jkl012 and also sk-xyz789tuv456rst123ghi890",
    );
    expect(result).toBe("key: ***REDACTED*** and also ***REDACTED***");
  });

  test("extra patterns from config are applied", () => {
    const redactor = createOutboundRedactor({
      extraPatterns: [/custom-secret-[a-z0-9]+/g],
    });
    const result = redactor.redact("found custom-secret-abc123 in text");
    expect(result).toBe("found ***REDACTED*** in text");
  });

  test("known secrets from config are redacted", () => {
    const redactor = createOutboundRedactor({
      knownSecrets: ["my-gateway-token-abc123"],
    });
    const result = redactor.redact("token: my-gateway-token-abc123 end");
    expect(result).toBe("token: ***REDACTED*** end");
  });

  test("text without secrets passes through unchanged", () => {
    const redactor = createOutboundRedactor();
    const text = "Hello, this is a normal message with no secrets.";
    const result = redactor.redact(text);
    expect(result).toBe(text);
  });

  test("redactionCount tracks cumulative redactions", () => {
    const redactor = createOutboundRedactor();
    expect(redactor.redactionCount).toBe(0);

    redactor.redact("sk-abc123def456ghi789jkl012 and sk-xyz789tuv456rst123ghi890");
    expect(redactor.redactionCount).toBe(2);

    redactor.redact("clean text");
    expect(redactor.redactionCount).toBe(2);

    redactor.redact("another sk-abc123def456ghi789jkl012");
    expect(redactor.redactionCount).toBe(3);
  });

  test("addSensitiveValue escapes regex special characters", () => {
    const redactor = createOutboundRedactor();
    redactor.addSensitiveValue("secret+$*?{}()[]value");
    const result = redactor.redact("found secret+$*?{}()[]value in text");
    expect(result).toBe("found ***REDACTED*** in text");
  });

  test("longer dynamic secrets take precedence over shorter ones", () => {
    const redactor = createOutboundRedactor();
    redactor.addSensitiveValue("gateway-token-long");
    redactor.addSensitiveValue("gateway-token-longer-suffix");
    const result = redactor.redact("found gateway-token-longer-suffix in text");
    expect(result).toBe("found ***REDACTED*** in text");
  });

  test("BOT_TOKEN param is redacted", () => {
    const redactor = createOutboundRedactor();
    const result = redactor.redact("BOT_TOKEN=abc123def456");
    expect(result).toBe("***REDACTED***");
  });
});
