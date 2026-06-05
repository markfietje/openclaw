import { describe, expect, it } from "vitest";
import { createOutboundRedactor, isOutboundRedactionEnabled } from "./outbound-redact.js";

describe("outbound redaction", () => {
  describe("createOutboundRedactor", () => {
    it("redacts Stripe live keys", () => {
      const redactor = createOutboundRedactor();
      const prefix = "sk_live_";
      const suffix = "EXAMPLEplaceholder1234567890a";
      expect(redactor.redact(`key: ${prefix}${suffix}`)).toContain("***REDACTED***");
    });

    it("redacts OpenAI keys", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("key: sk-abc123def456ghi789jkl012mno345")).toContain("***REDACTED***");
    });

    it("redacts GitHub PATs", () => {
      const redactor = createOutboundRedactor();
      const prefix = "ghp_";
      const suffix = "EXAMPLEplaceholder1234567890abcd";
      expect(redactor.redact(`token: ${prefix}${suffix}`)).toContain("***REDACTED***");
    });

    it("redacts Slack tokens", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("token: xoxb-EXAMPLE-1234-placeholder99")).toContain("***REDACTED***");
    });

    it("redacts private keys", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")).toContain(
        "***REDACTED***",
      );
    });

    it("redacts generic api_key params", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("api_key=EXAMPLEplaceholder123456789")).toContain("***REDACTED***");
    });

    it("redacts generic token params", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("token=supersecretvalue12345678")).toContain("***REDACTED***");
    });

    it("redacts generic password params", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("password=mysecretpassword123456")).toContain("***REDACTED***");
    });

    it("does not redact normal text", () => {
      const redactor = createOutboundRedactor();
      expect(redactor.redact("Hello, how are you today?")).toBe("Hello, how are you today?");
    });

    it("redacts dynamic secrets", () => {
      const redactor = createOutboundRedactor();
      redactor.addSensitiveValue("my-gateway-token-value");
      expect(redactor.redact("token is my-gateway-token-value")).toContain("***REDACTED***");
    });

    it("ignores dynamic secrets shorter than 8 chars", () => {
      const redactor = createOutboundRedactor();
      redactor.addSensitiveValue("short");
      expect(redactor.redact("the value is short")).toBe("the value is short");
    });

    it("tracks redaction count", () => {
      const redactor = createOutboundRedactor();
      const input = "api_key=secretvalue12345678 and token=anothervalue12345678";
      redactor.redact(input);
      expect(redactor.redactionCount).toBeGreaterThanOrEqual(1);
    });

    it("redacts known secrets from config", () => {
      const redactor = createOutboundRedactor({
        knownSecrets: ["my-super-secret-gateway-token-12345"],
      });
      expect(redactor.redact("Bearer my-super-secret-gateway-token-12345")).toContain(
        "***REDACTED***",
      );
    });
  });

  describe("isOutboundRedactionEnabled", () => {
    it("returns true by default", () => {
      expect(isOutboundRedactionEnabled({})).toBe(true);
      expect(isOutboundRedactionEnabled(undefined)).toBe(true);
    });

    it("returns true when explicitly enabled", () => {
      expect(
        isOutboundRedactionEnabled({
          gateway: { security: { enableOutboundRedaction: true } },
        } as any),
      ).toBe(true);
    });

    it("returns false when explicitly disabled", () => {
      expect(
        isOutboundRedactionEnabled({
          gateway: { security: { enableOutboundRedaction: false } },
        } as any),
      ).toBe(false);
    });
  });
});
