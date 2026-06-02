import { describe, expect, it } from "vitest";
import { createOutboundDeliveryPayloadRedactor } from "./redaction.js";

describe("createOutboundDeliveryPayloadRedactor", () => {
  it("returns identity function when redaction is disabled", () => {
    const redact = createOutboundDeliveryPayloadRedactor({
      gateway: { security: { enableOutboundRedaction: false } },
    } as any);
    const payload = { text: "api_key=secretvalue12345678" };
    expect(redact(payload as any)).toBe(payload);
  });

  it("redacts secrets from payload text when enabled", () => {
    const redact = createOutboundDeliveryPayloadRedactor({
      gateway: { security: {} },
    } as any);
    const payload = { text: "my key is api_key=supersecretkey123456789012" };
    const result = redact(payload as any);
    expect(result.text).toContain("***REDACTED***");
    expect(result.text).not.toContain("supersecretkey123456789012");
  });

  it("redacts known gateway secrets from config", () => {
    const redact = createOutboundDeliveryPayloadRedactor({
      gateway: {
        auth: { token: "my-super-secret-gateway-token-12345" },
        security: {},
      },
    } as any);
    const payload = { text: "Bearer my-super-secret-gateway-token-12345" };
    const result = redact(payload as any);
    expect(result.text).toContain("***REDACTED***");
  });

  it("preserves non-sensitive text", () => {
    const redact = createOutboundDeliveryPayloadRedactor({
      gateway: { security: {} },
    } as any);
    const payload = { text: "Hello, how are you?" };
    const result = redact(payload as any);
    expect(result.text).toBe("Hello, how are you?");
  });

  it("preserves metadata on redacted payload", () => {
    const redact = createOutboundDeliveryPayloadRedactor({
      gateway: { security: {} },
    } as any);
    const payload = {
      text: "api_key=secretvalue12345678",
      sessionId: "abc-123",
      channelId: "discord",
    };
    const result = redact(payload as any);
    expect(result.sessionId).toBe("abc-123");
    expect(result.channelId).toBe("discord");
    expect(result.text).toContain("***REDACTED***");
  });
});
