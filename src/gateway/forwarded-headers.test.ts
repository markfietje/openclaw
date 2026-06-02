import { describe, expect, it } from "vitest";
import {
  parseForwardedHeader,
  parseForwardedChain,
  validateProtoMismatch,
} from "./forwarded-headers.js";

describe("parseForwardedHeader", () => {
  it("parses RFC 7239 Forwarded header", () => {
    const entries = parseForwardedHeader("for=192.0.2.1;host=example.com;proto=https");
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual({
      for: "192.0.2.1",
      host: "example.com",
      proto: "https",
    });
  });

  it("parses multiple entries", () => {
    const entries = parseForwardedHeader('for=192.0.2.1, for="[2001:db8:cafe::17]", for=unknown');
    expect(entries).toHaveLength(3);
    expect(entries[0]?.for).toBeDefined();
    expect(entries[1]?.for).toBeDefined();
    expect(entries[2]?.for).toBeDefined();
  });

  it("handles quoted values", () => {
    const entries = parseForwardedHeader('for="192.0.2.1:47011"');
    expect(entries).toHaveLength(1);
  });

  it("returns empty for undefined", () => {
    expect(parseForwardedHeader(undefined)).toEqual([]);
  });

  it("returns empty for empty string", () => {
    expect(parseForwardedHeader("")).toEqual([]);
  });

  it("handles array input", () => {
    const entries = parseForwardedHeader(["for=1.2.3.4", "for=5.6.7.8"]);
    expect(entries).toHaveLength(2);
  });

  it("caps at MAX_PROXY_CHAIN_DEPTH", () => {
    const chain = Array.from({ length: 10 }, (_, i) => `for=192.0.2.${i}`).join(", ");
    const entries = parseForwardedHeader(chain);
    expect(entries.length).toBeLessThanOrEqual(5);
  });
});

describe("parseForwardedChain", () => {
  it("extracts client IP from Forwarded header with trusted proxies", () => {
    const result = parseForwardedChain({
      forwardedHeader: "for=192.0.2.1, for=10.0.0.1",
      trustedProxies: ["10.0.0.1"],
    });
    expect(result.clientIp).toBeDefined();
    expect(result.originalHost).toBeUndefined();
  });

  it("extracts host and proto from first entry", () => {
    const result = parseForwardedChain({
      forwardedHeader: "for=192.0.2.1;host=example.com;proto=https",
      trustedProxies: [],
    });
    expect(result.originalHost).toBe("example.com");
    expect(result.originalProto).toBe("https");
  });

  it("falls back to X-Forwarded-Host", () => {
    const result = parseForwardedChain({
      xForwardedHost: "example.com",
      trustedProxies: [],
    });
    expect(result.originalHost).toBe("example.com");
  });

  it("falls back to X-Forwarded-Proto", () => {
    const result = parseForwardedChain({
      xForwardedProto: "https",
      trustedProxies: [],
    });
    expect(result.originalProto).toBe("https");
  });

  it("extracts client IP from X-Forwarded-For with trusted proxies", () => {
    const result = parseForwardedChain({
      xForwardedFor: "192.0.2.1, 10.0.0.1",
      trustedProxies: ["10.0.0.1"],
    });
    expect(result.clientIp).toBeDefined();
  });

  it("returns undefined clientIp without trusted proxies and X-Forwarded-For", () => {
    const result = parseForwardedChain({
      xForwardedFor: "192.0.2.1, 10.0.0.1",
    });
    expect(result.clientIp).toBeUndefined();
  });

  it("handles IPv6 addresses in Forwarded header", () => {
    const result = parseForwardedChain({
      forwardedHeader: 'for="[2001:db8::1]"',
      trustedProxies: [],
    });
    expect(result.entries.length).toBeGreaterThanOrEqual(1);
    expect(result.entries[0]?.for).toBeDefined();
  });
});

describe("validateProtoMismatch", () => {
  it("returns ok when no forwarded proto", () => {
    expect(validateProtoMismatch({ originProto: "https" })).toEqual({ ok: true });
  });

  it("returns ok when proto matches", () => {
    expect(
      validateProtoMismatch({
        originProto: "https",
        forwardedProto: "https",
      }),
    ).toEqual({ ok: true });
  });

  it("returns error on mismatch with Forwarded proto", () => {
    const result = validateProtoMismatch({
      originProto: "https",
      forwardedProto: "http",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("Forwarded proto");
    }
  });

  it("returns error on mismatch with X-Forwarded-Proto", () => {
    const result = validateProtoMismatch({
      originProto: "https",
      xForwardedProto: "http",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("X-Forwarded-Proto");
    }
  });
});
