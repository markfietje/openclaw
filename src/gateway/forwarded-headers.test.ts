import { describe, expect, it } from "vitest";
import { validateProtoMismatch } from "./forwarded-headers.js";

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
