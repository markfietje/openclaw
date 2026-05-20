import { describe, expect, it } from "vitest";
import { DEFAULT_MAX_PAYLOAD_BYTES, resolveMaxPayloadBytes } from "./server-constants.js";

const MIN_PAYLOAD_BYTES = 64 * 1024; // 64 KB
const ABSOLUTE_MAX_PAYLOAD_BYTES = 100 * 1024 * 1024; // 100 MB

describe("resolveMaxPayloadBytes", () => {
  it("returns the default when config value is undefined", () => {
    expect(resolveMaxPayloadBytes(undefined)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("returns the default when config value is NaN", () => {
    expect(resolveMaxPayloadBytes(NaN)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("returns the default when config value is Infinity", () => {
    expect(resolveMaxPayloadBytes(Infinity)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("returns the default when config value is -Infinity", () => {
    expect(resolveMaxPayloadBytes(-Infinity)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("returns the default when config value is zero", () => {
    expect(resolveMaxPayloadBytes(0)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("returns the default when config value is negative", () => {
    expect(resolveMaxPayloadBytes(-1)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("returns the default when config value is a non-finite number string cast", () => {
    // Number.isFinite catches these
    expect(resolveMaxPayloadBytes(Number("abc"))).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("clamps to MIN_PAYLOAD_BYTES when config value is below minimum", () => {
    expect(resolveMaxPayloadBytes(1)).toBe(MIN_PAYLOAD_BYTES);
    expect(resolveMaxPayloadBytes(1024)).toBe(MIN_PAYLOAD_BYTES);
    expect(resolveMaxPayloadBytes(MIN_PAYLOAD_BYTES - 1)).toBe(MIN_PAYLOAD_BYTES);
  });

  it("returns exactly MIN_PAYLOAD_BYTES when config value equals minimum", () => {
    expect(resolveMaxPayloadBytes(MIN_PAYLOAD_BYTES)).toBe(MIN_PAYLOAD_BYTES);
  });

  it("clamps to ABSOLUTE_MAX_PAYLOAD_BYTES when config value exceeds maximum", () => {
    expect(resolveMaxPayloadBytes(200 * 1024 * 1024)).toBe(ABSOLUTE_MAX_PAYLOAD_BYTES);
    expect(resolveMaxPayloadBytes(ABSOLUTE_MAX_PAYLOAD_BYTES + 1)).toBe(ABSOLUTE_MAX_PAYLOAD_BYTES);
  });

  it("returns exactly ABSOLUTE_MAX_PAYLOAD_BYTES when config value equals maximum", () => {
    expect(resolveMaxPayloadBytes(ABSOLUTE_MAX_PAYLOAD_BYTES)).toBe(ABSOLUTE_MAX_PAYLOAD_BYTES);
  });

  it("returns the config value when it is within valid range", () => {
    const oneMB = 1024 * 1024;
    expect(resolveMaxPayloadBytes(oneMB)).toBe(oneMB);
    expect(resolveMaxPayloadBytes(10 * oneMB)).toBe(10 * oneMB);
    expect(resolveMaxPayloadBytes(DEFAULT_MAX_PAYLOAD_BYTES)).toBe(DEFAULT_MAX_PAYLOAD_BYTES);
  });

  it("handles boundary just above MIN_PAYLOAD_BYTES", () => {
    expect(resolveMaxPayloadBytes(MIN_PAYLOAD_BYTES + 1)).toBe(MIN_PAYLOAD_BYTES + 1);
  });

  it("handles boundary just below ABSOLUTE_MAX_PAYLOAD_BYTES", () => {
    expect(resolveMaxPayloadBytes(ABSOLUTE_MAX_PAYLOAD_BYTES - 1)).toBe(
      ABSOLUTE_MAX_PAYLOAD_BYTES - 1,
    );
  });
});
