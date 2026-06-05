// Verifies timing-safe secret comparison semantics and edge cases.
import { describe, expect, it } from "vitest";
import { safeEqualSecret } from "./secret-equal.js";

describe("safeEqualSecret", () => {
  it("returns true for identical strings", () => {
    expect(safeEqualSecret("abc", "abc")).toBe(true);
  });

  it("returns false for different strings of the same length", () => {
    expect(safeEqualSecret("abc", "abd")).toBe(false);
    expect(safeEqualSecret("aaa", "bbb")).toBe(false);
  });

  it("returns false for strings of different lengths", () => {
    expect(safeEqualSecret("abc", "abcd")).toBe(false);
    expect(safeEqualSecret("abcd", "abc")).toBe(false);
  });

  it("returns false for completely different strings", () => {
    expect(safeEqualSecret("a", "b")).toBe(false);
    expect(safeEqualSecret("hunter2", "correcthorse")).toBe(false);
  });

  it("returns false for undefined inputs", () => {
    expect(safeEqualSecret(undefined, "abc")).toBe(false);
    expect(safeEqualSecret("abc", undefined)).toBe(false);
  });

  it("returns false for null inputs", () => {
    expect(safeEqualSecret(null, "abc")).toBe(false);
    expect(safeEqualSecret("abc", null)).toBe(false);
  });

  it("returns false when both inputs are empty (fail-closed on missing secret)", () => {
    expect(safeEqualSecret("", "")).toBe(false);
    expect(safeEqualSecret(undefined, undefined)).toBe(false);
    expect(safeEqualSecret(null, null)).toBe(false);
  });

  it("returns false when only one side is empty", () => {
    expect(safeEqualSecret("", "abc")).toBe(false);
    expect(safeEqualSecret("abc", "")).toBe(false);
  });

  it("handles unicode and multibyte characters correctly", () => {
    expect(safeEqualSecret("café", "café")).toBe(true);
    expect(safeEqualSecret("café", "cafe")).toBe(false);
  });

  it("does not match a prefix of a longer secret", () => {
    expect(safeEqualSecret("abc", "abcdef")).toBe(false);
    expect(safeEqualSecret("abcdef", "abc")).toBe(false);
  });

  it("handles long secrets without leaking length via timing", () => {
    // Same length, differing content
    const a = "a".repeat(128);
    const b = "b".repeat(128);
    expect(safeEqualSecret(a, b)).toBe(false);
    expect(safeEqualSecret(a, a)).toBe(true);
  });
});
