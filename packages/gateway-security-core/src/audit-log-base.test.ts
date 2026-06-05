// Tests for audit-log field truncation helper.
import { describe, expect, it } from "vitest";
import { MAX_AUDIT_STRING_LENGTH, truncateAuditField } from "./audit-log-base.js";

describe("truncateAuditField", () => {
  it("returns the value unchanged when shorter than the cap", () => {
    expect(truncateAuditField("alice")).toBe("alice");
  });

  it("returns the value unchanged when exactly at the cap", () => {
    const value = "a".repeat(MAX_AUDIT_STRING_LENGTH);
    expect(truncateAuditField(value)).toBe(value);
  });

  it("truncates with ellipsis when over the cap", () => {
    const value = "a".repeat(MAX_AUDIT_STRING_LENGTH + 10);
    const result = truncateAuditField(value) as string;
    expect(result.length).toBe(MAX_AUDIT_STRING_LENGTH + 1);
    expect(result.endsWith("\u2026")).toBe(true);
    expect(result.startsWith("a".repeat(10))).toBe(true);
  });

  it("returns empty string unchanged (no ellipsis on empty input)", () => {
    expect(truncateAuditField("")).toBe("");
  });

  it("returns undefined unchanged when no identity was supplied", () => {
    expect(truncateAuditField(undefined)).toBe(undefined);
  });
});
