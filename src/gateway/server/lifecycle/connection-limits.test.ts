// Connection lifecycle limits tests.
// Covers resolver functions for config-aware max-age and max-idle thresholds.

import { describe, expect, it } from "vitest";
import {
  resolveMaxConnectionAgeMs,
  resolveMaxIdleMs,
  MAX_CONNECTION_AGE_MS,
  MAX_IDLE_MS,
} from "./connection-limits.js";

describe("resolveMaxConnectionAgeMs", () => {
  it("returns the default when no config is provided", () => {
    expect(resolveMaxConnectionAgeMs()).toBe(MAX_CONNECTION_AGE_MS);
  });

  it("returns the default when config is undefined", () => {
    expect(resolveMaxConnectionAgeMs(undefined)).toBe(MAX_CONNECTION_AGE_MS);
  });

  it("returns the default when ws config is absent", () => {
    expect(resolveMaxConnectionAgeMs({})).toBe(MAX_CONNECTION_AGE_MS);
  });

  it("returns the configured value when valid", () => {
    expect(resolveMaxConnectionAgeMs({ ws: { maxConnectionAgeMs: 5000 } })).toBe(5000);
  });

  it("returns the default when maxConnectionAgeMs is zero", () => {
    expect(resolveMaxConnectionAgeMs({ ws: { maxConnectionAgeMs: 0 } })).toBe(
      MAX_CONNECTION_AGE_MS,
    );
  });

  it("returns the default when maxConnectionAgeMs is negative", () => {
    expect(resolveMaxConnectionAgeMs({ ws: { maxConnectionAgeMs: -1 } })).toBe(
      MAX_CONNECTION_AGE_MS,
    );
  });
});

describe("resolveMaxIdleMs", () => {
  it("returns the default when no config is provided", () => {
    expect(resolveMaxIdleMs()).toBe(MAX_IDLE_MS);
  });

  it("returns the default when config is undefined", () => {
    expect(resolveMaxIdleMs(undefined)).toBe(MAX_IDLE_MS);
  });

  it("returns the default when ws config is absent", () => {
    expect(resolveMaxIdleMs({})).toBe(MAX_IDLE_MS);
  });

  it("returns the configured value when valid", () => {
    expect(resolveMaxIdleMs({ ws: { maxIdleMs: 60000 } })).toBe(60000);
  });

  it("returns the default when maxIdleMs is zero", () => {
    expect(resolveMaxIdleMs({ ws: { maxIdleMs: 0 } })).toBe(MAX_IDLE_MS);
  });

  it("returns the default when maxIdleMs is negative", () => {
    expect(resolveMaxIdleMs({ ws: { maxIdleMs: -100 } })).toBe(MAX_IDLE_MS);
  });
});
