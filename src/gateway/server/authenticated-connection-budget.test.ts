import { describe, expect, it } from "vitest";
import {
  createAuthenticatedConnectionBudget,
  getMaxAuthenticatedConnectionsPerIdentityFromEnv,
} from "./authenticated-connection-budget.js";

describe("createAuthenticatedConnectionBudget", () => {
  it("acquires slots up to the limit", () => {
    const budget = createAuthenticatedConnectionBudget(3);
    expect(budget.acquire("device-a", "conn-1")).toBe(true);
    expect(budget.acquire("device-a", "conn-2")).toBe(true);
    expect(budget.acquire("device-a", "conn-3")).toBe(true);
    expect(budget.count("device-a")).toBe(3);
  });

  it("rejects acquisitions beyond the limit", () => {
    const budget = createAuthenticatedConnectionBudget(2);
    expect(budget.acquire("device-a", "conn-1")).toBe(true);
    expect(budget.acquire("device-a", "conn-2")).toBe(true);
    expect(budget.acquire("device-a", "conn-3")).toBe(false);
    expect(budget.count("device-a")).toBe(2);
  });

  it("releases slots and allows new acquisitions", () => {
    const budget = createAuthenticatedConnectionBudget(2);
    budget.acquire("device-a", "conn-1");
    budget.acquire("device-a", "conn-2");
    budget.release("device-a", "conn-1");
    expect(budget.count("device-a")).toBe(1);
    expect(budget.acquire("device-a", "conn-3")).toBe(true);
  });

  it("different devices have independent budgets", () => {
    const budget = createAuthenticatedConnectionBudget(2);
    budget.acquire("device-a", "conn-1");
    budget.acquire("device-a", "conn-2");
    expect(budget.acquire("device-b", "conn-1")).toBe(true);
    expect(budget.acquire("device-b", "conn-2")).toBe(true);
    expect(budget.acquire("device-b", "conn-3")).toBe(false);
  });

  it("handles undefined deviceId with fallback key", () => {
    const budget = createAuthenticatedConnectionBudget(2);
    expect(budget.acquire(undefined, "conn-1")).toBe(true);
    expect(budget.acquire(undefined, "conn-2")).toBe(true);
    expect(budget.acquire(undefined, "conn-3")).toBe(false);
  });

  it("release is idempotent for unknown connId", () => {
    const budget = createAuthenticatedConnectionBudget(2);
    budget.release("device-a", "nonexistent");
    expect(budget.count("device-a")).toBe(0);
  });

  it("dispose clears all tracking", () => {
    const budget = createAuthenticatedConnectionBudget(5);
    budget.acquire("device-a", "conn-1");
    budget.acquire("device-b", "conn-2");
    budget.dispose();
    expect(budget.count("device-a")).toBe(0);
    expect(budget.count("device-b")).toBe(0);
  });

  it("release cleans up empty device entries", () => {
    const budget = createAuthenticatedConnectionBudget(5);
    budget.acquire("device-a", "conn-1");
    budget.release("device-a", "conn-1");
    expect(budget.count("device-a")).toBe(0);
  });
});

describe("getMaxAuthenticatedConnectionsPerIdentityFromEnv", () => {
  it("returns default when no env set", () => {
    expect(getMaxAuthenticatedConnectionsPerIdentityFromEnv({})).toBe(8);
  });

  it("reads from env", () => {
    expect(
      getMaxAuthenticatedConnectionsPerIdentityFromEnv({
        OPENCLAW_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY: "16",
      }),
    ).toBe(16);
  });

  it("falls back to default for invalid values", () => {
    expect(
      getMaxAuthenticatedConnectionsPerIdentityFromEnv({
        OPENCLAW_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY: "not-a-number",
      }),
    ).toBe(8);
  });

  it("falls back to default for zero", () => {
    expect(
      getMaxAuthenticatedConnectionsPerIdentityFromEnv({
        OPENCLAW_MAX_AUTHENTICATED_CONNECTIONS_PER_IDENTITY: "0",
      }),
    ).toBe(8);
  });
});
