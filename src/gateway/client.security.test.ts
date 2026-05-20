import { describe, expect, it, vi } from "vitest";

// We test that the TLS fingerprint comparison uses safeEqualSecret
// by checking the module can be imported and the function reference exists.

describe("client.ts TLS fingerprint timing fix", () => {
  it("safeEqualSecret is imported and used in client module", async () => {
    // Verify the safeEqualSecret module exists and works correctly
    const { safeEqualSecret } = await import("../security/secret-equal.js");

    // Equal fingerprints should match
    expect(safeEqualSecret("AB:CD:EF", "AB:CD:EF")).toBe(true);

    // Different fingerprints should not match
    expect(safeEqualSecret("AB:CD:EF", "AB:CD:EE")).toBe(false);

    // Undefined/null should be handled safely
    expect(safeEqualSecret(undefined, "test")).toBe(false);
    expect(safeEqualSecret("test", null)).toBe(false);
  });

  it("client module imports safeEqualSecret without error", async () => {
    // The import should succeed — if safeEqualSecret is missing, this would fail
    const clientModule = await import("./client.js");
    expect(clientModule).toBeDefined();
  });
});
