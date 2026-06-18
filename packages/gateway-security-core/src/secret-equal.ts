// Canonical constant-time secret comparison.
//
// Lives in gateway-security-core so every gateway surface (the gateway-client
// package, src/ host wiring, and plugins via the SDK barrel) shares one
// implementation. src/security/secret-equal.ts re-exports this module so
// existing call sites keep working.
//
// OWASP Authentication Cheat Sheet — "Compare user-supplied passwords against
// stored password hashes using secure functions ... [that] protect against
// denial of service attacks, type confusion, and timing attacks by having
// maximum input lengths, explicit type checking, and constant-time execution."
// Verified against OWASP Cheat Sheet Series via Context7 on 2026-06-18.
import { timingSafeEqual } from "node:crypto";

/**
 * Compare two optional UTF-8 secrets without leaking length through
 * `timingSafeEqual` errors. Fail-closed: any absent side returns false so
 * callers never receive a positive match on missing input.
 *
 * Pads both buffers to equal length so timing does not leak the byte count,
 * then XORs the length check into the timing-safe result so length mismatches
 * still return false but only after constant work.
 */
export function safeEqualSecret(
  provided: string | undefined | null,
  expected: string | undefined | null,
): boolean {
  if (typeof provided !== "string" || typeof expected !== "string") {
    return false;
  }
  if (provided.length === 0 || expected.length === 0) {
    return false;
  }
  const providedBytes = Buffer.from(provided, "utf8");
  const expectedBytes = Buffer.from(expected, "utf8");
  // Pad both buffers to the same length so timingSafeEqual always runs
  // for the same duration regardless of length mismatch.
  const maxLen = Math.max(providedBytes.length, expectedBytes.length);
  const paddedProvided = Buffer.alloc(maxLen);
  const paddedExpected = Buffer.alloc(maxLen);
  providedBytes.copy(paddedProvided);
  expectedBytes.copy(paddedExpected);
  // XOR the real length check into the timing-safe result so we still
  // return false for length mismatches, but after constant work.
  const lengthMatch = providedBytes.length === expectedBytes.length;
  return timingSafeEqual(paddedProvided, paddedExpected) && lengthMatch;
}
