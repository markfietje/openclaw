// Compares secret strings with timing-safe equality.
import { timingSafeEqual } from "node:crypto";

/**
 * Compare two optional UTF-8 secrets without leaking length through
 * `timingSafeEqual` errors. Fail-closed: any absent side returns false so
 * callers never receive a positive match on missing input.
 * OWASP Authentication Cheat Sheet — constant-time comparison.
 * Pads to equal length so timing does not leak byte count.
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
