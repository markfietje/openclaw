// Compares secret strings with timing-safe equality.
import { timingSafeEqual } from "node:crypto";

function padSecretBytes(bytes: Buffer, length: number): Buffer {
  if (bytes.length === length) {
    return bytes;
  }
  const padded = Buffer.alloc(length);
  bytes.copy(padded);
  return padded;
}

/**
 * Compare two optional UTF-8 secrets without leaking length through
 * `timingSafeEqual` errors. Fail-closed: any absent side returns false so
 * callers never receive a positive match on missing input. Pad-to-max-length
 * keeps the comparison timing roughly constant.
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
  if (providedBytes.length !== expectedBytes.length) {
    return false;
  }
  return timingSafeEqual(providedBytes, expectedBytes);
}
