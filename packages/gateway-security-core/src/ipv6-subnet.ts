/**
 * IPv6 address expansion and subnet masking helpers.
 *
 * Shared between the connection-level and request-level rate limiters so
 * rate-limit key generation uses the same canonical address form. The
 * helpers also live in this package so any cross-package caller (gateway
 * code, tests, future tools) can share the same masking semantics.
 *
 * IPv6 rate limiting follows OWASP guidance: ISPs and mobile carriers
 * delegate /56 or /64 prefixes to a single subscriber, so iterating every
 * address inside that prefix should be treated as the same client.
 */

/** Number of 16-bit blocks in a fully-expanded IPv6 address. */
const IPV6_BLOCK_COUNT = 8;

/**
 * Expand `::` compression to a full 8-block IPv6 address so masking
 * operates on a predictable number of blocks. Already-expanded addresses
 * are returned unchanged.
 */
export function expandIPv6(address: string): string {
  if (!address.includes("::")) {
    return address;
  }
  const halves = address.split("::");
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves[1] ? halves[1].split(":") : [];
  const missing = IPV6_BLOCK_COUNT - left.length - right.length;
  const expanded = [...left, ...Array(missing).fill("0"), ...right];
  return expanded.map((p) => p.padStart(4, "0")).join(":");
}

/**
 * Apply a bitwise subnet mask to an IPv6 address.
 * For example /56 keeps 3 full 16-bit blocks and masks the 4th to
 * the first 8 bits (e.g. "abcd" -> "ab00"). /128 returns the address
 * unchanged. Out-of-range masks are clamped to 0..128.
 */
export function applyIpv6SubnetMask(address: string, maskBits: number): string {
  const expanded = expandIPv6(address);
  const parts = expanded.split(":");
  const safeMask = Math.max(0, Math.min(128, Math.floor(maskBits)));
  const fullBlocks = Math.floor(safeMask / 16);
  const remainingBits = safeMask % 16;

  const result: string[] = [];

  for (let i = 0; i < fullBlocks && i < parts.length; i++) {
    result.push(parts[i]);
  }

  if (remainingBits > 0 && fullBlocks < parts.length) {
    const blockValue = Number.parseInt(parts[fullBlocks], 16);
    const safeBlockValue = Number.isFinite(blockValue) ? blockValue : 0;
    const mask = 0xffff << (16 - remainingBits);
    result.push((safeBlockValue & mask).toString(16).padStart(4, "0"));
  }

  while (result.length < IPV6_BLOCK_COUNT) {
    result.push("0000");
  }

  return result.join(":");
}
