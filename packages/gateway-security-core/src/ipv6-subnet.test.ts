import { describe, expect, it } from "vitest";
import { applyIpv6SubnetMask, expandIPv6 } from "./ipv6-subnet.js";

describe("expandIPv6", () => {
  it("returns already-expanded addresses unchanged", () => {
    expect(expandIPv6("2001:0db8:0000:0000:0000:0000:0000:0001")).toBe(
      "2001:0db8:0000:0000:0000:0000:0000:0001",
    );
  });

  it("expands trailing ::1", () => {
    expect(expandIPv6("::1")).toBe("0000:0000:0000:0000:0000:0000:0000:0001");
  });

  it("expands leading ::", () => {
    expect(expandIPv6("::")).toBe("0000:0000:0000:0000:0000:0000:0000:0000");
  });

  it("expands mid ::", () => {
    expect(expandIPv6("2001:db8::1")).toBe("2001:0db8:0000:0000:0000:0000:0000:0001");
  });

  it("expands address with multiple consecutive zero blocks", () => {
    expect(expandIPv6("fe80::1:2:3:4")).toBe("fe80:0000:0000:0000:0001:0002:0003:0004");
  });
});

describe("applyIpv6SubnetMask", () => {
  it("returns the full address for /128", () => {
    expect(applyIpv6SubnetMask("2001:db8::1", 128)).toBe("2001:0db8:0000:0000:0000:0000:0000:0001");
  });

  it("zeroes the address for /0", () => {
    expect(applyIpv6SubnetMask("2001:db8::1", 0)).toBe("0000:0000:0000:0000:0000:0000:0000:0000");
  });

  it("masks to /56 boundary (3 full blocks + first 8 bits of 4th)", () => {
    expect(applyIpv6SubnetMask("2001:0db8:abcd:1234::1", 56)).toBe(
      "2001:0db8:abcd:1200:0000:0000:0000:0000",
    );
  });

  it("masks to /64 boundary (4 full blocks)", () => {
    expect(applyIpv6SubnetMask("2001:0db8:abcd:1234:5678:9abc:def0:1234", 64)).toBe(
      "2001:0db8:abcd:1234:0000:0000:0000:0000",
    );
  });

  it("clamps negative mask to 0", () => {
    expect(applyIpv6SubnetMask("2001:db8::1", -10)).toBe("0000:0000:0000:0000:0000:0000:0000:0000");
  });

  it("clamps mask > 128 to 128", () => {
    expect(applyIpv6SubnetMask("2001:db8::1", 256)).toBe("2001:0db8:0000:0000:0000:0000:0000:0001");
  });

  it("is idempotent (masking twice at the same width is a no-op)", () => {
    const once = applyIpv6SubnetMask("2001:0db8:abcd:1234::1", 56);
    const twice = applyIpv6SubnetMask(once, 56);
    expect(twice).toBe(once);
  });

  it("is monotonic: smaller masks produce a coarser address than larger ones", () => {
    const a48 = applyIpv6SubnetMask("2001:0db8:abcd:1234:5678::1", 48);
    const a56 = applyIpv6SubnetMask("2001:0db8:abcd:1234:5678::1", 56);
    const a64 = applyIpv6SubnetMask("2001:0db8:abcd:1234:5678::1", 64);
    // Each larger mask preserves more bits (more non-zero blocks possible)
    expect(a48.startsWith("2001:0db8:abcd:0000")).toBe(true);
    expect(a56.startsWith("2001:0db8:abcd:1200")).toBe(true);
    expect(a64.startsWith("2001:0db8:abcd:1234")).toBe(true);
  });

  it("groups two addresses in the same /56 into the same key", () => {
    const a = applyIpv6SubnetMask("2001:0db8:abcd:1234::1", 56);
    const b = applyIpv6SubnetMask("2001:0db8:abcd:12ff:ffff::1", 56);
    expect(a).toBe(b);
  });

  it("separates two addresses in different /56s", () => {
    const a = applyIpv6SubnetMask("2001:0db8:abcd:1234::1", 56);
    const b = applyIpv6SubnetMask("2001:0db8:abcd:1300::1", 56);
    expect(a).not.toBe(b);
  });

  it("preserves the link-local /10 prefix at /10", () => {
    expect(applyIpv6SubnetMask("fe80::1", 10)).toBe("fe80:0000:0000:0000:0000:0000:0000:0000");
  });
});
