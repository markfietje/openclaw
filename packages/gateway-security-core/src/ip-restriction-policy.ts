import { isIpInCidr, normalizeIpAddress } from "@openclaw/net-policy/ip";

/**
 * IP restriction configuration for gateway access control.
 */
export interface IpRestrictionConfig {
  /**
   * IP addresses/networks allowed to access the gateway.
   * Supports CIDR notation (e.g., "192.168.1.0/24") and individual IPs.
   * When set, only clients from these IPs/networks can connect.
   */
  ipAllowlist?: string[];

  /**
   * IP addresses/networks blocked from gateway access.
   * Supports CIDR notation and individual IPs.
   * Takes precedence over ipAllowlist.
   */
  ipBlocklist?: string[];
}

/**
 * Checks if an IP address matches any entry in a list.
 * Supports both individual IPs and CIDR notation.
 */
function ipMatchesList(ip: string, list: string[]): boolean {
  const normalized = normalizeIpAddress(ip);
  if (!normalized) {
    return false;
  }

  for (const entry of list) {
    const trimmed = entry.trim();
    if (!trimmed) {
      continue;
    }

    const normalizedEntry = normalizeIpAddress(trimmed);
    if (normalizedEntry && normalized === normalizedEntry) {
      return true;
    }

    if (trimmed.includes("/")) {
      try {
        if (isIpInCidr(normalized, trimmed)) {
          return true;
        }
      } catch {
        console.warn(`[IP Restriction] Invalid CIDR entry skipped: "${trimmed}"`);
      }
    }
  }

  return false;
}

/**
 * Checks if a client IP is allowed based on IP restriction configuration.
 *
 * Logic:
 * 1. If blocklist is set and IP matches → BLOCK (takes precedence)
 * 2. If allowlist is set → IP must match to be ALLOWED
 * 3. If neither is set → ALLOW all
 */
export function isIpAllowed(clientIp: string | undefined, config: IpRestrictionConfig): boolean {
  const allowlist = config.ipAllowlist ?? [];
  const blocklist = config.ipBlocklist ?? [];

  if (allowlist.length === 0 && blocklist.length === 0) {
    return true;
  }

  if (!clientIp) {
    return false;
  }

  if (blocklist.length > 0 && ipMatchesList(clientIp, blocklist)) {
    return false;
  }

  if (allowlist.length > 0) {
    return ipMatchesList(clientIp, allowlist);
  }

  return true;
}
