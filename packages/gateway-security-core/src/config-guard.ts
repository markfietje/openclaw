/**
 * Protected config path guard.
 *
 * Prevents unauthorized modification of security-sensitive config paths
 * via config.set / config.patch. Protected paths require the `admin:config`
 * capability, which is only granted to local loopback operators with the
 * wildcard `*` scope.
 *
 * @see FORK_SECURITY.md § test_11 — config.set auth persistence
 */

export const PROTECTED_CONFIG_PATHS = [
  "gateway.auth",
  "gateway.tailscale",
  "gateway.security",
  "gateway.trustedProxies",
  "gateway.bind",
  "gateway.port",
] as const;

export type ProtectedConfigPath = (typeof PROTECTED_CONFIG_PATHS)[number];

export function isProtectedConfigPath(path: string): boolean {
  const normalized = path.trim().replace(/\.+$/, "");
  if (!normalized) {
    return false;
  }
  return PROTECTED_CONFIG_PATHS.some(
    (protectedPrefix) =>
      normalized === protectedPrefix || normalized.startsWith(`${protectedPrefix}.`),
  );
}

export function hasProtectedConfigPath(changedPaths: readonly string[]): boolean {
  return changedPaths.some((path) => isProtectedConfigPath(path));
}

export function filterProtectedPaths(changedPaths: readonly string[]): string[] {
  return changedPaths.filter((path) => isProtectedConfigPath(path));
}

export function assertNoProtectedPaths(changedPaths: readonly string[]): string | null {
  const protectedPaths = filterProtectedPaths(changedPaths);
  if (protectedPaths.length === 0) {
    return null;
  }
  return `protected config paths require admin:config capability: ${protectedPaths.join(", ")}`;
}
