import { defineConfig } from "tsdown";

/**
 * Externalize cross-package relative imports so the bundler does not try to
 * follow them out of the package root. The relative path stays in the emitted
 * import; resolution happens at runtime via the source tree.
 */
function isCrossPackageImport(id: string): boolean {
  return id.startsWith("../../../src/");
}

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/auth-audit-log.ts",
    "src/capabilities.ts",
    "src/connection-rate-limit.ts",
    "src/device-session-authority.ts",
    "src/exec-deny-paths.ts",
    "src/ip-restriction-policy.ts",
    "src/message-auth.ts",
    "src/net-helpers.ts",
    "src/paths.ts",
    "src/request-rate-limit.ts",
    "src/startup-security-checks.ts",
    "src/tool-audit.ts",
    "src/ws-endpoint.ts",
    "src/ws-protocol.ts",
  ],
  platform: "node",
  format: "esm",
  dts: true,
  outDir: "dist",
  clean: true,
  external: isCrossPackageImport,
});
