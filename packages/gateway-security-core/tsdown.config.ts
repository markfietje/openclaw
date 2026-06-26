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
    "src/connection-rate-limit.ts",
    "src/device-session-authority.ts",
    "src/exec-deny-paths.ts",
    "src/ip-restriction-policy.ts",
    "src/ip.ts",
    "src/request-rate-limit.ts",
    "src/sliding-window-store.ts",
    "src/startup-security-checks.ts",
    "src/tool-audit.ts",
    "src/ws-endpoint.ts",
    "src/ws-protocol.ts",
    "src/config-guard.ts",
    "src/ws-frame-validator.ts",
    "src/ws-keepalive.ts",
    "src/security-config.ts",
    "src/message-replay-guard.ts",
    "src/secret-equal.ts",
    "src/credential-vault.ts",
    "src/credential-keystore.ts",
    "src/credential-vault-cache.ts",
    "src/credential-store-cell.ts",
  ],
  platform: "node",
  format: "esm",
  dts: true,
  outDir: "dist",
  clean: true,
  external: isCrossPackageImport,
  outputOptions: {
    // Stable chunk names without content hashes so the package.json "exports"
    // map can reference them deterministically.
    chunkFileNames: "chunks/[name].mjs",
  },
});
