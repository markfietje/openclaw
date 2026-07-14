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
  entry: ["src/index.ts", "src/ip.ts"],
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
