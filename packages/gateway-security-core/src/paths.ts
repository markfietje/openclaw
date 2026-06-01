/**
 * Local re-export of the state-directory resolver so package modules can
 * resolve runtime paths without crossing the package boundary for a single
 * helper. Keep this barrel narrow — only expose what is consumed inside
 * `@openclaw/gateway-security-core`.
 */
export { resolveStateDir } from "../../../src/config/paths.js";
