// Constant-time secret comparison is canonical in gateway-security-core so the
// gateway-client package, src/ host wiring, and the plugin SDK barrel all share
// one implementation. Re-export here so existing src/ call sites keep working.
export { safeEqualSecret } from "@openclaw/gateway-security-core/secret-equal";
