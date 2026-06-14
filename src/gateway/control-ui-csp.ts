// Control UI content-security-policy helpers.
// Computes inline script hashes and builds the Gateway-served CSP header.
import { createHash } from "node:crypto";
import { normalizeLowercaseStringOrEmpty } from "@openclaw/normalization-core/string-coerce";

const SCRIPT_ATTRIBUTE_NAME_RE = /\s([^\s=/>]+)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?/g;

/**
 * Compute SHA-256 CSP hashes for inline `<script>` blocks in an HTML string.
 * Only scripts without a `src` attribute are considered inline.
 */
export function computeInlineScriptHashes(html: string): string[] {
  const hashes: string[] = [];
  const re = /<script(?:\s[^>]*)?>([^]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const openTag = match[0].slice(0, match[0].indexOf(">") + 1);
    if (hasScriptSrcAttribute(openTag)) {
      continue;
    }
    const content = match[1];
    if (!content) {
      continue;
    }
    const hash = createHash("sha256").update(content, "utf8").digest("base64");
    hashes.push(`sha256-${hash}`);
  }
  return hashes;
}

function hasScriptSrcAttribute(openTag: string): boolean {
  return Array.from(openTag.matchAll(SCRIPT_ATTRIBUTE_NAME_RE)).some(
    (match) => normalizeLowercaseStringOrEmpty(match[1]) === "src",
  );
}

/** Compute SHA-256 CSP hashes for inline `<style>` blocks in an HTML string. */
export function computeInlineStyleHashes(html: string): string[] {
  const hashes: string[] = [];
  const re = /<style(?:\s[^>]*)?>([^]*?)<\/style>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const content = match[1];
    if (!content?.trim()) {
      continue;
    }
    const hash = createHash("sha256").update(content, "utf8").digest("base64");
    hashes.push(`sha256-${hash}`);
  }
  return hashes;
}

// Default trusted external origins for the Control UI connect-src directive.
// These must be updated if OpenAI API or TweakCN domains change, or replaced
// with a configured allowlist for air-gapped deployments.
const DEFAULT_CONNECT_SRC_EXTERNAL = "https://api.openai.com https://tweakcn.com";

/** Build the CSP header applied to Gateway-served Control UI HTML. */
export function buildControlUiCspHeader(opts?: {
  inlineScriptHashes?: string[];
  inlineStyleHashes?: string[];
  /** Override the default connect-src external origins. Pass an empty string to allow only 'self'. */
  connectSrcExternal?: string;
}): string {
  const hashes = opts?.inlineScriptHashes;
  const scriptSrc = hashes?.length
    ? `script-src 'self' ${hashes.map((h) => `'${h}'`).join(" ")}`
    : "script-src 'self'";
  const styleHashes = opts?.inlineStyleHashes;
  const styleSrcBase = "'self'";
  const styleSrc = styleHashes?.length
    ? `style-src ${styleSrcBase} ${styleHashes.map((h) => `'${h}'`).join(" ")}`
    : `style-src ${styleSrcBase}`;
  // connect-src: always 'self' plus optionally configured external origins.
  // Pass empty string to restrict to 'self' only (strictest CSP for air-gapped).
  const connectSrcExternal = opts?.connectSrcExternal ?? DEFAULT_CONNECT_SRC_EXTERNAL;
  const connectSrc =
    connectSrcExternal.trim().length > 0
      ? `connect-src 'self' ${connectSrcExternal}`
      : "connect-src 'self'";
  return [
    "default-src 'self'",
    "base-uri 'none'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    scriptSrc,
    styleSrc,
    "img-src 'self' data: blob:",
    "media-src 'self' data: blob:",
    "font-src 'self'",
    "worker-src 'self'",
    connectSrc,
  ].join("; ");
}
