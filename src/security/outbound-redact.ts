import type { OpenClawConfig } from "../config/types.openclaw.js";

/**
 * Redacts known sensitive values from outbound message text.
 *
 * Scans for common secret formats (API keys, tokens, private keys) and
 * dynamically-added sensitive values, replacing any occurrence with
 * `"***REDACTED***"`.
 *
 * Pattern compilation happens once at init. Dynamic secrets are stored in a
 * Set and compiled lazily on the next `redact()` call.
 */

// Minimum length for dynamically-added secrets to avoid false positives.
const MIN_DYNAMIC_SECRET_LENGTH = 8;

const REDACTION_PLACEHOLDER = "***REDACTED***";

// Intermediate sentinel used during multi-pass replacement to prevent
// generic patterns from re-matching values already redacted by specific
// patterns. Contains '&' which is excluded by generic pattern char classes.
// Swapped to the final placeholder at the end of `redact()`.
const SENTINEL = "&REDACTED&";

// ── Static patterns for common secret formats ──────────────────────────────

// Specific high-signal patterns — applied first to avoid generic patterns
// consuming the distinctive prefix portion of structured secrets.
const SPECIFIC_PATTERNS: readonly RegExp[] = [
  /sk_live_[a-zA-Z0-9]{20,}/g, // Stripe live keys (before generic sk-)
  /sk_test_[a-zA-Z0-9]{20,}/g, // Stripe test keys (before generic sk-)
  /sk-[a-zA-Z0-9]{20,}/g, // OpenAI API keys
  /ghp_[a-zA-Z0-9]{36}/g, // GitHub PATs
  /gho_[a-zA-Z0-9]{36}/g, // GitHub OAuth tokens
  /ghs_[a-zA-Z0-9]{36}/g, // GitHub app tokens
  /xox[bpras]-[a-zA-Z0-9-]+/g, // Slack tokens
  /BOT_TOKEN=[^\s&"'`,;]+/gi, // Bot tokens in URLs/params
  /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, // Private keys
];

// Generic param-style patterns — applied after specific patterns so that
// structured secrets (e.g. ghp_...) are already redacted.
const GENERIC_PATTERNS: readonly RegExp[] = [
  /api[_-]?key[=:]\s*[^\s&"'`,;]{8,}/gi, // Generic API key params
  /token[=:]\s*[^\s&"'`,;]{8,}/gi, // Generic token params
  /password[=:]\s*[^\s&"'`,;]{8,}/gi, // Password params
];

// ── Helpers ────────────────────────────────────────────────────────────────

/** Escape a string for safe inclusion in a `RegExp` constructor. */
function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ── Public interface ───────────────────────────────────────────────────────

export interface OutboundRedactor {
  /** Redact known sensitive values from text. */
  redact(text: string): string;
  /** Add a dynamic sensitive value to track (e.g., from config/env). */
  addSensitiveValue(value: string): void;
  /** Get count of redacted values for metrics. */
  readonly redactionCount: number;
}

export interface OutboundRedactorConfig {
  /** Additional patterns to redact. */
  extraPatterns?: RegExp[];
  /** Known sensitive values to redact (e.g., gateway token, API keys from config). */
  knownSecrets?: string[];
}

export function isOutboundRedactionEnabled(config: OpenClawConfig | undefined): boolean {
  return config?.gateway?.security?.enableOutboundRedaction !== false;
}

// ── Factory ────────────────────────────────────────────────────────────────

export function createOutboundRedactor(config?: OutboundRedactorConfig): OutboundRedactor {
  const extraPatterns = config?.extraPatterns ?? [];
  const knownSecrets = config?.knownSecrets ?? [];

  // Static patterns — stored as three ordered groups.
  // 1. Specific high-signal patterns (OpenAI, GitHub, Slack, etc.)
  // 2. User-supplied extra patterns
  // 3. Generic param-style patterns (token=, password=, etc.)
  const specificPatterns: RegExp[] = [...SPECIFIC_PATTERNS];
  const genericPatterns: RegExp[] = [...GENERIC_PATTERNS];

  // Dynamic secret values — added at runtime.
  const dynamicSecrets = new Set<string>();
  let _redactionCount = 0;
  let _dynamicRegexDirty = true;
  let _dynamicRegex: RegExp | null = null;

  // Seed with known secrets that meet the minimum length requirement.
  for (const secret of knownSecrets) {
    if (secret.length >= MIN_DYNAMIC_SECRET_LENGTH) {
      dynamicSecrets.add(secret);
    }
  }

  /** Build (or rebuild) the combined regex for dynamic secrets. */
  function compileDynamicRegex(): void {
    if (dynamicSecrets.size === 0) {
      _dynamicRegex = null;
      _dynamicRegexDirty = false;
      return;
    }
    const escaped = Array.from(dynamicSecrets).map(escapeRegExp);
    // Sort by length descending so longer secrets match first.
    escaped.sort((a, b) => b.length - a.length);
    _dynamicRegex = new RegExp(escaped.join("|"), "g");
    _dynamicRegexDirty = false;
  }

  return {
    addSensitiveValue(value: string): void {
      if (value.length < MIN_DYNAMIC_SECRET_LENGTH) {
        return;
      }
      if (!dynamicSecrets.has(value)) {
        dynamicSecrets.add(value);
        _dynamicRegexDirty = true;
      }
    },

    redact(text: string): string {
      let result = text;

      // 1. Apply specific high-signal patterns (OpenAI, GitHub, Slack, etc.).
      for (const pattern of specificPatterns) {
        pattern.lastIndex = 0;
        result = result.replace(pattern, SENTINEL);
      }

      // 2. Apply extra patterns (user-supplied).
      for (const pattern of extraPatterns) {
        pattern.lastIndex = 0;
        result = result.replace(pattern, SENTINEL);
      }

      // 3. Apply dynamic secret patterns (lazy-compiled).
      if (_dynamicRegexDirty) {
        compileDynamicRegex();
      }
      if (_dynamicRegex) {
        _dynamicRegex.lastIndex = 0;
        result = result.replace(_dynamicRegex, SENTINEL);
      }

      // 4. Apply generic param-style patterns last. These won't match the
      //    null-byte sentinel, so previously-redacted positions are safe.
      for (const pattern of genericPatterns) {
        pattern.lastIndex = 0;
        result = result.replace(pattern, SENTINEL);
      }

      // 5. Swap sentinels to final placeholder and count.
      const sentinelCount = result.split(SENTINEL).length - 1;
      if (sentinelCount > 0) {
        result = result.replaceAll(SENTINEL, REDACTION_PLACEHOLDER);
        _redactionCount += sentinelCount;
      }

      return result;
    },

    get redactionCount(): number {
      return _redactionCount;
    },
  };
}
