/**
 * Security hardening configuration types for the OpenClaw gateway.
 *
 * This is the canonical type definition for `gateway.security.*` config.
 * `src/config/types.gateway.ts` re-exports from here.
 * `src/config/zod-schema.ts` validates the same field names at runtime.
 *
 * Organized by OWASP defense-in-depth layers:
 *   Layer 0 — Transport (TLS)
 *   Layer 1 — Pre-Handshake (verifyClient pipeline, steps 0–5)
 *   Layer 2 — Authentication (nonce challenge, step 6)
 *   Layer 3 — Authorization (capability gating, steps 7–8)
 *   Layer 4 — Operational (keep-alive, rate limiting, steps 9–10)
 *
 * @see docs/gateway/security/FORK_SECURITY.md
 * @see OWASP WebSocket Security Cheat Sheet (2025)
 * @see src/gateway/server/verify-client.ts — pre-handshake pipeline
 */

// ---------------------------------------------------------------------------
// Sub-types owned by their respective modules
// ---------------------------------------------------------------------------

export type { ConnectionRateLimitConfig } from "./connection-rate-limit.js";
export type { WsKeepaliveConfig } from "./ws-keepalive.js";

// Import for inline use in GatewaySecurityConfig fields.
import type { ConnectionRateLimitConfig } from "./connection-rate-limit.js";

// ---------------------------------------------------------------------------
// Audit flag (shared shape for authAudit, toolAudit, messageAuth)
// ---------------------------------------------------------------------------

/**
 * Generic audit toggle. Shared shape for authAudit, toolAudit, messageAuth.
 */
export type GatewayAuditFlagConfig = {
  /** Enable this audit/category. */
  enabled?: boolean;
};

// ---------------------------------------------------------------------------
// Main config type — organized by defense layer
// ---------------------------------------------------------------------------

/**
 * Security hardening configuration for the OpenClaw gateway.
 *
 * All features are default-on unless marked opt-in.
 * "DANGEROUS" prefixed fields are escape hatches that weaken security.
 *
 * @see docs/gateway/security/FORK_SECURITY.md
 * @see src/gateway/server/verify-client.ts — pre-handshake pipeline
 */
export type GatewaySecurityConfig = {
  // ─── Layer 0: Transport ────────────────────────────────────────────

  /**
   * Minimum TLS version for gateway HTTPS listeners.
   * OWASP Transport Layer Security Cheat Sheet: enforce TLS 1.3 minimum.
   * @default "TLSv1.3"
   */
  tlsMinVersion?: "TLSv1.2" | "TLSv1.3";

  // ─── Layer 1: Pre-Handshake (verifyClient pipeline) ────────────────

  /**
   * Reject duplicate/chained X-Forwarded-* headers (comma-separated values).
   * FORK_SECURITY.md § test_04, test_05. CWE-345.
   * verifyClient step 1.
   * @default true
   */
  strictHeaderValidation?: boolean;

  /**
   * Reject proxy headers (X-Forwarded-For/Host/Proto, Forwarded)
   * from IPs not in gateway.trustedProxies.
   * FORK_SECURITY.md § test_07. CWE-345.
   * verifyClient step 2.
   * @default true
   */
  rejectUntrustedProxyHeaders?: boolean;

  /**
   * Auto-disable localhost loopback privilege when proxy headers are present.
   * Prevents Tailscale Serve loopback bypass.
   * FORK_SECURITY.md § test_06. CWE-346.
   * verifyClient step 3.
   * @default true
   */
  autoDisableLocalhostBehindProxy?: boolean;

  /**
   * Whether the loopback client gets implicit privilege (auto-paired).
   * @default true
   */
  disableLocalhostPrivilege?: boolean;

  /**
   * Validate Host header against the allowlist.
   * @default false
   */
  validateHostHeader?: boolean;

  /**
   * Reject when forwarded-proto does not match the Origin scheme.
   * Detects SSL stripping / protocol downgrade.
   * FORK_SECURITY.md § test_03, test_14. CWE-346.
   * verifyClient step 3.
   * @default true
   */
  strictProtoValidation?: boolean;

  /**
   * Enforce origin check for non-browser clients (those without Origin header).
   * Default false: non-browser clients (CLI, native) typically omit Origin.
   * Enable for internet-facing deployments where all clients are known.
   * FORK_SECURITY.md § test_01.
   * @default false (opt-in)
   */
  enforceOriginCheckForAllClients?: boolean;

  /**
   * IP allowlist (CIDR notation). When set, only matching IPs can connect.
   * Blocklist takes precedence over allowlist. Unknown IPs fail closed.
   * FORK_SECURITY.md § test_08. CWE-284. verifyClient step 4.
   */
  ipAllowlist?: string[];

  /**
   * IP blocklist (CIDR notation). Takes precedence over allowlist.
   * FORK_SECURITY.md § test_08. CWE-284.
   */
  ipBlocklist?: string[];

  /** Legacy IP allow/deny list (deprecated: use ipAllowlist/ipBlocklist). */
  ipRestriction?: {
    allow?: string[];
    deny?: string[];
  };

  /**
   * Require the `openclaw-gateway-v1` WebSocket subprotocol header on upgrade.
   * FORK_SECURITY.md § Backward Compatibility.
   * verifyClient step 5.
   * @default true
   */
  requireSubprotocol?: boolean;

  /**
   * Global WebSocket connection limit. Rejects new connections when reached.
   * OWASP: enforce resource limits. CWE-770. verifyClient step 0.
   * @default 64
   */
  maxWebSocketConnections?: number;

  /**
   * Pre-handshake per-IP connection rate limit configuration.
   * FORK_SECURITY.md § test_09. CWE-770. verifyClient step 0b.
   */
  connectionRateLimit?: ConnectionRateLimitConfig;

  /**
   * Max WebSocket message payload in bytes.
   * Clamped to [64 KB, 100 MB]. Pre-auth limit is always 64 KB.
   * FORK_SECURITY.md § Operational Hardening. CWE-770.
   * @default 26_214_400 (25 MB)
   * @see src/gateway/server-constants.ts — resolveMaxPayloadBytes
   */
  maxPayloadBytes?: number;

  // ─── Layer 2: Authentication ───────────────────────────────────────

  /**
   * Enable nonce-based handshake token challenge.
   * FORK_SECURITY.md § Post-Handshake step 6.
   * @default true
   */
  enableHandshakeTokens?: boolean;

  // ─── Layer 3: Authorization ────────────────────────────────────────

  /**
   * Enable per-message capability gating (80+ methods mapped).
   * FORK_SECURITY.md § test_10. CWE-862.
   * @default true
   */
  enableMessageAuthorization?: boolean;

  /**
   * Allow unmapped RPC methods to execute without capability check.
   * DANGEROUS — weakens authorization. FORK_SECURITY.md § test_10.
   * @default false
   */
  dangerouslyAllowUnmappedMethods?: boolean;

  /**
   * Grant wildcard `*` capabilities on unknown WS paths.
   * DANGEROUS — allows endpoint confusion attacks.
   * FORK_SECURITY.md § test_13. CWE-862.
   * @default false
   */
  dangerouslyAllowLegacyEndpointFallback?: boolean;

  /**
   * Fall back to Host header when Origin is missing.
   * DANGEROUS — weakens origin validation.
   * Use only behind a trusted reverse proxy.
   * @default false
   */
  dangerouslyAllowHostHeaderOriginFallback?: boolean;

  // ─── Layer 4: Operational ──────────────────────────────────────────

  /**
   * Enable WebSocket ping/pong keep-alive with dead-connection detection.
   * Prevents silent drops behind reverse proxies.
   * @default true
   */
  enablePingPong?: boolean;

  /**
   * Interval between ping frames in milliseconds.
   * Only effective when enablePingPong is true.
   * @default 25_000 (25 s)
   */
  pingIntervalMs?: number;

  /**
   * Time to wait for pong response before closing connection.
   * Only effective when enablePingPong is true.
   * @default 10_000 (10 s)
   */
  pongTimeoutMs?: number;

  /**
   * Enable post-handshake per-connection frame/message rate limiting.
   * FORK_SECURITY.md § test_09.
   * @default true
   */
  enableRateLimiting?: boolean;

  // ─── Observability ─────────────────────────────────────────────────

  /** Whether to redact known secret values from outbound gateway messages. */
  enableOutboundRedaction?: boolean;

  /** Per-method rate limits (method name → requests per minute). */
  methodRateLimits?: Record<string, number>;

  /** Connection rate limit (connections per minute per IP). Legacy scalar. */
  connectionRateLimitPerMinute?: number;

  /** Browser origin fallback rate limit (per IP, per minute). */
  browserRateLimitPerMinute?: number;

  /**
   * Auth audit: append-only HMAC-signed record of accepted/rejected
   * connect attempts. Env override: OPENCLAW_AUTH_AUDIT=1.
   */
  authAudit?: GatewayAuditFlagConfig;

  /**
   * Tool audit: append-only HMAC-signed record of every tools/invoke
   * surface tool call.
   */
  toolAudit?: GatewayAuditFlagConfig;

  /**
   * Per-message auth for defense-in-depth capability gating
   * (secrets, config-protected, node-role methods).
   * When enabled, extra capability checks run beyond standard operator scope.
   */
  messageAuth?: GatewayAuditFlagConfig;
};
