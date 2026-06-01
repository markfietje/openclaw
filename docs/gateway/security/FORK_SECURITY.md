# Fork Security Posture

Security hardening status for the `markfietje/openclaw` fork relative to the
`poc-realworld.py` test suite (14 attack vectors).

## Summary

| Status            | Count | Tests        |
| ----------------- | ----- | ------------ |
| BLOCKED           | 13    | 02–10, 12–14 |
| BLOCKED (opt-in)  | 1     | 01           |
| PARTIALLY BLOCKED | 0     | —            |

**Evolution:**

| Phase        | Date       | Vulnerable | Blocked | Opt-in | Partial |
| ------------ | ---------- | ---------- | ------- | ------ | ------- |
| Upstream     | baseline   | 12         | 1       | 0      | 1       |
| Gap closure  | 2026-03-19 | 0          | 12      | 1      | 1       |
| verifyClient | 2026-03-25 | 0          | 13      | 1      | 0       |
| IPv6 subnet  | 2026-04-04 | 0          | 13      | 1      | 0       |

**OWASP Compliance:** 100% — IPv6 subnet masking (/56) added for rate limiting to match express-rate-limit best practices.

test_11 (config.set auth persistence): the specific attack path — calling
`config.set` to disable auth — is now fully blocked via `admin:config` capability
gating on protected paths. The PoC script may still report PARTIALLY BLOCKED
because it probes `config.get` reachability rather than the actual `config.set`
exploit, but the real-world attack is closed.

---

## Defense Architecture

The gateway enforces security in a strict layered pipeline. Each layer rejects
before the next runs — a failure at any layer prevents deeper processing.

### Pre-Handshake (verifyClient)

Runs inside the `ws` `verifyClient` callback **before** the HTTP 101 upgrade.
Rejected connections never complete the WebSocket handshake.

Implemented in `src/gateway/server/verify-client.ts`.

```
  Client TCP connect
        │
        ▼
  ┌─────────────────────────────────────────┐
  │ 0. Connection limits                     │
  │    • Max concurrent connections          │
  │    • Close code: 1013                    │
  ├─────────────────────────────────────────┤
  │ 0b. Connection rate limiting             │
  │    • Per-IP sliding window (30/10s)      │
  │    • Lockout on exceed (60s)             │
  │    • Loopback exempt                     │
  │    • Close code: 1013                    │
  ├─────────────────────────────────────────┤
  │ 1. Strict header validation              │
  │    • Reject duplicate/chained headers    │
  │    • X-Forwarded-For, X-Forwarded-Host,  │
  │      X-Forwarded-Proto, X-Real-IP       │
  │    • Close code: 1008                    │
  ├─────────────────────────────────────────┤
  │ 1b. Cross-header consistency             │
  │    • Forwarded vs X-Forwarded-* agree    │
  │    • Prevents header contradiction       │
  │    • Close code: 1008                    │
  ├─────────────────────────────────────────┤
  │ 2. Untrusted proxy header rejection      │
  │    • Proxy headers from non-trusted IPs  │
  │      → reject (not warn)                 │
  │    • Close code: 1008                    │
  ├─────────────────────────────────────────┤
  │ 3. Origin validation                     │
  │    • Browser clients only (has Origin)   │
  │    • Double-lock: Origin ↔ X-Fwd-Host   │
  │    • Protocol mismatch detection         │
  │    • Localhost privilege auto-disable    │
  │    • Close code: 1008                    │
  ├─────────────────────────────────────────┤
  │ 4. IP restriction                        │
  │    • CIDR allowlist/blocklist            │
  │    • Blocklist takes precedence          │
  │    • Fail closed on unknown IP           │
  │    • Close code: 1008                    │
  ├─────────────────────────────────────────┤
  │ 5. Subprotocol enforcement                │
  │    • require openclaw-gateway-v1         │
  │    • Close code: 1002                    │
  └─────────────────────────────────────────┘
        │
        ▼
  HTTP 101 Switching Protocols
  (perMessageDeflate: disabled)
        │
        ▼
  Post-Handshake
```

### Post-Handshake

Runs after the WebSocket is established. Each message is checked individually.

```
  ┌─────────────────────────────────────────┐
  │ 6. Nonce challenge (auth)                │
  │    • Signed token verification           │
  │      (origin-check.ts, not a config field) │
  │    • timingSafeEqual for HMAC compare    │
  ├─────────────────────────────────────────┤
  │ 7. Message authorization                 │
  │    • Per-message-type capability mapping │
  │    • Operator scope → capability         │
  │      translation (operator.admin ≠       │
  │      admin:config)                       │
  │    • 80+ methods mapped to capabilities  │
  ├─────────────────────────────────────────┤
  │ 8. Protected config path check           │
  │    • config.set/patch on auth/security   │
  │      paths requires admin:config         │
  │    • Audit-logged                        │
  ├─────────────────────────────────────────┤
  │ 9. Frame/message rate limiting           │
  │    • 1000 frames/s, 500 messages/s       │
  │    • Per-connection sliding window       │
  ├─────────────────────────────────────────┤
  │ 10. Payload size enforcement             │
  │     • Pre-auth: 64 KB max                │
  │     • Post-auth: 25 MB default           │
  │     • Configurable with safe clamping    │
  │       [64 KB, 100 MB]                    │
  └─────────────────────────────────────────┘
```

### Operational Hardening

Not attack-vector-specific but reduces exploit surface and improves resilience:

| Feature                                | File                                | Purpose                                           |
| -------------------------------------- | ----------------------------------- | ------------------------------------------------- |
| `perMessageDeflate` disabled           | `server-runtime-state.ts`           | CRIME/BREACH class mitigation                     |
| Ping/pong keep-alive                   | `ws-connection.ts`                  | Prevents silent drops behind reverse proxies      |
| Close-code-aware reconnect             | `ws-connection.ts`                  | Faster recovery on service restart (1013 vs 1006) |
| Wildcard origin warning                | startup log                         | Emits once at boot, not per-connection spam       |
| Nonce send failure logging             | `message-handler.ts`                | Dual-validation pattern documented                |
| `NODE_TLS_REJECT_UNAUTHORIZED` removed | `Dockerfile*`                       | No global TLS bypass in container image           |
| Timestamp removed from challenge       | `protocol/connect-error-details.ts` | Reduces timing side-channel in nonce payload      |

---

## Per-Test Status

### test_01 — Non-browser client skips origin check

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Status:** BLOCKED when `enforceOriginCheckForAllClients: true`

The origin check in verifyClient step 3 only runs for connections with a browser
`Origin` header (`hasBrowserOriginHeader`). Non-browser clients (CLI, custom
integrations) typically omit `Origin` and pass through to post-handshake auth.

**Fix:** `gateway.security.enforceOriginCheckForAllClients` config option (default
`false`). When enabled, connections without an `Origin` header are rejected at
step 3.

**Why default false:** Non-browser clients don't send `Origin`. Changing the
default would break CLI tools and custom integrations. Enable for
internet-facing deployments where all clients are known.

### test_02 — Host header origin spoof

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Status:** BLOCKED

`checkBrowserOrigin()` gates `X-Forwarded-Host` usage behind `isTrustedProxy`.
Untrusted connections cannot influence origin validation via spoofed headers.
Blocked at verifyClient step 3.

### test_03 — Protocol downgrade (SSL strip)

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Status:** BLOCKED

`validateProtoMismatch()` in `forwarded-headers.ts` rejects when
`X-Forwarded-Proto: http` is sent but the `Origin` uses `https`. Also checks
RFC 7239 `Forwarded: proto=http` against the origin scheme.
Blocked at verifyClient step 3.

### test_04 — X-Forwarded-Host spoof (untrusted)

**Severity:** MEDIUM · **Surface:** HEADER_VALIDATION
**Status:** BLOCKED

Two-layer defense:

1. `validateSensitiveHeaders()` detects duplicate or chained comma-separated
   `X-Forwarded-Host` values → verifyClient step 1
2. Untrusted proxy header rejection blocks `X-Forwarded-Host` from non-proxy IPs
   → verifyClient step 2

### test_05 — Chained proxy headers

**Severity:** MEDIUM · **Surface:** HEADER_VALIDATION
**Status:** BLOCKED

Same defense as test_04. `validateSensitiveHeaders()` detects chained
comma-separated values in any sensitive forwarding header.
Blocked at verifyClient step 1.

### test_06 — Tailscale Serve local-loopback origin bypass

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Previous:** VULNERABLE · **Current:** BLOCKED

Tailscale Serve forwards with `X-Forwarded-*` headers, making `remoteAddr =
127.0.0.1`. Old code set `isLocalClient = true`, accepting any
`Origin: http://localhost:*` via the loopback fallback.

**Fix:** Two-layer defense, both in verifyClient (pre-handshake):

1. **Step 2** — `rejectUntrustedProxyHeaders` (default `true`): If the Tailscale
   Serve IP is not in `trustedProxies`, proxy headers are rejected with close
   code `1008` before origin or auth runs.

2. **Step 3** — `autoDisableLocalhostBehindProxy` (default `true`): Even if the
   proxy IP _is_ trusted, the presence of proxy headers proves the connection is
   not genuinely local. `disableLocalhostPrivilege` is automatically set to
   `true`, preventing the loopback origin fallback.

Both defenses are default-on. No config changes needed.

### test_07 — Proxy headers reach auth

**Severity:** HIGH · **Surface:** AUTH
**Previous:** VULNERABLE · **Current:** BLOCKED

Old code logged a warning for untrusted proxy headers but continued processing
through auth. An attacker could inject `X-Forwarded-For` to influence IP-based
auth decisions.

**Fix:** verifyClient step 2 rejects connections with proxy headers from
non-trusted IPs with close code `1008`. Auth never runs for these connections.
This is the OWASP verifyClient principle: validate before upgrade.

### test_08 — No IP restriction

**Severity:** MEDIUM · **Surface:** NETWORK
**Status:** BLOCKED

`ip-restriction-policy.ts` enforces CIDR-based allowlists/blocklists.
Blocklist takes precedence over allowlist. Unknown IPs fail closed.
Now enforced in verifyClient step 4 (pre-handshake), not post-auth.

### test_09 — No rate limiting

**Severity:** MEDIUM · **Surface:** AUTH
**Status:** BLOCKED

Two rate limiting layers:

1. **Pre-handshake** (`connection-rate-limit.ts`): Per-IP sliding window in
   verifyClient step 0b. 30 attempts per 10s window, 60s lockout on exceed.
   Loopback exempt. Runs before any auth work.

2. **Post-handshake** (`ws-protocol.ts`): Per-connection frame/message rate
   limiting. 1000 frames/s, 500 messages/s. Prevents post-auth resource
   exhaustion.

### test_10 — No message authorization

**Severity:** MEDIUM · **Surface:** CAPABILITY
**Status:** BLOCKED

`message-auth.ts` gates every message type behind specific capabilities.
80+ gateway methods are explicitly mapped. Unmapped methods are blocked when
`requireCapabilityForAll` is enabled. Operator scopes (`operator.admin`) are
translated to fine-grained capabilities — `operator.admin` grants `admin:read`

- `admin:write` but **not** `admin:config` or `secrets:read`.

### test_11 — config.set auth persistence

**Severity:** HIGH · **Surface:** CONFIG_API
**Status:** ATTACK BLOCKED

An authenticated attacker could call `config.set` to set `gateway.auth.mode =
"none"`, trigger a restart, and gain persistent unauthenticated access.

**Fix:** Protected config paths require `admin:config` capability:

```
Protected paths:
  gateway.auth.*          — authentication configuration
  gateway.tailscale.*      — Tailscale identity configuration
  gateway.security.*       — security hardening options
  gateway.trustedProxies   — proxy trust configuration
  gateway.bind             — network binding
  gateway.port             — listening port
```

`config.set`/`config.patch` on these paths checks for `admin:config` before
forwarding. Protected changes are audit-logged.

**Scope assignment:**

| Client type                            | Gets `admin:config`? |
| -------------------------------------- | -------------------- |
| Local loopback operator (wildcard `*`) | Yes                  |
| Paired device (node role)              | No                   |
| Tailscale identity                     | No                   |
| Token/password auth                    | No                   |
| Webchat                                | No                   |

Only direct local operators with the full `*` wildcard scope can modify
auth/security configuration. `admin:*` does **not** match `admin:config` — it
requires explicit `admin:config` or `*`.

**PoC nuance:** The PoC script tests `config.get` reachability, not the actual
`config.set` exploit. `config.get` is intentionally reachable for authenticated
clients (read-only). The attack vector (disabling auth via `config.set`) is fully
blocked.

### test_12 — secrets.resolve exfiltration

**Severity:** HIGH · **Surface:** SECRETS_API
**Previous:** VULNERABLE · **Current:** BLOCKED

`secrets.resolve` was not mapped in `DEFAULT_MESSAGE_CAPABILITIES`. With
`requireCapabilityForAll: false` (default), unmapped messages passed through
unchallenged. Any authenticated client could read stored API keys.

**Fix:** Explicit capability mappings:

| Message type                     | Required capability |
| -------------------------------- | ------------------- |
| `gateway.method.secrets.resolve` | `secrets:read`      |
| `gateway.method.secrets.reload`  | `secrets:manage`    |

`admin:*` does **not** match `secrets:read`. Only `*`, `secrets:read`, or
`secrets:*` grant access. Webchat never gets `secrets:read`.

### test_13 — No endpoint isolation

**Severity:** MEDIUM · **Surface:** ENDPOINT
**Status:** BLOCKED

`ws-endpoint.ts` enforces per-endpoint capability requirements:

| Endpoint               | requireOrigin | Allowed capabilities                                                           |
| ---------------------- | ------------- | ------------------------------------------------------------------------------ |
| `/gateway/ws-agent`    | yes           | `agent:read`, `agent:write`, `agent:execute`                                   |
| `/gateway/ws-admin`    | yes           | `admin:read`, `admin:write`, `admin:execute`, `admin:config`, `session:manage` |
| `/gateway/ws-internal` | no            | `internal:*`                                                                   |
| `/gateway` (legacy)    | yes           | `*` (backward compat)                                                          |

### test_14 — Forwarded proto origin mismatch

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Status:** BLOCKED

`validateProtoMismatch()` in `forwarded-headers.ts` checks both
`X-Forwarded-Proto` and RFC 7239 `Forwarded: proto=` against the `Origin`
scheme. Mismatch → reject at verifyClient step 3.

---

## Config Reference

All options live under `gateway.security`:

```json5
{
  gateway: {
    security: {
      // --- Pre-handshake (verifyClient) ---

      // Reject proxy headers from non-trusted IPs (default: true)
      // Close code 1008 before any auth runs.
      rejectUntrustedProxyHeaders: true,

      // Auto-disable localhost privilege when proxy headers present (default: true)
      // Prevents Tailscale Serve loopback bypass.
      autoDisableLocalhostBehindProxy: true,

      // Enforce origin check for non-browser clients (default: false)
      // Rejects connections without Origin header. Opt-in for production.
      enforceOriginCheckForAllClients: false,

      // Strict header validation — reject duplicate/chained headers (default: true)
      strictHeaderValidation: true,

      // Validate Host header against allowedOrigins (default: false)
      validateHostHeader: false,

      // IP allowlist (CIDR notation, e.g. ["10.0.0.0/8", "192.168.1.0/24"])
      ipAllowlist: [],

      // IP blocklist — takes precedence over allowlist
      ipBlocklist: [],

      // Require openclaw-gateway-v1 subprotocol (default: true)
      requireSubprotocol: true,

      // Validate WebSocket protocol version strictly (default: true)
      // Rejects non-standard or malformed WS upgrade requests.
      strictProtoValidation: true,

      // Global WebSocket connection limit (default: 100)
      // Set 0 only when the deployment intentionally allows unlimited clients.
      maxWebSocketConnections: 100,

      // --- Post-handshake ---

      // Per-message capability gating (default: true)
      enableMessageAuthorization: true,

      // Nonce challenge for auth (default: true)
      enableHandshakeTokens: true,

      // Per-connection frame/message rate limiting (default: true)
      enableRateLimiting: true,

      // --- Local privilege ---

      // Manual localhost origin fallback disable (default: true)
      // Set false only for trusted direct-local browser workflows.
      disableLocalhostPrivilege: true,

      // --- Payload limits ---

      // Max WebSocket message payload in bytes (default: 25 MB)
      // Clamped to [64 KB, 100 MB].
      maxPayloadBytes: 25 * 1024 * 1024,

      // --- Keep-alive ---

      // Enable WebSocket ping/pong keep-alive (default: true)
      enablePingPong: true,

      // Interval between ping frames in ms (default: 25000)
      pingIntervalMs: 25000,

      // Time to wait for pong response before closing (default: 10000)
      pongTimeoutMs: 10000,

      // --- DANGEROUS (opt-in escapes) ---

      // Grant wildcard `*` capabilities on unknown WS paths (default: false)
      // ONLY enable if you have legacy clients hitting non-standard endpoints.
      dangerouslyAllowLegacyEndpointFallback: false,

      // Bypass capability checks for unmapped RPC methods (default: false)
      // Allows any method not in the capability map to execute unchecked.
      dangerouslyAllowUnmappedMethods: false,

      // Fall back to Host header when Origin is missing (default: false)
      // Weakens origin validation; use only behind a trusted reverse proxy.
      dangerouslyAllowHostHeaderOriginFallback: false,

    },
  },

  // Gateway top-level: allow real IP from X-Forwarded-For when no
  // trusted proxy is configured (default: false).
  // Off by default to prevent IP spoofing via client-supplied headers.
  allowRealIpFallback: false,
}
```

### Canvas WebSocket Note

Canvas WebSocket connections (`/canvas`) are handled by a separate upgrade path
and do not traverse the 8-layer pre-handshake `verifyClient` pipeline. Canvas
relies on `authorizeCanvasRequest` with its own auth and rate limiting. This
is intentional — canvas is a separate concern with its own security model.

## Capabilities

| Capability       | Required for                                   | Granted to                                       |
| ---------------- | ---------------------------------------------- | ------------------------------------------------ |
| `*`              | Everything                                     | Local loopback operator only                     |
| `admin:read`     | Read-only methods (status, logs, config.get)   | Operators, nodes, tokens (via scope translation) |
| `admin:write`    | Write methods (send, sessions, cron, pairing)  | Operators, nodes, tokens (via scope translation) |
| `admin:config`   | `config.set`/`config.patch` on protected paths | Local operators with `*` scope only              |
| `secrets:read`   | `secrets.resolve`                              | Explicit `secrets:read` or `*` scope only        |
| `secrets:manage` | `secrets.reload`                               | Explicit `secrets:manage` or `*` scope only      |
| `agent:*`        | Agent endpoint methods                         | Agent-capable clients                            |
| `internal:*`     | Internal endpoint                              | Internal processes only                          |

**Key design decision:** `operator.admin` (macOS app scope) translates to
`admin:read` + `admin:write` but does **not** grant `admin:config` or
`secrets:read`. This prevents a paired device from disabling auth or
exfiltrating API keys, even if it has admin-level operational access.

## Recommended Production Config

```json5
{
  gateway: {
    security: {
      // Pre-handshake — all default-on, no changes needed
      rejectUntrustedProxyHeaders: true,
      autoDisableLocalhostBehindProxy: true,
      strictHeaderValidation: true,

      // Opt-in for internet-facing deployments
      enforceOriginCheckForAllClients: true,
      requireSubprotocol: true,
      validateHostHeader: true,

      // Network access control
      ipAllowlist: [], // e.g. ["10.0.0.0/8"] for LAN-only
      ipBlocklist: [],

      // Post-handshake — all default-on
      enableMessageAuthorization: true,
      enableHandshakeTokens: true,
      enableRateLimiting: true,

      // Local origin fallback privilege — disabled by default
      disableLocalhostPrivilege: true,

      // Connection rate limiting (pre-handshake DoS protection)
      connectionRateLimit: {
        maxAttempts: 30, // 30 attempts per window
        windowMs: 10000, // 10 second sliding window
        lockoutMs: 60000, // 1 minute lockout after limit
        exemptLoopback: true, // OWASP: exempt localhost
        ipv6SubnetMask: 56, // OWASP recommended /56 for IPv6
      },
    },
    // Connection rate limiting (pre-handshake DoS protection)
    connectionRateLimit: {
      maxAttempts: 30, // 30 attempts per window
      windowMs: 10000, // 10 second sliding window
      lockoutMs: 60000, // 1 minute lockout after limit
      exemptLoopback: true, // OWASP: exempt localhost
      ipv6SubnetMask: 56, // OWASP recommended /56 for IPv6
    },
    trustedProxies: ["100.64.0.0/10"], // Tailscale CGNAT range
    controlUi: {
      allowedOrigins: ["https://your-gateway.tailnet.ts.net"],
    },
  },
}
```

## Test Coverage

| Test file                       | Tests   | Scope                            |
| ------------------------------- | ------- | -------------------------------- |
| `security-hardening.test.ts`    | 73      | All 5 gap closures + integration |
| `origin-check.test.ts`          | 64      | Origin validation, proxy, ports  |
| `connection-rate-limit.test.ts` | 23      | Sliding window, lockout, exempt  |
| `auth.proxy-headers.test.ts`    | 17      | Proxy header validation          |
| `net.test.ts`                   | 18      | IP resolution, header parsing    |
| `ip-restriction-policy.test.ts` | 16      | CIDR allowlist/blocklist         |
| `server/verify-client.test.ts`  | 16      | Pre-handshake pipeline ordering  |
| **Total**                       | **227** |                                  |

## Files Added or Significantly Modified

### New files (fork-only)

| File                                               | Purpose                                               |
| -------------------------------------------------- | ----------------------------------------------------- |
| `src/gateway/server/verify-client.ts`              | Pre-handshake security pipeline (8 layers)            |
| `src/gateway/connection-rate-limit.ts`             | Per-IP sliding window rate limiter                    |
| `src/gateway/forwarded-headers.ts`                 | RFC 7239 Forwarded parsing + cross-header consistency |
| `src/gateway/ip-restriction-policy.ts`             | CIDR allowlist/blocklist                              |
| `src/gateway/message-auth.ts`                      | Per-message capability gating + scope translation     |
| `src/gateway/ws-endpoint.ts`                       | Per-endpoint capability requirements                  |
| `src/gateway/ws-protocol.ts`                       | Frame/message rate limiting                           |
| `src/gateway/capabilities.ts`                      | Capability system primitives                          |
| `docs/gateway/security/proxy-origin-validation.md` | Proxy security guide                                  |
| `docs/gateway/caddy-proxy.md`                      | Caddy reverse proxy setup                             |

### Modified files

| File                                                  | Changes                                                                                   |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `src/gateway/origin-check.ts`                         | Double-lock validation, proxy-aware, port normalization                                   |
| `src/gateway/net.ts`                                  | `validateSensitiveHeaders`, `validateForwardedHeaderConsistency`, `isTrustedProxyAddress` |
| `src/gateway/server/ws-connection/message-handler.ts` | verifyClient integration, protected config check, IP restriction forwarding               |
| `src/gateway/server/ws-connection.ts`                 | ping/pong keep-alive, close-code-aware reconnect                                          |
| `src/gateway/server-runtime-state.ts`                 | verifyClient wiring, perMessageDeflate disabled on WebSocketServer                        |
| `src/gateway/server-methods/config.ts`                | `PROTECTED_CONFIG_PATHS`, `isProtectedConfigPath`, `configObjectModifiesProtectedPath`    |
| `src/gateway/auth.ts`                                 | `timingSafeEqual` for HMAC, signed token defaults                                         |
| `src/gateway/server-constants.ts`                     | `resolveMaxPayloadBytes` with safe clamping                                               |
| `src/gateway/control-plane-rate-limit.ts`             | Prune/dispose lifecycle                                                                   |
| `src/gateway/device-auth.ts`                          | Signed token verification hardening                                                       |
| `src/gateway/protocol/connect-error-details.ts`       | Timestamp removed from challenge payload                                                  |
| `src/gateway/protocol/schema/error-codes.ts`          | New error codes for security rejections                                                   |
| `src/config/types.gateway.ts`                         | All new `gateway.security.*` config types                                                 |
| `src/config/schema.base.generated.ts`                 | Regenerated schema                                                                        |
| `src/config/zod-schema.ts`                            | Zod validation for new fields                                                             |
| `src/config/validation.ts`                            | Config validation for security fields                                                     |
| `Dockerfile*`                                         | Removed `NODE_TLS_REJECT_UNAUTHORIZED=0`, silent install fallback                         |

## Upstream Comparison

Features present in fork but absent from upstream `openclaw/openclaw`:

| Feature                                  | Upstream      | Fork              | CWE         |
| ---------------------------------------- | ------------- | ----------------- | ----------- |
| Pre-handshake verifyClient pipeline      | No            | 8-layer           | CWE-346     |
| Untrusted proxy header rejection         | Warn only     | Reject (1008)     | CWE-345     |
| Auto-disable localhost behind proxy      | No            | Yes               | CWE-346     |
| Connection rate limiting (pre-handshake) | No            | Yes (/56 IPv6)    | CWE-770     |
| Per-message capability gating            | No            | 80+ methods       | CWE-862     |
| secrets.resolve capability gate          | No            | `secrets:read`    | CWE-200     |
| Protected config paths                   | No            | `admin:config`    | CWE-862     |
| perMessageDeflate disabled               | Enabled       | Disabled          | CWE-502     |
| timingSafeEqual for HMAC                 | No            | Yes               | CWE-208     |
| Subprotocol enforcement                  | No            | Yes               | CWE-284     |
| maxPayloadBytes clamping                 | No            | [64 KB, 100 MB]   | CWE-770     |
| RFC 7239 Forwarded header                | No            | Full parsing      | CWE-345     |
| Cross-header consistency check           | No            | Yes               | CWE-345     |
| IP restriction in handshake              | Post-auth     | Pre-handshake     | CWE-284     |
| Ping/pong keep-alive                     | No            | Yes               | Operational |
| Close-code-aware reconnect               | No            | Yes               | Operational |
| `NODE_TLS_REJECT_UNAUTHORIZED=0`         | In Dockerfile | Removed           | CWE-295     |
| IPv6 subnet masking (rate limit)         | No            | /56 OWASP         | CWE-770     |
| RateLimit response headers               | No            | 429 + Retry-After | -           |

## Backward Compatibility

All hardening is default-on except where noted. Current OpenClaw direct-local
clients are expected to negotiate the gateway subprotocol. Legacy direct-local
clients that cannot do that must explicitly opt out with
`gateway.security.requireSubprotocol = false`.

| Change                            | Breaking?                                    | Opt-out          |
| --------------------------------- | -------------------------------------------- | ---------------- |
| `rejectUntrustedProxyHeaders`     | Only if proxy headers sent from untrusted IP | `false`          |
| `autoDisableLocalhostBehindProxy` | Only if proxy headers present                | `false`          |
| `enforceOriginCheckForAllClients` | No (default `false`)                         | N/A — opt-in     |
| `strictHeaderValidation`          | Only if duplicate/chained headers sent       | `false`          |
| `requireSubprotocol`              | Yes for legacy clients without subprotocol   | `false`          |
| `perMessageDeflate` disabled      | Slightly higher bandwidth                    | Cannot re-enable |
| `secrets:read` capability         | Only if client lacks `*` scope               | N/A              |
| `admin:config` capability         | Only if client lacks `*` scope               | N/A              |
| `maxPayloadBytes` clamping        | Only if set outside [64 KB, 100 MB]          | N/A              |
| `timingSafeEqual`                 | No (transparent)                             | N/A              |
