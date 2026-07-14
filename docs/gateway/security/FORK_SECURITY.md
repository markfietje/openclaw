# Fork Security Posture

Reference for the gateway security hardening in the `markfietje/openclaw` fork, relative to `openclaw/openclaw`. It documents what the fork adds on top of upstream, how each control is wired into the live gateway path, and where upstream already provides a baseline.

> ⚠️ **Self-assessment, not a certified third-party audit.** Every control in this document was verified by reading the fork's source and confirming it is wired into the live gateway path. It has **not** been reviewed or certified by an external security firm. Treat it as engineering evidence, not an attestation of compliance.

## Executive Summary

`markfietje/openclaw` is a security-hardening fork of the open-source `openclaw/openclaw` agent gateway. The fork is a direct descendant of current upstream `main` and adds a dedicated `@openclaw/gateway-security-core` package plus per-message capability authorization on top of upstream's existing gateway.

**What the fork adds (fork-only):**

- **Secrets at rest:** AES-256-GCM envelope encryption via a credential vault, replacing the deleted plaintext `sealed-json-file.ts` and `secret-env.ts`.
- **Per-message authorization:** a default-deny capability gate layered on upstream's scope checks. Three high-risk methods (`secrets.resolve`, `secrets.reload`, `config.set_protected`) are pinned to stricter capabilities; all other methods derive their capability from the operator scope declared for that method.
- **Transport and connection hardening:** origin allowlisting (CSWSH), subprotocol enforcement, per-connection frame and message rate limits (1000 frames/s, 500 messages/s) plus a byte budget, a 64 KB pre-auth payload cap, `perMessageDeflate` disabled, keepalive, and multi-layer rate limiting (per-IP sliding windows and connection budgets).
- **Auditability and abuse resistance:** HMAC-signed append-only auth and tool-invocation logs, an exec deny-list, a protected-config path gate, IPv6 /56 subnet masking for rate-limit keys, per-connection replay protection, and fail-closed startup security checks.

**Risk posture:** the fork meets the core recommendations of the OWASP WebSocket Security Cheat Sheet (WSS, origin validation, per-action authorization, replay protection) and adds defense-in-depth beyond them. It does not change upstream's trust model for already-authenticated operators; the hardening targets unauthorized access, secret exfiltration, config tampering, and abuse or denial of service.

**Caveat:** this is a self-assessment. See the disclaimer above.

**OWASP coverage:** self-assessed against the [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html). The cheat sheet's core WS-specific recommendations are **met**: WSS/TLS enforcement, Origin-header allowlisting (CSWSH), per-action authorization, handshake nonce authentication, and per-message replay protection (`message-replay-guard`). General appsec controls layered on top include payload limits, multi-layer rate limiting, input validation, and HTTP security headers. This is a self-assessment, not a third-party audit or certification.

> **Methodology note (re-verified 2026-07-14):** the per-test statuses in [Per-Test Status](#per-test-status) are **code-level defense verifications**, not re-runs of an external PoC. For each test, the cited defense file/function was confirmed to exist and be wired into the live gateway path. The fork is a direct descendant of current `upstream/main` (`eb7c151d0753`), so it contains all upstream gateway code; this document lists the fork's _additions_ and notes where upstream already provides a baseline.

test_11 (`config.set` auth persistence): the specific attack path — calling `config.set` to disable auth — is fully blocked via `admin:config` capability gating on protected paths. A naive PoC may report PARTIALLY BLOCKED because it probes `config.get` reachability rather than the actual `config.set` exploit, but the real-world attack is closed.

---

## Code Organization

The fork's security hardening is split into two layers to minimize merge
conflicts with upstream:

### Independent package: `@openclaw/gateway-security-core`

**Path:** `packages/gateway-security-core/`

Contains all security modules that are independent of upstream gateway internals.
Upstream does not touch this package — it is fork-only. During upstream merges,
this package requires zero conflict resolution.

| Module                        | Export                                                   | Purpose                                                                                                |
| ----------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `security-config.ts`          | `GatewaySecurityConfig` type                             | Canonical config type for all `gateway.security.*` fields                                              |
| `connection-rate-limit.ts`    | `ConnectionRateLimiter`                                  | Pre-handshake per-IP sliding window rate limiter                                                       |
| `ip-restriction-policy.ts`    | `isIpAllowed()`                                          | CIDR allowlist/blocklist with blocklist precedence                                                     |
| `ws-protocol.ts`              | `hasGatewayWsSubprotocol()`, `DEFAULT_FRAME_LIMITS`      | Subprotocol enforcement + per-connection frame rate limits + byte budget                               |
| `ws-endpoint.ts`              | `ENDPOINT_SECURITY`, `classifyWsEndpoint()`              | Per-endpoint capability requirements (4 endpoints)                                                     |
| `ws-keepalive.ts`             | `createWsKeepalive()`                                    | Ping/pong dead-connection detection                                                                    |
| `config-guard.ts`             | `PROTECTED_CONFIG_PATHS`, `isProtectedConfigPath()`      | Protected config path gate (`admin:config` required)                                                   |
| `auth-audit-log.ts`           | `createAuthAuditLogger()`                                | HMAC-signed append-only auth event log                                                                 |
| `tool-audit.ts`               | `createToolAuditLogger()`                                | HMAC-signed append-only tool invocation log                                                            |
| `audit-log-base.ts`           | `createAuditLogBase()`                                   | Shared HMAC append-only log infrastructure                                                             |
| `ws-frame-validator.ts`       | `validateInboundFrame()`                                 | Defense-in-depth Zod frame validation                                                                  |
| `device-session-authority.ts` | `DeviceSessionAuthorityTracker`                          | Device generation tracking, session replay prevention                                                  |
| `startup-security-checks.ts`  | `runStartupSecurityChecks()`                             | Boot-time TLS/auth/bind safety checks                                                                  |
| `exec-deny-paths.ts`          | `checkExecDenyPath()`, `DEFAULT_EXEC_DENY_PATTERNS`      | Exec tool deny-list (secrets, .env, SSH keys)                                                          |
| `request-rate-limit.ts`       | `createRequestRateLimiter()`                             | HTTP REST endpoint per-IP sliding window                                                               |
| `ip.ts`                       | `isLoopbackAddress()`, `resolveClientIp()`               | Canonical IP resolution (loopback, proxy, RFC 7239); shared across gateway and cross-package consumers |
| `ipv6-subnet.ts`              | `applyIpv6SubnetMask()`                                  | IPv6 /56 subnet masking for rate-limit key generation (OWASP)                                          |
| `sliding-window-store.ts`     | `createSlidingWindowStore()`                             | Reusable sliding window data structure for rate limiters                                               |
| `credential-keystore.ts`      | `resolveCredentialVaultKek()`, `hasCredentialVaultKek()` | KEK resolution from external key-encryption key (file/env)                                             |
| `credential-store-cell.ts`    | `openAuthProfileStoreCell`, `sealAuthProfileStoreCell`   | Auth-profile cell open/seal helpers (vault at rest)                                                    |
| `credential-vault.ts`         | `createCredentialVault()`                                | AES-256-GCM AEAD envelope encryption at rest (replaces deleted `sealed-json-file.ts`)                  |
| `credential-vault-cache.ts`   | `createCredentialVaultKekCache()`                        | In-memory KEK cache, env-configurable                                                                  |
| `message-replay-guard.ts`     | `createMessageReplayGuard()`                             | Per-connection request-id replay guard (LRU + TTL)                                                     |
| `secret-equal.ts`             | `safeEqualSecret()`                                      | Constant-time secret compare (extends upstream `safeEqualSecret`)                                      |
| `index.ts`                    | barrel                                                   | Public sub-path exports (22 total)                                                                     |

> **Note:** `message-auth.ts` (per-message capability gating) is **not** in this package — it lives at `src/gateway/message-auth.ts`. It was moved out of the package during refactoring; see [Fork-only files outside the package](#fork-only-files-outside-the-package).

**Package config:**

- `tsconfig.json` — extends root, `rootDir: "../.."` for monorepo path alias resolution
- `tsdown.config.ts` — externalizes `../../../src/` cross-package imports
- `package.json` — `@openclaw/gateway-security-core`, exports **22** sub-path modules (including `./ip`); 25 source modules total

### Upstream-touched files (wired-in hardening)

These files are modified by both upstream and the fork. The fork adds security
calls and wrappers that call into `@openclaw/gateway-security-core`. During
upstream merges, these files may require conflict resolution — but the conflict
surface is minimized because the security logic lives in the independent package.

| File                                                     | Fork additions                                                                                                    | Merge risk |
| -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | ---------- |
| `src/gateway/server/verify-client.ts`                    | Wrapper — imports from `@openclaw/gateway-security-core/*`, wires into `ws` callback                              | Low        |
| `src/gateway/server-runtime-state.ts`                    | `createConnectionRateLimiter()`, `createRuntimeVerifyClient()`, `perMessageDeflate: false`                        | Medium     |
| `src/gateway/forwarded-headers.ts`                       | RFC 7239 `Forwarded` header parsing, cross-header consistency, proto mismatch                                     | Medium     |
| `src/gateway/net.ts`                                     | `validateSensitiveHeaders()`, `isTrustedProxyAddress()`                                                           | Medium     |
| `src/gateway/origin-check.ts`                            | `timingSafeEqual` for HMAC, double-lock origin validation, port normalization                                     | Medium     |
| `src/gateway/auth.ts`                                    | `safeEqualSecret` for constant-time connect-token/password comparison                                             | Low        |
| `src/gateway/server/ws-connection.ts`                    | Ping/pong keep-alive, close-code-aware reconnect                                                                  | Medium     |
| `src/gateway/server-methods/config.ts`                   | `isProtectedConfigPath()` gate on `config.set`/`config.patch`                                                     | Medium     |
| `src/gateway/server-constants.ts`                        | `resolveMaxPayloadBytes()` with safe clamping                                                                     | Low        |
| `src/gateway/device-auth.ts`                             | Re-export shim for device-auth helpers from `gateway-client` (no verification logic in this file)                 | Low        |
| `packages/gateway-protocol/src/connect-error-details.ts` | Timestamp removed from challenge payload (moved from `src/gateway/protocol/` into the `gateway-protocol` package) | Low        |
| `packages/gateway-protocol/src/schema/error-codes.ts`    | New error codes for security rejections (moved from `src/gateway/protocol/schema/`)                               | Low        |
| `src/config/types.gateway.ts`                            | Re-exports `GatewaySecurityConfig` from the package                                                               | Low        |
| `src/config/zod-schema.ts`                               | `GatewaySecurityConfigSchema` — Zod validation for all security fields                                            | Low        |
| `src/config/validation.ts`                               | Config validation for security fields                                                                             | Low        |
| `Dockerfile*`                                            | `NODE_TLS_REJECT_UNAUTHORIZED` not set (also absent upstream)                                                     | Low        |

### Fork-only files outside the package

| File                                                    | Purpose                                                                            |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `src/gateway/server/verify-client.ts`                   | Wrapper: calls into `@openclaw/gateway-security-core/*` for pre-handshake pipeline |
| `src/gateway/server/authenticated-connection-budget.ts` | Per-device connection budget (env-driven cap)                                      |
| `src/security/outbound-redact.ts`                       | Redacts secrets from outbound gateway messages                                     |
| `src/config/io.hmac-integrity.ts`                       | HMAC config file integrity verification                                            |

---

## Defense Architecture

The gateway enforces security in a strict layered pipeline. Each layer rejects
before the next runs — a failure at any layer prevents deeper processing.

### Server Side: Pre-Handshake (`verifyClient`)

Runs inside the `ws` `verifyClient` callback **before** the HTTP 101 upgrade.
Rejected connections never complete the WebSocket handshake.

**Implementation:** `src/gateway/server/verify-client.ts` (wrapper) calls into
`@openclaw/gateway-security-core/connection-rate-limit`, `ip-restriction-policy`,
`ws-protocol`.

```
  Client TCP connect
        │
        ▼
  ┌─────────────────────────────────────────┐
  │ 0. Connection limits                     │
  │    • Max concurrent connections          │
  │    • HTTP 503                            │
  ├─────────────────────────────────────────┤
  │ 0b. Connection rate limiting             │
  │    • Per-IP sliding window (30/10s)      │
  │    • Lockout on exceed (60s)             │
  │    • Loopback exempt                     │
  │    • IPv6 /56 subnet masking             │
  │    • HTTP 429                            │
  ├─────────────────────────────────────────┤
  │ 1. Strict header validation              │
  │    • Reject duplicate/chained headers    │
  │    • X-Forwarded-For, X-Forwarded-Host,  │
  │      X-Forwarded-Proto, X-Real-IP       │
  │    • HTTP 400                            │
  ├─────────────────────────────────────────┤
  │ 1b. Cross-header consistency             │
  │    • Forwarded vs X-Forwarded-* agree    │
  │    • Prevents header contradiction       │
  │    • HTTP 400                            │
  ├─────────────────────────────────────────┤
  │ 2. Untrusted proxy header rejection      │
  │    • Proxy headers from non-trusted IPs  │
  │      → reject (not warn)                 │
  │    • HTTP 403                            │
  ├─────────────────────────────────────────┤
  │ 3. Origin validation                     │
  │    • Browser clients only (has Origin)   │
  │    • Double-lock: Origin ↔ X-Fwd-Host   │
  │    • Protocol mismatch detection         │
  │    • Localhost privilege auto-disable    │
  │    • HTTP 403                            │
  ├─────────────────────────────────────────┤
  │ 4. IP restriction                        │
  │    • CIDR allowlist/blocklist            │
  │    • Blocklist takes precedence          │
  │    • Fail closed on unknown IP           │
  │    • HTTP 403                            │
  ├─────────────────────────────────────────┤
  │ 5. Subprotocol enforcement                │
  │    • require openclaw-gateway-v1         │
  │    • HTTP 400                            │
  └─────────────────────────────────────────┘
        │
        ▼
  HTTP 101 Switching Protocols
  (perMessageDeflate: disabled)
        │
        ▼
  Post-Handshake
```

### Server Side: Post-Handshake

Runs after the WebSocket is established. Each message is checked individually.

**Implementation:** `src/gateway/message-auth.ts` (per-message capability gating), plus `@openclaw/gateway-security-core/ws-protocol`, `config-guard`, `ws-keepalive`. Wired in `server-runtime-state.ts`, `message-handler.ts`.

```
  ┌─────────────────────────────────────────┐
  │ 6. Pre-handshake origin check (verify-client.ts) │
  │    • Sec-Fetch-Site cross-site detection          │
  │    • X-Forwarded-Proto mismatch validation         │
  ├─────────────────────────────────────────┤
  │ 7. Message authorization                 │
  │    • Per-message-type capability mapping │
  │    • Operator scope → capability         │
  │      translation (operator.admin ≠       │
  │      admin:config)                       │
  │    • All methods default-deny; 3 pinned  │
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
  │     • Configurable, clamped to ≤ 25 MB   │
  │       (you can lower it, not raise it)   │
  ├─────────────────────────────────────────┤
  │ 11. Keep-alive                           │
  │     • Ping every 25s, pong timeout 10s   │
  │     • Dead-connection detection          │
  └─────────────────────────────────────────┘
```

### Client Side: Reconnect Hardening

**Implementation:** `packages/gateway-client/src/client.ts` (shared with upstream), `src/gateway/server/ws-connection.ts`.

| Feature                    | Behavior                                                        |
| -------------------------- | --------------------------------------------------------------- |
| Close-code-aware reconnect | Distinguishes 1013 (try again later) from 1006 (abnormal close) |
| Exponential backoff        | Faster recovery on service restart                              |
| Clean disconnect           | Proper close frame with code + reason                           |

> **Note:** close-code-aware reconnect is **not** a fork-only feature — upstream's `gateway-client` already implements it. It is listed here for completeness of the data flow, not as a fork differentiator.

### Operational Hardening

Not attack-vector-specific but reduces exploit surface and improves resilience:

| Feature                                | Source file / package                                          | Purpose                                                              |
| -------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------- |
| `perMessageDeflate` disabled           | `server-runtime-state.ts`                                      | CRIME/BREACH class mitigation                                        |
| Ping/pong keep-alive                   | `@openclaw/gateway-security-core/ws-keepalive`                 | Prevents silent drops behind reverse proxies                         |
| Close-code-aware reconnect             | `packages/gateway-client/src/client.ts` (shared with upstream) | Faster recovery on service restart (not fork-only)                   |
| Wildcard origin warning                | startup log                                                    | Emits once at boot, not per-connection spam                          |
| Nonce send failure logging             | `message-handler.ts`                                           | Dual-validation pattern documented                                   |
| `NODE_TLS_REJECT_UNAUTHORIZED` not set | `Dockerfile*`                                                  | Not set in fork image (upstream also omits it; not a fork-only fix)  |
| Timestamp removed from challenge       | `packages/gateway-protocol/src/connect-error-details.ts`       | Reduces timing side-channel in nonce payload                         |
| Outbound secret redaction              | `src/security/outbound-redact.ts`                              | Prevents credential leakage through agent replies                    |
| Credential vault at rest               | `packages/gateway-security-core/credential-vault.ts`           | AES-256-GCM AEAD encryption for auth profiles at rest (KEK-supplied) |
| Config HMAC integrity                  | `src/config/io.hmac-integrity.ts`                              | Detects config file tampering between reads                          |
| Per-device connection budget           | `src/gateway/server/authenticated-connection-budget.ts`        | Prevents connection exhaustion from devices                          |
| Exec tool deny-paths                   | `@openclaw/gateway-security-core/exec-deny-paths`              | Blocks `exec` from reading secrets/credentials                       |
| Auth audit log                         | `@openclaw/gateway-security-core/auth-audit-log`               | HMAC-signed append-only connect attempt log                          |
| Tool audit log                         | `@openclaw/gateway-security-core/tool-audit`                   | HMAC-signed append-only tool invocation log                          |
| Device session authority               | `@openclaw/gateway-security-core/device-session-authority`     | Detects session replay after device revocation                       |
| Startup security checks                | `@openclaw/gateway-security-core/startup-security-checks`      | Refuses boot with insecure TLS/auth/bind config                      |
| HTTP request rate limiting             | `@openclaw/gateway-security-core/request-rate-limit`           | Per-IP sliding window for REST endpoints                             |

---

## Complete Data Flow (end-to-end)

A WebSocket connection from a client to the fork's gateway traverses these stages. Each stage is a separate file/function; each can reject before the next runs.

### Stage A — HTTP upgrade arrives (`src/gateway/server-http.ts`)

1. The HTTP server receives an `upgrade` event. `attachGatewayUpgradeHandler` resolves the client IP via `resolveRequestClientIp` (right-to-left `X-Forwarded-For` walk, fail-closed if a trusted proxy's headers are missing).
2. Plugin node-capability upgrades are routed through `authorizePluginNodeCapabilityRequest` (pre-dispatch auth so plugin handlers never see unauth scoped sockets).
3. The handler calls into the pre-handshake pipeline (Stage B). Only if it passes does `wss.handleUpgrade(...)` run, emitting `connection`.

### Stage B — Pre-handshake verifyClient (`src/gateway/server/verify-client.ts` → `@openclaw/gateway-security-core/*`)

Built by `createRuntimeVerifyClient(...)` in `server-runtime-state.ts`, invoked as `runGatewayUpgradePreflight(verifyClient, req)` in `server-http.ts`. The 6 steps (see `createGatewayVerifyClient` JSDoc):

1. **Connection limits** — `connection-rate-limit` + max-connection cap. Per-IP sliding window (30/10s, 60s lockout), IPv6 /56 subnet masking via `ipv6-subnet`, loopback-exempt. Exceed → 429/503.
2. **Strict header validation** — `net.ts::validateSensitiveHeaders` rejects duplicate/chained `Host`, `Origin`, `X-Forwarded-*`.
3. **Untrusted proxy header rejection** — `X-Forwarded-*` from non-trusted IPs → 403 (`rejectUntrustedProxyHeaders`, default on).
4. **Origin validation** — `origin-check.ts::checkBrowserOrigin` against an explicit allowlist (wildcard `*` rejected), with `Sec-Fetch-Site` cross-site detection and `autoDisableLocalhostBehindProxy`.
5. **IP allowlist/blocklist** — `ip-restriction-policy::isIpAllowed` (CIDR, blocklist wins, fail-closed).
6. **Subprotocol enforcement** — `ws-protocol::hasGatewayWsSubprotocol` requires `openclaw-gateway-v1`.

A failed step writes a failure response, logs `ip_blocked` to the auth audit log (if enabled), destroys the socket, and returns — **before** HTTP 101.

### Stage C — WebSocket established, handshake auth (`src/gateway/server/ws-connection.ts`, `auth.ts`)

1. `wss` is created with `noServer: true`, `maxPayload` (clamped by `server-constants.ts::resolveMaxPayloadBytes`), and `perMessageDeflate: false`.
2. A handshake timer is set; the server emits a `connect.challenge` with a nonce.
3. Auth resolves via `auth.ts`: modes `token` / `password` / `device-token` / `bootstrap-token` / `trusted-proxy` / `tailscale`. `timingSafeEqual` compares HMACs; Tailscale uses whois with a 5s timeout; trusted-proxy mode rejects loopback/local-interface sources.

### Stage D — Per-message authorization (`src/gateway/message-auth.ts`, `@openclaw/gateway-security-core/config-guard`)

1. Every inbound frame is scope-checked (default-deny). `authorizeMessage` enforces a capability gate: three high-risk methods are explicitly pinned (`secrets.resolve` → `secrets:read`, `secrets.reload` → `secrets:manage`, `config.set_protected` → `admin:config`); every other method derives its capability from the operator scope declared for that method, and `operator.admin` is translated to fine-grained capabilities but **not** `admin:config` or `secrets:read`.
2. `config-guard::isProtectedConfigPath` gates `config.set`/`config.patch` on `gateway.auth.*`, `gateway.security.*`, `gateway.trustedProxies`, bind/port behind `admin:config`.
3. `secrets.resolve` / `secrets.reload` require `secrets:read` / `secrets:manage`.

### Stage E — Payload + frame limits (`@openclaw/gateway-security-core/ws-protocol`, `ws-frame-validator`)

1. Pre-auth payload cap 64 KB; post-auth 25 MB default (configurable, clamped to ≤ 25 MB — you can lower it, not raise it).
2. Per-connection frame/message rate limits (1000 frames/s, 500 messages/s) and a cumulative byte budget (50 MB/min).
3. `validateInboundFrame` (defense-in-depth Zod) + malformed-frame counter (3 strikes → close 1008).

### Stage F — Outbound delivery (`src/gateway/server-chat.ts` → `src/security/outbound-redact.ts`)

1. Chat payloads pass through `createOutboundDeliveryPayloadRedactor(cfg)` (built lazily in `server-chat.ts`) which strips API keys, tokens, PEM blocks, and dynamic secrets before broadcast to channels (TUI/Telegram/Discord/WhatsApp).
2. Auth/tool audit entries (if enabled) are HMAC-signed and appended.

### Stage G — Keepalive + reconnect (`@openclaw/gateway-security-core/ws-keepalive`, `packages/gateway-client/src/client.ts`)

1. Server pings every 25s; pong timeout 10s → dead-connection close.
2. Client reconnect is close-code-aware (1013 try-again-later vs 1006), with exponential backoff. (Shared with upstream — not a fork differentiator.)

### How this differs from upstream's data flow

- Upstream's pre-handshake gate is `attachGatewayUpgradeHandler` (a custom `httpServer.on("upgrade")` handler), **not** the ws `verifyClient` option. Functionally equivalent placement (before `handleUpgrade`), but the fork's is a named 6-step pipeline with subprotocol + client CIDR + cross-header checks upstream lacks.
- Upstream's per-IP limit is a **concurrent-connection budget** (`preauth-connection-budget.ts`, 32/IP), not a sliding-window **rate** limit. The fork adds the rate limit on top.
- Upstream's per-message authz is **scope-based** (`method-scopes.ts`, default-deny). The fork adds a **capability-string** layer (`message-auth.ts`) with finer-grained names like `secrets:read`.
- Upstream redacts **logs/transcripts** (`logging/redact.ts`); the fork additionally redacts the **live delivery path**.
- Upstream's startup checks throw on missing/known-weak secrets but do **not** fail-close on critical audit findings; the fork does (`assertStartupSecurityFindingsAllowed`).

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

`checkBrowserOrigin()` in `src/gateway/origin-check.ts` gates `X-Forwarded-Host`
usage behind `isTrustedProxy`. Untrusted connections cannot influence origin
validation via spoofed headers.
Blocked at verifyClient step 3.

### test_03 — Protocol downgrade (SSL strip)

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Status:** BLOCKED

`validateProtoMismatch()` in `src/gateway/forwarded-headers.ts` rejects when
`X-Forwarded-Proto: http` is sent but the `Origin` uses `https`. Also checks
RFC 7239 `Forwarded: proto=http` against the origin scheme.
Blocked at verifyClient step 3.

### test_04 — X-Forwarded-Host spoof (untrusted)

**Severity:** MEDIUM · **Surface:** HEADER_VALIDATION
**Status:** BLOCKED

Two-layer defense:

1. `validateSensitiveHeaders()` in `src/gateway/net.ts` detects duplicate or
   chained comma-separated `X-Forwarded-Host` values → verifyClient step 1
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
   Serve IP is not in `trustedProxies`, proxy headers are rejected with HTTP 403
   before origin or auth runs.

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
non-trusted IPs with HTTP 403. Auth never runs for these connections.
This is the OWASP verifyClient principle: validate before upgrade.

### test_08 — No IP restriction

**Severity:** MEDIUM · **Surface:** NETWORK
**Status:** BLOCKED

`@openclaw/gateway-security-core/ip-restriction-policy` enforces CIDR-based
allowlists/blocklists. Blocklist takes precedence over allowlist. Unknown IPs
fail closed. Enforced in verifyClient step 4 (pre-handshake), not post-auth.

### test_09 — No rate limiting

**Severity:** MEDIUM · **Surface:** AUTH
**Status:** BLOCKED

Three rate limiting layers:

1. **Pre-handshake** (`@openclaw/gateway-security-core/connection-rate-limit`):
   Per-IP sliding window in verifyClient step 0b. 30 attempts per 10s window,
   60s lockout on exceed. Loopback exempt. IPv6 /56 subnet masking. Runs before
   any auth work.

2. **Post-handshake** (`@openclaw/gateway-security-core/ws-protocol`):
   Per-connection frame/message rate limiting. 1000 frames/s, 500 messages/s.
   Prevents post-auth resource exhaustion.

3. **HTTP REST** (`@openclaw/gateway-security-core/request-rate-limit`):
   Per-IP sliding window for REST endpoints. 120 requests per minute per IP.
   10,000 max tracked non-loopback IPs. Loopback exempt.

### test_10 — No message authorization

**Severity:** MEDIUM · **Surface:** CAPABILITY
**Status:** BLOCKED

`src/gateway/message-auth.ts` gates every message type behind
specific capabilities. Every gateway method is authorized by a default-deny
capability gate. Three high-risk methods are explicitly pinned
(`secrets.resolve` → `secrets:read`, `secrets.reload` → `secrets:manage`,
`config.set_protected` → `admin:config`); all other methods derive their
capability from the operator scope declared for that method. Unmapped methods
are blocked when `requireCapabilityForAll` is enabled. Operator scopes
(`operator.admin`) are translated to fine-grained capabilities —
`operator.admin` grants `admin:read` + `admin:write` but **not** `admin:config`
or `secrets:read`.

### test_11 — config.set auth persistence

**Severity:** HIGH · **Surface:** CONFIG_API
**Status:** ATTACK BLOCKED

An authenticated attacker could call `config.set` to set `gateway.auth.mode =
"none"`, trigger a restart, and gain persistent unauthenticated access.

**Fix:** `@openclaw/gateway-security-core/config-guard` defines protected config
paths that require `admin:config` capability:

```
Protected paths:
  gateway.auth.*          — authentication configuration
  gateway.tailscale.*     — Tailscale identity configuration
  gateway.security.*      — security hardening options
  gateway.trustedProxies  — proxy trust configuration
  gateway.bind            — network binding
  gateway.port            — listening port
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

`secrets.resolve` was not mapped in `DIRECT_MESSAGE_CAPABILITIES`. With
`requireCapabilityForAll: false` (default), unmapped messages passed through
unchallenged. Any authenticated client could read stored API keys.

**Fix:** Explicit capability mappings in `src/gateway/message-auth.ts`:

| Message type                          | Required capability |
| ------------------------------------- | ------------------- |
| `gateway.method.secrets.resolve`      | `secrets:read`      |
| `gateway.method.secrets.reload`       | `secrets:manage`    |
| `gateway.method.config.set_protected` | `admin:config`      |

`admin:*` does **not** match `secrets:read`. Only `*`, `secrets:read`, or
`secrets:*` grant access. Webchat never gets `secrets:read`.

### test_13 — No endpoint isolation

**Severity:** MEDIUM · **Surface:** ENDPOINT
**Status:** BLOCKED

`@openclaw/gateway-security-core/ws-endpoint` enforces per-endpoint capability
requirements:

| Endpoint               | requireOrigin | Allowed capabilities                                                           |
| ---------------------- | ------------- | ------------------------------------------------------------------------------ |
| `/gateway/ws-agent`    | yes           | `agent:read`, `agent:write`, `agent:execute`                                   |
| `/gateway/ws-admin`    | yes           | `admin:read`, `admin:write`, `admin:execute`, `admin:config`, `session:manage` |
| `/gateway/ws-internal` | no            | `internal:*`                                                                   |
| `/gateway` (legacy)    | yes           | `*` (backward compat)                                                          |

Unknown WebSocket paths are rejected before falling through to the legacy
endpoint, preventing endpoint confusion attacks.

### test_14 — Forwarded proto origin mismatch

**Severity:** MEDIUM · **Surface:** ORIGIN_CHECK
**Status:** BLOCKED

`validateProtoMismatch()` in `src/gateway/forwarded-headers.ts` checks both
`X-Forwarded-Proto` and RFC 7239 `Forwarded: proto=` against the `Origin`
scheme. Mismatch → reject at verifyClient step 3.

---

## Config Reference

### Type System

The canonical type is `GatewaySecurityConfig` in
`packages/gateway-security-core/src/security-config.ts`. It is re-exported from
`src/config/types.gateway.ts` so IDE autocomplete and TypeScript checking cover
the full security surface. The type is organized by OWASP defense-in-depth
layers:

- **Layer 0** — Transport (TLS)
- **Layer 1** — Pre-Handshake (verifyClient pipeline, steps 0–5)
- **Layer 2** — Authentication (nonce challenge, step 6)
- **Layer 3** — Authorization (capability gating, steps 7–8)
- **Layer 4** — Operational (keep-alive, rate limiting, steps 9–11)

### Zod Schema

The Zod schema in `src/config/zod-schema.ts` validates the same field names at
runtime. It uses `.strict()` to reject unknown fields. Sub-schemas:

```typescript
// Zod sub-schemas (src/config/zod-schema.ts)
const GatewayAuditFlagSchema = z
  .object({
    enabled: z.boolean().optional(),
  })
  .strict();

const GatewayConnectionRateLimitSchema = z
  .object({
    maxAttempts: z.number().int().positive().optional(),
    windowMs: z.number().int().positive().optional(),
    lockoutMs: z.number().int().positive().optional(),
    exemptLoopback: z.boolean().optional(),
    pruneIntervalMs: z.number().int().positive().optional(),
    ipv6SubnetMask: z.number().int().min(0).max(128).optional(),
  })
  .strict();
```

The main schema mirrors the package type field-for-field:

```typescript
const GatewaySecurityConfigSchema = z
  .object({
    // Layer 0: Transport
    tlsMinVersion: z.enum(["TLSv1.2", "TLSv1.3"]).default("TLSv1.3"),
    // Layer 1: Pre-Handshake
    strictHeaderValidation: z.boolean().default(true),
    rejectUntrustedProxyHeaders: z.boolean().default(true),
    autoDisableLocalhostBehindProxy: z.boolean().default(true),
    disableLocalhostPrivilege: z.boolean().default(true),
    validateHostHeader: z.boolean().default(false),
    strictProtoValidation: z.boolean().default(true),
    enforceOriginCheckForAllClients: z.boolean().default(false),
    ipAllowlist: z.array(CidrOrIpSchema).optional(),
    ipBlocklist: z.array(CidrOrIpSchema).optional(),
    requireSubprotocol: z.boolean().default(true),
    maxWebSocketConnections: z.number().int().min(0).max(10_000).optional(),
    connectionRateLimit: GatewayConnectionRateLimitSchema.optional(),
    maxPayloadBytes: z.number().int().min(1).max(26_214_400).optional(),
    // Layer 2: Authentication
    enableHandshakeTokens: z.boolean().default(true),
    enableMessageReplayProtection: z.boolean().default(true),
    messageReplayProtectionTtlMs: z.number().int().min(1_000).max(3_600_000).optional(),
    // Layer 3: Authorization
    enableMessageAuthorization: z.boolean().default(true),
    dangerouslyAllowUnmappedMethods: z.boolean().default(false),
    dangerouslyAllowLegacyEndpointFallback: z.boolean().default(false),
    dangerouslyAllowHostHeaderOriginFallback: z.boolean().default(false),
    allowWildcardOrigin: z.boolean().default(false),
    // Layer 4: Operational
    enablePingPong: z.boolean().default(true),
    pingIntervalMs: z.number().int().positive().optional(),
    pongTimeoutMs: z.number().int().positive().optional(),
    enableRateLimiting: z.boolean().default(true),
    // Observability
    enableOutboundRedaction: z.boolean().default(true),
    methodRateLimits: z.record(z.string(), z.number()).optional(),
    connectionRateLimitPerMinute: z.number().int().min(1).max(100_000).optional(),
    browserRateLimitPerMinute: z.number().int().min(1).max(100_000).optional(),
    authAudit: GatewayAuditFlagSchema.optional(),
    toolAudit: GatewayAuditFlagSchema.optional(),
    messageAuth: GatewayAuditFlagSchema.optional(),
  })
  .strict();
```

### Complete Config with Defaults

All options live under `gateway.security`. Gateway-level options are under
`gateway.*`:

```json5
{
  gateway: {
    security: {
      // ─── Layer 0: Transport ───────────────────────────────────────

      // Minimum TLS version for gateway HTTPS listeners.
      // OWASP Transport Layer Security Cheat Sheet: enforce TLS 1.3 minimum.
      // Default: "TLSv1.3"
      tlsMinVersion: "TLSv1.3",

      // ─── Layer 1: Pre-Handshake (verifyClient) ────────────────────

      // Reject duplicate/chained X-Forwarded-* headers.
      // verifyClient step 1. CWE-345. Default: true
      strictHeaderValidation: true,

      // Reject proxy headers from non-trusted IPs.
      // verifyClient step 2. CWE-345. Default: true
      rejectUntrustedProxyHeaders: true,

      // Auto-disable localhost privilege when proxy headers present.
      // Prevents Tailscale Serve loopback bypass. verifyClient step 3.
      // CWE-346. Default: true
      autoDisableLocalhostBehindProxy: true,

      // Whether loopback client gets implicit privilege (auto-paired).
      // Default: true
      disableLocalhostPrivilege: true,

      // Validate Host header against the allowlist.
      // Default: false
      validateHostHeader: false,

      // Allow a wildcard `*` origin in the allowlist (discouraged).
      // Default: false
      allowWildcardOrigin: false,

      // Reject when forwarded-proto does not match Origin scheme.
      // Detects SSL stripping. verifyClient step 3. CWE-346.
      // Default: true
      strictProtoValidation: true,

      // Enforce origin check for non-browser clients (no Origin header).
      // Opt-in for internet-facing deployments. Default: false
      enforceOriginCheckForAllClients: false,

      // IP allowlist (CIDR notation). Blocklist takes precedence.
      // Unknown IPs fail closed. verifyClient step 4. CWE-284.
      ipAllowlist: [],

      // IP blocklist (CIDR notation). Takes precedence over allowlist.
      ipBlocklist: [],

      // Require openclaw-gateway-v1 subprotocol on upgrade.
      // verifyClient step 5. Default: true
      requireSubprotocol: true,

      // Global WebSocket connection limit.
      // verifyClient step 0. CWE-770. Optional; server applies its own cap if unset (example: 64).
      maxWebSocketConnections: 64,

      // Pre-handshake per-IP connection rate limit.
      // verifyClient step 0b. CWE-770.
      connectionRateLimit: {
        maxAttempts: 30,           // per window. Default: 30
        windowMs: 10_000,          // sliding window. Default: 10s
        lockoutMs: 60_000,         // lockout duration. Default: 60s
        exemptLoopback: true,      // exempt localhost. Default: true
        pruneIntervalMs: 30_000,   // stale entry cleanup. Default: 30s
        ipv6SubnetMask: 56,        // OWASP recommended /56. Default: 56
      },

      // Max WebSocket message payload in bytes.
      // Clamped to ≤ 25 MB (you can lower it, not raise it). Pre-auth limit always 64 KB.
      // CWE-770. Optional; resolver clamps the configured value to ≤ 25 MB (26_214_400).
      maxPayloadBytes: 25 * 1024 * 1024,

      // ─── Layer 2: Authentication ──────────────────────────────────

      // Enable nonce-based handshake token challenge.
      // Post-handshake step 6. Default: true
      enableHandshakeTokens: true,

      // Enable per-message replay protection (request-id LRU + TTL).
      // Post-handshake. Default: true
      enableMessageReplayProtection: true,

      // ─── Layer 3: Authorization ───────────────────────────────────

      // Enable per-message capability gating (default-deny; 3 high-risk methods pinned).
      // Post-handshake step 7. CWE-862. Default: true
      enableMessageAuthorization: true,

      // Allow unmapped RPC methods without capability check.
      // DANGEROUS — weakens authorization. Default: false
      dangerouslyAllowUnmappedMethods: false,

      // Grant wildcard `*` on unknown WS paths.
      // DANGEROUS — allows endpoint confusion. CWE-862. Default: false
      dangerouslyAllowLegacyEndpointFallback: false,

      // Fall back to Host header when Origin is missing.
      // DANGEROUS — weakens origin validation. Default: false
      dangerouslyAllowHostHeaderOriginFallback: false,

      // ─── Layer 4: Operational ─────────────────────────────────────

      // Enable WebSocket ping/pong keep-alive.
      // Post-handshake step 11. Default: true
      enablePingPong: true,

      // Interval between ping frames in ms. Default: 25_000
      pingIntervalMs: 25_000,

      // Time to wait for pong response before closing. Default: 10_000
      pongTimeoutMs: 10_000,

      // Enable per-connection frame/message rate limiting.
      // Post-handshake step 9. Default: true
      enableRateLimiting: true,

      // ─── Observability ────────────────────────────────────────────

      // Redact known secret values from outbound gateway messages.
      // Default: true (effective when enableOutboundRedaction !== false)
      enableOutboundRedaction: true,

      // Per-method rate limits (method name → requests per minute).
      methodRateLimits: {},

      // Optional global per-IP gateway message rate limit (requests/minute).
      // Not set by default. (The HTTP REST limit is a fixed 120/min — see request-rate-limit.ts.)
      connectionRateLimitPerMinute: undefined,

      // Optional per-IP browser/client rate limit (requests/minute).
      browserRateLimitPerMinute: undefined,

      // Auth audit: HMAC-signed append-only log of connect attempts.
      // Env override: OPENCLAW_AUTH_AUDIT=1.
      authAudit: { enabled: false },

      // Tool audit: HMAC-signed append-only log of every tools/invoke.
      toolAudit: { enabled: false },

      // Per-message defense-in-depth capability gating beyond operator
      // scope. Extra checks for secrets.*, config.set_protected,
      // node-role methods.
      messageAuth: { enabled: false },
    },

    // ─── Gateway top-level security options ─────────────────────────

    // Trusted reverse proxy IPs (CIDR notation).
    // Only these IPs may send X-Forwarded-* headers.
    trustedProxies: [],

    // Allow real IP from X-Forwarded-For when no trusted proxy configured.
    // Default: false — prevents IP spoofing via client-supplied headers.
    allowRealIpFallback: false,

    // Control UI origin allowlist.
    controlUi: {
      allowedOrigins: [],
    },

    // TLS configuration.
    tls: {
      // cert and key paths for HTTPS listeners
    },

    // HTTP security headers.
    http: {
      securityHeaders: {
        // HSTS header value. Set false to disable.
        strictTransportSecurity: "max-age=63072000; includeSubDomains; preload",
      },
    },
  },
}
```

### Canvas WebSocket Note

Canvas WebSocket connections (`/canvas`) are handled by a separate upgrade path
and do not traverse the 6-step pre-handshake `verifyClient` pipeline. Canvas
relies on `authorizeCanvasRequest` with its own auth and rate limiting. This
is intentional — canvas is a separate concern with its own security model.

---

## Capabilities

| Capability       | Required for                                   | Granted to                                       |
| ---------------- | ---------------------------------------------- | ------------------------------------------------ |
| `*`              | Everything                                     | Local loopback operator only                     |
| `admin:read`     | Read-only methods (status, logs, config.get)   | Operators, nodes, tokens (via scope translation) |
| `admin:write`    | Write methods (send, sessions, cron, pairing)  | Operators, nodes, tokens (via scope translation) |
| `admin:config`   | `config.set`/`config.patch` on protected paths | Local operators with `*` scope only              |
| `secrets:read`   | `secrets.resolve`                              | Explicit `secrets:read` or `*` scope only        |
| `secrets:manage` | `secrets.reload`                               | Explicit `secrets:manage` or `*` scope only      |
| `talk:secrets`   | Talk secrets scope                             | Operators with `talk:secrets` scope              |
| `agent:*`        | Agent endpoint methods                         | Agent-capable clients                            |
| `internal:*`     | Internal endpoint                              | Internal processes only                          |

**Key design decision:** `operator.admin` (macOS app scope) translates to
`admin:read` + `admin:write` but does **not** grant `admin:config` or
`secrets:read`. This prevents a paired device from disabling auth or
exfiltrating API keys, even if it has admin-level operational access.

The scope → capability translation is implemented in
`src/gateway/message-auth.ts` (`OPERATOR_SCOPE_CAPABILITIES`).

---

## Recommended Production Config

### Internet-facing (maximum hardening)

For deployments exposed to the public internet behind a reverse proxy:

```json5
{
  gateway: {
    security: {
      // Transport
      tlsMinVersion: "TLSv1.3",

      // Pre-handshake — all default-on, listed explicitly for clarity
      strictHeaderValidation: true,
      rejectUntrustedProxyHeaders: true,
      autoDisableLocalhostBehindProxy: true,
      disableLocalhostPrivilege: true,
      strictProtoValidation: true,

      // Opt-in: enforce origin for ALL clients (not just browsers)
      enforceOriginCheckForAllClients: true,

      // Validate Host header against allowed origins
      validateHostHeader: true,

      // Require the gateway subprotocol
      requireSubprotocol: true,

      // Network access control — restrict to known networks
      // ipAllowlist: ["10.0.0.0/8", "172.16.0.0/12"],

      // Connection limits
      maxWebSocketConnections: 64,
      connectionRateLimit: {
        maxAttempts: 30,
        windowMs: 10_000,
        lockoutMs: 60_000,
        exemptLoopback: true,
        ipv6SubnetMask: 56,
      },

      // Payload limits
      maxPayloadBytes: 25 * 1024 * 1024,

      // Authentication
      enableHandshakeTokens: true,

      // Authorization
      enableMessageAuthorization: true,
      // Do NOT enable these in production:
      dangerouslyAllowUnmappedMethods: false,
      dangerouslyAllowLegacyEndpointFallback: false,
      dangerouslyAllowHostHeaderOriginFallback: false,

      // Operational
      enablePingPong: true,
      pingIntervalMs: 25_000,
      pongTimeoutMs: 10_000,
      enableRateLimiting: true,

      // Observability — enable all audit trails
      enableOutboundRedaction: true,
      authAudit: { enabled: true },
      toolAudit: { enabled: true },
      messageAuth: { enabled: true },
    },

    // Trusted proxy configuration
    trustedProxies: ["10.0.0.0/8"],  // Your reverse proxy network

    // Disable IP spoofing fallback
    allowRealIpFallback: false,

    // Strict origin allowlist
    controlUi: {
      allowedOrigins: ["https://your-gateway.example.com"],
    },

    // HTTP security headers
    http: {
      securityHeaders: {
        strictTransportSecurity: "max-age=63072000; includeSubDomains; preload",
      },
    },
  },
}
```

### Tailscale Serve (private network)

For deployments behind Tailscale Serve with no public internet exposure:

```json5
{
  gateway: {
    security: {
      // Pre-handshake — defaults are fine for Tailscale
      strictHeaderValidation: true,
      rejectUntrustedProxyHeaders: true,
      autoDisableLocalhostBehindProxy: true,
      requireSubprotocol: true,

      // Connection rate limiting (more relaxed for private network)
      connectionRateLimit: {
        maxAttempts: 60,
        windowMs: 10_000,
        lockoutMs: 30_000,
        exemptLoopback: true,
        ipv6SubnetMask: 56,
      },

      // Authorization still enforced
      enableMessageAuthorization: true,
      enableHandshakeTokens: true,
      enableRateLimiting: true,

      // Observability
      enableOutboundRedaction: true,
      authAudit: { enabled: true },
      toolAudit: { enabled: false },
      messageAuth: { enabled: true },
    },

    // Tailscale CGNAT range — the Tailscale Serve proxy IP
    trustedProxies: ["100.64.0.0/10"],

    allowRealIpFallback: false,

    controlUi: {
      allowedOrigins: ["https://your-gateway.tailnet.ts.net"],
    },
  },
}
```

---

## Test Coverage

Counts are **declared test cases** (static `it`/`test` block count) of the current source, re-verified 2026-07-14. Parameterized `it.each`/`test.each` blocks are counted once, so the runtime executes at least this many cases. They are a reproducible lower bound, not a substitute for a full suite run.

### Package `@openclaw/gateway-security-core` (all 18 test files)

| Test file                                    | Cases   | Covers                                 |
| -------------------------------------------- | ------- | -------------------------------------- |
| `audit-log-base.test.ts`                     | 5       | Shared HMAC append-only log infra      |
| `auth-audit-log.test.ts`                     | 4       | Auth audit log                         |
| `auth-audit-log-hmac.test.ts`                | 9       | HMAC signing and verification          |
| `config-guard.test.ts`                       | 14      | Protected config path gate             |
| `connection-rate-limit.test.ts`              | 25      | Pre-handshake per-IP rate limiter      |
| `credential-vault.test.ts`                   | 27      | AES-256-GCM vault at rest              |
| `device-session-authority.test.ts`           | 23      | Device generation and session tracking |
| `device-session-authority-handshake.test.ts` | 17      | Device handshake                       |
| `exec-deny-paths.test.ts`                    | 78      | Exec deny-list                         |
| `ip-restriction-policy.test.ts`              | 16      | CIDR allow/blocklist                   |
| `ipv6-subnet.test.ts`                        | 17      | IPv6 /56 subnet masking                |
| `message-replay-guard.test.ts`               | 11      | Per-connection replay guard            |
| `request-rate-limit.test.ts`                 | 11      | HTTP REST rate limiter                 |
| `startup-security-checks.test.ts`            | 15      | Boot-time safety checks                |
| `tool-audit.test.ts`                         | 11      | Tool invocation audit log              |
| `ws-endpoint.test.ts`                        | 6       | Per-endpoint capability requirements   |
| `ws-frame-validator.parity.test.ts`          | 3       | Frame validation parity                |
| `ws-protocol.test.ts`                        | 6       | Subprotocol and frame rate limits      |
| **Total**                                    | **298** |                                        |

### Gateway security-relevant tests (representative)

The gateway (`src/gateway`) contains many additional authentication, authorization, session, node, and network tests. Representative security-critical files:

| Test file                                                            | Cases | Area                        |
| -------------------------------------------------------------------- | ----- | --------------------------- |
| `origin-check.test.ts`                                               | 66    | Origin / CSWSH validation   |
| `auth.test.ts`                                                       | 69    | Gateway authentication      |
| `auth-rate-limit.test.ts`                                            | 24    | Auth rate limiting          |
| `auth.proxy-headers.test.ts`                                         | 17    | Proxy header validation     |
| `net.test.ts`                                                        | 43    | IP resolution, RFC 7239     |
| `message-auth.test.ts`                                               | 9     | Per-message capability gate |
| `method-scopes.test.ts`                                              | 26    | Operator scope model        |
| `credentials.test.ts`                                                | 31    | Credential handling         |
| `server/verify-client.test.ts`                                       | 26    | Handshake verify-client     |
| `server/verify-client.property.test.ts`                              | 15    | verify-client invariants    |
| `server/verify-client.path-classification.test.ts`                   | 10    | Path classification         |
| `server.preauth-hardening.test.ts`                                   | 8     | Pre-auth hardening          |
| `server.auth.browser-hardening.test.ts`                              | 13    | Browser hardening           |
| `server.device-pair-approve-authz.test.ts`                           | 8     | Device-pair authz           |
| `server.device-token-rotate-authz.test.ts`                           | 12    | Device token rotate         |
| `server.node-pairing-authz.test.ts`                                  | 12    | Node pairing authz          |
| `server.plugin-http-auth.test.ts`                                    | 22    | Plugin HTTP auth            |
| `server.shared-auth-rotation.test.ts`                                | 8     | Shared auth rotation        |
| `server.roles-allowlist-update.test.ts`                              | 12    | Role allowlist              |
| `server.silent-scope-upgrade-reconnect.poc.test.ts`                  | 8     | Scope-upgrade PoC guard     |
| `server/authenticated-connection-budget.test.ts`                     | 12    | Connection budget           |
| `server/preauth-connection-budget.test.ts`                           | 6     | Pre-auth budget             |
| `server/lifecycle/connection-limits.test.ts`                         | 12    | Connection limits           |
| `server/lifecycle/connection-type-gate.test.ts`                      | 9     | Connection-type gate        |
| `server/ws-connection/connect-policy.test.ts`                        | 14    | WS connect policy           |
| `server/ws-connection/auth-context.test.ts`                          | 27    | Auth context                |
| `server/ws-connection/auth-messages.test.ts`                         | 6     | Auth messages               |
| `server/ws-connection/handshake-auth-helpers.test.ts`                | 32    | Handshake helpers           |
| `server/ws-connection/message-handler.message-authorization.test.ts` | 10    | Message authorization       |
| `server/ws-connection/unauthorized-flood-guard.test.ts`              | 5     | Flood guard                 |
| `startup-auth.test.ts`                                               | 28    | Startup auth                |
| `security-path.test.ts`                                              | 7     | Security path handling      |

Additional gateway authorization coverage lives in `server-methods/*` (for example `server-methods.authorization`, `server-methods/secrets.test.ts`, `server-methods/config.shared-auth.test.ts`) and across node, session, and operator-approval test files.

---

## Files Added or Significantly Modified

### `@openclaw/gateway-security-core` package (fork-only, zero merge risk)

| Path in package                   | Purpose                                                       |
| --------------------------------- | ------------------------------------------------------------- |
| `src/security-config.ts`          | Canonical `GatewaySecurityConfig` type (4 OWASP layers)       |
| `src/connection-rate-limit.ts`    | Per-IP sliding window rate limiter                            |
| `src/ip-restriction-policy.ts`    | CIDR allowlist/blocklist                                      |
| `src/ws-protocol.ts`              | Frame/message rate limiting, subprotocol enforcement          |
| `src/ws-endpoint.ts`              | Per-endpoint capability requirements                          |
| `src/ws-keepalive.ts`             | Ping/pong dead-connection detection                           |
| `src/config-guard.ts`             | Protected config path gate (`admin:config` required)          |
| `src/auth-audit-log.ts`           | HMAC-signed append-only auth event log                        |
| `src/tool-audit.ts`               | HMAC-signed append-only tool invocation log                   |
| `src/audit-log-base.ts`           | Shared HMAC append-only log infrastructure                    |
| `src/ws-frame-validator.ts`       | Defense-in-depth Zod frame validation                         |
| `src/device-session-authority.ts` | Device generation tracking, session replay prevention         |
| `src/startup-security-checks.ts`  | Boot-time TLS/auth/bind safety checks                         |
| `src/exec-deny-paths.ts`          | Exec tool deny-list (secrets, .env, SSH keys)                 |
| `src/request-rate-limit.ts`       | HTTP REST endpoint rate limiting                              |
| `src/ipv6-subnet.ts`              | IPv6 /56 subnet masking for rate-limit key generation (OWASP) |
| `src/sliding-window-store.ts`     | Reusable sliding window data structure for rate limiters      |
| `src/credential-keystore.ts`      | KEK resolution from external key-encryption key               |
| `src/credential-store-cell.ts`    | Auth-profile cell open/seal helpers (vault at rest)           |
| `src/credential-vault.ts`         | AES-256-GCM AEAD envelope encryption at rest                  |
| `src/credential-vault-cache.ts`   | In-memory KEK cache, env-configurable                         |
| `src/message-replay-guard.ts`     | Per-connection request-id replay guard (LRU + TTL)            |
| `src/secret-equal.ts`             | Constant-time secret compare (extends upstream)               |
| `src/index.ts`                    | Public sub-path barrel (22 exports)                           |
| `package.json`                    | Package config, **22** sub-path exports (including `./ip`)    |
| `tsconfig.json`                   | `rootDir: "../.."` for monorepo path resolution               |
| `tsdown.config.ts`                | Build config, externalizes cross-package imports              |

### Fork-only files outside the package

| File                                                    | Purpose                                                                |
| ------------------------------------------------------- | ---------------------------------------------------------------------- |
| `src/gateway/server/verify-client.ts`                   | Wrapper: calls package modules for pre-handshake                       |
| `src/gateway/server/authenticated-connection-budget.ts` | Per-device connection budget (env-driven cap)                          |
| `src/gateway/message-auth.ts`                           | Per-message capability gating + operator scope translation (fork-only) |
| `src/security/outbound-redact.ts`                       | Redacts secrets from outbound gateway messages                         |
| `src/config/io.hmac-integrity.ts`                       | HMAC config file integrity verification                                |

### Upstream-touched files (fork modifications)

| File                                                     | Changes                                                                                                                                                                                                                                                                                                            |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/gateway/net.ts`                                     | `validateSensitiveHeaders`, `validateForwardedHeaderConsistency`; uses local IP resolution helpers                                                                                                                                                                                                                 |
| `src/gateway/origin-check.ts`                            | `Sec-Fetch-Site` cross-site detection, `X-Forwarded-Proto` mismatch (SSL-strip) validation, forwarded-host spoof rejection, host-header validation, and wildcard-origin rejection (all wired via `checkBrowserOrigin`); the earlier signed-origin-token verifier was removed as dead code (never wired, no issuer) |
| `src/gateway/forwarded-headers.ts`                       | RFC 7239 `Forwarded` header parsing, `validateProtoMismatch()`, cross-header consistency                                                                                                                                                                                                                           |
| `src/gateway/server-runtime-state.ts`                    | `createConnectionRateLimiter()`, `createRuntimeVerifyClient()`, `perMessageDeflate: false`                                                                                                                                                                                                                         |
| `src/gateway/server/verify-client.ts`                    | 6-step pre-handshake pipeline (new file) — see `createGatewayVerifyClient` JSDoc for check order                                                                                                                                                                                                                   |
| `src/gateway/server/ws-connection/message-handler.ts`    | verifyClient integration, protected config check, IP restriction forwarding, device credential invalidation                                                                                                                                                                                                        |
| `src/gateway/server/ws-connection.ts`                    | ping/pong keep-alive, close-code-aware reconnect                                                                                                                                                                                                                                                                   |
| `src/gateway/server-methods/config.ts`                   | `isProtectedConfigPath()` gate on `config.set`/`config.patch`                                                                                                                                                                                                                                                      |
| `src/gateway/auth.ts`                                    | `validateCredentialStrength()`, Tailscale whois timeout (5s), audit logger integration, IP restriction check before auth mode, trusted proxy user charset validation                                                                                                                                               |
| `src/gateway/method-scopes.ts`                           | Dynamic params default to DENY when unparseable (prevents silent auth bypass)                                                                                                                                                                                                                                      |
| `src/gateway/rate-limit-attempt-serialization.ts`        | Periodic cleanup timer (60s) to prevent memory leaks from pending attempt map                                                                                                                                                                                                                                      |
| `src/gateway/server-constants.ts`                        | `resolveMaxPayloadBytes` with safe clamping                                                                                                                                                                                                                                                                        |
| `src/gateway/control-plane-rate-limit.ts`                | LRU eviction instead of insertion-order, prune/dispose lifecycle                                                                                                                                                                                                                                                   |
| `src/gateway/device-auth.ts`                             | Re-export shim for device-auth helpers from `gateway-client` (no verification logic in this file)                                                                                                                                                                                                                  |
| `packages/gateway-protocol/src/connect-error-details.ts` | Timestamp removed from challenge payload (moved out of `src/gateway/protocol/`)                                                                                                                                                                                                                                    |
| `packages/gateway-protocol/src/schema/error-codes.ts`    | New error codes for security rejections (moved out of `src/gateway/protocol/`)                                                                                                                                                                                                                                     |
| `src/config/types.gateway.ts`                            | Re-exports `GatewaySecurityConfig` from package                                                                                                                                                                                                                                                                    |
| `src/config/zod-schema.ts`                               | `GatewaySecurityConfigSchema` — Zod validation for all security fields                                                                                                                                                                                                                                             |
| `src/config/validation.ts`                               | Config validation for security fields                                                                                                                                                                                                                                                                              |
| `Dockerfile*`                                            | `NODE_TLS_REJECT_UNAUTHORIZED` not set (upstream also omits it; not a fork-only fix); silent install fallback                                                                                                                                                                                                      |

---

## Upstream Comparison

> **Verified against `openclaw/openclaw@main` on 2026-06-17, re-verified 2026-07-14** by reading upstream source via `gh api` (custom upgrade handler, `preauth-connection-budget.ts`, `method-scopes.ts`, `gateway-client/client.ts`, `logging/redact.ts`, `src/security/secret-equal.ts`, etc.). The fork is a direct descendant of current `upstream/main` (`eb7c151d0753`), so it contains all upstream gateway code; the table below lists only the fork's _additions_ and notes where upstream already provides a baseline. Earlier drafts overclaimed upstream as "No" for features upstream actually has in a different shape; those rows are corrected below.

### Fork-only features (absent from upstream)

These genuinely do not exist upstream (verified: no equivalent found).

| Feature                                   | Fork                                                          | CWE      | Source                                                         |
| ----------------------------------------- | ------------------------------------------------------------- | -------- | -------------------------------------------------------------- |
| `@openclaw/gateway-security-core` package | 25 modules (22 exports)                                       | —        | `packages/gateway-security-core/`                              |
| HTTP request rate limiting (120/min/IP)   | Yes (REST sliding window)                                     | CWE-770  | `request-rate-limit.ts` (package)                              |
| Client IP allowlist/blocklist (CIDR)      | Yes, pre-handshake                                            | CWE-284  | `ip-restriction-policy.ts` (package)                           |
| Subprotocol enforcement                   | `openclaw-gateway-v1` required                                | CWE-284  | `ws-protocol.ts` (package)                                     |
| RFC 7239 `Forwarded:` header parsing      | `proto` + client-IP (`for`) only (host not fully parsed)      | CWE-345  | `forwarded-headers.ts` → `origin-check.ts`                     |
| Cross-header consistency check            | `XFF`/`XFH`/`XFP` agree                                       | CWE-345  | `net.ts` → `forwarded-headers.ts`                              |
| IPv6 subnet masking (rate-limit key)      | /56 OWASP                                                     | CWE-770  | `connection-rate-limit.ts` (package)                           |
| Outbound secret redaction in delivery     | Wired into chat delivery path                                 | CWE-200  | `outbound-redact.ts` → `server-chat.ts`                        |
| Credential vault at rest                  | AES-256-GCM AEAD, KEK-supplied (no scrypt)                    | CWE-311  | `credential-vault.ts` (replaces deleted `sealed-json-file.ts`) |
| Auth audit log (HMAC, append-only)        | Yes                                                           | CWE-778  | `auth-audit-log.ts` (package)                                  |
| Tool audit log (HMAC, append-only)        | Yes                                                           | CWE-778  | `tool-audit.ts` (package)                                      |
| Device session authority                  | Replay-after-revocation detect                                | CWE-384  | `device-session-authority.ts` (package)                        |
| Exec tool deny-paths                      | secrets/.env/SSH/GPG deny-list                                | CWE-200  | `exec-deny-paths.ts` (package)                                 |
| Config HMAC integrity                     | Tamper detection between reads                                | CWE-354  | `io.hmac-integrity.ts`                                         |
| Per-device connection budget              | Yes (env-driven cap)                                          | CWE-770  | `authenticated-connection-budget.ts`                           |
| Endpoint isolation (4 endpoints)          | Capability per endpoint                                       | CWE-284  | `ws-endpoint.ts` (package)                                     |
| Cumulative byte budget (50 MB/min)        | Per-connection per-minute                                     | CWE-770  | `ws-protocol.ts` (package)                                     |
| Zod schema defaults + bounds              | 16 boolean fields + `tlsMinVersion` default; numerics bounded | CWE-20   | `zod-schema.ts`                                                |
| CIDR format validation                    | `CidrOrIpSchema`                                              | CWE-20   | `zod-schema.ts`                                                |
| Per-message Zod frame validator           | `validateInboundFrame()`                                      | CWE-20   | `ws-frame-validator.ts` (package)                              |
| Startup security checks (fail-closed)     | Critical findings block boot                                  | CWE-1188 | `startup-security-checks.ts` → `server.impl.ts`                |
| `perMessageDeflate` explicitly disabled   | `false`                                                       | CWE-502  | `server-runtime-state.ts`                                      |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` not set  | Not set in fork (also absent upstream)                        | CWE-295  | `Dockerfile*`                                                  |

### Proxy and origin support features

The fork hardens browser-origin and reverse-proxy handling on top of upstream's `checkBrowserOrigin` allowlist. These are wired into the pre-handshake `verifyClient` path (`src/gateway/server/verify-client.ts` → `checkBrowserOrigin`) and are active whenever a browser `Origin` header is present:

- **Trusted-proxy model:** upstream `authorizeTrustedProxy` is retained; the fork adds cross-header consistency so `X-Forwarded-For` / `X-Forwarded-Host` / `X-Forwarded-Proto` must agree (`net.ts` → `forwarded-headers.ts`).
- **RFC 7239 `Forwarded` parsing:** protocol and client-IP (`for`) are parsed; the fork extracts the forwarded protocol to detect SSL stripping (`extractProtoFromForwardedHeader`).
- **Forwarded-host spoof rejection:** if `X-Forwarded-Host` is present but the connection is not from a trusted proxy, the request is rejected outright (no allowlist bypass via header spoofing).
- **Protocol mismatch (SSL-strip) validation:** when behind a trusted proxy with `strictProtoValidation` (default on), the origin protocol is checked against the forwarded protocol and `X-Forwarded-Proto`; a mismatch is rejected.
- **Host-header validation:** when enabled, the `Host` header must match the `Origin` or the allowlist; otherwise the request is rejected.
- **`Sec-Fetch-Site` cross-site rejection:** a `cross-site` Fetch Metadata header is rejected (defense-in-depth against CSRF-style WS upgrades).
- **Wildcard-origin rejection:** a `*` allowlist entry is only honored when `allowWildcardOrigin` is enabled AND the request is local or behind a trusted proxy AND not cross-site.
- **Localhost-privilege disable behind proxy:** `autoDisableLocalhostBehindProxy` / `disableLocalhostPrivilege` remove the loopback privilege grant when proxy headers are present, so a proxied request cannot claim localhost trust.
- **Explicit host-header fallback:** `dangerouslyAllowHostHeaderOriginFallback` gates whether the direct `Host` may substitute for `X-Forwarded-Host` in trusted-proxy mode.
- **Client IP from socket, not header:** when the source is not a trusted proxy, the connection IP is taken from the socket, never from proxy headers (`verify-client.ts` IP restriction).

Non-browser clients (CLI, agent) do not send an `Origin` header, so these checks are skipped for them by design; they authenticate via device token, shared secret, or Tailscale instead.

### Features upstream ALSO has (do not claim as fork-only)

These were previously listed here as fork-only but **upstream implements them too** — listed for an honest comparison.

| Feature                                       | Upstream reality (verified 2026-06-17)                                                                            | Fork delta (if any)                                                                                 |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Pre-handshake connection gating               | `attachGatewayUpgradeHandler` (`server-http.ts`) runs before `handleUpgrade` — functional verifyClient equivalent | Fork uses the ws `verifyClient` path + a 6-step pipeline                                            |
| Per-IP connection limiting                    | `preauth-connection-budget.ts` — 32 concurrent unauth sockets/IP                                                  | Fork adds a sliding-window **rate** limit (30/10s) on top                                           |
| Per-message authorization                     | `method-scopes.ts` + `message-handler.ts` — default-deny, role+scope, audit-logged                                | Fork adds a `message-auth.ts` capability-string map (`secrets:read`, `admin:config`, …)             |
| Ping/pong keep-alive                          | 25s ping (`ws-connection.ts`)                                                                                     | Fork shares this; not a differentiator                                                              |
| Close-code-aware reconnect                    | `gateway-client/client.ts` — 1013/1006 handling, backoff                                                          | Shared with upstream; not a differentiator                                                          |
| Payload size cap                              | `maxPayload: MAX_PREAUTH_PAYLOAD_BYTES` on the ws server                                                          | Fork clamps configured maxPayload to ≤ 25 MB                                                        |
| Secret redaction                              | `logging/redact.ts` — API keys, PEM, Bearer, etc. (logs + transcripts)                                            | Fork additionally wires it into the live delivery path                                              |
| Startup auth checks                           | Throws on missing token/password + known-weak placeholder secrets                                                 | Fork additionally fail-closes on critical audit findings via `assertStartupSecurityFindingsAllowed` |
| Trusted-proxy validation                      | `auth.ts::authorizeTrustedProxy` — rejects loopback proxy sources, required headers, user allowlist               | Both solid; fork adds cross-header consistency                                                      |
| `perMessageDeflate`                           | Not set → ws default (disabled)                                                                                   | Fork sets it explicitly `false` (defense in depth)                                                  |
| Origin-header check (`checkBrowserOrigin`)    | Upstream has `checkBrowserOrigin` (`src/gateway/origin-check.ts`)                                                 | Fork extends it (proto mismatch, forwarded-host gating, `Sec-Fetch-Site`, wildcard rejection)       |
| Constant-time secret compare (`secret-equal`) | Upstream has `safeEqualSecret` (`src/security/secret-equal.ts`, `plugin-sdk/security-runtime.ts`)                 | Fork ships a hardened variant in `gateway-security-core`                                            |

### Fair summary

- **Fork-only, high-value:** encrypted credentials at rest (`credential-vault`), HMAC config integrity, HMAC append-only audit logs, exec deny-paths, client CIDR allow/block, HTTP per-IP rate limiting, delivery-path secret redaction, fail-closed startup checks, `@openclaw/gateway-security-core` as an auditable package.
- **Upstream already strong on:** pre-handshake upgrade gating, per-IP preauth connection budget, default-deny per-method scope authz, trusted-proxy model, Tailscale whois auth, known-weak-secret rejection, log/transcript redaction, control-plane write rate limiting, bilateral keepalive.
- **Net:** the fork's differentiators are mostly **deeper defense-in-depth and tamper-evidence** (encryption at rest, HMAC integrity/audit, static deny-lists, fail-closed boot), plus a few **genuine gaps upstream leaves open** (client CIDR allow/block, generic HTTP per-IP rate limiting, delivery-path redaction).

---

## Backward Compatibility

All hardening is default-on except where noted. Current OpenClaw direct-local
clients are expected to negotiate the gateway subprotocol. Legacy direct-local
clients that cannot do that must explicitly opt out with
`gateway.security.requireSubprotocol = false`.

| Change                            | Breaking?                                                                           | Opt-out                                                  |
| --------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------- |
| `rejectUntrustedProxyHeaders`     | Only if proxy headers sent from untrusted IP                                        | `false`                                                  |
| `autoDisableLocalhostBehindProxy` | Only if proxy headers present                                                       | `false`                                                  |
| `enforceOriginCheckForAllClients` | No (default `false`)                                                                | N/A — opt-in                                             |
| `strictHeaderValidation`          | Only if duplicate/chained headers sent                                              | `false`                                                  |
| `requireSubprotocol`              | Yes for legacy clients without subprotocol                                          | `false`                                                  |
| `perMessageDeflate` disabled      | Slightly higher bandwidth                                                           | Cannot re-enable                                         |
| `secrets:read` capability         | Only if client lacks `*` scope                                                      | N/A                                                      |
| `admin:config` capability         | Only if client lacks `*` scope                                                      | N/A                                                      |
| `maxPayloadBytes` clamping        | Only if set above 25 MB                                                             | N/A                                                      |
| Per-message replay protection     | Only if a client reuses a request `id` on the same connection within the TTL window | `gateway.security.enableMessageReplayProtection = false` |
| `timingSafeEqual`                 | No (transparent)                                                                    | N/A                                                      |
| `validateCredentialStrength`      | Network-exposed: rejects weak creds at boot                                         | `auth.mode=none` or loopback bind                        |
| `TAILSCALE_WHOIS_TIMEOUT_MS`      | No (transparent timeout, fail-closed)                                               | N/A                                                      |
| Dynamic method params → DENY      | Only if dynamic params cannot be parsed                                             | N/A (handler returns precise error)                      |
| Rate limit attempt map cleanup    | No (background timer, no user-visible effect)                                       | N/A                                                      |

---

## OWASP Gap Analysis

Self-assessed against the [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html) and OWASP REST Security Cheat Sheet (current as of 2026-06-17; cheat sheet content verified via OWASP's official source). This is a self-assessment, not a third-party audit.

### OWASP WebSocket Cheat Sheet — core recommendations

These are the WS-specific recommendations from the cheat sheet.

| Cheat-sheet recommendation          | Implementation                                                                                                                                                      | Status |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **Use WSS** (transport encryption)  | `tlsMinVersion: "TLSv1.3"`; container image does not set `NODE_TLS_REJECT_UNAUTHORIZED=0` (upstream also omits it)                                                  | ✅ Met |
| **Validate Origin headers** (CSWSH) | `checkBrowserOrigin()` with explicit allowlist, wildcard `*` rejected                                                                                               | ✅ Met |
| **Per-action authorization**        | `message-auth.ts` — default-deny capability gate; 3 high-risk methods explicitly pinned, all other methods derive capability from their declared operator scope     | ✅ Met |
| **Prevent message replay**          | Per-connection `message-replay-guard` rejects request frames reusing an `id` within the TTL window (default 60s); bounded LRU + TTL. OWASP WS CS § replay. CWE-294. | ✅ Met |

### Additional appsec controls layered on top

These are general application-security controls (not WS-cheat-sheet items) the fork applies to the gateway surface.

| Control                  | Implementation                                                                                         | Status |
| ------------------------ | ------------------------------------------------------------------------------------------------------ | ------ |
| Input validation         | Zod schema with defaults, bounds, CIDR validation + defense-in-depth frame validator                   | ✅     |
| Rate limiting            | 4 layers: pre-handshake, post-handshake, HTTP REST, byte budget                                        | ✅     |
| Payload size limits      | `maxPayload` on WebSocketServer, clamped to ≤ 25 MB; pre-auth 64 KB                                    | ✅     |
| Cumulative byte budget   | `maxBytesPerMinute: 50MB` per connection per minute                                                    | ✅     |
| Handshake authentication | Nonce challenge, `timingSafeEqual` HMAC verification (token-based)                                     | ✅     |
| Subprotocol enforcement  | `requireSubprotocol: true` (default)                                                                   | ✅     |
| HTTP security headers    | `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, HSTS, `X-Frame-Options: DENY` (API) | ✅     |
| Content-Security-Policy  | Strict CSP for Control UI, `frame-ancestors` for canvas embedding                                      | ✅     |
| IPv6-aware rate limiting | Bitwise AND subnet masking (/56), loopback exempt                                                      | ✅     |
| Audit logging            | HMAC-signed append-only auth + tool audit, JSONL format                                                | ✅     |

### Completed hardening (this release)

| Item                                    | Was                                  | Now                                                                                                  | Priority |
| --------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------- | -------- |
| IPv6 /56 subnet masking                 | Incorrect zero-fill, no :: expansion | Bitwise AND + `expandIPv6()`, loopback never masked                                                  | P1 ✅    |
| Zod `.default()` on security booleans   | Defaults in JSDoc only               | 16 boolean fields + `tlsMinVersion` carry `.default()`, enforced at parse time                       | P2 ✅    |
| Zod `.min()`/`.max()` on numeric fields | `z.number().int().positive()`        | Bounded ranges on all numeric fields                                                                 | P2 ✅    |
| CIDR format validation in Zod           | `z.array(z.string())`                | `CidrOrIpSchema` with `superRefine` for IPv4/IPv6                                                    | P2 ✅    |
| HTTP security headers                   | Configurable HSTS only               | `XCTO: nosniff`, `Referrer-Policy`, `Permissions-Policy` already in `http-common.ts`                 | P3 ✅    |
| Per-connection byte budget              | Per-message size only                | `maxBytesPerMinute: 50MB` in `ws-protocol.ts`                                                        | P3 ✅    |
| Audit log JSON format option            | JSONL only                           | `AuditLogFormat` type added, JSONL kept for HMAC safety                                              | P4 ✅    |
| Per-message Zod frame validation        | Capability gating only               | `ws-frame-validator.ts` — defense-in-depth Zod schemas mirroring TypeBox protocol schemas            | P3 ✅    |
| Property-based tests for verify-client  | Unit/integration tests only          | 15 property-based invariant tests covering pipeline ordering, crash safety, CIDR, and config toggles | P4 ✅    |
| `X-Frame-Options` header                | Omitted (canvas framing)             | `X-Frame-Options: DENY` on all API responses via `setApiSecurityHeaders()`                           | P4 ✅    |
| `Content-Security-Policy` header        | Not set                              | `setControlUiSecurityHeaders()` with strict CSP for Control UI, `frame-ancestors` for canvas         | P4 ✅    |

### Remaining hardening opportunities

All core OWASP WebSocket Cheat Sheet recommendations are now met (including per-message replay protection). The remaining items are improvements beyond the baseline:

| Item                           | Current state                | Recommendation                            | Priority |
| ------------------------------ | ---------------------------- | ----------------------------------------- | -------- |
| CSP inline script hash support | `'unsafe-inline'` for styles | Add per-build script hash for tighter CSP | P5       |

> **Recently completed:** per-message replay protection is now implemented — `packages/gateway-security-core/src/message-replay-guard.ts` (bounded LRU + TTL, default 60s), wired in `message-handler.ts` to reject request frames that reuse an `id` on the same connection (OWASP WS CS § "Prevent message replay attacks", CWE-294). Opt out with `gateway.security.enableMessageReplayProtection = false`. Completed 2026-06-17.
