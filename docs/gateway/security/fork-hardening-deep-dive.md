---
summary: "How the security-hardened fork resolves upstream conflicts, what defense-in-depth modules it adds, and why they matter."
read_when:
  - Evaluating the fork vs upstream for production gateway security
  - Understanding the merge conflict resolution strategy
  - Auditing the security modules not present in upstream
title: "Fork Security Hardening: Deep Dive"
---

This article documents the security-hardening layer maintained in the `markfietje/openclaw` fork, explains the 20+ defense-in-depth modules that upstream does not ship, and walks through a real merge conflict resolution to show how fork hardening survives upstream refactors without regressing security.

## Why a hardened fork?

The upstream OpenClaw gateway prioritizes convenience and rapid iteration. Its security posture assumes a **trusted local network** with a single operator. That model works for personal LAN deployments but becomes dangerous when you:

- Expose the gateway over the internet (Tailscale, Cloudflare Tunnel, VPS)
- Run multiple agents that share tool execution authority
- Handle OAuth tokens from multiple providers
- Accept connections from non-loopback clients

The fork closes these gaps by adding layered defense-in-depth modules that upstream either hasn't implemented or has explicitly deprioritized. Every module is tested, documented, and designed to fail closed — if a security check cannot complete, the connection is rejected.

## What upstream does well

To be fair, upstream has made genuine security improvements that the fork benefits from and integrates:

| Upstream change                      | Commit                 | Benefit                                                                                                                                                     |
| ------------------------------------ | ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Share provider OAuth runtime helpers | `75de853c379`          | Centralized `parseOAuthAuthorizationInput`, `resolveOAuthTokenExpiresAt`, `resolveOAuthTokenLifetimeMs` prevent duplicate validation logic across providers |
| Move terminal core into package      | `de1dfab03ef` (#88279) | Cleaner dependency graph, proper package isolation                                                                                                          |
| Share prompt template arguments      | `deb48a96fb8`          | Removes copy-paste argument parsing code                                                                                                                    |
| Persist subagent registry in SQLite  | `5374c7a8a20` (#88260) | Durable agent run tracking across restarts                                                                                                                  |
| Centralize timeout grace clamping    | `5f4fc7512e3`          | Consistent timer behavior across all plugins                                                                                                                |

These are good refactors. The fork integrates them fully. The conflict arises because the fork's security hardening touches the same surfaces — but with stricter validation.

## The conflict: both sides improved the same code

When rebasing the fork's `feat(security): fork hardening on upstream/main` commit onto the latest `upstream/main`, 8 files had merge conflicts. Every single conflict had the same pattern:

> **Upstream refactored** (extracted helpers, renamed imports, moved packages).  
> **Fork hardened** (added validated coercion, rate limiting, audit logging, endpoint isolation).  
> Both modified the same import blocks and validation checks.

This is the healthiest kind of merge conflict — both sides independently improved the same code. The resolution strategy is to **keep the fork's hardened validation while adopting upstream's cleaner module structure**.

### Conflict map

| File                                 | Upstream's change                                                                        | Fork's hardening                                                                                              | Resolution                                                                                           |
| ------------------------------------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `openai-codex-oauth-flow.runtime.ts` | Removed inlined `typeof` checks, expects centralized helpers                             | `resolveOAuthTokenLifetimeMs()` / `resolveOAuthTokenExpiresAt()` — validate NaN, Infinity, negative, clamping | Keep fork's hardened helpers — they catch more edge cases than `typeof json.expires_in !== "number"` |
| `zalo-js.ts`                         | Centralized timer helpers into `number-runtime`                                          | `resolveTimerTimeoutMs()` — prevents zero/negative/infinite timeout values                                    | Keep both: fork's used timer helper + upstream's shared `parseStrictNonNegativeInteger`              |
| `prompt-templates.ts`                | Extracted functions to `file-loader-utils.js`, then upstream deleted it and inlined back | Uses `resolveKind`, `parseFrontmatter`, `basenameEnvPath`                                                     | Adopt upstream's inline structure (module deleted), keep all function implementations                |
| `subagent-registry-state.ts`         | Renamed imports: `*FromDisk` → `*FromSqlite`                                             | Same function calls in the body                                                                               | Keep fork's sqlite-named imports — matches actual call sites                                         |
| `tui-cli.ts`                         | Moved terminal imports into `packages/terminal-core`                                     | Added `resolveGatewayAuthOptions` for gateway auth                                                            | Keep existing imports + add missing gateway auth import                                              |
| `doctor-auth.ts`                     | Removed unused `fs`, `path`, agent-scope imports                                         | `note()` used throughout for auth health reporting                                                            | Keep `note` import, drop genuinely unused imports                                                    |
| `doctor-auth.profile-health.test.ts` | Removed `note` import (test only needs mock)                                             | Import ensures mocked module is loaded                                                                        | Keep — harmless and matches fork's test style                                                        |
| `number-runtime.ts`                  | No change to exports                                                                     | Added `asFiniteNumberInRange`, `asSafeIntegerInRange` re-exports                                              | Keep fork's hardened exports — used across plugins                                                   |

## The 20+ security modules the fork adds

These modules are **not present in upstream** and represent the core value of the hardened fork:

### Pre-handshake connection hardening

#### `connection-rate-limit.ts`

In-memory sliding-window rate limiter that runs **before** the WebSocket handshake completes. Tracks connection attempts per client IP. Loopback addresses are exempt by default.

- Default: 30 connection attempts per 10-second window per IP
- 60-second lockout on exceed
- Close code `1013` (Try Again Later) on rejection
- Automatic Map pruning to prevent memory leaks

#### `verify-client.ts`

The `ws` `verifyClient` callback implements a strict 6-layer security pipeline. Each layer rejects before the next runs:

1. Connection limits (max concurrent)
2. Connection rate limiting (per-IP sliding window)
3. Strict header validation (reject duplicate/chained `X-Forwarded-*`)
4. Cross-header consistency (`Forwarded` vs `X-Forwarded-*`)
5. Untrusted proxy header rejection
6. Origin validation (double-lock: Origin ↔ `X-Forwarded-Host`)

Connections that fail any layer never complete the WebSocket handshake — they're rejected at the HTTP 101 upgrade stage.

#### `ip-restriction-policy.ts`

CIDR-aware IP allowlist/blocklist for gateway access control. Supports both IPv4 and IPv6 subnet matching. Blocklist takes precedence over allowlist.

#### `forwarded-headers.ts`

RFC 7239 `Forwarded` header parser with proxy chain depth limiting (max 5 hops). Extracts the original client IP, host, and protocol from reverse proxy chains. Prevents header spoofing through cross-header inconsistency checks.

### Authentication hardening

#### `auth-audit-log.ts`

HMAC-authenticated, append-only audit log for all auth events. Every entry is tamper-evident via per-entry HMAC and chain hash. Log rotation with max size limits prevents disk exhaustion.

Events tracked: `auth_failure`, `auth_success`, `rate_limited`, `ip_blocked`. Each entry includes client IP, method, reason, user, and actor ID.

#### `device-session-authority.ts`

Tracks device identity and role generations to detect session invalidation. When a device is re-paired, its generation increments — old sessions with stale generations are rejected. This prevents session replay after device revocation.

#### `message-auth.ts`

Operator scope → capability translation layer. Maps macOS app `operator.*` scopes to fine-grained capability strings. Critical: `operator.admin` does **not** grant `secrets:*` or `admin:config` — those require explicit opt-in.

#### `startup-security-checks.ts`

Runs a battery of security checks at gateway startup:

- TLS enforcement (detects network exposure without TLS)
- Credential strength (flags weak token/password when exposed)
- Bind address safety (detects `0.0.0.0` fallback)

Returns `critical` or `warn` severity levels with human-readable descriptions.

### Rate limiting

#### `request-rate-limit.ts`

In-memory sliding-window rate limiter for HTTP REST endpoints. Mirrors the connection-level limiter's design for consistency.

- Default: 120 requests per minute per IP
- 10,000 max tracked non-loopback IPs
- Automatic background pruning every 30 seconds
- Loopback exemption

### Endpoint isolation

#### `ws-endpoint.ts`

Defines distinct WebSocket endpoints with per-endpoint security requirements:

| Endpoint               | Auth         | Origin       | Capabilities                                                                   |
| ---------------------- | ------------ | ------------ | ------------------------------------------------------------------------------ |
| `/gateway/ws-agent`    | Required     | Required     | `agent:read`, `agent:write`, `agent:execute`                                   |
| `/gateway/ws-admin`    | Required     | Required     | `admin:read`, `admin:write`, `admin:execute`, `admin:config`, `session:manage` |
| `/gateway/ws-internal` | Required     | Required     | Internal services only                                                         |
| `/gateway` (legacy)    | Configurable | Configurable | Backward compat                                                                |

Each endpoint has its own `requireOrigin`, `requireAuth`, and `allowedCapabilities` — a compromise between upstream's single-endpoint model and full endpoint isolation.

#### `ws-protocol.ts`

Typed WebSocket close codes and subprotocol negotiation constants. Ensures clients and servers agree on the protocol version during the handshake.

### Tool execution safety

#### `tool-audit.ts`

Append-only audit log for tool invocations. Tracks tool name, actor ID, session, channel, model, run ID, tool call ID, result status, and duration. Sensitive arguments are **never** logged. Log rotation with max size limits.

#### `exec-deny-paths.ts`

Configurable deny-list of filesystem glob patterns that the `exec` tool cannot access. Default patterns block:

- `**/.openclaw/secrets/**`
- `**/.openclaw/credentials/**`
- `**/.env`, `**/.env.*`
- `**/*secret*`, `**/*credential*`
- `**/ssh/id_*`

When a command attempts to access a matching path, the gate returns the matched pattern and the caller blocks execution.

### Data protection

#### `outbound-redact.ts`

Automatically redacts gateway secrets (tokens, passwords) from outbound message payloads before they reach messaging channels. Scans text, buttons, interactive blocks, and TTS supplements. Prevents accidental credential leakage through agent replies.

#### `sealed-json-file.ts`

AES-256-GCM encrypted JSON file storage for sensitive data at rest. Uses a key derived from a machine-specific secret. File integrity is verified on every read.

#### `secret-env.ts`

Validates and sanitizes environment variables containing secrets. Detects common misconfigurations: empty values, whitespace-padded secrets, quotes included in the value, and default/placeholder values.

#### `io.hmac-integrity.ts`

HMAC integrity verification for config files. Detects tampering with configuration files between reads. Each file gets a companion `.hmac` file with a keyed hash.

### Runtime hardening

#### `capabilities.ts`

Fine-grained capability system for gateway method authorization. Maps method names to required capabilities, ensuring least-privilege access.

#### `credential-strength.test.ts` + validation

Credential strength validation that rejects weak tokens, short passwords, and common patterns. Enforced at config load time, not just at connection time.

#### `authenticated-connection-budget.ts`

Per-device connection budget that limits the number of simultaneous authenticated WebSocket connections. Prevents connection exhaustion attacks from compromised devices.

## Hardened SDK helpers

The fork extends the plugin SDK with validated coercion helpers that upstream lacks:

### `provider-oauth-runtime.ts`

```ts
// Upstream: raw typeof check
if (typeof json.expires_in !== "number") { ... }

// Fork: hardened coercion via resolveOAuthTokenLifetimeMs()
if (resolveOAuthTokenLifetimeMs(json.expires_in) === undefined) { ... }
```

The fork's version catches:

- `NaN` (typeof is `"number"` but value is invalid)
- `Infinity` / `-Infinity` (typeof is `"number"` but value is dangerous)
- Negative values (negative `expires_in` makes no sense)
- Zero (zero-second expiry is a protocol violation)
- Non-number types (string `"3600"` passes typeof but isn't safe for arithmetic)

### `number-coercion.ts` exports

```ts
// Fork re-exports hardened helpers from number-runtime.ts:
asFiniteNumberInRange(value, { min: 0, max: 3600 }); // Bounds-checked finite number
asSafeIntegerInRange(value, { min: 0, max: 65535 }); // Bounds-checked safe integer
```

These are used across plugins (Zalo QR timeout clamping, Discord retry-after parsing, Teams error code validation) to prevent NaN, Infinity, and out-of-range values from reaching timer APIs and network calls.

## Security posture comparison

| Threat vector                       | Upstream                    | Fork                                                     |
| ----------------------------------- | --------------------------- | -------------------------------------------------------- |
| **Rapid connection flood**          | No pre-handshake rate limit | Connection rate limiter (30/10s per IP)                  |
| **WebSocket endpoint confusion**    | Single endpoint             | 4 isolated endpoints with distinct capabilities          |
| **Proxy header spoofing**           | Basic origin check          | 6-layer verifyClient pipeline + Forwarded header parsing |
| **IP-based attacks**                | No IP filtering             | CIDR-aware allowlist/blocklist                           |
| **Exec tool file access**           | No filesystem deny patterns | Configurable glob deny-list                              |
| **Credential leakage in replies**   | Not protected               | Automatic outbound redaction                             |
| **Config file tampering**           | No integrity check          | HMAC integrity verification                              |
| **Secret storage at rest**          | Plaintext JSON              | AES-256-GCM sealed files                                 |
| **OAuth token validation**          | `typeof` check              | Hardened coercion (NaN, Infinity, bounds)                |
| **Timer value attacks**             | Raw arithmetic              | Clamped timeout with grace period                        |
| **Auth event forensics**            | Console logs only           | HMAC-authenticated append-only audit log                 |
| **Session replay after revocation** | No generation tracking      | Device-session authority with generation counters        |
| **Weak credentials**                | Accepted                    | Strength validation at config load                       |
| **Connection exhaustion**           | No per-device budget        | Authenticated connection budget                          |
| **Startup misconfiguration**        | Silent degradation          | Battery of startup security checks                       |

## Resolution strategy: how to keep hardening alive across upstream merges

Maintaining a security fork against a fast-moving upstream requires a consistent resolution strategy. Here is the approach used for this rebase:

### 1. Never replace hardened validation with raw checks

When upstream uses `typeof json.expires_in !== "number"` and the fork uses `resolveOAuthTokenLifetimeMs(json.expires_in) === undefined`, always keep the fork's version. The fork's helper catches `NaN`, `Infinity`, and negative values that pass `typeof` checks.

### 2. Adopt upstream's module structure, keep fork's implementations

When upstream extracts functions into shared modules, adopt the new module structure. But keep the fork's hardened implementations within that structure. This means:

- Using upstream's import paths
- Keeping fork's validated coercion functions
- Dropping fork's inlined copies when upstream provides a shared module

### 3. Remove unused imports, keep used ones

Several conflicts involved import blocks where the fork added security-related imports alongside existing ones. Resolution: keep only the imports actually used in the file body. Unused imports (even security-related ones) add noise.

### 4. Preserve fork-only modules entirely

The 20+ new modules (`connection-rate-limit.ts`, `message-auth.ts`, etc.) are fork-only additions that don't exist upstream. These never conflict because upstream doesn't touch them. They're preserved as-is.

### 5. Verify no regression after resolution

After resolving all conflicts:

1. Grep for remaining conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`)
2. Verify all imports resolve (no references to deleted modules)
3. Confirm fork's hardened helpers are still called (not replaced by raw checks)
4. Stage resolved files and continue the rebase

### Post-resolution bug: stale `expires_in` arithmetic

Even with conflict markers removed, the `openai-codex-oauth-flow.runtime.ts` merge left a subtle bug that only shows up as TypeScript diagnostics, not as a merge conflict:

The fork's hardened code computes `expires` via `resolveOAuthTokenExpiresAt(json.expires_in)` and then guards on `expires === undefined`. But after the guard, the success return still used upstream's original expression:

```ts
// After merge resolution (WRONG) — stale upstream arithmetic:
expires: Date.now() + json.expires_in * 1000,
```

Two problems with this:

1. **TypeScript error**: `json.expires_in` is typed as `number | undefined` in `TokenResponseJson`. After the guard confirms `expires !== undefined`, TypeScript still doesn't narrow `json.expires_in` — it remains `possibly undefined`. This produces two `TS2532` errors.

2. **Semantic drift**: Even if `json.expires_in` were guaranteed defined, `Date.now() + json.expires_in * 1000` is raw arithmetic that bypasses the fork's hardened `resolveOAuthTokenExpiresAt()`. That helper applies skew compensation, safe-integer clamping, and `positiveSecondsToSafeMilliseconds()` validation. Using raw arithmetic silently discards all of that.

The fix is to use the already-computed `expires` value directly:

```ts
// After fix (CORRECT) — use the hardened value:
return {
  type: "success",
  access: json.access_token,
  refresh: json.refresh_token,
  expires,
};
```

This pattern — stale upstream arithmetic surviving behind a guard that was upgraded to use hardened helpers — is the most dangerous class of merge resolution bug. It doesn't produce conflict markers. It passes visual inspection. But it silently discards the security hardening the fork provides.

A third diagnostic (`Cannot find module 'openclaw/plugin-sdk/provider-oauth-runtime'`) is a build-order issue: the import resolves through the root `package.json` export map to `./dist/plugin-sdk/provider-oauth-runtime.d.ts`, which only exists after `pnpm build`. This is the same pattern used by all other `openclaw/plugin-sdk/*` imports across extensions. It resolves after the first build.

## Conclusion

The fork's security hardening adds 20+ defense-in-depth modules that upstream does not ship. These modules protect against real attack vectors documented in the [CWE-290 TUI client spoofing advisory](/security/ADVISORY-CWE-290-TUI-CLIENT-SPOOFING) and the [PoC vulnerability test suite](https://github.com/openclaw/openclaw/blob/main/scripts/poc-vulnerability/).

The conflict resolution strategy is straightforward because both sides share the same intent — better code. Upstream improves structure; the fork improves security. By adopting upstream's structure while keeping the fork's hardened implementations, you get the best of both: clean architecture with defense-in-depth.

For the full security posture details, see [FORK_SECURITY.md](/gateway/security/FORK_SECURITY.md) and [PROPERTY-EVIDENCE.md](/gateway/security/PROPERTY-EVIDENCE.md).
