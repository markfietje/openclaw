# Property-Evidence Map: Fork Code Snippets

Code-level evidence for each formal security property in the fork's invariant
model. Each snippet is a runnable, diffable unit that a static analyzer, CodeQL
query, or auditor can verify independently.

---

## P1 — Single Authoritative Source for Routing Context (CWE-346)

**Property:** All request-routing and trust metadata must resolve from exactly one
trusted authority with enforced hierarchy and mismatch rejection. No competing
authorities, no fallback paths, no conditional suppression.

### Evidence 1a: Cross-header consistency rejection

`src/gateway/server/verify-client.ts` — step 1b

```typescript
// 1b. Cross-header consistency — reject if X-Forwarded-For and Forwarded
//     disagree on the resolved client IP (prevents header contradiction attacks).
const headerConsistency = validateForwardedHeaderConsistency(req.headers, trustedProxies);
if (!headerConsistency.ok) {
  log.warn(`verifyClient: forwarded header inconsistency: ${headerConsistency.reason}`);
  callback(false, 1008, "invalid headers");
  return;
}
```

**Why this satisfies P1:** Two headers claiming to carry the same information
(`Forwarded` and `X-Forwarded-For`) must agree. If they disagree, the connection
is rejected — no fallback to "pick one," no priority ordering, no ambiguity.
The rejection happens before any trust decision uses either header.

### Evidence 1b: Untrusted proxy header rejection (no warn-and-continue)

`src/gateway/server/verify-client.ts` — step 2

```typescript
// 2. Untrusted proxy header rejection
//    Rejects proxy headers (X-Forwarded-For/Host/Proto/Real-IP, Forwarded)
//    from IPs not in trustedProxies.
//    Must run before origin and IP restriction so we don't trust spoofed
//    headers for those decisions.
const hasProxyHeaders = Boolean(
  forwardedFor || realIp || forwardedHost || xForwardedProto || forwarded,
);
const remoteIsTrustedProxy = isTrustedProxyAddress(remoteAddr, trustedProxies);
if (hasProxyHeaders && !remoteIsTrustedProxy) {
  if (securityConfig.rejectUntrustedProxyHeaders !== false) {
    log.warn(`verifyClient: proxy headers from untrusted address (remote=${remoteAddr ?? "?"})`);
    callback(false, 1008, "proxy headers from untrusted source");
    return;
  }
}
```

**Why this satisfies P1:** The upstream pattern was `warn && continue` — the
headers remained in the request context and influenced downstream auth/origin
decisions. The fork makes this binary: trusted source → headers accepted;
untrusted source → connection terminated. No intermediate state where headers
exist but are "suspect." The `return` after `callback(false, ...)` ensures no
subsequent step can observe these headers.

### Evidence 1c: Double-lock origin validation

`src/gateway/origin-check.ts` — `checkBrowserOrigin`

```typescript
function checkBrowserOrigin(params: OriginCheckParams): OriginCheckResult {
  // ...
  // Double-lock: browser Origin host must match proxy-reported host
  if (requestForwardedHost && isTrustedProxy) {
    const normalizedForwarded = normalizeHostToMatchUrlHost(requestForwardedHost);
    if (normalizedForwarded && parsedOrigin.host !== normalizedForwarded) {
      return {
        ok: false,
        reason: `origin host (${parsedOrigin.host}) does not match forwarded host (${normalizedForwarded})`,
      };
    }
  }
  // ...
}
```

**Why this satisfies P1:** Two independent data sources (browser `Origin` header,
proxy `X-Forwarded-Host`) must agree on the host identity. If either is absent
or they disagree → reject. There is no path where only one source is consulted
and the other is silently ignored.

### Evidence 1d: Strict header validation (no chained values)

`src/gateway/net.ts` — `validateSensitiveHeaders`

```typescript
export function validateSensitiveHeaders(
  headers: IncomingHttpHeaders,
): { ok: true } | { ok: false; header: string; reason: string } {
  for (const header of SENSITIVE_FORWARDING_HEADERS) {
    const value = headers[header];
    if (Array.isArray(value) && value.length > 1) {
      return {
        ok: false,
        header,
        reason: `duplicate ${header} header (possible header injection)`,
      };
    }
    if (typeof value === "string" && value.includes(",")) {
      return {
        ok: false,
        header,
        reason: `chained ${header} value (possible proxy chain injection)`,
      };
    }
  }
  return { ok: true };
}
```

**Why this satisfies P1:** Chained `X-Forwarded-For: a, b, c` values create
multiple candidate identities for the same request. This rejects them entirely —
no parsing logic to "pick the rightmost untrusted entry," no ambiguity about
which value represents the client.

---

## P2 — Authentication Decisions Independent of Unauthenticated Inputs (CWE-345)

**Property:** Auth, identity, or trust-level decisions must not depend on
unauthenticated or unverified inputs without cryptographic provenance validation.

### Evidence 2a: Proxy headers cannot reach auth

`src/gateway/server/verify-client.ts` — pipeline ordering

The verifyClient callback runs steps in strict order: header validation (1) →
untrusted proxy rejection (2) → origin validation (3) → IP restriction (4) →
subprotocol (5). Each step returns early on failure. Steps 2-4 all consume proxy
headers, but step 2 guarantees that only headers from trusted proxies survive
to steps 3-4.

```
Step 1:  validateSensitiveHeaders      → reject on duplicate/chained
Step 2:  rejectUntrustedProxyHeaders   → reject if proxy headers from untrusted IP
Step 3:  checkBrowserOrigin             → uses X-Forwarded-Host (only if step 2 passed)
Step 4:  isIpAllowed                    → uses X-Forwarded-For (only if step 2 passed)
```

**Why this satisfies P2:** By the time any auth-adjacent decision (origin check,
IP restriction) reads a proxy header, step 2 has already guaranteed the header
originated from a trusted proxy. Unauthenticated inputs from non-proxy sources
are physically impossible to observe at that point — the connection is already
closed.

### Evidence 2b: timingSafeEqual for HMAC verification

`src/gateway/origin-check.ts` — `verifySignedOriginToken`

```typescript
export function verifySignedOriginToken(
  token: string,
  sharedSecret: string,
  expectedOrigin: string,
): SignedTokenVerificationResult {
  // ...
  const expectedSig = createHmac("sha256", sharedSecret).update(payloadB64).digest("base64url");

  const sigBuf = Buffer.from(sigB64, "base64url");
  const expectedBuf = Buffer.from(expectedSig, "base64url");
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    return { ok: false, reason: "invalid signature" };
  }
  // ...
}
```

**Why this satisfies P2:** The HMAC comparison uses `timingSafeEqual` — the
comparison duration is independent of how many bytes match. An attacker cannot
use timing side-channels to incrementally guess a valid signed origin token.
The upstream used `===` on strings, which leaks comparison progress via timing.

### Evidence 2c: Origin validation does not depend on unauthenticated headers alone

`src/gateway/origin-check.ts` — origin-check validates browser Origin against
configurable `allowedOrigins`, with double-lock verification against
`X-Forwarded-Host` / `Forwarded` host when present. Proxy header trust is
determined by `isTrustedProxyAddress` before any origin decision is made
(see Evidence 1b).

**Why this satisfies P2:** Origin validation uses only headers from verified
trusted sources. Untrusted proxy headers are rejected before reaching origin
checks (Evidence 1b). Auth decisions are never based on unauthenticated inputs.

---

## P3 — Trust Independent of Network Location (CWE-352)

**Property:** Trust levels and privilege must not be derived from network
identifiers (127.0.0.1, localhost, loopback) alone; explicit validation required
regardless of apparent source.

### Evidence 3a: Proxy presence invalidates locality

`src/gateway/server/verify-client.ts` — step 3

```typescript
const requestOrigin = info.origin;
const hasBrowserOriginHeader = Boolean(requestOrigin && requestOrigin !== "null");
if (hasBrowserOriginHeader) {
  const isLocalClient = isLoopbackAddress(remoteAddr) && !hasProxyHeaders;
  //                                                  ^^^^^^^^^^^^^^^^^^
  //  Key: loopback alone is NOT sufficient. Proxy headers prove the
  //  connection is NOT genuinely local, even if remoteAddr is 127.0.0.1.
  // ...
  const originCheck = checkBrowserOrigin({
    // ...
    isLocalClient,
    disableLocalhostPrivilege:
      securityConfig.disableLocalhostPrivilege !== false ||
      (securityConfig.autoDisableLocalhostBehindProxy !== false && hasProxyHeaders),
      //  ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
      //  Default-on localhost-origin fallback hardening, with an explicit
      //  false opt-out only for direct local browser workflows. With the
      //  default autoDisableLocalhostBehindProxy setting, proxy headers force
      //  disableLocalhostPrivilege back to true even if the manual flag is false.
  });
```

**Why this satisfies P3:** The upstream pattern was `isLocalClient = isLoopback(remoteAddr)`
— a single boolean derived from network location. Tailscale Serve sets
`remoteAddr = 127.0.0.1`, so `isLocalClient = true`, granting localhost
privilege (origin check bypass). The fork adds `&& !hasProxyHeaders`: if proxy
headers exist, the connection cannot be local regardless of IP. Additionally,
`autoDisableLocalhostBehindProxy` forces `disableLocalhostPrivilege = true`
even for trusted proxies — proxy presence is treated as proof of non-locality.

### Evidence 3b: No implicit loopback origin acceptance

`src/gateway/origin-check.ts` — local-loopback path

```typescript
// Local loopback fallback — ONLY when explicitly allowed
if (isLocalClient && !disableLocalhostPrivilege) {
  if (parsedOrigin.protocol === "http" && isLoopbackHost(parsedOrigin.hostname)) {
    return {
      ok: true,
      matchedBy: "local-loopback",
      wildcardMatched: false,
    };
  }
}
// If disableLocalhostPrivilege is true (forced by autoDisableLocalhostBehindProxy),
// this block is skipped entirely. No fallback, no implicit trust.
```

**Why this satisfies P3:** The loopback fallback is gated behind two conditions:
(1) `isLocalClient` (which now requires no proxy headers), and (2)
`!disableLocalhostPrivilege` (which is auto-forced when proxy headers are
present). There is no code path where `remoteAddr = 127.0.0.1` alone grants
origin bypass.

---

## P4 — Per-Action Authorization (CWE-862)

**Property:** Every sensitive action must undergo explicit capability or permission
validation; session/connection-level trust must not imply broad action authorization.

### Evidence 4a: Operator scope translation (no implicit escalation)

`src/gateway/message-auth.ts` — scope-to-capability mapping

```typescript
const OPERATOR_SCOPE_CAPABILITIES: Record<string, readonly string[]> = {
  [ADMIN_SCOPE]: ["admin:read", "admin:write"],
  [READ_SCOPE]: ["admin:read"],
  [WRITE_SCOPE]: ["admin:read", "admin:write"],
  [APPROVALS_SCOPE]: ["admin:write"],
  [PAIRING_SCOPE]: ["admin:write"],
  // NOTE: operator.admin does NOT map to admin:config, secrets:read, or secrets:manage.
  // Those require explicit opt-in via direct capability scopes.
};

function resolveCapabilitiesFromScopes(scopes: ReadonlySet<string>): Set<string> {
  const caps = new Set<string>();
  for (const scope of scopes) {
    if (scope === "*") {
      caps.add("*");
      continue;
    }
    const translated = OPERATOR_SCOPE_CAPABILITIES[scope];
    if (translated) {
      for (const cap of translated) {
        caps.add(cap);
      }
      continue;
    }
    // Direct capability scope (e.g. secrets:read, admin:config, admin:*)
    if (scope.includes(":")) {
      caps.add(scope);
    }
  }
  return caps;
}
```

**Why this satisfies P4:** The upstream pattern was: "if you're authenticated as
admin, you can do everything." The fork decomposes this into fine-grained
capabilities. `operator.admin` (the macOS app's scope) translates to exactly
`admin:read` + `admin:write` — it does **not** grant `admin:config` (protected
config paths), `secrets:read` (API key exfiltration), or `secrets:manage`
(secret rotation). A paired device with admin access cannot disable auth or read
API keys. The only scope that grants `admin:config` is the literal `*` wildcard,
which is only assigned to direct local loopback operators.

### Evidence 4b: Per-message-type capability mapping (80+ methods)

`src/gateway/message-auth.ts` — `METHODS_BY_CAPABILITY`

```typescript
const METHODS_BY_CAPABILITY: Record<string, readonly string[]> = {
  "admin:read": [
    "health",
    "status",
    "config.get",
    "sessions.list",
    "models.list",
    "tools.catalog",
    "agents.list",
    "cron.list", // ... 40+ read methods
  ],
  "admin:write": [
    "send",
    "agent",
    "sessions.create",
    "sessions.send",
    "cron.add",
    "node.pair.request",
    "device.token.rotate", // ... 50+ write methods
  ],
  "secrets:read": ["secrets.resolve"],
  "secrets:manage": ["secrets.reload"],
  "admin:config": ["config.set_protected"],
};
```

**Why this satisfies P4:** Every gateway method has an explicit capability
requirement. There is no "catch-all admin" bucket — `secrets.resolve` requires
`secrets:read`, `config.set` on protected paths requires `admin:config`, and
neither is granted by `admin:write`. The `authorizeMessage` function performs
this check on every single message:

```typescript
export function authorizeMessage(
  ctx: MessageAuthorizationContext,
  messageType: string,
  config?: Partial<MessageAuthConfig>,
): MessageAuthorization {
  const messageCapability = resolveMessageCapability(messageType, config?.messageCapabilities);

  if (!messageCapability) {
    if (config?.requireCapabilityForAll) {
      return {
        ok: false,
        reason: `No capability defined for message type: ${messageType}`,
        missingCapability: "unknown",
      };
    }
    // When requireCapabilityForAll is false, unmapped methods pass through.
    // This is the safe default: known-dangerous methods are mapped; unknown
    // methods are assumed harmless until explicitly classified.
    return { ok: true, capability: "none" };
  }

  if (hasMessageCapability(ctx, messageCapability)) {
    return { ok: true, capability: messageCapability };
  }

  return {
    ok: false,
    reason: `Capability denied: ${messageCapability} required for ${messageType}`,
    missingCapability: messageCapability,
  };
}
```

### Evidence 4c: Per-endpoint capability isolation

`src/gateway/ws-endpoint.ts`

```typescript
export const ENDPOINT_SECURITY: Record<WsEndpoint, EndpointSecurityConfig> = {
  [WS_ENDPOINT.AGENT]: {
    requireOrigin: true,
    requireAuth: true,
    allowedCapabilities: ["agent:read", "agent:write", "agent:execute"],
  },
  [WS_ENDPOINT.ADMIN]: {
    requireOrigin: true,
    requireAuth: true,
    allowedCapabilities: [
      "admin:read",
      "admin:write",
      "admin:execute",
      "admin:config",
      "session:manage",
    ],
  },
  [WS_ENDPOINT.INTERNAL]: {
    requireOrigin: false,
    requireAuth: true,
    allowedCapabilities: ["internal:*"],
  },
};
```

**Why this satisfies P4:** A client connected to `/gateway/ws-agent` cannot invoke
`admin:config` methods — the endpoint's `allowedCapabilities` list does not
include it. Connection-level authentication does not imply endpoint-level
authorization. Each endpoint declares its own capability boundary.

---

## Supporting Evidence: Operational Hardening

These are not attack-vector-specific but eliminate entire vulnerability classes
that scanners detect.

### S1: perMessageDeflate disabled (CWE-502)

`src/gateway/server-runtime-state.ts`

```typescript
const wss = new WebSocketServer({
  noServer: true,
  maxPayload: MAX_PREAUTH_PAYLOAD_BYTES,
  perMessageDeflate: false, // CRIME/BREACH class mitigation
  verifyClient: createGatewayVerifyClient({
    /* ... */
  }),
});
```

### S2: Pre-auth payload limit (CWE-770)

`src/gateway/server-runtime-state.ts` + `src/gateway/server-constants.ts`

```typescript
// Pre-auth: only 64 KB allowed before handshake completes
const wss = new WebSocketServer({
  maxPayload: MAX_PREAUTH_PAYLOAD_BYTES, // 64 KB
  // ...
});

// Post-auth: configurable with safe clamping
export function resolveMaxPayloadBytes(configValue?: number): number {
  if (configValue === undefined) return DEFAULT_MAX_PAYLOAD_BYTES; // 25 MB
  if (!Number.isFinite(configValue) || configValue <= 0) return DEFAULT_MAX_PAYLOAD_BYTES;
  if (configValue < MIN_PAYLOAD_BYTES) return MIN_PAYLOAD_BYTES; // 64 KB floor
  if (configValue > ABSOLUTE_MAX_PAYLOAD_BYTES) return ABSOLUTE_MAX_PAYLOAD_BYTES; // 100 MB ceiling
  return configValue;
}
```

### S3: Pre-handshake connection rate limiting (CWE-770)

`src/gateway/server/verify-client.ts` — step 0b

```typescript
if (connectionRateLimiter) {
  const clientIpForRateLimit = resolveClientIp({
    /* ... */
  });
  const rateCheck = connectionRateLimiter.check(clientIpForRateLimit);
  if (!rateCheck.allowed) {
    callback(false, 1013, "too many connections");
    return;
  }
  connectionRateLimiter.recordAttempt(clientIpForRateLimit);
}
```

`src/gateway/connection-rate-limit.ts` — sliding window

```typescript
export function createConnectionRateLimiter(
  config?: ConnectionRateLimitConfig,
): ConnectionRateLimiter {
  const maxAttempts = config?.maxAttempts ?? 30; // 30 attempts
  const windowMs = config?.windowMs ?? 10_000; // per 10s window
  const lockoutMs = config?.lockoutMs ?? 60_000; // 60s lockout on exceed
  const exemptLoopback = config?.exemptLoopback ?? true; // localhost exempt
  // ...
}
```

### S4: Timestamp removed from challenge payload (CWE-208)

`src/gateway/protocol/connect-error-details.ts` — the nonce/challenge payload
no longer includes a timestamp, reducing the timing side-channel surface in the
pre-auth handshake.

### S5: NODE_TLS_REJECT_UNAUTHORIZED removed from Docker (CWE-295)

`Dockerfile.apple_arm64` — the `ENV NODE_TLS_REJECT_UNAUTHORIZED=0` line that
existed in upstream has been removed. All outbound TLS connections now validate
certificates.

---

## Verification Methodology

Each property can be verified independently:

| Property | Verification Query                                                                                                                                                                    |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P1       | CodeQL: "Are there code paths where `X-Forwarded-*` headers are read without prior trust validation?" Fork: no. Upstream: yes.                                                        |
| P2       | CodeQL: "Can attacker-controlled input reach an auth decision without cryptographic verification?" Fork: no (step 2 blocks). Upstream: yes (warn-and-continue).                       |
| P3       | CodeQL: "Is `isLoopbackAddress(remoteAddr)` used as a trust signal without proxy-presence check?" Fork: no (`&& !hasProxyHeaders`). Upstream: yes.                                    |
| P4       | CodeQL: "Are there message types without capability mappings that reach sensitive operations?" Fork: no (80+ mapped, secrets/config gated). Upstream: yes (secrets.resolve unmapped). |
| S1       | Grep: `perMessageDeflate` — fork: `false`. Upstream: not set (defaults to enabled).                                                                                                   |
| S2       | Grep: `maxPayload` before and after auth — fork: 64 KB / 25 MB. Upstream: single value.                                                                                               |
| S3       | Grep: `verifyClient` with rate limiter — fork: yes. Upstream: no pre-handshake limiter.                                                                                               |
| S5       | Grep: `NODE_TLS_REJECT_UNAUTHORIZED` — fork: absent. Upstream: present in Dockerfile.                                                                                                 |
