# Security Advisory: Device-Identity / Pairing Bypass via TUI Client ID Spoofing

| Field                  | Detail                                                                                                                                                                                                                                                                   |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **CVE**                | Pending                                                                                                                                                                                                                                                                  |
| **CWE**                | CWE-290: Authentication Bypass by Spoofing                                                                                                                                                                                                                               |
| **Severity**           | 🟠 High (local privilege escalation with default quickstart config), 🟡 Medium (remote deployments require `dangerouslyDisableDeviceAuth` + token)                                                                                                                       |
| **Affected Component** | `src/gateway/server/ws-connection/message-handler.ts`                                                                                                                                                                                                                    |
| **Introduced In**      | PR [#55730](https://github.com/openclaw/openclaw/pull/55730) — "fix: improve local onboarding and TUI hatch for loopback gateways"                                                                                                                                       |
| **Introduced By**      | `@shakkernerd`                                                                                                                                                                                                                                                           |
| **Merged By**          | `@shakkernerd` (same account as author; merge timestamp 2026-03-27 10:32:13 UTC)                                                                                                                                                                                         |
| **Merged At**          | 2026-03-27 10:32:13 UTC                                                                                                                                                                                                                                                  |
| **Fix Status**         | **Unfixed** in upstream `openclaw/openclaw` as of 2026-06-02. Zero commits, zero PRs, zero issues addressing CWE-290. Three automated security bots flagged the PR at merge time; no follow-up has been opened or merged since. Mitigated in fork `markfietje/openclaw`. |
| **Detection**          | Flagged by Aisle Security bot (🟠 High) and Greptile review bot. No human response.                                                                                                                                                                                      |

---

## 1. Executive Summary

On 2026-03-27, `@shakkernerd` opened and merged [PR #55730](https://github.com/openclaw/openclaw/pull/55730) into `openclaw/openclaw`. The PR was opened and merged within **4 minutes** with **no human review**, **no linked issue**, and **no response to automated security findings**.

The change widened `isOperatorUiClient()` to return `true` for both the browser Control UI (`openclaw-control-ui`) and the terminal UI (`openclaw-tui`). This function's return value was then used as the `isControlUi` flag to gate security-critical authentication policy decisions in the WebSocket handshake, including device-identity enforcement, pairing requirements, and auth bypass paths.

Because `client.id` is **client-supplied metadata** — any WebSocket client can set `connectParams.client.id = "openclaw-tui"` — this creates a textbook CWE-290 authentication bypass. A non-browser client can spoof the TUI identity to inherit Control UI privilege relaxation, bypassing device pairing, skipping device-identity checks, and accessing `shouldSkipControlUiPairing` / `isTrustedProxyControlUiOperatorAuth` bypass paths.

**Important caveat (corrected 2026-06-02):** The exploitation surface is narrower than initially assessed. Three key constraints apply:

1. **Browser CSRF is blocked.** The upstream's `enforceOriginCheckForAnyClient` mechanism rejects any browser-origin connection (see Section 9.2).
2. **`authMode: "none"` does NOT enable exploitation.** Exhaustive source-code tracing through `evaluateMissingDeviceIdentity()` confirms that `authMode: "none"` yields `sharedAuthOk=false`, causing `roleCanSkipDeviceIdentity()` to return `false`, and the connection is closed with `reject-device-required`.
3. **Remote exploitation requires `dangerouslyDisableDeviceAuth`.** The `allowInsecureAuth` gate in `evaluateMissingDeviceIdentity` explicitly rejects non-local clients (`!allowInsecureAuthConfigured || !isLocalClient`). Remote Docker/VPS deployments with only `allowInsecureAuth=true` are **not** exploitable unless `dangerouslyDisableDeviceAuth=true` is also set.

The realistic attack surface is: **localhost + valid auth token + `allowInsecureAuth=true`** (the default quickstart configuration), or any network position + `dangerouslyDisableDeviceAuth=true`, or local privilege escalation on loopback with a known token.

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
// Commit e4125f4c — "fix: add dedicated tui gateway client auth"
import { isOperatorUiClient } from "../../../utils/message-channel.js";
// ...
const isControlUi = isOperatorUiClient(connectParams.client);
```

Where `isOperatorUiClient` is defined as:

```ts
// src/utils/message-channel.ts:47-50 (verified on upstream/main 2026-06-02)
export function isOperatorUiClient(client?: GatewayClientInfoLike | null): boolean {
  const clientId = normalizeGatewayClientName(client?.id);
  return clientId === GATEWAY_CLIENT_NAMES.CONTROL_UI || clientId === GATEWAY_CLIENT_NAMES.TUI;
  //       ↑ Added by PR #55730 — now matches "openclaw-tui" too
}
```

### 2.2 How `isControlUi` Is Used (Attack Surface)

The `isControlUi` boolean gates the following security-critical paths:

#### Path 1: `resolveControlUiAuthPolicy()` — Auth Policy Relaxation

```ts
// src/gateway/server/ws-connection/connect-policy.ts (verified on upstream/main)
const allowInsecureAuthConfigured =
  params.isControlUi && params.controlUiConfig?.allowInsecureAuth === true;

const dangerouslyDisableDeviceAuth =
  params.isControlUi && params.controlUiConfig?.dangerouslyDisableDeviceAuth === true;
```

When `isControlUi` is `true`, these config-level bypass flags become active. If either is set in the gateway configuration, a spoofed TUI client inherits the bypass.

Note: `allowBypass` is derived from `dangerouslyDisableDeviceAuth` only (not from `allowInsecureAuth`). This means `allowInsecureAuth` alone does not directly grant `allowBypass`. The `allowInsecureAuth` flag prevents a specific rejection (`reject-control-ui-insecure-auth`) but does not short-circuit to `{ kind: "allow" }` — it falls through to `roleCanSkipDeviceIdentity()` which requires `sharedAuthOk` (valid token/password).

#### Path 2: `shouldSkipControlUiPairing()` — Pairing Skip (Irrelevant for Device-Less Exploitation)

```ts
export function shouldSkipControlUiPairing(
  policy: ControlUiAuthPolicy,
  role: GatewayRole,
  _trustedProxyAuthOk = false,
  authMode?: string,
  authMethod?: string,
): boolean {
  if (policy.isControlUi && role === "operator" && authMethod === "tailscale" && policy.device) {
    return true;
  }
  if (policy.isControlUi && role === "operator" && authMode === "none") {
    return true; // ← Pairing skipped when no auth is configured
  }
  return role === "operator" && policy.allowBypass;
}
```

**This function is not reached for the primary exploit path.** `shouldSkipControlUiPairing()` is only called inside `if (device && devicePublicKey)` in `message-handler.ts`. When the attacker sends `device: null` (matching legitimate TUI behavior under `allowInsecureAuth`), the entire pairing check block is skipped — not bypassed, but simply never entered. There is no pairing gate for device-less connections.

This means the `authMode === "none"` branch above is irrelevant to the TUI spoofing attack: a device-less spoofed TUI never reaches `shouldSkipControlUiPairing()` regardless of `authMode`. The actual exploit path is gated by `evaluateMissingDeviceIdentity()` (Path 3 below), not by the pairing skip.

#### Path 3: `evaluateMissingDeviceIdentity()` — Device Identity Relaxation (Primary Exploit Gate)

This function is the actual gate for the exploit. The full decision flow for a spoofed TUI client with `device: null`:

```ts
// connect-policy.ts:109-158 — full trace for device-less spoofed TUI

// Step 1: hasDeviceIdentity = false → continue (no device sent)
// Step 2: isControlUi && trustedProxyAuthOk → false → continue
// Step 3: isControlUi && allowBypass && operator → false (unless dangerouslyDisableDeviceAuth)
// Step 4: localBackendSelfPairingOk && operator → false → continue
// Step 5: isControlUi && !allowBypass → TRUE → enters block

if (params.isControlUi && !params.controlUiAuthPolicy.allowBypass) {
  // Step 5a: Locality gate
  if (!params.controlUiAuthPolicy.allowInsecureAuthConfigured || !params.isLocalClient) {
    // allowInsecureAuth=false OR non-local → REJECT
    return { kind: "reject-control-ui-insecure-auth" };
  }
  // Step 5b: Locality gate passed (allowInsecureAuth + localhost)
  // Falls through to roleCanSkipDeviceIdentity()
}

// Step 6: roleCanSkipDeviceIdentity(role, sharedAuthOk)
// From role-policy.ts:17-19:
//   return role === "operator" && sharedAuthOk;
//
// When authMode="none": sharedAuthOk=false → returns false → reject-device-required
// When authMode="token" with valid token: sharedAuthOk=true → returns true → allow
```

**The exploit requires all three of:**

1. `isControlUi = true` (spoofed `client.id = "openclaw-tui"`)
2. `isLocalClient = true` (localhost/loopback) — **or** `dangerouslyDisableDeviceAuth = true`
3. `sharedAuthOk = true` (valid token or password)

Without a valid token (`authMode: "none"`), `roleCanSkipDeviceIdentity()` returns `false` and the connection is closed with `reject-device-required`. The `allowInsecureAuth` flag prevents the locality rejection but does **not** short-circuit to `{ kind: "allow" }` — it requires shared authentication to succeed.

Once `evaluateMissingDeviceIdentity` returns `{ kind: "allow" }`, scope clearing is also defeated:

```ts
// message-handler.ts:866-870
const preserveInsecureLocalControlUiScopes =
  isControlUi && allowInsecureAuthConfigured && isLocalClient && authMethod === "token";
// ALL TRUE for the exploit: spoofed TUI + allowInsecureAuth + localhost + token auth

// connect-policy.ts:73-92
// shouldClearUnboundScopesForMissingDeviceIdentity returns false when
// preserveInsecureLocalControlUiScopes is true → scopes are NOT cleared
```

The attacker registers with their self-declared admin scopes intact.

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

A TUI-spoofed client behind a trusted proxy with `authMode: "trusted-proxy"` gains the same trusted-proxy auth shortcuts as the Control UI.

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

#### 2.4.1 The Constants Change (`packages/gateway-protocol/src/client-info.ts`)

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

Note: `GATEWAY_CLIENT_IDS` has since been extended with `MACOS_APP`, `IOS_APP`, `ANDROID_APP`, `NODE_HOST`, `TEST`, `FINGERPRINT`, and `PROBE` entries. The TUI entry remains.

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

Verified on `upstream/main` 2026-06-02: `auth-messages.ts` line 3 imports `isOperatorUiClient` and line 18 sets `const isControlUi = isOperatorUiClient(client);`. This is in the auth-failure hint path (`formatGatewayAuthFailureMessage`), not the handshake gate — but it confirms the same vulnerable helper is used across the codebase.

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

Note: the origin check now uses `isBrowserOperatorUi` (only matches `"openclaw-control-ui"`) while auth policy uses `isOperatorUiClient` (matches both). A TUI-spoofed client skips the `isBrowserOperatorUi` and `isWebchat` branches, **but** `enforceOriginCheckForAnyClient` is `true` when any browser `Origin` header is present (see Section 9.2 for why this blocks browser CSRF).

Verified on `upstream/main` 2026-06-02: `message-handler.ts` line 91 imports `isOperatorUiClient`, line 671 sets `const isControlUi = isOperatorUiClient(connectParams.client);`, and line 672 sets `const isBrowserOperatorUi = isBrowserOperatorUiClient(connectParams.client);`.

#### 2.4.3 The Test Confirmation (`src/gateway/server.auth.browser-hardening.test.ts`)

A new test was added that demonstrates the origin check does block browser-origin TUI spoofing:

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
      // ↑ This test PASSES — the origin check blocks browser-origin TUI spoofing
    } finally {
      ws.close();
    }
  });
});
```

This test confirms that the `enforceOriginCheckForAnyClient` mechanism blocks browser-origin TUI spoofing attacks. The test correctly rejects a browser-origin connection claiming to be a TUI client.

It does **not** test the non-browser attack path: a non-browser client (script, native app, server-side) spoofing TUI identity without a browser `Origin` header. That path remains open.

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
    deviceIdentity: connection.allowInsecureLocalOperatorUi ? null : undefined,
    //                              ↑
    //              When allowInsecureAuth=true (default), device identity is NULL
    //              This is the exact state an attacker needs to achieve
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

The vulnerability is confirmed: the server trusts `client.id = "openclaw-tui"` as sufficient proof to gate Control UI auth policy relaxation.

**Non-browser exploitation vector:** A non-browser WebSocket client (script, native app, server process) connects without a browser `Origin` header and sends a `connect` frame with the spoofed identity. Because `enforceOriginCheckForAnyClient` depends on the presence of a browser `Origin` header, a non-browser attacker bypasses the origin check entirely.

Required fields:

- `client.id`: **Must be `"openclaw-tui"`** to trigger `isControlUi = true`
- `client.mode`: `"ui"` — matches the TUI client's actual mode
- `device`: `null` — matches the TUI client's behavior when `allowInsecureAuth` is enabled
- `role`: `"operator"` — required for all bypass paths
- `token`: **Always required.** `authMode: "none"` does **not** enable exploitation because `evaluateMissingDeviceIdentity` falls through to `roleCanSkipDeviceIdentity(operator, false)` which returns `false`, closing the connection with `reject-device-required`.

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

**A valid token is mandatory.** The exploit path through `evaluateMissingDeviceIdentity` requires `sharedAuthOk=true` (verified via `roleCanSkipDeviceIdentity` in `role-policy.ts:17-19`). Without a valid token, the connection is rejected regardless of `authMode`. The attacker must know or leak the gateway's authentication token.

**The exploit also requires localhost** (or `dangerouslyDisableDeviceAuth=true`). The `allowInsecureAuth` locality gate (`!allowInsecureAuthConfigured || !isLocalClient`) rejects non-local clients. Remote exploitation without `dangerouslyDisableDeviceAuth` is not possible through this path.

---

## 3. Exploitation Scenarios

### 3.1 Prerequisites

- Network access to the OpenClaw gateway WebSocket endpoint (default port 18789)
- **Non-browser** attack tool (no browser `Origin` header sent)
- A **valid auth token** (the exploit requires `sharedAuthOk=true` — `authMode: "none"` is rejected)
- One of the following network positions:
  - **Localhost/loopback** with `allowInsecureAuth: true` (default quickstart config)
  - **Any network position** with `dangerouslyDisableDeviceAuth: true`
  - **Behind a trusted proxy** with `authMode: "trusted-proxy"`

### 3.2 Attack Steps (Primary Exploit: Localhost + Token + allowInsecureAuth)

This is the default quickstart configuration: gateway on localhost, `allowInsecureAuth: true`, `authMode: "token"`.

**Step 1:** Establish a non-browser WebSocket connection to the gateway (no `Origin` header):

```python
import websocket
ws = websocket.create_connection("ws://127.0.0.1:18789/gateway")
```

**Step 2:** Send a `connect` frame with spoofed `client.id` and a known/leaked token:

```json
{
  "type": "connect",
  "token": "KNOWN_OR_LEAKED_TOKEN",
  "client": {
    "id": "openclaw-tui",
    "mode": "ui",
    "version": "2026.4.9",
    "platform": "darwin"
  },
  "device": null,
  "role": "operator",
  "scopes": ["admin:read", "admin:write", "admin:config"]
}
```

**Step 3:** The server evaluates:

```ts
const isControlUi = isOperatorUiClient(connectParams.client); // true — matches "openclaw-tui"
```

**Step 4:** `evaluateMissingDeviceIdentity()` is reached (no device sent). The decision trace:

1. `hasDeviceIdentity = false` → continue
2. `isControlUi && allowBypass` → false (no `dangerouslyDisableDeviceAuth`) → continue
3. `isControlUi && !allowBypass` → TRUE → enters block
4. `!allowInsecureAuthConfigured || !isLocalClient` → `!true || !true` = false → does NOT reject
5. `roleCanSkipDeviceIdentity("operator", true)` → `true` (sharedAuthOk=true, valid token)
6. Returns `{ kind: "allow" }`

**Step 5:** Scope preservation fires:

```ts
preserveInsecureLocalControlUiScopes =
  isControlUi && allowInsecureAuthConfigured && isLocalClient && authMethod === "token";
// ALL TRUE → shouldClearUnboundScopesForMissingDeviceIdentity returns false
// Scopes are NOT cleared
```

**Step 6:** No device → `if (device && devicePublicKey)` block skipped → no pairing check.

**Step 7:** The attacker has operator access with full self-declared admin scopes. They can:

- Read and modify gateway configuration
- Access conversation history
- Send messages through connected channels (Discord, Telegram, WhatsApp, etc.)
- Install or modify plugins
- Exfiltrate stored credentials and API keys

### 3.3 Exploit Surface Truth Table

The following table shows which combinations of configuration and network position are exploitable:

| Config / Position                             | Localhost + token           | Localhost + no token        | Remote + token                       | Remote + no token                    |
| --------------------------------------------- | --------------------------- | --------------------------- | ------------------------------------ | ------------------------------------ |
| `allowInsecureAuth=true` (default quickstart) | ✅ **EXPLOITABLE**          | ❌ `reject-device-required` | ❌ `reject-control-ui-insecure-auth` | ❌ `reject-control-ui-insecure-auth` |
| `dangerouslyDisableDeviceAuth=true`           | ✅ **EXPLOITABLE**          | ❌ `reject-device-required` | ✅ **EXPLOITABLE**                   | ❌ `reject-device-required`          |
| `authMode: "trusted-proxy"`                   | ✅ via trusted-proxy        | N/A                         | ✅ via trusted-proxy                 | N/A                                  |
| `authMode: "none"` (no auth)                  | ❌ `reject-device-required` | ❌ `reject-device-required` | ❌ `reject-control-ui-insecure-auth` | ❌ `reject-control-ui-insecure-auth` |

Key takeaway: **a valid token is always required**, and **remote exploitation requires `dangerouslyDisableDeviceAuth`** (not just `allowInsecureAuth`).

### 3.4 Attack Variants

| Variant                                      | Config Required                                 | Network Position        | Auth Required      | Impact                                                                  |
| -------------------------------------------- | ----------------------------------------------- | ----------------------- | ------------------ | ----------------------------------------------------------------------- |
| Localhost + token + `allowInsecureAuth`      | `allowInsecureAuth: true` (default quickstart)  | Localhost only          | Valid token        | Operator access, device identity bypassed, scopes preserved             |
| Any network + `dangerouslyDisableDeviceAuth` | `dangerouslyDisableDeviceAuth: true`            | Any network             | Valid token        | Full operator access, no device identity, no locality gate              |
| Trusted proxy abuse                          | Behind reverse proxy + trusted proxy configured | Any network (via proxy) | Trusted-proxy auth | `isTrustedProxyControlUiOperatorAuth` returns `true`                    |
| Local privilege escalation                   | Loopback, any auth mode with token              | Local only              | Known/leaked token | Escalation from local user to gateway operator                          |
| ~~Browser CSRF to localhost~~                | ~~Any~~                                         | ~~Local~~               | ~~None~~           | ~~**Blocked by `enforceOriginCheckForAnyClient`**~~                     |
| ~~Remote + `allowInsecureAuth` only~~        | ~~`allowInsecureAuth: true`~~                   | ~~Remote~~              | ~~Token~~          | ~~**Blocked by locality gate**~~                                        |
| ~~`authMode: "none"`~~                       | ~~No auth~~                                     | ~~Any~~                 | ~~None~~           | ~~**Blocked by `roleCanSkipDeviceIdentity` requiring `sharedAuthOk`**~~ |

---

## 4. Detection Timeline

### 4.1 Automated Detection (All Ignored)

| Time (UTC) | Actor                  | Finding                                                                        | Severity | Response   |
| ---------- | ---------------------- | ------------------------------------------------------------------------------ | -------- | ---------- |
| `10:28:56` | `@shakkernerd`         | PR #55730 created                                                              | —        | —          |
| `10:29:03` | **Aisle Security bot** | 🟡 CWE: Terminal escape / log injection via unsanitized input                  | Medium   | ❌ Ignored |
| `10:32:13` | `@shakkernerd`         | PR **self-merged**                                                             | —        | No review  |
| `10:35:48` | **Greptile bot**       | P2: Backward-compat gap; `isOperatorUiClient` scope warning                    | Medium   | ❌ Ignored |
| `10:37:01` | **Aisle Security bot** | 🟠 Re-confirmed High severity — device-identity bypass via TUI client spoofing | **High** | ❌ Ignored |

Note: The initial Aisle finding at `10:29:03` was a different issue (terminal escape injection, Medium). The CWE-290-specific finding came in the second Aisle comment at `10:37:01`, which landed after the merge. The Greptile review also landed after merge. The merge timestamp (`10:32:13`) preceded three of the four bot comments.

### 4.2 What Was Said vs What Was Done

**Three automated security tools** flagged this PR. The PR author:

- Did not wait for any automated review to complete (merged in 4 minutes)
- Did not respond to any bot finding
- Did not request review from any other human
- Carried the `maintainer` label on the PR
- Force-pushed the branch (`d329000 → ab0331b`) after initial comments appeared, then merged immediately

The `maintainer` label is documented on the PR. Whether it is configured to bypass required-reviewer gates in this repository is a configuration question; the label is observable on the PR.

---

## 5. Observations on the PR Lifecycle

### 5.1 Project Context

The recorded state of `openclaw/openclaw` PRs in the window surrounding PR #55730 shows:

1. **External security PRs are merged with long latencies or are closed without merge.** See Appendix D for a catalog.
2. **PRs labelled `maintainer` are merged in minutes.** The six PRs in Appendix A were all self-merged by the author account; median time from PR open to merge for the four that merged on the same day was under 5 minutes.
3. **Security bot findings receive no human responses on the PRs in this set.** Section 4.1 records the bot output; Section B.2 records the same pattern across Appendix A.
4. **`@openclaw/secops` is the designated reviewer in CODEOWNERS for the security-sensitive paths in question** (see Appendix B.2), but is not requested on any of the six PRs in Appendix A.

### 5.2 The Specific Failure Mode of PR #55730

PR #55730 was a **convenience fix** for TUI onboarding — making the terminal UI work more smoothly on loopback. The security implications were a side effect of using `isOperatorUiClient()` for security-sensitive gating instead of keeping a precise client ID check.

The failure was:

1. **Conflating UX classification with security classification.** `isOperatorUiClient()` was a UX helper ("is this an operator-facing client?") that got repurposed as a security gate ("is this the privileged Control UI?").
2. **No separation of concerns.** A single boolean `isControlUi` was used for both "should we show operator UI features" and "should we bypass device identity requirements."
3. **No threat modeling.** The PR considered TUI convenience but did not consider that `client.id` is attacker-controlled.
4. **No human review.** The author merged their own PR before automated tools finished analyzing it.

### 5.3 The 4-Minute Merge

The merge timestamp (`10:32:13`) preceded three of the four bot comments. A PR-merge gating rule that waits for automated security review to complete would have caught this before ship. The absence of such a gate is a process issue: security tooling generates output that no process enforces acting on before merge.

---

## 6. The Mitigated Alternative

The fork `markfietje/openclaw` by **Mark Fietje** (`@markfietje`) ships a working fix for CWE-290. The fix is a one-line behavior change at the existing call site, plus test coverage. Verified by code reading against fork commit `132eb8a0531` ("fix(gateway): close CWE-290 TUI client spoofing in handshake") on 2026-06-02.

### 6.1 Root Cause Fix: Use the Strict Helper at the Call Site

The strict helper `isBrowserOperatorUiClient` already existed in the upstream codebase at `src/utils/message-channel.ts:52-55` and was already imported in the message handler at `src/gateway/server/ws-connection/message-handler.ts:89`. It was being used for the origin check gate on line 672 (`isBrowserOperatorUi`) but **not** for the `isControlUi` boolean on line 671. The fix is to use the strict helper for `isControlUi` too:

```diff
--- a/src/gateway/server/ws-connection/message-handler.ts
+++ b/src/gateway/server/ws-connection/message-handler.ts
@@ -93,7 +93,6 @@
 import {
   isBrowserOperatorUiClient,
   isGatewayCliClient,
-  isOperatorUiClient,
   isWebchatClient,
 } from "../../../utils/message-channel.js";
@@ -694,7 +693,7 @@ export function attachGatewayWsMessageHandler(params: GatewayWsMessageHandlerPar
         connectParams.role = role;
         connectParams.scopes = scopes;

-        const isControlUi = isOperatorUiClient(connectParams.client);
+        const isControlUi = isBrowserOperatorUiClient(connectParams.client);
         const isBrowserOperatorUi = isBrowserOperatorUiClient(connectParams.client);
         const isWebchat = isWebchatConnect(connectParams);
```

The two helpers, side by side at `src/utils/message-channel.ts:47-55`:

```ts
export function isOperatorUiClient(client?: GatewayClientInfoLike | null): boolean {
  const clientId = normalizeGatewayClientName(client?.id);
  return clientId === GATEWAY_CLIENT_NAMES.CONTROL_UI || clientId === GATEWAY_CLIENT_NAMES.TUI;
}

export function isBrowserOperatorUiClient(client?: GatewayClientInfoLike | null): boolean {
  const clientId = normalizeGatewayClientName(client?.id);
  return clientId === GATEWAY_CLIENT_NAMES.CONTROL_UI;
}
```

`isOperatorUiClient` matches both `openclaw-control-ui` and `openclaw-tui`. `isBrowserOperatorUiClient` matches only `openclaw-control-ui`. The fork switches the `isControlUi` boolean to use the strict helper.

### 6.2 Why This Closes the Bypass

`isControlUi` flows into `src/gateway/server/ws-connection/connect-policy.ts` where it gates Control-UI-specific bypass paths. With the strict helper, a TUI client (`id = "openclaw-tui"`) produces `isControlUi = false` and cannot trigger any of them:

| Bypass path                                                                 | File:line                   | TUI result                                | CONTROL_UI result          |
| --------------------------------------------------------------------------- | --------------------------- | ----------------------------------------- | -------------------------- |
| `evaluateMissingDeviceIdentity`: trusted-proxy auth shortcut                | `connect-policy.ts:117`     | `reject-device-required` (no shared auth) | `allow`                    |
| `evaluateMissingDeviceIdentity`: `dangerouslyDisableDeviceAuth` break-glass | `connect-policy.ts:120`     | `reject-device-required`                  | `allow`                    |
| `evaluateMissingDeviceIdentity`: `allowInsecureAuth` localhost gate         | `connect-policy.ts:131-139` | falls through to shared-auth path         | `allow` (with shared auth) |
| `shouldSkipControlUiPairing`: tailscale+operator+device pairing skip        | `connect-policy.ts:44`      | `false` (must pair)                       | `true` (skip)              |
| `shouldSkipControlUiPairing`: `authMode: none` pairing skip                 | `connect-policy.ts:54`      | `false` (must pair)                       | `true` (skip)              |
| `isTrustedProxyControlUiOperatorAuth`                                       | `connect-policy.ts:63-77`   | `false`                                   | `true`                     |

TUI clients continue to authenticate via the generic shared-auth path (`roleCanSkipDeviceIdentity` in `src/gateway/role-policy.ts:17`) and via full device identity. They simply do not inherit the browser Control UI's break-glass flags or localhost shortcut. The downstream policy functions are unchanged; they were correct given the input boolean — only the boolean was wrong.

### 6.3 Test Coverage Added

Five new tests in `src/gateway/server/ws-connection/connect-policy.test.ts` derive `isControlUi` from a real `client` object via `isBrowserOperatorUiClient`, so a regression that reintroduces `isOperatorUiClient` at the call site would be caught by the policy tests as well as by reading the diff. The tests cover all five bypass paths above and assert TUI is rejected while CONTROL_UI is allowed.

Six new test cases in `src/utils/message-channel.test.ts` lock down the helper contract:

- `isOperatorUiClient` matches both CONTROL_UI and TUI
- `isBrowserOperatorUiClient` matches only CONTROL_UI, never TUI
- `isWebchatClient` matches WEBCHAT mode and WEBCHAT_UI id
- Whitespace and case are normalized before matching
- Empty, null, undefined, and unknown client info return `false`
- TUI id is never classified as Control UI even when `mode` is omitted

Four fixtures in `src/gateway/server/ws-connection/message-handler.post-connect-health.test.ts` were updated. They were sending `client.id = "openclaw-tui"` to bypass the device-identity and origin checks during handshake, which only worked because of the bug. After the fix, they correctly use `client.id = "openclaw-control-ui"` with `mode: "ui"` and a matching `Origin` header. The tests' purpose is post-connect health behavior, not handshake, so this is a fixture correction, not a test change in behavior.

### 6.4 Test Counts After the Fix

| Test file                                                                      | Cases | Notes                                                         |
| ------------------------------------------------------------------------------ | ----- | ------------------------------------------------------------- |
| `src/utils/message-channel.test.ts`                                            | 12    | 6 pre-existing + 6 new (helper contract)                      |
| `src/gateway/server/ws-connection/connect-policy.test.ts`                      | 13    | 8 pre-existing + 5 new (TUI cannot trigger Control-UI bypass) |
| `src/gateway/server/ws-connection/message-handler.post-connect-health.test.ts` | 17    | unchanged count; 4 fixtures corrected                         |

All targeted tests pass on 2026-06-02 against fork HEAD `e8d43139495`. The full `pnpm tsgo:all` typecheck shows a single pre-existing error in `src/gateway/server/verify-client.test.ts:8` unrelated to this fix (verified against `origin/main`).

### 6.5 Defense-in-Depth Layers (Fork)

The fork's broader security posture that the upstream lacks:

| Security Feature                    | Upstream (`openclaw/openclaw`)         | Fork (`markfietje/openclaw`)                                     |
| ----------------------------------- | -------------------------------------- | ---------------------------------------------------------------- |
| Client identity spoofing protection | ❌ `isOperatorUiClient()` (vulnerable) | ✅ `isBrowserOperatorUiClient()` (strict)                        |
| Reverse proxy origin awareness      | ❌ 5-param `checkBrowserOrigin`        | ✅ RFC 7239 `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto` |
| Trusted proxy gate                  | ❌ Not present                         | ✅ `isTrustedProxy` validation                                   |
| Endpoint classification             | ❌ Not present                         | ✅ `classifyWsEndpoint` / `isKnownWsEndpoint`                    |
| Per-connection rate limiting        | ❌ Not present                         | ✅ `connection-rate-limit` module                                |
| Per-method capability auth          | ❌ Not present                         | ✅ `message-auth` module                                         |
| Audit log                           | ❌ Not present                         | ✅ `auth-audit-log` module (HMAC-signed)                         |
| Startup security checks             | ❌ Not present                         | ✅ `startup-security-checks` module                              |
| Timing-safe secret comparison       | ❌ Uses `!==`                          | ✅ `safeEqualSecret` / `timingSafeEqual`                         |

The fork's PR to upstream was **closed** by upstream maintainers (PR [#35109](https://github.com/openclaw/openclaw/pull/35109), "fix(gateway): surgical proxy-aware origin validation 🤖", opened 2026-03-05, closed without merge). The CWE-290-specific fix in the fork is commit `132eb8a0531` ("fix(gateway): close CWE-290 TUI client spoofing in handshake").

---

## 7. Recommendations

### For Upstream (`openclaw/openclaw`)

1. **Immediately replace** the `isOperatorUiClient()` usage for `isControlUi` in `message-handler.ts` and `auth-messages.ts` with `isBrowserOperatorUiClient()` or a direct `GATEWAY_CLIENT_IDS.CONTROL_UI` comparison.

2. **Separate UX classification from security classification.** Create distinct types for "is this an operator UI client" (UX) vs "is this the privileged Control UI" (security).

3. **Require human review** for all PRs touching authentication, authorization, or security-critical code paths — including maintainer-authored PRs.

4. **Block merge** until automated security review tools complete analysis. The 4-minute merge-before-review window must not recur.

5. **Respond to security bot findings.** Ignoring High severity findings from automated tools is a governance failure.

### For Users and Deployers

1. **Audit your gateway configuration.** If you have `allowInsecureAuth: true` (the default quickstart setting) and your gateway is accessible on localhost, any local process with a known or leaked token can gain operator access by spoofing the TUI client ID. If you have `dangerouslyDisableDeviceAuth: true`, the attack works from any network position.

2. **Protect your auth tokens.** The exploit requires a valid token (`sharedAuthOk=true`). Token exfiltration vectors include config file exposure, environment variable leaks, log output, and compromised developer tools. Rotate tokens if exposure is suspected.

3. **Do not set `dangerouslyDisableDeviceAuth: true` on network-accessible gateways.** This flag bypasses the locality gate entirely, enabling remote exploitation. If you must use it, restrict network access to the gateway endpoint (firewall rules, VPN, etc.).

4. **Ensure the gateway is not exposed to untrusted networks** without understanding the risk profile. Docker with default `bind=lan` exposes the endpoint, but remote TUI spoofing is only exploitable with `dangerouslyDisableDeviceAuth: true` (not `allowInsecureAuth` alone).

5. **Consider the `markfietje/openclaw` fork** if you need production-grade reverse proxy support and comprehensive gateway security.

6. **Monitor WebSocket connections** for `client.id` values of `"openclaw-tui"` coming from non-TUI clients, which may indicate exploitation attempts.

---

## 8. Post-Merge Verification

As of **2026-06-02** — ~9 weeks after PR #55730 introduced the vulnerability — the upstream `openclaw/openclaw` repository has taken **no action** to address the CWE-290 finding. Re-verification commands and outputs are recorded below.

### 8.1 Verified Upstream State (2026-06-02)

The vulnerable code remains **identical** to what was merged on 2026-03-27. Direct inspection of `upstream/main` (`6c7644268f5`):

- `src/utils/message-channel.ts:47-50` — `isOperatorUiClient` still returns `true` for both `CONTROL_UI` and `TUI` (no fix).
- `src/gateway/server/ws-connection/message-handler.ts:671` — `const isControlUi = isOperatorUiClient(connectParams.client);` unchanged.
- `src/gateway/server/ws-connection/auth-messages.ts:18` — `const isControlUi = isOperatorUiClient(client);` unchanged.
- `src/gateway/server/ws-connection/connect-policy.ts:102-148` — `evaluateMissingDeviceIdentity` still gates on `params.isControlUi` for all bypass paths.
- `git log upstream/main --all -S 'isControlUi = isOperatorUiClient'` returns only the original PR #55730 commits and fork-side commits; no upstream-side replacement.

### 8.2 Activity Since Merge (2026-03-27 → 2026-06-02)

| Metric                                                     | Value        |
| ---------------------------------------------------------- | ------------ |
| Commits touching `isControlUi` / `isOperatorUiClient`      | **0**        |
| Open PRs proposing a fix for CWE-290                       | **0**        |
| Open issues filed about CWE-290                            | **0**        |
| Human responses to Aisle/Greptile/Codex findings on #55730 | **0**        |
| Time the High severity finding has been publicly visible   | **~9 weeks** |

### 8.3 PR Search Results (2026-06-02)

`gh pr list --repo openclaw/openclaw --state all --search 'CWE-290 OR TUI spoofing OR isControlUi isOperatorUiClient'` returns the original PR #55730 and unrelated PRs that mention `isControlUi` in passing; **no PR proposes a fix for the vulnerable `isOperatorUiClient()` assignment**. `gh issue list` against the same terms returns no issue filed about CWE-290.

### 8.4 Observations

The data is publicly observable:

1. **Security bot findings on PR #55730 received zero human responses.** Three independent automated tools flagged the PR at merge time (Aisle, Greptile, Codex). The bot comments remain on the PR with no maintainer reply, and the underlying code is unchanged.

2. **The `maintainer` label was applied to PR #55730.** Whether that label affects required-reviewers in this repository is a configuration question; the label is visible on the PR and on every other PR in Appendix A.

3. **The `markfietje/openclaw` fork's PR (#35109) — which addresses CWE-290 and additional gateway hardening — was closed by upstream without merge.** The fork's fix is documented in Section 6.

---

## 9. Risk Assessment

### 9.1 The "I Only Use It Locally" Defense

**The argument:** "My gateway is on `127.0.0.1`. No one can reach it. Therefore the vulnerability doesn't matter."

**The default bind mode confirms this on bare metal:**

```ts
// src/gateway/net.ts — defaultGatewayBindMode()
return isContainerEnvironment() ? "auto" : "loopback";
//                                       ↑ bare-metal default: loopback only
```

On a bare-metal host running the Mac/CLI directly, the gateway binds to `127.0.0.1`. Remote attackers on the internet cannot connect to the WebSocket endpoint directly.

### 9.2 Browser CSRF is Blocked by `enforceOriginCheckForAnyClient`

The original version of this advisory claimed that browser-based CSRF to localhost was the most realistic attack. This is **incorrect**. The upstream has a defense-in-depth mechanism that blocks this:

```ts
// src/gateway/server/ws-connection/handshake-auth-helpers.ts (verified on upstream/main)
const hasBrowserOriginHeader = Boolean(params.requestOrigin && params.requestOrigin.trim() !== "");
return {
  hasBrowserOriginHeader,
  enforceOriginCheckForAnyClient: hasBrowserOriginHeader,
  // ...
};
```

When any browser sends a WebSocket upgrade with an `Origin` header (which all browsers do), `enforceOriginCheckForAnyClient` is set to `true`. The origin check gate in `message-handler.ts` is:

```ts
if (enforceOriginCheckForAnyClient || isBrowserOperatorUi || isWebchat) {
```

Because of the `||` (OR) logic, when `enforceOriginCheckForAnyClient` is `true`, the origin check fires for **all** clients — including TUI-spoofed ones. A malicious website's `Origin: https://attacker.example` is validated and rejected.

This defense was present at the time PR #55730 was merged (verified at PR #55730 commit `f90b0c5c4b` — "fix: keep tui out of browser origin checks"). The browser-hardening test in `server.auth.browser-hardening.test.ts` confirms this works.

**Browser CSRF to localhost is not exploitable.**

### 9.3 Where the Vulnerability Remains Exploitable

The CWE-290 bypass is exploitable in these non-browser scenarios. Note: every exploitable path requires a **valid auth token** — `authMode: "none"` connections are rejected by `roleCanSkipDeviceIdentity()` (see Section 2.2, Path 3).

#### Scenario 1: Local Privilege Escalation (Primary Exploit)

The default quickstart configuration — `allowInsecureAuth: true`, `authMode: "token"`, loopback bind — is exploitable by any local process that can reach `127.0.0.1:18789` and knows the auth token. This is the most common deployment configuration.

```ts
// Exploit conditions (ALL must be true):
// 1. isControlUi = true           (spoofed client.id = "openclaw-tui")
// 2. allowInsecureAuth = true     (default quickstart)
// 3. isLocalClient = true         (loopback)
// 4. sharedAuthOk = true          (valid token)
// 5. device = null                (no device identity)
```

A local process (malware, compromised dev tool, another user on a shared machine) opens a raw WebSocket to `127.0.0.1:18789` without a browser `Origin` header, sends the spoofed TUI `connect` frame with a known token, and gains operator access with self-declared scopes.

Token exfiltration vectors: config file reads (`~/.openclaw/openclaw.json`), environment variable leaks, log output, or compromised developer tooling.

#### Scenario 2: Docker Deployments (Requires `dangerouslyDisableDeviceAuth`)

Docker exposes the WebSocket endpoint to the full network:

```yaml
# Default docker-compose.yml
command:
  ["node", "dist/index.js", "gateway", "bind", "${OPENCLAW_GATEWAY_BIND:-lan}", "port", "18789"]
ports:
  - "${OPENCLAW_GATEWAY_PORT:-18789}:18789"
```

The `auto` bind mode inside containers resolves to `0.0.0.0`. However, the `allowInsecureAuth` locality gate rejects non-local spoofed TUI clients:

```ts
// evaluateMissingDeviceIdentity for remote Docker connection:
// !allowInsecureAuthConfigured || !isLocalClient
// !true || !false = TRUE → reject-control-ui-insecure-auth
```

Remote Docker exploitation is only possible when `dangerouslyDisableDeviceAuth: true` is set, which bypasses the locality gate entirely (Path 3, Step 3: `isControlUi && allowBypass && operator` → `{ kind: "allow" }`).

From inside the container (localhost relative to the gateway process), the same local exploit applies if the attacker has the auth token.

#### Scenario 3: VPS / Cloud / Remote Server (Requires `dangerouslyDisableDeviceAuth`)

Self-hosted deployments on VPS (Hetzner, DigitalOcean, AWS Lightsail) that bind to `lan` or sit behind a reverse proxy are reachable from the internet. As with Docker, the `allowInsecureAuth` locality gate rejects non-local clients. Remote exploitation requires `dangerouslyDisableDeviceAuth: true`.

#### Scenario 4: Tailscale / VPN Exposure

When Tailscale is enabled, the gateway may be reachable from other tailnet devices. Tailscale authenticates network access, but the application-level CWE-290 exploit still applies if the attacker has a valid token and `dangerouslyDisableDeviceAuth: true` is set (for non-local access) or the attacker is on the same host (local exploit).

#### Scenario 5: OpenShell / Remote Sandbox

`extensions/openshell/src/config.ts` defines a `gatewayEndpoint` parameter that points at the OpenClaw gateway. An OpenShell sandbox that can reach the gateway's WebSocket endpoint can execute the CWE-290 attack. If the sandbox runs on the same host as the gateway, the local exploit path applies. If remote, `dangerouslyDisableDeviceAuth` is required. See Appendix E.

#### Exploit Surface Summary

| Config                              | Local (token)  | Local (no token) | Remote (token) | Remote (no token) |
| ----------------------------------- | -------------- | ---------------- | -------------- | ----------------- |
| `allowInsecureAuth=true` only       | ✅ Exploitable | ❌ Rejected      | ❌ Rejected    | ❌ Rejected       |
| `dangerouslyDisableDeviceAuth=true` | ✅ Exploitable | ❌ Rejected      | ✅ Exploitable | ❌ Rejected       |
| `authMode: "none"`                  | ❌ Rejected    | ❌ Rejected      | ❌ Rejected    | ❌ Rejected       |
| `authMode: "trusted-proxy"`         | ✅ Via proxy   | N/A              | ✅ Via proxy   | N/A               |

### 9.4 Risk Summary

| Scenario                                                 | Network Position | Exploit Method                                | Risk (Updated 2026-06-02)                                                                     |
| -------------------------------------------------------- | ---------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **Bare-metal, loopback**                                 | Local only       | Browser CSRF via malicious website            | 🟢 **Blocked** — `enforceOriginCheckForAnyClient` validates browser origins                   |
| **Bare-metal, loopback + token**                         | Local only       | Direct non-browser WebSocket with known token | 🟠 **High** — default quickstart config is exploitable by any local process                   |
| **Docker (default config)**                              | LAN / internet   | Direct WebSocket connection                   | 🟡 **Medium** — only exploitable from inside container or with `dangerouslyDisableDeviceAuth` |
| **Docker + `dangerouslyDisableDeviceAuth`**              | LAN / internet   | Direct WebSocket connection with token        | 🔴 **Critical** — no locality gate, any network attacker with token                           |
| **Tailscale**                                            | Tailnet          | Any tailnet device                            | 🟡 **Medium** — requires `dangerouslyDisableDeviceAuth` for non-local                         |
| **VPS / reverse proxy + `dangerouslyDisableDeviceAuth`** | Internet         | Direct WebSocket connection with token        | 🔴 **Critical** — no locality gate                                                            |
| **VPS / reverse proxy, `allowInsecureAuth` only**        | Internet         | Direct WebSocket connection                   | 🟢 **Blocked** — locality gate rejects non-local clients                                      |
| **OpenShell sandbox**                                    | Sandbox→Gateway  | Sandbox-initiated WebSocket                   | 🟡 **Medium** — requires token + local or `dangerouslyDisableDeviceAuth`                      |
| **Shared office / LAN**                                  | LAN              | Any device on same network                    | 🟡 **Medium** — requires token + `dangerouslyDisableDeviceAuth` for non-local                 |

### 9.5 Note on the "I Don't Use It" Reasoning

A common response to this kind of report is "I don't use the TUI / Control UI / reverse proxy, so this doesn't affect me." This reasoning is partially valid for browser-based attacks (which are blocked by `enforceOriginCheckForAnyClient`), but the CWE-290 flaw still matters because:

1. **The vulnerability targets the default config.** Quickstart sets `allowInsecureAuth: true` and binds to `loopback` on bare metal, `0.0.0.0` inside containers.
2. **Non-browser network attackers are not blocked.** Scenarios 1–5 above are exploitable by any client that can reach the gateway without a browser `Origin` header.
3. **The vulnerability is in the gateway, not the client.** `isOperatorUiClient()` is evaluated server-side.
4. **"I don't use X" narrows the threat model to a single developer's workflow.** The threat model covers documented deployment configurations: MacBook localhost, Docker, Tailscale, VPS, and shared office/LAN.

---

## 10. Timeline

| Date                    | Event                                                                                                                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 2026-03-27              | Commit `e4125f4c` ("fix: add dedicated tui gateway client auth"): `isOperatorUiClient()` introduced for `isControlUi`                                                          |
| 2026-03-27              | Commit `f90b0c5c4b` ("fix: keep tui out of browser origin checks"): `isBrowserOperatorUiClient()` added for origin checks, but `isControlUi` still uses `isOperatorUiClient()` |
| 2026-03-27 10:28        | PR #55730 opened                                                                                                                                                               |
| 2026-03-27 10:29        | Aisle Security bot flags Medium severity (terminal escape injection)                                                                                                           |
| 2026-03-27 10:32        | **PR #55730 merged** (merge commit `8fa62985b9`) — `merged_by` is the same account as the author, no recorded human review                                                     |
| 2026-03-27 10:35        | Greptile bot flags backward-compat and `isOperatorUiClient` scope concerns                                                                                                     |
| 2026-03-27 10:37        | Aisle Security bot flags 🟠 HIGH severity (CWE-290 device-identity bypass)                                                                                                     |
| 2026-03-27 10:39        | No human response to any of the bot findings                                                                                                                                   |
| 2026-03-27 → 2026-06-02 | **No upstream commit, PR, or issue addresses the CWE-290 vulnerability.** Commits to `message-handler.ts` in this window are unrelated lint/refactor/lifecycle work.           |
| 2026-06-02              | Re-verification: `upstream/main` (`6c7644268f5`) still carries the vulnerable pattern. No fix PR or issue exists.                                                              |

---

## 11. References

- [PR #55730](https://github.com/openclaw/openclaw/pull/55730) — "fix: improve local onboarding and TUI hatch for loopback gateways"
- [PR #35109](https://github.com/openclaw/openclaw/pull/35109) — "fix(gateway): surgical proxy-aware origin validation 🤖" (closed without merge)
- [CWE-290: Authentication Bypass by Spoofing](https://cwe.mitre.org/data/definitions/290.html)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- Aisle Security Analysis (bot comments on PR #55730, commits `ab0331b3df` and others)
- Greptile Review (bot review on PR #55730)
- `markfietje/openclaw` fork: commit `132eb8a0531` — CWE-290 fix; broader security hardening in surrounding commits

---

## 12. Disclosure

This advisory documents a vulnerability in a public open-source project. The vulnerability was introduced in a public PR with public automated security findings that were publicly visible and unaddressed for **9 weeks** at the time of this update. No private disclosure was made because:

1. The vulnerable code is already public in the `openclaw/openclaw` repository.
2. The security findings were already posted publicly on PR #55730 by automated tools.
3. The maintainers had ample time to respond to the publicly visible findings and chose not to.

The author of this advisory is **Mark Fietje** (`@markfietje`), whose security hardening PR to `openclaw/openclaw` was closed by maintainers, and who maintains the `markfietje/openclaw` fork with comprehensive gateway security improvements.

---

## Appendix C: "I Don't Use the Control UI Either" — Why This Doesn't Fully Reduce Risk

A common variant of the dismissal is: _"I only use the TUI locally on my MacBook. I don't use proxies, I don't use the Control UI. Therefore these vulnerabilities don't affect me."_ This is partially valid but incomplete.

### C.1 The TUI Is the Vulnerability, Not the Control UI

The CWE-290 vulnerability is not about spoofing the Control UI. It's about spoofing **the TUI**. The vulnerable code:

```ts
// upstream — STILL VULNERABLE (2026-06-02)
const isControlUi = isOperatorUiClient(connectParams.client);
//                        ↑ matches "openclaw-tui" — a real client ID
```

`isOperatorUiClient()` returns `true` for `"openclaw-tui"` — a documented, real client ID. The attack impersonates a client that actually ships and runs; it does not need the operator to also use a different client surface for the bypass to exist.

### C.2 The Default Config Opens the Door

The quickstart wizard sets `allowInsecureAuth: true` by default:

```ts
// src/wizard/setup.gateway-config.ts (verified on upstream/main)
if (
  flow === "quickstart" &&
  bind === "loopback" &&
  nextConfig.gateway?.controlUi?.allowInsecureAuth === undefined
) {
  nextConfig = {
    ...nextConfig,
    gateway: {
      ...nextConfig.gateway,
      controlUi: { ...nextConfig.gateway?.controlUi, allowInsecureAuth: true },
    },
  };
}
```

The TUI reads this flag to decide whether to skip device identity:

```ts
// src/tui/gateway-chat.ts (verified on upstream/main)
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

When `allowInsecureAuth: true` and the URL is localhost, the TUI connects with `deviceIdentity: null` — no device pairing, no cryptographic identity. This is the same path a spoofed TUI client takes. There is **no distinguishing signal** between a legitimate TUI and a malicious WebSocket claiming to be `"openclaw-tui"`.

### C.3 Why "I Don't Use X" Is Incomplete

The "I don't use X" argument narrows the threat model to a single personal workflow. But the documented deployment surface for OpenClaw is wider than one developer's MacBook: Docker containers on VPS, Tailscale networks, home servers, shared offices, and MacBooks with browsers open. The vulnerability affects every user who:

- Ran the quickstart wizard (`allowInsecureAuth: true` by default)
- Has the gateway running
- Is on a network where non-browser clients can reach the gateway

For loopback-only bare-metal users, the risk is limited to local privilege escalation (another local process without a browser `Origin` header). For Docker/Tailscale/VPS users, the risk is significantly higher.

---

## Appendix A: Systematic Catalog of Ignored Bot Security Findings in Merged PRs

This appendix documents a broader pattern: **CWE-290 is not an isolated incident.** Across recent merged PRs in `openclaw/openclaw`, automated security bots flagged multiple HIGH and MEDIUM severity findings that were merged without remediation.

### Methodology

Investigation covered ~100 recently closed PRs in `openclaw/openclaw`. All PRs with comments from `aisle-research-bot`, `greptile-apps[bot]`, and `chatgpt-codex-connector[bot]` were analyzed for security-relevant findings. Findings were cross-referenced with merge timestamps.

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

#### PR [#63199](https://github.com/openclaw/openclaw/pull/63199) — `fix(android): auto-resume pairing approval`

| Field                           | Detail                                                  |
| ------------------------------- | ------------------------------------------------------- |
| **Author**                      | `obviyus`                                               |
| **Created**                     | 2026-04-08 14:51:18 UTC                                 |
| **Merged**                      | 2026-04-08 16:28:57 UTC                                 |
| **Aisle finding posted**        | 2026-04-08 14:51:25 UTC (**~1 hr 37 min BEFORE merge**) |
| **Human responses to findings** | **0**                                                   |

**1 HIGH + 1 MEDIUM severity finding, available for 1h 37m, merged without addressing:**

| #   | Severity  | CWE     | Title                                                                                                | Location                                    |
| --- | --------- | ------- | ---------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| 1   | 🟠 HIGH   | CWE-269 | Operator session can authenticate using gateway bootstrap token when no operator device token exists | `apps/android/.../NodeRuntime.kt:1341-1348` |
| 2   | 🟡 Medium | CWE-400 | Unbounded auto-retry loop triggered by untrusted status text (client-side DoS)                       | `apps/android/.../GatewayPairingRetry.kt`   |

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

---

### A.2 Aggregate Statistics

| Metric                                                      | Value                               |
| ----------------------------------------------------------- | ----------------------------------- |
| Total merged PRs with bot-flagged security findings         | **6+**                              |
| Total HIGH severity findings merged without remediation     | **7+**                              |
| Total MEDIUM severity findings merged without remediation   | **10+**                             |
| Total human responses to bot security findings before merge | **0**                               |
| Average time from bot finding to merge                      | **< 10 minutes** (for same-day PRs) |

### A.3 CWE Distribution

| CWE       | Count | Description                                       |
| --------- | ----- | ------------------------------------------------- |
| CWE-200   | 5+    | Exposure of Sensitive Information                 |
| CWE-22/59 | 3+    | Path Traversal / Improper Link Resolution         |
| CWE-400   | 4+    | Uncontrolled Resource Consumption (DoS)           |
| CWE-290   | 1     | Authentication Bypass by Spoofing (this advisory) |
| CWE-285   | 1     | Improper Authorization                            |
| CWE-269   | 1     | Improper Privilege Management                     |
| CWE-346   | 1     | Origin Validation Error                           |

### A.4 The Pattern

Every finding in this appendix shares the same lifecycle:

1. **PR opened** by maintainer or contributor
2. **Aisle Security bot** posts findings within seconds to minutes
3. **No human reads or responds** to the findings
4. **PR merged** — often within minutes, sometimes hours, never with security remediation
5. **Finding sits unaddressed** on the PR indefinitely

---

## Appendix B: PR Author and Review Data

### B.1 PR Author and Merge Data

| PR                                                        | Author        | Self-Merged   | Bot Findings Before Merge                                                              | Human Responses |
| --------------------------------------------------------- | ------------- | ------------- | -------------------------------------------------------------------------------------- | --------------- |
| [#55730](https://github.com/openclaw/openclaw/pull/55730) | `shakkernerd` | Yes (~4 min)  | Aisle 🟡 (terminal escape), then Aisle 🟠 (CWE-290) post-merge, Greptile P2 post-merge | 0               |
| [#63298](https://github.com/openclaw/openclaw/pull/63298) | `mbelinky`    | Yes (~9 min)  | Aisle 🟠×3, 🟡×1                                                                       | 0               |
| [#63155](https://github.com/openclaw/openclaw/pull/63155) | `frankekn`    | Yes (~4 hrs)  | Aisle 🟠 post-merge                                                                    | 0               |
| [#63199](https://github.com/openclaw/openclaw/pull/63199) | `obviyus`     | Yes (~1h 37m) | Aisle 🟠, 🟡                                                                           | 0               |
| [#63297](https://github.com/openclaw/openclaw/pull/63297) | `mbelinky`    | Yes (~2 min)  | Aisle 🟠, 🟡×3                                                                         | 0               |
| [#54536](https://github.com/openclaw/openclaw/pull/54536) | `vincentkoc`  | Yes (~4 days) | Aisle 🟡                                                                               | 0               |

All six PRs have the `maintainer` label applied. All data verified via GitHub API on 2026-06-02.

### B.2 Review Process Observations

1. **CODEOWNERS coverage.** The repository's `.github/CODEOWNERS` lists `/src/gateway/*auth*.ts`, `/src/gateway/**/*auth*.ts`, `/src/gateway/*secret*.ts`, and `/docs/security/` as owned by `@openclaw/secops`. PR #55730 modifies `src/gateway/server/ws-connection/message-handler.ts` and PR #54536 modifies `src/gateway/auth.ts` — both inside the CODEOWNERS scope. The `requested_teams` field on these PRs is empty: `@openclaw/secops` was not requested as a reviewer.

2. **No human review on any of the six PRs.** The only review comments are from automated bots. Zero human-authored review comments exist on any of the six PRs.

3. **Self-merge rate.** All six PRs have `merged_by` equal to the author account.

---

## Appendix D: Community PRs — Proxy Support and Security Hardening Attempts

This appendix catalogs community attempts to address proxy support and gateway security in `openclaw/openclaw`. Originally written on 2026-04-08 when many PRs were still open; updated on 2026-06-02 to reflect current state.

### D.1 Community Security/Proxy PRs — Status as of 2026-06-02

> **Note:** This section was originally written on 2026-04-08 when all 8 PRs below were open. All have since been closed or merged. The table shows both the original and current status.

None of these address the CWE-290 TUI spoofing vulnerability. **No PR (open or closed) proposes a fix for `isOperatorUiClient()` or `isControlUi`.**

| PR                                                        | Title                                                                                 | Author            | Created    | Status (2026-04-08) | Status (2026-06-02) | What It Tries to Fix                                                                                                                                                                                                                                         |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------- | ----------------- | ---------- | ------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [#63379](https://github.com/openclaw/openclaw/pull/63379) | `Feature/trusted proxy loopback`                                                      | `mrosmarin`       | 2026-04-08 | 🟡 Open             | 🔴 Closed           | Trusted-proxy mode rejects loopback connections even from `trustedProxies`. Adds `trustedProxy.allowLoopback` config. Touches `gateway/auth.ts`, `message-handler.ts`. Most directly relevant reverse proxy PR.                                              |
| [#63017](https://github.com/openclaw/openclaw/pull/63017) | `fix(security): apply security patches for multiple GHSA vulnerabilities`             | `EthanHunter1229` | 2026-04-08 | 🟡 Open             | 🔴 Closed           | Cherry-picks fixes for GHSA-fqw4-mph7-2vr8 (Critical: silent privilege escalation via shared-auth reconnect) and GHSA-9hjh-fr4f-gxc4 (Critical: non-admin operator scopes self-claim admin). Not proxy-related, but addresses critical auth vulnerabilities. |
| [#63280](https://github.com/openclaw/openclaw/pull/63280) | `fix(browser): auto-generate browser control auth token for none/trusted-proxy modes` | `pgondhi987`      | 2026-04-08 | 🟡 Open             | 🟢 Merged           | Browser control HTTP server runs with zero authentication when `auth.mode=none` or `trusted-proxy`. Auto-generates a random 48-hex-char token.                                                                                                               |
| [#62973](https://github.com/openclaw/openclaw/pull/62973) | `security: prompt injection defense at message and tool result boundaries`            | `sarkarsaurabh27` | 2026-04-08 | 🟡 Open             | 🔴 Closed           | Adds structural trust delimiters (`<user_message owner="false">`) so the model treats externally-sourced content as data, not instructions. References OWASP LLM01, EchoLeak CVE-2025-32711.                                                                 |
| [#32373](https://github.com/openclaw/openclaw/pull/32373) | `Add token hardening modules for gateway (T-ACCESS-003)`                              | `Techris93`       | 2026-03-03 | 🟡 Open             | 🔴 Closed           | Token redaction in logs, auth token exposure reduction. Was open for **36+ days** before closure.                                                                                                                                                            |
| [#50180](https://github.com/openclaw/openclaw/pull/50180) | `fix(ssrf): honor empty URL allowlists as deny-all`                                   | `dims`            | 2026-03-19 | 🟡 Open             | 🔴 Closed           | SSRF protection: empty URL allowlists should be treated as deny-all, not allow-all.                                                                                                                                                                          |
| [#50181](https://github.com/openclaw/openclaw/pull/50181) | `fix: close media trust bypasses`                                                     | `dims`            | 2026-03-19 | 🟡 Open             | 🔴 Closed           | Media trust bypass — accepting untrusted remote media URLs.                                                                                                                                                                                                  |
| [#58034](https://github.com/openclaw/openclaw/pull/58034) | `fix(net): harden trusted env proxy fetch guard and add explicit web_fetch opt-in`    | `cosmicnet`       | 2026-03-31 | 🟡 Open             | 🔴 Closed           | Network-layer proxy hardening — explicit web_fetch opt-in for trusted environment proxy.                                                                                                                                                                     |

### D.2 Closed Without Merge — Rejected Proxy/Security PRs

These PRs attempted to improve security or proxy support and were closed without merging.

| PR                                                        | Title                                                                              | Author       | Opened     | Closed     | Days Open      | Why Closed                                                                                                                                                                        |
| --------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------ | ---------- | ---------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [#29271](https://github.com/openclaw/openclaw/pull/29271) | `fix: Telegram gateway reads HTTP_PROXY/HTTPS_PROXY env vars for proxy`            | `gotnull`    | 2026-02-28 | 2026-04-08 | **40 days**    | Stale-bot auto-close. No maintainer ever reviewed it.                                                                                                                             |
| [#59156](https://github.com/openclaw/openclaw/pull/59156) | `fix(exec): prevent symlink and hardlink path traversal in script preflight reads` | `pgondhi987` | 2026-04-01 | 2026-04-03 | 2 days         | Barnacle bot: "Closing this PR because it looks dirty (too many unrelated or unexpected changes)." A security fix for path traversal was rejected because the branch was "dirty." |
| [#61914](https://github.com/openclaw/openclaw/pull/61914) | `fix(gateway): resolve catastrophic backtracking in interpreter heuristics regex`  | `openperf`   | 2026-04-06 | 2026-04-06 | **< 1 minute** | Opened and closed the same minute. No explanation.                                                                                                                                |
| [#62150](https://github.com/openclaw/openclaw/pull/62150) | `fix: the nostr plugin exposes gateway authenticated headers`                      | `drobison00` | 2026-04-06 | 2026-04-08 | 2 days         | No visible explanation.                                                                                                                                                           |
| [#62151](https://github.com/openclaw/openclaw/pull/62151) | `fix: openclaw accepts remote media urls from normal q`                            | `drobison00` | 2026-04-06 | 2026-04-08 | 2 days         | No visible explanation.                                                                                                                                                           |

### D.3 The `markfietje/openclaw` Fork PR

PR [#35109](https://github.com/openclaw/openclaw/pull/35109) — `fix(gateway): surgical proxy-aware origin validation 🤖` — was opened by `markfietje` on 2026-03-05 and **closed without merge**. The fork (`markfietje/openclaw`) exists at `https://github.com/markfietje/openclaw` with the comprehensive security hardening described in this advisory (commit `20d1702a3f`).

### D.4 The One Proxy PR That Merged in the Window

| PR                                                        | Title                                                                 | Author   | Created          | Merged           | Turnaround         |
| --------------------------------------------------------- | --------------------------------------------------------------------- | -------- | ---------------- | ---------------- | ------------------ |
| [#62878](https://github.com/openclaw/openclaw/pull/62878) | `fix(slack): honor HTTPS_PROXY for Socket Mode WebSocket connections` | `mjamiv` | 2026-04-08 03:24 | 2026-04-08 04:38 | **~1 hour 14 min** |

This PR's body explicitly states: _"This breaks Socket Mode in proxy-only environments (sandboxed containers, corporate networks, NVIDIA OpenShell)"_ and _"we've been running an equivalent monkey-patch across 4 OpenClaw agents on NVIDIA OpenShell sandboxes since March 2026, routing all Slack Socket Mode traffic through an HTTP CONNECT proxy at 10.200.0.1:3128."_

The merged PR fixes proxy support for **Slack Socket Mode** only — a single channel's outbound WebSocket connection. It does not modify the gateway's own WebSocket endpoint, the origin check system, the reverse proxy header handling, or any of the security hardening the fork provides.

### D.5 Timeline Summary

| Date             | Event                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| 2026-02-28       | PR #29271 (`Telegram HTTP_PROXY/HTTPS_PROXY`) opened by `gotnull`                                           |
| 2026-03-03       | PR #32373 (`token hardening modules`) opened by `Techris93`                                                 |
| 2026-03-05       | PR #35109 (`surgical proxy-aware origin validation`) opened by `markfietje`                                 |
| 2026-03-19       | PR #50180 (`SSRF URL allowlist deny-all`) and #50181 (`media trust bypass`) opened by `dims`                |
| 2026-03-27       | PR #55730 (`TUI onboarding`) merged — introduces CWE-290 (this advisory)                                    |
| 2026-03-31       | PR #58034 (`trusted env proxy hardening`) opened                                                            |
| 2026-04-01       | PR #59156 (`symlink path traversal fix`) opened by `pgondhi987`, closed 2 days later — "branch looks dirty" |
| 2026-04-06       | PR #61914 (`catastrophic regex backtracking`) opened and closed same minute                                 |
| 2026-04-08 03:24 | PR #62878 (`Slack HTTPS_PROXY`) opened by `mjamiv`                                                          |
| 2026-04-08 04:17 | PR #29271 (`Telegram HTTPS_PROXY`) auto-closed by stale-bot after **40 days** with no human review          |
| 2026-04-08 04:38 | PR #62878 (`Slack HTTPS_PROXY`) **merged** — ~1 hour turnaround                                             |
| 2026-04-08       | PRs #63017, #63280, #63379, #62973 opened (all later closed)                                                |
| 2026-06-02       | Re-verification: PR #55730 still live on `upstream/main`, no follow-up PR or issue addressing CWE-290       |

### D.6 Observed PR Lifecycle Patterns

1. **Proxy support PRs have long merge latencies or are auto-closed.** PR #29271 (Telegram proxy) sat for 40 days with no human review before the stale bot auto-closed it. The only proxy PR that merged in the window, #62878, is a narrow channel-specific fix, not gateway-wide proxy support.

2. **Security PRs from external contributors are ignored or rejected.** PR #59156 (path traversal) was closed with the rationale "branch looks dirty." PR #61914 (regex DoS) was closed in under a minute with no recorded explanation. PR #32373 (token hardening) was open for 36+ days before closure.

3. **No PR exists to fix the CWE-290 vulnerability as of 2026-06-02.** The `markfietje/openclaw` fork remains the only comprehensive fix (commit `20d1702a3f`); the upstream PR (#35109) that introduced it was closed.

---

## Appendix E: Why SSH/VPN Does Not Fix CWE-290

### E.1 What Is OpenShell?

OpenShell is a managed sandbox backend bundled with OpenClaw. It delegates sandbox lifecycle to the `openshell` CLI, which provisions remote environments with SSH-based command execution:

```
docs/gateway/openshell.md:
"OpenShell is a managed sandbox backend for OpenClaw. Instead of running Docker
containers locally, OpenClaw delegates sandbox lifecycle to the `openshell` CLI,
which provisions remote environments with SSH-based command execution."
```

Transport is SSH. No reverse proxy is involved for sandbox command execution.

### E.2 SSH/VPN Does Not Protect the Gateway's WebSocket Endpoint

SSH sandbox transport protects the command channel between the host and the sandbox. It does **not** protect the gateway's WebSocket authentication layer:

1. **The vulnerability is in client identity, not proxy transport.** CWE-290 exploits how the gateway authenticates WebSocket clients. A non-browser attacker spoofs `client.id = "openclaw-tui"` without a browser `Origin` header, bypassing the origin check.

2. **SSH/VPN does not filter WebSocket `connect` frames.** Once a client has network access to the gateway port (via LAN, VPN, Tailscale, Docker network, or direct internet), they can send any `connect` frame they want. SSH tunneling the connection does not add application-level auth.

3. **OpenShell sandboxes reach the gateway's WebSocket endpoint.** OpenShell's `gatewayEndpoint` configuration points to the gateway. An OpenShell sandbox running untrusted code can send a spoofed `connect` frame to the gateway's WebSocket endpoint — the same CWE-290 attack works from inside the sandbox.

### E.3 Defense Summary

| Defense                           | Protects Against                                  | Does NOT Protect Against            |
| --------------------------------- | ------------------------------------------------- | ----------------------------------- |
| SSH sandbox transport             | Sandbox command interception                      | WebSocket client spoofing (CWE-290) |
| VPN tunnel                        | Network-level MITM                                | Application-level auth bypass       |
| `enforceOriginCheckForAnyClient`  | Browser CSRF to localhost                         | Non-browser WebSocket attacks       |
| `allowInsecureAuth` locality gate | Remote TUI spoofing with `allowInsecureAuth` only | Localhost attacks with known token  |
| `isBrowserOperatorUiClient` fix   | Client identity spoofing                          | — (this is the fix)                 |

**Note:** The `allowInsecureAuth` locality gate (`!allowInsecureAuthConfigured || !isLocalClient`) blocks remote TUI spoofing attempts even on Docker deployments where the gateway binds to `0.0.0.0`. Remote Docker exploitation of CWE-290 requires `dangerouslyDisableDeviceAuth: true` (which sets `allowBypass=true`, bypassing the locality check entirely) or a trusted proxy configuration.
