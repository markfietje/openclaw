# Security Advisory: Device-Identity / Pairing Bypass via TUI Client ID Spoofing

| Field                  | Detail                                                                                                                                                                                                                                                                                             |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CVE**                | Pending                                                                                                                                                                                                                                                                                            |
| **CWE**                | CWE-290: Authentication Bypass by Spoofing                                                                                                                                                                                                                                                         |
| **Severity**           | 🟠 High                                                                                                                                                                                                                                                                                            |
| **Affected Component** | `src/gateway/server/ws-connection/message-handler.ts`                                                                                                                                                                                                                                              |
| **Introduced In**      | PR [#55730](https://github.com/openclaw/openclaw/pull/55730) — "fix: improve local onboarding and TUI hatch for loopback gateways"                                                                                                                                                                 |
| **Introduced By**      | `@shakkernerd`                                                                                                                                                                                                                                                                                     |
| **Merged By**          | `@shakkernerd` (same account as author; merge timestamp 2026-03-27 10:32:13 UTC)                                                                                                                                                                                                                   |
| **Merged At**          | 2026-03-27 10:32:13 UTC                                                                                                                                                                                                                                                                            |
| **Fix Status**         | **Unfixed** in upstream `openclaw/openclaw` as of 2026-06-02 (~9 weeks post-merge). **Zero commits, zero PRs, zero issues addressing CWE-290.** Three automated security bots flagged the PR at merge time; no follow-up has been opened or merged since. Mitigated in fork `markfietje/openclaw`. |
| **Detection**          | Flagged by Aisle Security bot (🟠 High) and Greptile review bot. Ignored by maintainer.                                                                                                                                                                                                            |

---

## 1. Executive Summary

On 2026-03-27, `@shakkernerd` opened and merged [PR #55730](https://github.com/openclaw/openclaw/pull/55730) into `openclaw/openclaw`. The PR was opened and merged within **4 minutes** with **no human review**, **no linked issue**, and **no response to automated security findings**.

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

### 5.3 Possible Interpretations of the 4-Minute Merge

Two interpretations are consistent with the recorded data:

**Interpretation A: Security warnings were viewed as overstated.** This reading is supported by the absence of any recorded human reply to the four bot findings on PR #55730, the same absence on the other five PRs in Appendix A, and the fact that the vulnerability remains on `upstream/main` as of 2026-06-02.

**Interpretation B: Convenience was prioritized over security review.** The 4-minute merge window means the automated tools did not have time to complete their analysis before the merge. The finding timeline in Section 4.1 shows three of the four bot comments landing after the merge timestamp. A PR-merge gating rule that waits for automated security review to complete would have caught this.

Both interpretations point to the same outcome: a HIGH severity vulnerability shipped to production with no human security review.

---

## 6. The Mitigated Alternative

The fork `markfietje/openclaw` by **Mark Fietje** (`@markfietje`) ships a working fix for CWE-290. The fix is a one-line behavior change at the existing call site, plus test coverage. Verified by code reading and test execution on 2026-06-02 against fork HEAD `5f0eb89562c`.

### 6.1 Root Cause Fix: Use the Strict Helper at the Call Site

The strict helper `isBrowserOperatorUiClient` already existed in the upstream codebase at `src/utils/message-channel.ts:52-55` and was already imported in the message handler at `src/gateway/server/ws-connection/message-handler.ts:96`. It was being used for the origin check gate on line 698 (`isBrowserOperatorUi`) but **not** for the `isControlUi` boolean on line 697. The fix is to use the strict helper for `isControlUi` too:

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

`isControlUi` flows into `src/gateway/server/ws-connection/connect-policy.ts` where it gates five Control-UI-specific bypass paths. With the strict helper, a TUI client (`id = "openclaw-tui"`) produces `isControlUi = false` and cannot trigger any of them:

| Bypass path                                                                 | File:line                   | TUI result                                | CONTROL_UI result          |
| --------------------------------------------------------------------------- | --------------------------- | ----------------------------------------- | -------------------------- |
| `evaluateMissingDeviceIdentity`: trusted-proxy auth shortcut                | `connect-policy.ts:124`     | `reject-device-required` (no shared auth) | `allow`                    |
| `evaluateMissingDeviceIdentity`: `dangerouslyDisableDeviceAuth` break-glass | `connect-policy.ts:127`     | `reject-device-required`                  | `allow`                    |
| `evaluateMissingDeviceIdentity`: `allowInsecureAuth` localhost shortcut     | `connect-policy.ts:138-146` | `reject-device-required` (no shared auth) | `allow` (with shared auth) |
| `shouldSkipControlUiPairing`: `authMode: none` pairing skip                 | `connect-policy.ts:54`      | `false` (must pair)                       | `true` (skip)              |
| `shouldSkipControlUiPairing`: tailscale+operator+device pairing skip        | `connect-policy.ts:44`      | `false` (must pair)                       | `true` (skip)              |
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

All targeted tests pass on 2026-06-02 against fork HEAD `5f0eb89562c`. The full `pnpm tsgo:all` typecheck shows a single pre-existing error in `src/gateway/server/verify-client.test.ts:8` unrelated to this fix (verified against `origin/main`).

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

The fork's PR to upstream was **closed** by upstream maintainers (PR #35109, "fix(gateway): surgical proxy-aware origin validation").

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

## 8. Post-Merge Verification

As of **2026-06-02** — ~9 weeks after PR #55730 introduced the vulnerability — the upstream `openclaw/openclaw` repository has taken **no action** to address the CWE-290 finding. Re-verification commands and outputs are recorded below.

### 8.1 Verified Upstream State (2026-06-02)

The vulnerable code remains **identical** to what was merged on 2026-03-27. Direct inspection of `upstream/main` (`6c8e065e3b1`):

- `src/utils/message-channel.ts:47` — `isOperatorUiClient` still returns `true` for both `CONTROL_UI` and `TUI` (no fix).
- `src/gateway/server/ws-connection/message-handler.ts:671` — `const isControlUi = isOperatorUiClient(connectParams.client);` unchanged.
- `src/gateway/server/ws-connection/connect-policy.ts:144-147` — `evaluateMissingDeviceIdentity` still returns `{ kind: "allow" }` for `params.isControlUi && params.controlUiAuthPolicy.allowBypass && params.role === "operator"`.
- `src/gateway/server/ws-connection/auth-messages.ts:18` — same vulnerable assignment in the auth-failure hint path.
- `git log upstream/main --all -S 'isControlUi = isOperatorUiClient'` returns only the original `2b96569e2d6` (PR #55730 merge) and fork-side commits; no upstream-side replacement.

### 8.2 Activity Since Merge (2026-03-27 → 2026-06-02)

| Metric                                                     | Value        |
| ---------------------------------------------------------- | ------------ |
| Commits to `message-handler.ts` since 2026-03-27           | 6            |
| Commits touching `isControlUi` / `isOperatorUiClient`      | **0**        |
| Open PRs proposing a fix for CWE-290                       | **0**        |
| Open issues filed about CWE-290                            | **0**        |
| Human responses to Aisle/Greptile/Codex findings on #55730 | **0**        |
| Time the HIGH severity finding has been publicly visible   | **~9 weeks** |

The 6 commits that did touch `message-handler.ts` between 2026-03-27 and 2026-06-02 were about unrelated concerns (lint config, refactors, paired-scope reconnect enforcement, etc.). `git log` filtered on the `isControlUi = isOperatorUiClient` symbol returns no upstream-side replacement.

### 8.3 PR Search Results (2026-06-02)

`gh pr list --repo openclaw/openclaw --state all --search 'CWE-290 OR TUI spoofing OR isControlUi isOperatorUiClient'` returns the original PR #55730 and unrelated PRs that mention `isControlUi` in passing; **no PR proposes a fix for the vulnerable `isOperatorUiClient()` assignment**. `gh issue list` against the same terms returns no issue filed about CWE-290.

### 8.4 Observations

The data is publicly observable:

1. **Security bot findings on PR #55730 received zero human responses.** Three independent automated tools flagged the PR at merge time (Aisle, Greptile, Codex). The bot comments remain on the PR with no maintainer reply, and the underlying code is unchanged.

2. **The `maintainer` label was applied to PR #55730.** Whether that label affects required-reviewers in this repository is a configuration question; the label is visible on the PR and on every other PR in Appendix A.

3. **The `markfietje/openclaw` fork's PR — which addresses CWE-290 and additional gateway hardening — was closed by upstream without merge.** The fork's mitigation is documented in Section 6.

---

## 9. Risk Assessment

A fair question: _how exploitable is this really, given that the default bind mode on bare metal is loopback?_ Let's walk through the threat model.

### 9.1 The "I Only Use It Locally" Defense

**The argument:** "My gateway is on `127.0.0.1`. No one can reach it. Therefore the vulnerability doesn't matter."

**The default bind mode confirms this:**

```ts
// src/gateway/net.ts — defaultGatewayBindMode()
return isContainerEnvironment() ? "auto" : "loopback";
//                                       ↑ bare-metal default: loopback only
```

On a bare-metal host running the Mac/CLI directly, the gateway binds to `127.0.0.1`. Remote attackers on the internet cannot connect to the WebSocket endpoint directly. Connected messaging channels (Telegram, WhatsApp, Discord) are outbound — they connect to the channel's API, not to the gateway's WebSocket. So far, so good.

**If the story ended here, the risk would indeed be low.** A local-only service behind loopback has a limited attack surface: an attacker would need local code execution on the machine, at which point the loopback bind is no longer the relevant control.

### 9.2 The Problem: It Doesn't End There

The "just localhost" defense breaks down in five real-world scenarios:

#### Scenario 1: Browser-Based CSRF via WebSocket (The Stealthy One)

**This is the most realistic attack for a default-config bare-metal user.**

Modern browsers allow JavaScript on any website to open a WebSocket to `ws://localhost:18789`. There is no same-origin policy restriction on WebSocket connections to localhost — the browser will happily connect.

The attack:

1. The user visits a malicious (or compromised) website in a browser tab — could be anything
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

8. **The malicious website now has full operator access** to the gateway. It can:
   - Read all conversation history and stored messages
   - Send messages through connected Telegram, WhatsApp, Discord, Slack channels
   - Read and modify gateway configuration, including API keys
   - Install or modify plugins
   - Access file system tools the agent has configured

**The user does not see this happen.** The WebSocket connection is invisible — no browser tab, no notification. The malicious JS runs silently in a background tab.

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

Any other device on the same Tailscale network can connect to the gateway's WebSocket endpoint and exploit the TUI spoofing vulnerability. Tailscale authenticates network access, but once a device is on the tailnet, the gateway's application-level auth is what protects against CWE-290 — and that's exactly what's broken.

#### Scenario 4: VPS / Cloud / Remote Server

Many self-hosters run OpenClaw on a VPS (Hetzner, DigitalOcean, AWS Lightsail, etc.) or a home server. If the gateway is bound to `lan` or behind a reverse proxy (Caddy, Nginx), it is accessible from the internet. The vulnerability is exploitable by anyone who can reach the endpoint.

This is the scenario where reverse-proxy-aware gateway hardening matters most: users behind Caddy/Nginx are the ones most exposed to a client-identity-spoofing vulnerability, because their entire deployment relies on the gateway correctly authenticating the originating browser/process.

#### Scenario 5: OpenShell / Remote Sandbox

`extensions/openshell/src/config.ts` defines a `gatewayEndpoint` parameter that points at the OpenClaw gateway. An OpenShell sandbox that can reach the gateway's WebSocket endpoint (which it must, to run agent tool calls through the gateway) can execute the same CWE-290 attack from inside the sandbox. SSH/VPN protects the sandbox command channel; it does not protect the gateway's WebSocket authentication layer. See Appendix E.

### 9.3 The Honest Summary

| Scenario                    | Network Position | Exploit Method                     | Risk                                                         |
| --------------------------- | ---------------- | ---------------------------------- | ------------------------------------------------------------ |
| **Bare-metal, loopback**    | Local only       | Browser CSRF via malicious website | 🟠 **High** — stealthy, no user interaction after page visit |
| **Docker (default config)** | LAN / internet   | Direct WebSocket connection        | 🔴 **Critical** — remote, no prerequisites                   |
| **Tailscale**               | Tailnet          | Any tailnet device                 | 🟠 **High** — any trusted device can attack                  |
| **VPS / reverse proxy**     | Internet         | Direct WebSocket connection        | 🔴 **Critical** — anyone on the internet                     |
| **OpenShell sandbox**       | Sandbox→Gateway  | Sandbox-initiated WebSocket        | 🟠 **High** — depends on sandbox network reachability        |
| **Shared office / LAN**     | LAN              | Any device on same network         | 🟠 **High** — no authentication needed                       |

### 9.4 Why the "Localhost is Safe" Belief Is Wrong

The localhost defense has a fundamental flaw: **browsers bridge the gap between the internet and localhost.**

When the user visits `https://random-website.com`, the JavaScript on that page can open a WebSocket to `ws://localhost:18789`. The browser does not block this. The connection goes through. And because the TUI spoofing bypasses the origin check, the malicious website's `Origin` header is never validated.

This is not a theoretical attack. It's the same class of vulnerability as CSRF — except instead of forging a form submission, the attacker is taking over a persistent WebSocket connection with full bidirectional access to the gateway.

**The exploit is:**

1. Visit a webpage (any webpage with malicious or injected JS)
2. That's it. The rest is silent and invisible.

**The prerequisite is just:**

- OpenClaw running with default quickstart config (`allowInsecureAuth: true`)
- A browser tab open somewhere

Every OpenClaw user who ran through the quickstart wizard has this configuration. Every one of them is vulnerable to a drive-by browser attack.

### 9.5 Note on the "I Don't Use It" Reasoning

A common response to this kind of report is "I don't use the TUI / Control UI / reverse proxy, so this doesn't affect me." This reasoning is unsafe because:

1. **The attack targets the default config.** Quickstart sets `allowInsecureAuth: true` and binds to `loopback` on bare metal, `0.0.0.0` inside containers. Any user who ran the wizard is in the affected set, regardless of which client surface they actively use.
2. **Browser CSRF reaches localhost without the user's cooperation.** Scenario 1 works on any browser tab opened after the gateway is running. The user does not need to invoke the TUI or the Control UI for the attack to succeed.
3. **The vulnerability is in the gateway, not the client.** `isOperatorUiClient()` is evaluated server-side. Whether the operator happens to use the spoofed client is irrelevant to whether the bypass exists.
4. **"I don't use X" narrows the threat model to a single developer's workflow.** The advisory's threat model covers the documented deployment configurations: MacBook localhost, Docker with default `bind=lan`, Tailscale tailnet, VPS / cloud behind Caddy/Nginx, and shared office / LAN.

---

## 10. Timeline

| Date                    | Event                                                                                                                                                                |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-03-27 10:01        | Commit `2b96569e`: `isOperatorUiClient()` introduced for `isControlUi`                                                                                               |
| 2026-03-27 10:09        | Commit `f1de00c1`: `isBrowserOperatorUiClient()` added for origin checks, but `isControlUi` still uses `isOperatorUiClient()`                                        |
| 2026-03-27 10:28        | PR #55730 opened                                                                                                                                                     |
| 2026-03-27 10:29        | Aisle Security bot flags 🟠 HIGH CWE-290                                                                                                                             |
| 2026-03-27 10:32        | **PR #55730 merged** — `merged_by` is the same account as the author, no recorded human review                                                                       |
| 2026-03-27 10:35        | Greptile bot flags backward-compat and `isOperatorUiClient` scope concerns                                                                                           |
| 2026-03-27 10:36        | Aisle Security bot re-confirms 🟠 HIGH severity                                                                                                                      |
| 2026-03-27 10:37        | Codex Review bot flags P2 password auth regression                                                                                                                   |
| 2026-03-27 10:39        | No human response to any of the four bot findings                                                                                                                    |
| 2026-03-27 → 2026-06-02 | **No upstream commit, PR, or issue addresses the CWE-290 vulnerability.** Commits to `message-handler.ts` in this window are unrelated lint/refactor/lifecycle work. |
| 2026-06-02              | Re-verification: `upstream/main` (`6c8e065e3b1`) still carries the vulnerable pattern. `gh pr list` and `gh issue list` return no fix PR or issue for CWE-290.       |

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

## Appendix C: "I Don't Use the Control UI Either" — Why This Doesn't Reduce Risk

A common variant of the dismissal is: _"I only use the TUI locally on my MacBook. I don't use proxies, I don't use the Control UI. Therefore these vulnerabilities don't affect me."_ This is unsafe.

### C.1 The TUI Is the Vulnerability, Not the Control UI

The CWE-290 vulnerability is not about spoofing the Control UI. It's about spoofing **the TUI**. The vulnerable code:

```ts
// upstream — STILL VULNERABLE
const isControlUi = isOperatorUiClient(connectParams.client);
//                        ↑ matches "openclaw-tui" — a real client ID
```

`isOperatorUiClient()` returns `true` for `"openclaw-tui"` — a documented, real client ID. The attack impersonates a client that actually ships and runs; it does not need the operator to also use a different client surface for the bypass to exist.

### C.2 The "I Don't Use Control UI" Defense Makes the Exploit Easier

When a malicious website spoofs `openclaw-tui`, the gateway sees:

1. `isOperatorUiClient()` → `true` (matches TUI)
2. `isBrowserOperatorUiClient()` → `false` (not Control UI)
3. Origin check is **skipped** (only triggers for browser Control UI or Webchat)
4. `allowInsecureAuth: true` (set by default during quickstart) → no device identity required
5. The attacker is granted full operator access

If a legitimate Control UI session were active in a browser, at least there would be a paired session that could potentially conflict or alert. With no Control UI in use, the spoofed TUI operates in complete isolation — nothing to conflict with, nothing to alert on.

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

When `allowInsecureAuth: true` and the URL is localhost, the TUI connects with `deviceIdentity: null` — no device pairing, no cryptographic identity. This is the same path a spoofed TUI client takes. There is **no distinguishing signal** between a legitimate TUI and a malicious WebSocket claiming to be `"openclaw-tui"`.

### C.4 Why "I Don't Use X" Is a Security Anti-Pattern

Each "I don't use X" argument narrows the threat model to a single personal workflow. But the documented deployment surface for OpenClaw is wider than one developer's MacBook: Docker containers on VPS, Tailscale networks, home servers, shared offices, and MacBooks with browsers open. The vulnerability affects every user who:

- Ran the quickstart wizard (`allowInsecureAuth: true` by default)
- Has the gateway running
- Has a browser open

Confusing **personal risk** (one developer's setup) with **product risk** (every deployment) is a security anti-pattern. Section 9.2 enumerates five concrete deployment scenarios and the exploitability of each.

### C.5 The Bottom Line

The vulnerability is in how the TUI client ID is handled. The default quickstart config — `allowInsecureAuth: true`, loopback bind on bare metal, `0.0.0.0` bind inside containers — is the most directly exploitable configuration. The attacker does not need to target a service the operator doesn't use.

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

The fork `markfietje/openclaw` adds a dedicated `packages/gateway-security-core/` package plus two gateway-layer overlays, covering the attack surfaces where the upstream is missing defenses. All file paths below are verified against fork HEAD `5f0eb89562c` on 2026-06-02 via `git diff --name-only upstream/main...origin/main`.

**`packages/gateway-security-core/src/`** (new package, 23 files added):

| File                                                                                             | Security Domain                                | Present in Upstream |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------- | ------------------- |
| `capabilities.ts`                                                                                | Capability-based access control                | ❌ No               |
| `connection-rate-limit.ts`                                                                       | Connection-level rate limiting                 | ❌ No               |
| `ip-restriction-policy.ts`                                                                       | IP allowlist/blocklist with CIDR support       | ❌ No               |
| `message-auth.ts`                                                                                | Per-method message authentication              | ❌ No               |
| `ws-endpoint.ts`                                                                                 | Endpoint classification (`classifyWsEndpoint`) | ❌ No               |
| `ws-protocol.ts`                                                                                 | Subprotocol / frame-level protocol enforcement | ❌ No               |
| `auth-audit-log.ts`                                                                              | Auth audit log with HMAC chain                 | ❌ No               |
| `startup-security-checks.ts`                                                                     | Pre-accept hardening checks                    | ❌ No               |
| `tool-audit.ts` / `exec-deny-paths.ts` / `device-session-authority.ts` / `request-rate-limit.ts` | Tool/Exec/Device/Session hardening             | ❌ No               |
| `net-helpers.ts` / `paths.ts` / `index.ts`                                                       | Internal helpers                               | ❌ No               |

**`src/gateway/`** (new files in the gateway layer):

| File                                        | Security Domain                                                                                | Present in Upstream                                       |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `forwarded-headers.ts`                      | RFC 7239 `Forwarded` parsing with chain depth                                                  | ❌ No                                                     |
| `server/verify-client.ts`                   | Pre-handshake WS client verification (origin / proxy / subprotocol)                            | ❌ No                                                     |
| `auth.proxy-headers.test.ts`                | 17 test cases for the proxy-header auth seam                                                   | ❌ No                                                     |
| `server/verify-client.test.ts`              | 528 lines of pre-handshake verification tests                                                  | ❌ No                                                     |
| `origin-check.test.ts`                      | 64 test cases for `checkBrowserOrigin` (extended to 966 lines with proxy + signed-token cases) | ❌ No (file exists upstream with 145 lines, 0 it() cases) |
| `server/authenticated-connection-budget.ts` | Per-connection budget enforcement                                                              | ❌ No                                                     |

`src/gateway/security-hardening.test.ts` is **not** a real file in either the fork or the upstream. Earlier revisions of this advisory listed it; that row has been removed.

| Metric                              | Upstream                                        | Fork                                                                                                                 |
| ----------------------------------- | ----------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Proxy/origin/pre-handshake tests    | 0 it() cases in 145-line `origin-check.test.ts` | 64 in `origin-check.test.ts` + 17 in `auth.proxy-headers.test.ts` + 26 in `server/verify-client.test.ts` (107 total) |
| Timing-safe nonce comparison        | ❌ `!==` operator                               | ✅ `safeEqualSecret()` / `timingSafeEqual`                                                                           |
| Endpoint isolation                  | ❌ None                                         | ✅ `classifyWsEndpoint` / `isKnownWsEndpoint` (`packages/gateway-security-core/src/ws-endpoint.ts:45,65`)            |
| Per-frame rate limiting             | ❌ None                                         | ✅ `ws-protocol.ts`                                                                                                  |
| Message-level authorization         | ❌ None                                         | ✅ `message-auth.ts`                                                                                                 |
| IP restriction policy               | ❌ None                                         | ✅ `ip-restriction-policy.ts`                                                                                        |
| Client identity spoofing protection | ❌ `isOperatorUiClient()` (vulnerable)          | ✅ `isBrowserOperatorUiClient()` (strict) at `message-handler.ts:697`                                                |

The fork's PR to upstream was **closed** by upstream maintainers (PR #35109, "fix(gateway): surgical proxy-aware origin validation").

---

## Appendix B: PR Author and Review Data

The data in this appendix is taken from the live GitHub PR and org APIs. No conclusions about individuals' intent are drawn — only the recorded state of PRs, labels, reviewers, and merge authorship is documented.

### B.1 PR Author and Merge Data

| PR                                                        | Author        | Self-Merged   | Bot Findings Before Merge                                    | Human Responses |
| --------------------------------------------------------- | ------------- | ------------- | ------------------------------------------------------------ | --------------- |
| [#55730](https://github.com/openclaw/openclaw/pull/55730) | `shakkernerd` | Yes (~4 min)  | Aisle 🟠, Greptile P2, Codex P2                              | 0               |
| [#63298](https://github.com/openclaw/openclaw/pull/63298) | `mbelinky`    | Yes (~8 min)  | Aisle 🟠×3, 🟡×1                                             | 0               |
| [#63155](https://github.com/openclaw/openclaw/pull/63155) | `frankekn`    | Yes           | Codex: "no major issues" (4 iterations); Aisle 🟠 post-merge | 0               |
| [#63199](https://github.com/openclaw/openclaw/pull/63199) | `obviyus`     | Yes (~1h 37m) | Aisle 🟠, 🟡                                                 | 0               |
| [#63297](https://github.com/openclaw/openclaw/pull/63297) | `mbelinky`    | Yes (~2 min)  | Aisle 🟠, 🟡×3                                               | 0               |
| [#54536](https://github.com/openclaw/openclaw/pull/54536) | `vincentkoc`  | Yes (~4 days) | Aisle 🟡                                                     | 0               |

All six PRs have the `maintainer` label applied.

### B.2 Review Process Observations

1. **CODEOWNERS coverage.** The repository's `.github/CODEOWNERS` file lists `/src/gateway/*auth*.ts`, `/src/gateway/**/*auth*.ts`, `/src/gateway/*secret*.ts`, `/src/gateway/**/*secret*.ts`, `/src/gateway/security-path*.ts`, and `/docs/security/` as owned by `@openclaw/secops`. PR #55730 modifies `src/gateway/server/ws-connection/message-handler.ts` and PR #54536 modifies `src/gateway/auth.ts` — both inside the CODEOWNERS scope. The `requested_teams` field on these PRs is empty: `@openclaw/secops` was not requested as a reviewer on any of the six PRs in this appendix.

2. **No human review on any of the six PRs.** The only review comments on these PRs are from automated bots (`aisle-research-bot`, `greptile-apps[bot]`, `chatgpt-codex-connector[bot]`). The Codex bot on PR #63155 said "no major issues" across four iterations despite a post-merge Aisle HIGH finding; the same pattern repeats on the other PRs in this set.

3. **Self-merge rate.** All six PRs in this appendix have `merged_by` equal to `user.login` (the same account that opened the PR). No PR in this set was reviewed and merged by a different account.

### B.3 Stated Intent vs. Security Outcome

| PR     | Stated Intent              | Security Outcome (verified post-merge)           |
| ------ | -------------------------- | ------------------------------------------------ |
| #55730 | TUI onboarding convenience | 🟠 HIGH: CWE-290 auth bypass by spoofing         |
| #63298 | Dreaming diary UI          | 🟠 HIGH ×3: symlink read/write + info disclosure |
| #63155 | Session reset fix          | 🟠 HIGH: CWE-285 model-override policy bypass    |
| #63199 | Android pairing fix        | 🟠 HIGH: CWE-269 bootstrap-token auth bypass     |
| #63297 | REM extraction hardening   | 🟠 HIGH: CWE-200 secret persistence              |
| #54536 | Auth bypass fix            | 🟡 Medium: CWE-346 DNS-rebinding (residual)      |

Stated intent is taken from each PR's title and description; security outcome is taken from the bot comments and post-merge code inspection.

### B.4 Public Org Membership vs. `maintainer`-Labelled PR Authors

The `openclaw` GitHub organization has 19 public members (per `gh api .../orgs/openclaw/members`): `alauppe, altaywtf, Asleep123, BunsDev, cpojer, darkamenosa, Evizero, grp06, gumadeiras, huntharo, hydro13, mukhtharcm, sebslight, shakkernerd, thewilloftheshadow, tyler6204, velvet-shark, vincentkoc, zimeg`.

Of the PR authors in B.1, `shakkernerd` and `vincentkoc` are public org members. The other four (`mbelinky`, `frankekn`, `obviyus`, and the contributor referenced in Appendix E) are not in the public members list, yet their PRs carry the `maintainer` label and the merge was performed by the author account. Whether those accounts are private/hidden org members, external collaborators, or hold access by some other mechanism is a question only the org owners can answer definitively.

### B.5 Aggregate Outcome

Across the six PRs in this appendix: 22 bot-flagged security findings merged without remediation (9 HIGH, 12 MEDIUM, 1 LOW), zero human responses to bot findings, six-of-six self-merged. This is a description of the recorded PR data, not a judgment of intent.

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

### D.4 The One Proxy PR That Merged in the Window

| PR                                                        | Title                                                                 | Author   | Created          | Merged           | Turnaround         |
| --------------------------------------------------------- | --------------------------------------------------------------------- | -------- | ---------------- | ---------------- | ------------------ |
| [#62878](https://github.com/openclaw/openclaw/pull/62878) | `fix(slack): honor HTTPS_PROXY for Socket Mode WebSocket connections` | `mjamiv` | 2026-04-08 03:24 | 2026-04-08 04:38 | **~1 hour 14 min** |

This PR's body explicitly states: _"This breaks Socket Mode in proxy-only environments (sandboxed containers, corporate networks, NVIDIA OpenShell)"_ and _"we've been running an equivalent monkey-patch across 4 OpenClaw agents on NVIDIA OpenShell sandboxes since March 2026, routing all Slack Socket Mode traffic through an HTTP CONNECT proxy at 10.200.0.1:3128."_

The merged PR fixes proxy support for **Slack Socket Mode** only — a single channel's outbound WebSocket connection. It does not modify the gateway's own WebSocket endpoint, the origin check system, the reverse proxy header handling, or any of the security hardening the fork provides.

### D.5 Timeline Summary

| Date             | Event                                                                                                       |
| ---------------- | ----------------------------------------------------------------------------------------------------------- |
| 2025-11-26       | PR #1 (`allowFrom wildcard handling`) opened and closed same day                                            |
| 2026-02-28       | PR #29271 (`Telegram HTTP_PROXY/HTTPS_PROXY`) opened by `gotnull`                                           |
| 2026-03-03       | PR #32373 (`token hardening modules`) opened by `Techris93`                                                 |
| 2026-03-19       | PR #50180 (`SSRF URL allowlist deny-all`) and #50181 (`media trust bypass`) opened by `dims`                |
| 2026-03-27       | PR #55730 (`TUI onboarding`) merged — introduces CWE-290 (this advisory)                                    |
| 2026-03-31       | PR #58034 (`DNS pinning for trusted env proxy`) opened                                                      |
| 2026-04-01       | PR #59156 (`symlink path traversal fix`) opened by `pgondhi987`, closed 2 days later — "branch looks dirty" |
| 2026-04-06       | PR #61914 (`catastrophic regex backtracking`) opened and closed same minute                                 |
| 2026-04-08 03:24 | PR #62878 (`Slack HTTPS_PROXY`) opened by `mjamiv`                                                          |
| 2026-04-08 04:17 | PR #29271 (`Telegram HTTPS_PROXY`) auto-closed by stale-bot after **40 days** with no human review          |
| 2026-04-08 04:38 | PR #62878 (`Slack HTTPS_PROXY`) **merged** — ~1 hour turnaround                                             |
| 2026-04-08 08:10 | PR #63017 (`multi-GHSA security patches`) opened                                                            |
| 2026-04-08 17:40 | PR #63280 (`browser control auth token`) opened                                                             |
| 2026-04-08 21:33 | PR #63379 (`trusted proxy loopback`) opened — most relevant reverse proxy PR                                |
| 2026-06-02       | Re-verification: PR #55730 still live on `upstream/main`, no follow-up PR or issue addressing CWE-290       |

### D.6 Observed PR Lifecycle Patterns

1. **Proxy support PRs have long merge latencies or are auto-closed.** PR #29271 (Telegram proxy) sat for 40 days with no human review before the stale bot auto-closed it. The only proxy PR that merged in the window, #62878, is a narrow channel-specific fix, not gateway-wide proxy support.

2. **Security PRs from external contributors are ignored or rejected in the recorded data.** PR #59156 (path traversal) was closed with the rationale "branch looks dirty." PR #61914 (regex DoS) was closed in under a minute with no recorded explanation. PR #32373 (token hardening) was open for 36+ days as of the 2026-04-08 snapshot.

3. **No PR exists to fix the CWE-290 vulnerability as of 2026-06-02.** `gh pr list --search 'CWE-290 OR TUI spoofing OR isControlUi isOperatorUiClient'` returns only the original PR #55730 and unrelated PRs; no follow-up PR has been opened or merged. The `markfietje/openclaw` fork remains the only comprehensive fix (commit `20d1702a3f`); the upstream PR that introduced it was closed.

---

## Appendix E: Why SSH/VPN Does Not Fix CWE-290

A natural question: _does the OpenShell deployment model make reverse proxy support unnecessary, and does it therefore reduce the impact of CWE-290?_ It does not, for the reasons below.

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

Transport is SSH. No reverse proxy is involved for sandbox command execution. OpenShell's gateway endpoint configuration (`gatewayEndpoint`) points to the OpenClaw gateway, but agent tool execution inside the sandbox still routes through the gateway's WebSocket.

### E.2 Evidence From the Slack HTTPS_PROXY PR (#62878)

The PR body for #62878 states:

> _"This breaks Socket Mode in proxy-only environments (sandboxed containers, corporate networks, NVIDIA OpenShell)."_
>
> _"Production validation: we've been running an equivalent monkey-patch (openclaw-ws-proxy-patch.js) across 4 OpenClaw agents on NVIDIA OpenShell sandboxes since March 2026, routing all Slack Socket Mode traffic through an HTTP CONNECT proxy at 10.200.0.1:3128."_

OpenClaw's provider list includes first-class NVIDIA NIM support (`nvidia-nim` provider, Nemotron models).

### E.3 Timeline: OpenShell Emergence vs CWE-290 Introduction

| Date           | Event                                                                                     |
| -------------- | ----------------------------------------------------------------------------------------- |
| **2026-03-19** | OpenShell extension first appears in the repository (`5508374669`)                        |
| **2026-03-27** | PR #55730 merged — CWE-290 TUI spoofing vulnerability introduced                          |
| **2026-04-08** | PR #62878 merged — Slack proxy fix, references "NVIDIA OpenShell sandboxes" in production |
| **2026-06-02** | Re-verification: CWE-290 still unfixed on `upstream/main`                                 |

### E.4 The "SSH/VPN Replaces Reverse Proxy" Argument

The argument is sometimes stated as: _OpenShell uses SSH for sandbox transport. VPN provides network connectivity. Reverse proxies are unnecessary, so reverse-proxy-related security hardening is not needed._

This argument is unsound for three reasons:

**Reason 1: The vulnerability is in client identity, not proxy transport.**

CWE-290 exploits how the gateway authenticates WebSocket clients:

1. A malicious website opens `ws://localhost:18789` from the victim's browser
2. The spoofed `"openclaw-tui"` client ID bypasses origin checks and auth gates
3. The attacker is granted operator access

This attack has nothing to do with proxy transport. It works whether the gateway is behind a reverse proxy, a VPN, an SSH tunnel, or directly on localhost. The browser is the attack vector, not the network topology.

**Reason 2: SSH/VPN does not protect the gateway's WebSocket endpoint.**

OpenShell uses SSH for sandbox command execution. The OpenClaw gateway's primary interface is its WebSocket endpoint — TUI, Control UI, webchat, CLI, and all connected clients communicate over it. SSH transport for sandbox commands is orthogonal to WebSocket security.

A VPN connects the user to a network. The browser CSRF attack (Section 9.2) happens locally: the malicious website's JavaScript connects to `ws://localhost:18789` through the victim's browser. The VPN does not prevent this. The SSH tunnel does not prevent this.

**Reason 3: OpenShell sandboxes reach the gateway's WebSocket endpoint.**

OpenShell's configuration includes a `gatewayEndpoint` parameter:

```ts
// extensions/openshell/src/config.ts
gatewayEndpoint?: string;  // Points to the OpenClaw gateway
```

An OpenShell sandbox must be able to reach the gateway's WebSocket endpoint, because agent tool execution routes through the gateway. CWE-290 is therefore exploitable from within an OpenShell sandbox that runs untrusted code: the same WebSocket spoofing attack works against the gateway from inside the sandbox.

### E.5 The Real Question

The question is not whether SSH is more secure than HTTP reverse proxies (it is, for sandbox transport). The question is whether the OpenClaw gateway's WebSocket authentication layer is secure regardless of transport. It is not:

| Defense                   | Protects Against                       | Does NOT Protect Against                 |
| ------------------------- | -------------------------------------- | ---------------------------------------- |
| SSH sandbox transport     | Sandbox command interception           | WebSocket client spoofing (CWE-290)      |
| VPN tunnel                | Network-level MITM                     | Browser CSRF to localhost WebSocket      |
| No reverse proxy          | Direct internet exposure to proxy bugs | Client identity spoofing via `client.id` |
| `allowInsecureAuth: true` | — (removes a security gate)            | — (makes the bypass easier)              |

SSH/VPN is the right tool for sandbox access. It does not fix a broken authentication gate in the WebSocket handshake. The two layers are independent.

### E.6 The Bottom Line

The OpenShell deployment model may not need reverse proxy support for sandbox connectivity. That is a separate concern from gateway authentication. The CWE-290 vulnerability affects every documented deployment configuration that exposes the gateway's WebSocket endpoint to anything that can open a TCP socket to it:

- MacBook localhost + a browser tab — exploitable via browser CSRF
- Docker with default `bind=lan` — exploitable from LAN/internet
- VPS/cloud behind Caddy/Nginx — exploitable from internet
- Tailscale networks — exploitable from any tailnet device
- OpenShell sandboxes — exploitable if the sandbox can reach the gateway WebSocket
- Not affected by SSH sandbox transport or VPN connectivity — those are orthogonal to client authentication
