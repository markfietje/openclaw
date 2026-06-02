# Run Your Own AI Assistant on MacOS Apple Container, One Terminal Command

**No Docker. No cloud. Your API keys stay on your Mac.**

**You need:** a Mac with Apple Silicon (M1/M2/M3/M4) running macOS 26 Tahoe. That's it.

Open Terminal. Paste this. Press Enter.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh)
```

Done. It pulls a pre-built image, creates a hardened sandboxed container, generates a secure token (stored in Keychain), and prints your next steps.

No Docker. No Homebrew. No config files to touch yet.

---

## Start → Configure → Chat

Three steps, in this order:

**1. Start the gateway:**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) run
```

Wait for the ✓. The gateway runs in the background — you can close Terminal and it stays up. (It won't survive a reboot though — just run the same command again after restarting.)

**2. Add your AI provider:**

```bash
npx openclaw onboard
```

This downloads the OpenClaw CLI and launches a guided wizard. Pick your provider (OpenAI, Anthropic, Google — you just need one API key), paste it, done.

> **The gateway must be running** before this step — `onboard` talks to it. If you get a connection error, run the `run` command first.

**3. Chat:**

```bash
npx openclaw tui --url ws://localhost:18789 --token "$(security find-generic-password -s ai.openclaw.apple-container.gateway-token -w)"
```

This reads the token from your macOS Keychain and opens the terminal chat interface. Type a message, get a response. That's it.

## Make it shorter — add aliases

That TUI command is long. Add this to `~/.zshrc`:

```bash
alias oc='npx openclaw tui --url ws://localhost:18789 --token "$(security find-generic-password -s ai.openclaw.apple-container.gateway-token -w)"'
alias oc-run='bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) run'
alias oc-stop='bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) stop'
alias oc-upgrade='bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) upgrade'
```

Then `source ~/.zshrc`. Your daily workflow:

```
oc-run        # start (also needed after reboot)
oc            # chat
oc-stop       # done for the day
oc-upgrade    # update to latest version
```

## Connect to Telegram, Discord, WhatsApp

Run the wizard again: `npx openclaw onboard`. It walks you through adding messaging channels. Your AI is then reachable from your phone, desktop, or browser — anywhere you use those apps.

## Stop, update, remove

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) stop      # stop
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) upgrade  # update (preserves config & data)
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) status   # check health
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) logs     # view logs
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) uninstall # remove everything
```

## Troubleshooting

- **"Apple Container not installed"** — Download the installer from [github.com/apple/container/releases](https://github.com/apple/container/releases), double-click the `.pkg`, enter your admin password. Then re-run the bootstrap.
- **Gateway won't start** — Check logs (the `logs` command above). Common cause: invalid JSON in `~/.openclaw/openclaw.json`.
- **AI doesn't respond** — You need a provider configured. Run `npx openclaw onboard`.
- **Nothing works after a reboot** — The gateway doesn't auto-start. Just run `oc-run` again.

## What's inside the container

|                  | Details                                                                      |
| ---------------- | ---------------------------------------------------------------------------- |
| **Image size**   | ~185 MB download (production-only deps, no source maps, no type definitions) |
| **Idle memory**  | ~80–120 MB RSS (Node.js 24)                                                  |
| **Under load**   | ~200–300 MB RSS (streaming, tool calls, multiple agents)                     |
| **Base image**   | `node:24-bookworm-slim`                                                      |
| **Exposed port** | 18789 (localhost only)                                                       |
| **JS runtime**   | Node.js 24 (default) or Bun (opt-in via `--runtime bun`)                     |

---

## Security

The container is hardened by default — these aren't optional toggles, they're always on unless you explicitly opt out.

### The "double lock" (the headline)

- **Read-only root filesystem** — nothing can modify the container image at runtime
- **All Linux capabilities dropped** (`--cap-drop ALL`) — zero kernel capabilities
- **Non-root process** — runs as `node` user, never root
- **Strict file permissions** — `umask 077`, credentials directory `0700`
- **Loopback-only network** — the gateway binds to `127.0.0.1:18789`, not `0.0.0.0`. No inbound traffic from your LAN or the internet.

### Token & credential storage

- **Gateway token in macOS Keychain** — stored in the login keychain, never on disk inside the image
- **Encrypted credential storage at rest** — API keys and channel tokens are sealed with **AES-256-GCM** (authenticated encryption) before being written to disk
- **HMAC integrity checks** — every read of the gateway token verifies an HMAC tag; tampering is detected
- **Optional Keychain bridge** (full installer) — token can be delivered over a localhost Keychain bridge instead of a mounted volume, so it never sits on disk at all

### Authentication & origin gating

- **Token + role + scope model** — every WebSocket connect is authenticated, then authorized for specific roles (`operator` vs `node`) and scopes (`operator.read`, `operator.write`, `operator.admin`, `operator.approvals`, `operator.pairing`, `operator.talk.secrets`)
- **Pre-handshake verifyClient** — accepts or rejects WebSocket upgrades before any payload is parsed. The defense-in-depth order is:
  1. **Connection limits** — per-IP connection rate cap (default 30 / 10s)
  2. **Strict header validation** — every required `Upgrade`/`Connection`/`Sec-WebSocket-*` header must be present and well-formed
  3. **Cross-header consistency** — `Host`, `X-Forwarded-Host`, and `Origin` must agree
  4. **Untrusted proxy header rejection** — if you put a reverse proxy in front, `X-Forwarded-*` headers from non-trusted IPs are dropped
  5. **Origin validation** — browser clients must present a matching `Origin` against an explicit allowlist. Wildcard `*` is **rejected** (no exceptions)
  6. **IP allowlist / blocklist** — CIDR-aware. Default-deny on unknown ranges if you configure an allowlist
  7. **Subprotocol enforcement** — clients must advertise `openclaw-v1` or be rejected
- **Per-device connection budget** — one paired device can't open 1000 WebSockets. Defaults to 64 per device identity.
- **Forwarded header consistency** — if a client lies about `X-Forwarded-For` in a way that contradicts the trusted proxy's view, the request is dropped with `ip_blocked`

### Rate limiting

- **Connection rate limit** — 30 connections per 10 seconds per IP (sliding window, loopback exempt)
- **Per-IP request rate limit** — 100 HTTP requests per 60s per IP (HTTP gateway, loopback exempt)
- **WebSocket preauth payload cap** — first message is size-limited; oversize frames are rejected with close code `1009`
- **Malformed frame guard** — clients that send garbage JSON get 3 strikes, then close code `1008` (no more invalid frames)

### Per-message auth (opt-in, but ships enabled-ready)

- **Message-level capability context** — every WebSocket connection has a `MessageAuthorizationContext` with the client's role, scopes, and resolved capabilities
- **Defense-in-depth capability checks** (opt-in via `gateway.security.messageAuth.enabled`): even after a successful connect, calls to `secrets.resolve`, `secrets.reload`, and `config.set_protected` are checked against dedicated capabilities (`secrets:read`, `secrets:manage`, `admin:config`) — not just `operator.admin`
- **Node-role gating** — node-only methods (e.g. `node.event`, `node.invoke.result`) require `role === "node"`, enforced at both `server-methods.ts` and the optional message-auth layer

### Startup security checks

On every gateway start, a battery of checks runs against the resolved bind address + auth mode:

- **TLS required when network-exposed** — refuses to start if bound to a non-loopback address without TLS or a trusted upstream proxy
- **Token length** — refuses network-exposed starts with a token shorter than 32 characters
- **Password strength** — refuses network-exposed starts with a password shorter than 12 characters, and warns on digit-only / single-case passwords
- **Auth disabled warning** — refuses network-exposed starts with `auth.mode === "none"` unless `OPENCLAW_DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE=1` is set
- **Bind-all warning** — warns when bound to `0.0.0.0` / `::` (you almost always want loopback)
- **Extra credential strength checks** — `validateCredentialStrength` adds character-variety warnings (digit-only passwords, etc.) on top of the basic length check

All critical findings block startup. All warnings are logged to the startup-security prefix.

### Exec approval (shell command gating)

When the AI runs a shell command, four gates run in order:

1. **Allowlist match** — is the command in the configured allowlist?
2. **Deny-path match** — does the command reference `.openclaw/secrets/`, `.openclaw/credentials/`, `.env`, SSH keys, GPG keys, or any other sensitive file? **Always forces explicit user approval** unless the agent runs in `yolo` mode.
3. **Heredoc / inline-eval / security-audit-suppression** — each forces approval in their own conditions
4. **Host security** — full / allowlist / sandbox; ask = always / off / on-miss

If any gate says "ask", the user gets a prompt before the command runs.

### Audit logging (tamper-evident)

- **Auth audit log** — append-only HMAC-signed record of every accept/reject decision. Events: `auth_success`, `auth_failure`, `rate_limited`, `ip_blocked`. Enable with `OPENCLAW_AUTH_AUDIT=1` or `gateway.security.authAudit.enabled: true`.
- **Tool audit log** — append-only HMAC-signed record of every `tools/invoke` call. Events: `tool.result` (success), `tool.error` (denied, input failure, exec failure). Enable with `gateway.security.toolAudit.enabled: true`.
- Both logs HMAC-chain each line to the gateway token, so removing or editing a line breaks the chain and is detectable.

### Outbound redaction

Before any AI response reaches a channel (TUI, Telegram, Discord, WhatsApp), the gateway strips:

- API keys (`sk-...`, `sk-ant-...`, `AIza...`, etc.)
- Bearer tokens and JWTs
- Private keys (`-----BEGIN ... PRIVATE KEY-----` blocks)
- Passwords in common env-var or config patterns

The redaction is enforced at the outbound layer, not the model layer — even if the model tries to exfiltrate a key, the user never sees it.

---

## Two install paths

The one-liner above is the **lite installer** (single file, easy to audit). It
stages the gateway token in a container volume that the gateway reads at
startup. For production / shared-host use, the repo also ships a
**full setup** (`scripts/apple-container/setup.sh` + `run.sh`) that delivers
the token over a host-side Keychain bridge on localhost, so the token
never sits on disk. Both paths share the same container hardening
(`--read-only`, `--cap-drop ALL`, non-root, 127.0.0.1-only port).

The full installer also supports running behind a reverse proxy
([Caddy](https://github.com/markfietje/openclaw/blob/main/docs/gateway/caddy-proxy.md)
or [Tailscale Serve](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/examples/secure-tailscale-serve.json))
while preserving the untrusted-proxy-header rejection and origin validation
described above.

---

## What's hardened (audit summary)

| Layer                    | Protection                                                                              | Wired?                                                              | Source                                                                 |
| ------------------------ | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| Container                | Read-only root, `--cap-drop ALL`, non-root, `umask 077`, loopback-only                  | ✅                                                                  | `Dockerfile.apple_arm64`, `scripts/apple-container/{bootstrap,run}.sh` |
| Credential storage       | AES-256-GCM, HMAC integrity, Keychain-bridge option                                     | ✅                                                                  | `src/infra/sealed-json-file.ts`, `src/config/io.hmac-integrity.ts`     |
| Auth                     | Token/role/scope, `validateCredentialStrength` at startup                               | ✅                                                                  | `src/gateway/auth.ts`, `server.impl.ts:798`                            |
| Pre-handshake            | 7-stage verifyClient (rate → headers → consistency → proxy → origin → IP → subprotocol) | ✅                                                                  | `src/gateway/server/verify-client.ts`                                  |
| WebSocket per-message    | Preauth payload cap, malformed-frame counter, message-auth context                      | ✅                                                                  | `src/gateway/server/ws-connection/message-handler.ts`                  |
| HTTP                     | Per-IP request rate limit (100/60s), healthz short-circuit, HSTS auto                   | ✅                                                                  | `src/gateway/server-http.ts`                                           |
| Connection               | Per-IP rate (30/10s), per-device budget (64/identity), max payload 64 MB                | ✅                                                                  | `src/gateway/server-runtime-state.ts`                                  |
| Exec approval            | Allowlist + deny-path + heredoc + inline-eval + security-audit suppression              | ✅                                                                  | `src/infra/exec-approvals.ts`, `src/agents/bash-tools.exec-host-*`     |
| Audit                    | HMAC-signed auth + tool audit, `ip_blocked` / `auth_failure` / `rate_limited` events    | ✅                                                                  | `packages/gateway-security-core/src/{auth-audit-log,tool-audit}.ts`    |
| Outbound                 | Strip API keys / tokens / private keys from responses                                   | ✅                                                                  | `src/infra/outbound/redaction.ts`                                      |
| Startup checks           | TLS required, token ≥ 32, password ≥ 12, no-auth refuses, bind-all warns                | ✅                                                                  | `packages/gateway-security-core/src/startup-security-checks.ts`        |
| Origin check             | Wildcard `*` rejected, signed tokens, browser control-UI matching                       | ✅                                                                  | `src/gateway/origin-check.ts`                                          |
| Forwarded headers        | Sensitive-header validation, cross-header consistency                                   | ✅                                                                  | `src/gateway/forwarded-headers.ts`, `src/gateway/net.ts`               |
| Optional extras (opt-in) | Per-message auth context for `secrets.*` / `config.set_protected`                       | ⚙️ off by default, set `gateway.security.messageAuth.enabled: true` | `src/gateway/server/ws-connection/message-handler.ts:1977`             |

For a deep dive on the threat model, attacker surface, and proof-of-concept exploits this hardening closes, see:

- [Fork Security Overview](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/FORK_SECURITY.md)
- [Fork Hardening Deep-Dive](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/fork-hardening-deep-dive.md)
- [Property-Based Evidence](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/PROPERTY-EVIDENCE.md)
- [CWE-290 TUI Client Spoofing Advisory](https://github.com/markfietje/openclaw/blob/main/docs/security/ADVISORY-CWE-290-TUI-CLIENT-SPOOFING.md)

## What is OpenClaw?

[OpenClaw](https://github.com/markfietje/openclaw) is an open-source AI gateway. It connects AI models (OpenAI, Anthropic, Google) to your messaging apps (Telegram, Discord, WhatsApp). You run it on your own Mac — no cloud, no third-party servers, your API keys stay local.

## Disclaimer

This is **not** the official OpenClaw project. The container image and hardening are my own build — the official OpenClaw repository does not ship a dedicated Apple Silicon Apple Container image. Use at your own risk, no warranties included.

If you'd like to see this upstreamed or want to chat about it, find me at [linkedin.com/in/markfietje](https://linkedin.com/in/markfietje).

## Full documentation

→ [Apple Container guide](https://github.com/markfietje/openclaw/blob/main/docs/install/apple-container.md)
