# Run Your Own AI Assistant on macOS Apple Container, One Terminal Command

**No Docker. No cloud. Your API keys stay on your Mac.**

## Prerequisites

| Requirement                         | Why                                                                                       | How to check                                    |
| ----------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------- |
| **Apple Silicon Mac** (M1/M2/M3/M4) | Apple Container only supports ARM                                                         | `sysctl -n hw.optional.arm64` → prints `1`      |
| **macOS 26 Tahoe**                  | Apple Container requires it                                                               | Apple menu → About This Mac                     |
| **Apple Container CLI**             | Runtime for sandboxed Linux containers                                                    | `container --version` — if not found, see below |
| **~2 GB free disk**                 | Image (~500 MB download, ~1.2 GB uncompressed) + volumes + state                          | Finder → Storage                                |
| **Internet connection**             | Image pull + AI provider API                                                              | Obvious, but noted                              |
| **Node.js** (optional)              | For `npx openclaw tui` on the host; not needed if you use the container-based TUI instead | `node --version`                                |

### Install Apple Container (if you don't have it)

1. Go to [github.com/apple/container/releases](https://github.com/apple/container/releases)
2. Download the latest `.pkg`
3. Double-click → enter your admin password
4. **Restart Terminal** (the `container` command won't be visible until you do)

Verify:

```bash
container --version
```

You should see a version number. If not, restart Terminal and try again.

> **Tested with:** Apple Container CLI 0.12.3. Newer versions should work. If you hit issues with a different version, [file an issue](https://github.com/markfietje/openclaw/issues).

> **Why no Docker?** Apple Container uses the macOS virtualization framework to run lightweight Linux containers natively. No daemon, no Docker Desktop, no separate VM. The container shares your Mac's kernel scheduling but has its own isolated filesystem, users, and network.

---

## Install

Open Terminal. Paste this. Press Enter.

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh)
```

**What happens (about 2–5 minutes depending on your connection):**

1. **Preflight** — checks you're on Apple Silicon with Apple Container running
2. **Image pull** — downloads the pre-built container image (~400–500 MB compressed) from GitHub Container Registry
3. **Token generation** — creates a cryptographically random gateway token (64 hex chars, 256 bits) and stores it in your macOS Keychain
4. **Container creation** — creates a hardened, read-only, sandboxed container

You'll see a **macOS Keychain dialog** asking to store the token. Click **Allow**.

When it finishes, you'll see:

```
==> Setup complete!

  Gateway token:  (stored in Keychain — you don't need it)
  Gateway port:   18789
  Config dir:     ~/.openclaw
  Script:         ~/.openclaw/bin/openclaw-container.sh
```

The script also installs itself to `~/.openclaw/bin/openclaw-container.sh` for convenience.

> **If something goes wrong:** see the [Troubleshooting](#troubleshooting) section below.

---

## Start → Configure → Chat

Three steps, in this order:

### 1. Start the gateway

```bash
~/.openclaw/bin/openclaw-container.sh run
```

Wait for the ✓. The gateway runs in the background — you can close Terminal and it stays up.

> **After a reboot**, the gateway won't auto-start. Just run this command again.

### 2. Add your AI provider

Edit the config file:

```bash
nano ~/.openclaw/openclaw.json
```

Find the `models` → `providers` section and add your API key. For example, with OpenAI:

```json
{
  "models": {
    "providers": {
      "openai": {
        "apiKey": "sk-your-key-here"
      }
    }
  }
}
```

You only need one provider. Save and exit (`Ctrl+X`, `Y`, `Enter`).

> **The gateway must be running** for this config to take effect. If you edited the file while the gateway was stopped, start it with step 1 — it reads the config on startup.

### 3. Chat

**If you have Node.js on your Mac** (or are willing to install it — [nodejs.org](https://nodejs.org) or `brew install node`):

```bash
npx openclaw tui --url ws://localhost:18789 --token "$(security find-generic-password -s ai.openclaw.apple-container.gateway-token -w)"
```

**If you don't have Node.js** — run the TUI inside the container instead (it has its own Node.js):

```bash
container exec openclaw openclaw tui --url ws://127.0.0.1:18789 --token-file /home/node/.openclaw/bridge-token
```

Either way, you'll see a **Keychain dialog** — click **Always Allow** to avoid being asked every time.

Type a message, get a response. That's it.

> **`npx` downloads the OpenClaw CLI on first use** (~10 seconds). After that it's cached and instant. The `container exec` alternative requires no host-side Node.js at all.

---

## Make it shorter — add aliases

That TUI command is long. Add this to `~/.zshrc` (or `~/.bashrc` if you use bash):

```bash
# With host Node.js (npx):
alias oc='npx openclaw tui --url ws://localhost:18789 --token "$(security find-generic-password -s ai.openclaw.apple-container.gateway-token -w)"'

# Without host Node.js (runs inside the container):
alias oc='container exec openclaw openclaw tui --url ws://127.0.0.1:18789 --token-file /home/node/.openclaw/bridge-token'

# Common commands (both paths use these):
alias oc-run='~/.openclaw/bin/openclaw-container.sh run'
alias oc-stop='~/.openclaw/bin/openclaw-container.sh stop'
alias oc-upgrade='~/.openclaw/bin/openclaw-container.sh upgrade'
```

Then reload your shell:

```bash
source ~/.zshrc
```

Your daily workflow:

```
oc-run        # start (also needed after reboot)
oc            # chat
oc-stop       # done for the day
oc-upgrade    # update to latest version
```

---

## Connect to Telegram, Discord, WhatsApp

Edit `~/.openclaw/openclaw.json` and add channel credentials under the `channels` section. See the [OpenClaw docs](https://docs.openclaw.ai) for provider-specific setup guides.

Once configured, your AI is reachable from your phone, desktop, or browser — anywhere you use those apps.

---

## Stop, update, remove

```bash
~/.openclaw/bin/openclaw-container.sh stop       # stop the gateway
~/.openclaw/bin/openclaw-container.sh upgrade     # update to latest (preserves config & data)
~/.openclaw/bin/openclaw-container.sh status      # check health
~/.openclaw/bin/openclaw-container.sh logs        # view logs
~/.openclaw/bin/openclaw-container.sh uninstall   # remove everything (deletes config, data, volumes)
```

You can also use the one-liner form if you prefer:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/markfietje/openclaw/main/scripts/apple-container/bootstrap.sh) stop
```

---

## Troubleshooting

### Installation problems

| Problem                                             | Cause                                     | Fix                                                                                                                                        |
| --------------------------------------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **"Apple Silicon (M1/M2/M3/M4) is required"**       | Intel Mac                                 | Apple Container doesn't support Intel. You need an M-series Mac.                                                                           |
| **"Apple Container is not installed"**              | `container` CLI not found                 | Download from [github.com/apple/container/releases](https://github.com/apple/container/releases), install the `.pkg`, **restart Terminal** |
| **"Apple Container runtime did not start in time"** | Background service didn't launch          | Run `container system start` manually. If that fails, try `sudo container system start` (requires admin password).                         |
| **Keychain dialog: you clicked "Deny"**             | Token wasn't stored                       | Re-run the install command. Click **Allow** or **Always Allow** this time.                                                                 |
| **Image pull hangs or fails**                       | Network / GitHub Container Registry issue | Check your internet connection. Try again. If behind a corporate proxy, the GHCR domain `ghcr.io` needs to be accessible.                  |
| **"Container 'openclaw' already exists"**           | You ran install twice                     | Run `~/.openclaw/bin/openclaw-container.sh uninstall` first, then install again. Or use `upgrade` instead.                                 |

### Runtime problems

| Problem                          | Cause                                         | Fix                                                                                                                                                                                                                           |
| -------------------------------- | --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------- |
| **Gateway won't start**          | Config error or port conflict                 | Run the `logs` command. Common cause: invalid JSON in `~/.openclaw/openclaw.json`. Validate it with `cat ~/.openclaw/openclaw.json                                                                                            | python3 -m json.tool`. |
| **"AI doesn't respond"**         | No provider configured                        | Edit `~/.openclaw/openclaw.json` and add an API key under `models.providers` (see step 2 above).                                                                                                                              |
| **"Connection refused" in TUI**  | Gateway isn't running                         | Run `oc-run` first, wait for the ✓, then `oc`.                                                                                                                                                                                |
| **Nothing works after a reboot** | Gateway doesn't auto-start                    | Run `oc-run` again.                                                                                                                                                                                                           |
| **Keychain prompts every time**  | You clicked "Allow" instead of "Always Allow" | Next time the dialog appears, click **Always Allow**. Or: open Keychain Access → find "ai.openclaw.apple-container.gateway-token" → double-click → Access Control → add `/usr/bin/security`.                                  |
| **`npx` not found**              | Node.js not installed on your Mac             | Either install it ([nodejs.org](https://nodejs.org) or `brew install node`), or use the container-based TUI: `container exec openclaw openclaw tui --url ws://127.0.0.1:18789 --token-file /home/node/.openclaw/bridge-token` |
| **Port 18789 already in use**    | Another process on that port                  | Set `OPENCLAW_HOST_PORT=18790` before running, or stop the other process.                                                                                                                                                     |

### How to check if everything is working

```bash
# Is the container running?
~/.openclaw/bin/openclaw-container.sh status

# Is the gateway responding?
curl -s http://localhost:18789/health

# View live logs
~/.openclaw/bin/openclaw-container.sh logs
```

---

## What's inside the container

All numbers below are measured from a live container (Apple Container 0.12.3, image built 2026-06-02):

|                         | Details                                                                                               |
| ----------------------- | ----------------------------------------------------------------------------------------------------- |
| **Uncompressed image**  | ~1.2 GB (27 OCI layers, `node:24-bookworm-slim` base + OpenClaw)                                      |
| **Compressed download** | ~400–500 MB (estimated from typical OCI compression ratio)                                            |
| **App breakdown**       | `dist/` 149 MB · `node_modules/` 485 MB · `extensions/` 27 MB · `docs/` 17 MB                         |
| **Idle RSS**            | ~330 MB (gateway process, 11 threads, includes V8 heap + buffers)                                     |
| **Init RSS**            | ~13 MB (`.cz-init` signal handler, PID 1)                                                             |
| **Memory cap**          | 1 GB (`--memory 1073741824`)                                                                          |
| **CPU cap**             | 2 cores (`--cpus 2`)                                                                                  |
| **Base image**          | `node:24-bookworm-slim` (pinned by SHA256 digest, not floating tag)                                   |
| **Node.js**             | v24.14.1                                                                                              |
| **Exposed port**        | `127.0.0.1:18789` (loopback only — verified from `container inspect`)                                 |
| **JS runtime**          | Node.js 24 (default) or Bun (opt-in via `--runtime bun`)                                              |
| **Process user**        | `node` uid=1000 gid=1000 — never root (verified with `id` inside container)                           |
| **Filesystem**          | Read-only root (`readOnly: true`) + tmpfs for `/tmp`, `/home/node/.cache`, `/app/node_modules/.cache` |
| **File permissions**    | App files: `root:root 0644/0755` · State dir: `node:node 0750` · Credentials: `node:node 0700`        |
| **Entrypoint**          | `container-entrypoint` → `umask 0027` → `exec "$@"`                                                   |
| **Network**             | Isolated network `openclaw-net`, MTU 1280, no IPv4 gateway exposure to host                           |

<details>
<summary>How to verify these yourself</summary>

```bash
# Container security config (read-only, caps, user, port binding)
container inspect openclaw | python3 -m json.tool

# Process user and filesystem permissions inside container
container exec openclaw id
container exec openclaw ls -la /app/openclaw.mjs
container exec openclaw ls -ld /home/node/.openclaw /home/node/.openclaw/credentials

# Memory usage
container exec openclaw cat /proc/2/status | grep VmRSS

# Disk breakdown
container exec openclaw du -sh /app/dist /app/node_modules /app/extensions

# Health check
curl -s http://127.0.0.1:18789/health

# Verify port binding is loopback-only
container inspect openclaw | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'{p[\"hostAddress\"]}:{p[\"hostPort\"]} -> :{p[\"containerPort\"]}') for p in d[0]['configuration']['publishedPorts']]"
```

</details>

---

## Security

The container is hardened by default — these aren't optional toggles, they're always on unless you explicitly opt out.

### The "double lock" (the headline)

The container is locked down at two levels — the container runtime and the gateway process:

**Container-level hardening (verified from `container inspect openclaw`):**

- **Read-only root filesystem** (`readOnly: true`) — nothing can modify the container image at runtime. Writable paths use `tmpfs` (in-memory, ephemeral).
- **All Linux capabilities dropped** (`capDrop: ["ALL"]`, `capAdd: []`) — zero kernel capabilities. The process can't mount filesystems, load kernel modules, or access raw network sockets.
- **Non-root process** (`user: "1000:1000"`) — runs as `node` user, never root. App files are owned by `root:root` so the process can't modify its own code.
- **Loopback-only network** (`hostAddress: "127.0.0.1"`) — port 18789 is published on localhost only. No inbound traffic from your LAN or the internet.
- **Init process** (`useInit: true`) — `.cz-init` handles PID 1 signal forwarding, prevents zombie processes.
- **No Rosetta, no SSH, no virtualization extensions** — minimal attack surface.

**Process-level hardening:**

- **Strict file permissions** — `umask 0027` (owner read/write, group read, no other access). Credentials directory is `0700` (owner only).
- **Resource limits** — CPU capped at 2 cores, memory capped at 1 GB.

### Token & credential storage

- **Gateway token in macOS Keychain** — stored in the login keychain under service name `ai.openclaw.apple-container.gateway-token`. The token is 64 hex characters (256 bits of randomness), generated via `openssl rand -hex 32`.
- **HMAC integrity checks** — every read of the config file verifies an HMAC-SHA256 tag signed with the gateway token. Tampering is detected via timing-safe comparison.
- **AES-256-GCM encryption at rest** — when the `OPENCLAW_PASSPHRASE` env var is set, API keys and channel tokens are sealed with authenticated encryption (scrypt key derivation + AES-256-GCM with random IV) before being written to disk. The sealed format is versioned: `openclaw-sealed-json-v1:<base64(...)>.` Without the passphrase, credentials are stored as plain JSON.

### Authentication & origin gating

The codebase implements a 7-stage pre-handshake security gate (`verify-client.ts`) designed to accept or reject WebSocket connections **before any payload is parsed**. The stages are:

1. **Connection rate limit** — max 30 connections per 10 seconds per IP (sliding window). Loopback is exempt.
2. **Strict header validation** — every required WebSocket upgrade header (`Upgrade`, `Connection`, `Sec-WebSocket-*`) must be present and well-formed. Duplicate or chained sensitive headers (`Host`, `Origin`, `X-Forwarded-*`) are rejected.
3. **Cross-header consistency** — `Host`, `X-Forwarded-Host`, and `Origin` must agree. Contradictions indicate header spoofing and are rejected.
4. **Untrusted proxy header rejection** — if you put a reverse proxy in front, `X-Forwarded-*` headers from non-trusted IPs are silently dropped. Only explicitly trusted proxies may set forwarding headers.
5. **Origin validation** — browser clients must present a matching `Origin` against an explicit allowlist. Wildcard `*` is **rejected** — there is no way to allow all origins.
6. **IP allowlist / blocklist** — CIDR-aware (supports `192.168.1.0/24`, `fd00::/48`, etc.). Blocklist takes precedence over allowlist. Default-deny on unknown ranges if you configure an allowlist.
7. **Subprotocol enforcement** — clients must advertise the `openclaw-gateway-v1` WebSocket subprotocol or the upgrade is rejected.

> **Wiring note:** This pipeline is implemented in `verify-client.ts` but is not yet wired through `server.impl.ts` into the production gateway (see [audit summary](#what-is-hardened-audit-summary) for status). The origin validation (stage 5) and forwarded header checks (stages 3–4) are also enforced post-handshake in `message-handler.ts` and `origin-check.ts`, which are active.

After the handshake:

- **Per-device connection budget** — one authenticated device identity can't open unlimited WebSockets. Default cap is 8 concurrent connections per device.
- **Token + password + Tailscale auth** — every connection is authenticated via token, password, or Tailscale header verification.

### Rate limiting

Three independent rate limiters, all sliding-window, loopback-exempt:

| Layer                     | Limit                                     | Purpose                               |
| ------------------------- | ----------------------------------------- | ------------------------------------- |
| **Connection rate**       | 30 connections / 10s per IP               | Prevent connection floods             |
| **HTTP request rate**     | 120 requests / 60s per IP                 | Prevent HTTP-level abuse              |
| **Malformed frame guard** | 3 invalid JSON frames → close with `1008` | Prevent slow-loris via garbage frames |

WebSocket preauth payloads are size-limited (default 64 KB). Oversize frames are rejected with close code `1009`.

### Per-message auth (opt-in, ships enabled-ready)

Even after a successful WebSocket handshake, sensitive operations are gated by capabilities — not just the initial auth:

- **`secrets.resolve` / `secrets.reload`** — requires `secrets:read` or `secrets:manage` capability. Even an authenticated `operator.admin` can't read stored API keys without the explicit capability.
- **`config.set_protected`** — requires `admin:config` capability. Prevents auth config changes from any client that happens to be authenticated.
- **Node-role gating** — methods like `node.event` and `node.invoke.result` require `role === "node"`. An operator client cannot invoke node methods.

Enable with `gateway.security.messageAuth.enabled: true` in your config. The lite installer leaves this off by default for compatibility; the full installer enables it.

### Startup security checks

On every gateway start, a battery of checks runs against the resolved bind address + auth mode:

- **TLS required when network-exposed** — logs a critical warning if bound to a non-loopback address without TLS or a trusted upstream proxy.
- **Token length** — logs a critical warning for network-exposed starts with a token shorter than 32 characters.
- **Password strength** — logs a critical warning for network-exposed starts with a password shorter than 12 characters (startup gate), with additional warnings at 15 characters and for digit-only / single-case passwords.
- **Auth disabled warning** — logs a critical warning for network-exposed starts with `auth.mode === "none"` unless `OPENCLAW_DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE=1` is set.
- **Bind-all warning** — warns when bound to `0.0.0.0` / `::` (you almost always want loopback).

All findings are logged on every startup. The `assertStartupSecurityFindingsAllowed` function (which would block startup on critical findings) is available but not yet called from the main gateway start path — so the gateway will currently start even with critical findings. The checks serve as operational warnings for now.

### Exec approval (shell command gating)

When the AI runs a shell command, four independent gates run in order:

1. **Allowlist match** — is the command in the configured allowlist?
2. **Deny-path match** — does the command reference `.openclaw/secrets/`, `.openclaw/credentials/`, `.env`, SSH keys, GPG keys, or other sensitive files? **Always forces explicit user approval** unless the agent runs in `yolo` mode.
3. **Heredoc / inline-eval / security-audit-suppression detection** — each forces user approval under its own conditions.
4. **Host security policy** — full / allowlist / sandbox; ask = always / off / on-miss.

If any gate says "ask", the user gets a prompt before the command runs. The deny-path patterns support glob matching (`*`, `**`, `?`) and are extracted from shell commands accounting for pipes, redirects, flags, and quotes.

### Audit logging (tamper-evident)

Two optional audit logs, both HMAC-chained to the gateway token:

- **Auth audit** — append-only record of every accept/reject decision. Events: `auth_success`, `auth_failure`, `rate_limited`, `ip_blocked`. Each entry is individually HMAC-signed. Enable with `OPENCLAW_AUTH_AUDIT=1` or `gateway.security.authAudit.enabled: true`.
- **Tool audit** — append-only record of every `tools/invoke` call. Events: `tool.result` (success), `tool.error` (denied, input failure, exec failure). Records tool name, actor, session, channel, model, and duration — but never logs sensitive arguments. Enable with `gateway.security.toolAudit.enabled: true`.

Both logs use HMAC-SHA256 with timing-safe verification. Each entry is individually signed — editing a line breaks its HMAC and is detectable. Note: entries are not chained to each other, so deletion or reordering of entries would not be detected. Log files are written with mode `0600` (owner-only).

### Outbound redaction (module ready, not yet wired)

A regex-based redaction module (`outbound-redact.ts`) can strip secrets from AI responses before they reach channels (TUI, Telegram, Discord, WhatsApp). It covers:

- **Specific patterns** (applied first): OpenAI keys (`sk-...`), Anthropic keys (`sk-ant-...`), Google keys (`AIza...`), Stripe keys (`sk_live_...`), GitHub PATs (`ghp_`, `gho_`, `ghs_`), Slack tokens (`xox[bpras]-...`), private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- **Generic patterns** (applied last): `api_key=`, `token=`, `password=` with 8+ character values
- **Dynamic secrets**: runtime-known values (gateway token, config passwords) are added to the redaction set automatically

The module defaults to enabled (`gateway.security.enableOutboundRedaction !== false`) and uses a multi-pass sentinel approach to prevent partial-match bypass. However, **the function is not yet called from the live delivery pipeline** — `createOutboundDeliveryPayloadRedactor` is exported but has zero importers in the response path. See the [audit summary](#what-is-hardened-audit-summary) for wiring status.

---

## Two install paths

The one-liner above is the **lite installer** — a single 600-line bash script, easy to audit, pulls a pre-built image from GitHub Container Registry. It stores the gateway token in a container volume that the gateway reads at startup.

For production or shared-host use, the repo also ships a **full installer** (`scripts/apple-container/setup.sh` + `run.sh`) that:

- **Builds the image locally** from source (takes 5–15 minutes, verifies everything)
- **Delivers the token over a localhost Keychain bridge** — a tiny HTTP server on the host reads the token from macOS Keychain and serves it to the container via bearer-authenticated HTTP. The token never sits on disk inside the container.
- **Applies stricter defaults**: `--user 1000:1000`, `127.0.0.1` port binding, `--cpus 2`, `--memory 1g`, tmpfs for caches
- **Supports running behind a reverse proxy** ([Caddy](https://github.com/markfietje/openclaw/blob/main/docs/gateway/caddy-proxy.md) or [Tailscale Serve](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/examples/secure-tailscale-serve.json)) while preserving untrusted-proxy-header rejection and origin validation

Both paths share the same container hardening (`--read-only`, `--cap-drop ALL`, non-root, loopback-only port). The lite path is a quick start; the full path is for when you want maximum security or need reverse proxy support.

### Quick comparison

|                             | Lite (`bootstrap.sh`)         | Full (`setup.sh` + `run.sh`)                 |
| --------------------------- | ----------------------------- | -------------------------------------------- |
| **Setup time**              | 2–5 minutes                   | 10–20 minutes (builds from source)           |
| **Token delivery**          | Volume mount                  | Keychain bridge over localhost HTTP          |
| **Port binding**            | All interfaces (`0.0.0.0`)    | Loopback only (`127.0.0.1`)                  |
| **User in container**       | Default (image's `USER node`) | Explicit `--user 1000:1000`                  |
| **Resource limits**         | None                          | CPU 2 cores, memory 1 GB                     |
| **Reverse proxy support**   | Manual config needed          | Auto-detects Tailscale, syncs trustedProxies |
| **Requires repo clone**     | No (curl pipe)                | Yes                                          |
| **Requires `node` on host** | No                            | Yes                                          |

> **If you're only using this on your personal Mac on loopback**, the lite installer is fine. If you're exposing it through a reverse proxy, VPS, or Tailscale, use the full installer.

---

## What's hardened (audit summary)

Every feature listed below exists in the codebase. The "Status" column reflects whether it's active in the production gateway or requires explicit opt-in.

| Layer              | Protection                                                                         | Status                                                                      | Source                                                                                                                 |
| ------------------ | ---------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| Container          | Read-only root, `--cap-drop ALL`, `umask 0027`                                     | ✅ Always on (Dockerfile + both scripts)                                    | `Dockerfile.apple_arm64`, `scripts/apple-container/{bootstrap,run}.sh`                                                 |
| Container          | Non-root process (`USER node`)                                                     | ✅ Always on (Dockerfile)                                                   | `Dockerfile.apple_arm64`; `run.sh` adds explicit `--user 1000:1000`                                                    |
| Credential storage | AES-256-GCM + scrypt encryption at rest                                            | ⚙️ Opt-in — requires `OPENCLAW_PASSPHRASE` env var                          | `src/infra/sealed-json-file.ts`                                                                                        |
| Credential storage | HMAC-SHA256 config file integrity                                                  | ✅ Always on (when gateway token exists)                                    | `src/config/io.hmac-integrity.ts`                                                                                      |
| Auth               | Token/password/Tailscale auth, credential strength logging                         | ✅ Always on                                                                | `src/gateway/auth.ts`                                                                                                  |
| Startup checks     | TLS required, token ≥ 32, password ≥ 12, no-auth warns, bind-all warns             | ✅ Runs on every start (logs warnings)                                      | `packages/gateway-security-core/src/startup-security-checks.ts`                                                        |
| Pre-handshake      | verifyClient with rate limiting, header validation, origin, IP, subprotocol checks | ⚠️ Code exists but not wired into production gateway                        | `src/gateway/server/verify-client.ts`                                                                                  |
| WebSocket          | Preauth payload cap (64 KB), malformed frame counter (3 strikes)                   | ✅ Always on                                                                | `src/gateway/server/ws-connection/message-handler.ts`                                                                  |
| HTTP               | Per-IP request rate limit (120/60s), healthz short-circuit, auto-HSTS              | ✅ Always on                                                                | `src/gateway/server-http.ts`                                                                                           |
| Connection         | Per-IP rate (30/10s), per-device budget (8/identity)                               | ✅ Always on                                                                | `packages/gateway-security-core/src/connection-rate-limit.ts`, `src/gateway/server/authenticated-connection-budget.ts` |
| Exec approval      | Allowlist + deny-path (glob) + heredoc + inline-eval + suppression detection       | ✅ Always on                                                                | `packages/gateway-security-core/src/exec-deny-paths.ts`, `src/infra/exec-approvals.ts`                                 |
| Audit              | HMAC-signed auth + tool audit (per-entry, not chained)                             | ⚙️ Opt-in — `OPENCLAW_AUTH_AUDIT=1` or `gateway.security.toolAudit.enabled` | `packages/gateway-security-core/src/{auth-audit-log,tool-audit}.ts`                                                    |
| Outbound           | Regex-based secret stripping (API keys, tokens, private keys)                      | ⚠️ Module exists, not wired into delivery pipeline                          | `src/security/outbound-redact.ts`, `src/infra/outbound/redaction.ts`                                                   |
| Origin             | Wildcard `*` rejected, signed origin tokens, browser Origin matching               | ✅ Always on                                                                | `src/gateway/origin-check.ts`                                                                                          |
| Forwarded headers  | Sensitive-header validation, cross-header consistency, proxy trust                 | ✅ Always on                                                                | `src/gateway/forwarded-headers.ts`, `src/gateway/net.ts`                                                               |
| Per-message auth   | Capability checks for `secrets.*` / `config.set_protected` / `node.*`              | ⚙️ Opt-in — `gateway.security.messageAuth.enabled`                          | `packages/gateway-security-core/src/message-auth.ts`                                                                   |

> **Three items need attention before this hardening is production-complete:**
>
> 1. **Pre-handshake verifyClient** — the 7-stage pipeline exists in `verify-client.ts` but `server.impl.ts` never passes `verifyClient` to the runtime state. Wiring it in requires passing the factory through `createGatewayRuntimeState({ verifyClient: ... })`.
> 2. **Outbound redaction** — the redactor module is complete but `createOutboundDeliveryPayloadRedactor` has zero callers in the live delivery path. It needs to be wired into the WebSocket response and channel send pipelines.
> 3. **Startup security checks** — the checks run and log warnings, but `assertStartupSecurityFindingsAllowed` (which throws and blocks startup on critical findings) is not called from `server.impl.ts`. The gateway will start even with critical findings like missing TLS on a network-exposed bind.

For a deep dive on the threat model, attacker surface, and proof-of-concept exploits this hardening closes, see:

- [Fork Security Overview](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/FORK_SECURITY.md)
- [Fork Hardening Deep-Dive](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/fork-hardening-deep-dive.md)
- [Property-Based Evidence](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/PROPERTY-EVIDENCE.md)
- [CWE-290 TUI Client Spoofing Advisory](https://github.com/markfietje/openclaw/blob/main/docs/security/ADVISORY-CWE-290-TUI-CLIENT-SPOOFING.md)

---

## What is OpenClaw?

[OpenClaw](https://github.com/openclaw/openclaw) is an open-source AI gateway. It connects AI models (OpenAI, Anthropic, Google) to your messaging apps (Telegram, Discord, WhatsApp). You run it on your own Mac — no cloud, no third-party servers, your API keys stay local.

## Disclaimer

This is **not** the official OpenClaw project. The container image and hardening are my own build — the official OpenClaw repository does not ship a dedicated Apple Silicon Apple Container image. Use at your own risk, no warranties included.

If you'd like to see this upstreamed or want to chat about it, find me at [linkedin.com/in/markfietje](https://linkedin.com/in/markfietje).

## Full documentation

→ [Apple Container guide](https://github.com/markfietje/openclaw/blob/main/docs/install/apple-container.md)
→ [OpenClaw docs](https://docs.openclaw.ai)
