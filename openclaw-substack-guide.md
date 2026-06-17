# Run Your Own AI Assistant on macOS Apple Container, One Terminal Command

**No Docker. No cloud. Your API keys stay on your Mac.**

## Prerequisites

- **Apple Silicon Mac (M1/M2/M3/M4)** — Apple Container only supports ARM. Check: `sysctl -n hw.optional.arm64` → prints `1`.
- **macOS 26 Tahoe** — Apple Container requires it. Check: Apple menu → About This Mac.
- **Apple Container CLI** — the runtime for sandboxed Linux containers. Check: `container --version` (if not found, see below).
- **~2 GB free disk** — image (~500 MB download, ~1.2 GB uncompressed) + volumes + state. Check: Finder → Storage.
- **Internet connection** — for the image pull and the AI provider API.
- **Node.js (optional)** — only needed for `npx openclaw tui` on the host; not needed if you use the container-based TUI instead. Check: `node --version`.

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
curl -fsSL https://markfietje.github.io/openclaw/install | bash
```

Prefer the auditable raw script (no short-URL wrapper)? Same thing:

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

> **What you get:** a hardened, read-only, sandboxed gateway running in one command. Its config lives **inside the container** (on a persisted volume), so you add providers and channels with an in-container command — step 2 below. Your host `~/.openclaw/` is not shared with the container, and it doesn't need to be.

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

The gateway's config lives **inside the container**, on a persisted volume mounted at `/home/node/.openclaw`. You configure it by running the onboarding wizard _inside_ the container — it writes straight to that volume, and the config survives restarts and upgrades.

```bash
container exec -it openclaw openclaw onboard --mode local
```

The wizard walks you through: pick one provider (OpenAI, Anthropic, or Google), paste your API key, and optionally add messaging channels. `--mode local` sets `gateway.mode=local`, which is what lets the gateway start cleanly.

Then restart so the new config loads:

```bash
~/.openclaw/bin/openclaw-container.sh stop && ~/.openclaw/bin/openclaw-container.sh run
```

> **Why inside the container?** The container runs a **read-only** root filesystem, so config can't live just anywhere. It lives on the `openclaw-state` volume, which is mounted at the gateway's config path and stays writable even though the root is read-only. Editing your host `~/.openclaw/openclaw.json` has no effect on the container — and it doesn't need to, because `onboard` runs inside.
>
> To edit config directly instead of the wizard: `container exec -it openclaw nano /home/node/.openclaw/openclaw.json`, then restart.

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

Run the same in-container onboarding wizard again — it walks you through adding channels so you can reach your AI from your phone:

```bash
container exec -it openclaw openclaw onboard --mode local
~/.openclaw/bin/openclaw-container.sh stop && ~/.openclaw/bin/openclaw-container.sh run
```

Or edit the in-container config directly and add credentials under `channels`, then restart:

```bash
container exec -it openclaw nano /home/node/.openclaw/openclaw.json
```

See the [OpenClaw docs](https://docs.openclaw.ai) for provider-specific setup guides. Once configured, your AI is reachable from your phone, desktop, or browser — anywhere you use those apps.

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

- **"Apple Silicon (M1/M2/M3/M4) is required"** — you're on an Intel Mac. Apple Container doesn't support Intel; you need an M-series Mac.
- **"Apple Container is not installed"** — the `container` CLI wasn't found. Download from [github.com/apple/container/releases](https://github.com/apple/container/releases), install the `.pkg`, and **restart Terminal**.
- **"Apple Container runtime did not start in time"** — the background service didn't launch. Run `container system start` manually; if that fails, try `sudo container system start` (needs your admin password).
- **Keychain dialog: you clicked "Deny"** — the token wasn't stored. Re-run the install command and click **Allow** or **Always Allow** this time.
- **Image pull hangs or fails** — network or GitHub Container Registry issue. Check your connection and retry. Behind a corporate proxy, the `ghcr.io` domain must be reachable.
- **"Container 'openclaw' already exists"** — you ran install twice. Run `~/.openclaw/bin/openclaw-container.sh uninstall` first, then install again (or just use `upgrade`).

### Runtime problems

- **Gateway won't start** — config error or port conflict. Run the `logs` command. Common cause: invalid JSON in the in-container config. Validate it with `container exec openclaw cat /home/node/.openclaw/openclaw.json | python3 -m json.tool`.
- **"AI doesn't respond"** — no provider configured. Run `container exec -it openclaw openclaw onboard --mode local`, then restart the gateway.
- **"Connection refused" in the TUI** — the gateway isn't running. Run `oc-run` first, wait for the ✓, then `oc`.
- **Nothing works after a reboot** — the gateway doesn't auto-start. Run `oc-run` again.
- **Keychain prompts every time** — you clicked "Allow" instead of "Always Allow". Next time click **Always Allow**; or open Keychain Access → find "ai.openclaw.apple-container.gateway-token" → double-click → Access Control → add `/usr/bin/security`.
- **`npx` not found** — Node.js isn't installed on your Mac. Either install it ([nodejs.org](https://nodejs.org) or `brew install node`), or use the container-based TUI: `container exec openclaw openclaw tui --url ws://127.0.0.1:18789 --token-file /home/node/.openclaw/bridge-token`.
- **Port 18789 already in use** — another process is on that port. Set `OPENCLAW_HOST_PORT=18790` before running, or stop the other process.

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

- **Uncompressed image** — ~1.2 GB (27 OCI layers, `node:24-bookworm-slim` base + OpenClaw).
- **Compressed download** — ~400–500 MB (estimated from the typical OCI compression ratio).
- **App breakdown** — `dist/` 149 MB · `node_modules/` 485 MB · `extensions/` 27 MB · `docs/` 17 MB.
- **Idle RSS** — ~330 MB (gateway process, 11 threads, includes V8 heap + buffers).
- **Init RSS** — ~13 MB (`.cz-init` signal handler, PID 1).
- **Memory cap** — 1 GB (`--memory 1073741824`).
- **CPU cap** — 2 cores (`--cpus 2`).
- **Base image** — `node:24-bookworm-slim`, pinned by SHA256 digest (not a floating tag).
- **Node.js** — v24.14.1.
- **Exposed port** — `127.0.0.1:18789` (loopback only — verified from `container inspect`).
- **JS runtime** — Node.js 24 (default) or Bun (opt-in via `--runtime bun`).
- **Process user** — `node` uid=1000 gid=1000 — never root (verified with `id` inside the container).
- **Filesystem** — read-only root (`readOnly: true`) + tmpfs for `/tmp`, `/home/node/.cache`, and `/app/node_modules/.cache`.
- **File permissions** — app files `root:root 0644/0755` · state dir `node:node 0750` · credentials `node:node 0700`.
- **Entrypoint** — `container-entrypoint` → `umask 0027` → `exec "$@"`.
- **Network** — isolated network `openclaw-net`, MTU 1280, no IPv4 gateway exposure to the host.

### How to verify these yourself

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

The codebase implements a 6-step pre-handshake security gate (`verify-client.ts`) that accepts or rejects WebSocket connections **before any payload is parsed** — before the HTTP 101 upgrade completes. The steps (in check order):

1. **Connection limits** — reject when the max-connection cap is reached, or when an IP exceeds the per-IP connection rate limit (30 per 10s). Loopback is exempt.
2. **Strict header validation** — required WebSocket upgrade headers must be present and well-formed; duplicate or chained sensitive headers (`Host`, `Origin`, `X-Forwarded-*`) are rejected.
3. **Untrusted proxy header rejection** — `X-Forwarded-*` headers from non-trusted IPs are rejected (HTTP 403). Only explicitly trusted proxies may set forwarding headers.
4. **Origin validation** — browser clients must present a matching `Origin` against an explicit allowlist. Wildcard `*` is **rejected** — there is no way to allow all origins.
5. **IP allowlist / blocklist** — CIDR-aware (supports `192.168.1.0/24`, `fd00::/48`, etc.). Blocklist takes precedence over allowlist; default-deny on unknown ranges if an allowlist is configured.
6. **Subprotocol enforcement** — clients must advertise the `openclaw-gateway-v1` WebSocket subprotocol or the upgrade is rejected.

> **Wiring:** this pipeline **is live in the production gateway.** `server-runtime-state.ts` builds the verifyClient via `createRuntimeVerifyClient(...)` (default; tests can inject an override) and passes it as `verifyUpgradeRequest`; `server-http.ts` runs it on every WebSocket upgrade via `runGatewayUpgradePreflight(...)` and rejects the upgrade (writes a failure response, logs `ip_blocked`, destroys the socket) when a step fails — all before the handshake completes.
>
> Defense in depth: origin validation and forwarded-header checks are **also** enforced post-handshake in `message-handler.ts` (via `origin-check.ts`'s `checkBrowserOrigin` and the `hasForwardedRequestHeaders` / `isTrustedProxyAddress` helpers), so a missed pre-handshake signal still gets caught.

After the handshake:

- **Per-device connection budget** — one authenticated device identity can't open unlimited WebSockets. Default cap is 8 concurrent connections per device.
- **Token + password + Tailscale auth** — every connection is authenticated via token, password, or Tailscale header verification.

### Rate limiting

Three independent rate limiters, all sliding-window and loopback-exempt:

- **Connection rate** — 30 connections / 10s per IP. Prevents connection floods.
- **HTTP request rate** — 120 requests / 60s per IP. Prevents HTTP-level abuse.
- **Malformed frame guard** — 3 invalid JSON frames → close with `1008`. Prevents slow-loris via garbage frames.

WebSocket preauth payloads are size-limited (default 64 KB). Oversize frames are rejected with close code `1009`.

### Per-message auth (opt-in, ships enabled-ready)

Even after a successful WebSocket handshake, sensitive operations are gated by capabilities — not just the initial auth:

- **`secrets.resolve` / `secrets.reload`** — requires `secrets:read` or `secrets:manage` capability. Even an authenticated `operator.admin` can't read stored API keys without the explicit capability.
- **`config.set_protected`** — requires `admin:config` capability. Prevents auth config changes from any client that happens to be authenticated.
- **Node-role gating** — methods like `node.event` and `node.invoke.result` require `role === "node"`. An operator client cannot invoke node methods.

Enable with `gateway.security.messageAuth.enabled: true` in your config. It ships off by default for compatibility; turn it on with `container exec -it openclaw nano /home/node/.openclaw/openclaw.json`, then restart.

### Startup security checks

On every gateway start, a battery of checks runs against the resolved bind address + auth mode:

- **TLS required when network-exposed** — logs a critical warning if bound to a non-loopback address without TLS or a trusted upstream proxy.
- **Token length** — logs a critical warning for network-exposed starts with a token shorter than 32 characters.
- **Password strength** — logs a critical warning for network-exposed starts with a password shorter than 12 characters (startup gate), with additional warnings at 15 characters and for digit-only / single-case passwords.
- **Auth disabled warning** — logs a critical warning for network-exposed starts with `auth.mode === "none"` unless `OPENCLAW_DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE=1` is set.
- **Bind-all warning** — warns when bound to `0.0.0.0` / `::` (you almost always want loopback).

All findings are logged on every startup, and `server.impl.ts` then calls `assertStartupSecurityFindingsAllowed(findings, process.env)` — so **critical findings now block startup** (throw) unless explicitly allowed via env. The checks are fail-closed on critical severity, not just operational warnings.

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

### Outbound redaction

A regex-based redaction module (`outbound-redact.ts`) strips secrets from AI responses before they reach channels (TUI, Telegram, Discord, WhatsApp). It's wired into the chat delivery path via `server-chat.ts` (`createOutboundDeliveryPayloadRedactor`), which runs every outbound chat payload through it before broadcast. It covers:

- **Specific patterns** (applied first): OpenAI keys (`sk-...`), Anthropic keys (`sk-ant-...`), Google keys (`AIza...`), Stripe keys (`sk_live_...`), GitHub PATs (`ghp_`, `gho_`, `ghs_`), Slack tokens (`xox[bpras]-...`), private key blocks (`-----BEGIN ... PRIVATE KEY-----`)
- **Generic patterns** (applied last): `api_key=`, `token=`, `password=` with 8+ character values
- **Dynamic secrets**: runtime-known values (gateway token, config passwords) are added to the redaction set automatically

The module defaults to enabled (`gateway.security.enableOutboundRedaction !== false`) and uses a multi-pass sentinel approach to prevent partial-match bypass. It runs on every chat payload in the live delivery path — see the [audit summary](#what-is-hardened-audit-summary).

---

## Don't want a container? (npm / pnpm)

Two distinct things to keep straight, because the npm package is **not** this fork:

### Upstream OpenClaw (official, no hardening)

The `openclaw` package on npm is the official upstream project (`github.com/openclaw/openclaw`). It is **not** this fork — none of the container hardening or Keychain token work is in it. If you just want OpenClaw running on your host with zero ceremony and you trust your own machine, this is the fastest path:

```bash
# Requires Node.js 22.19 or newer. Pick one:
npm install -g openclaw        # npm  → upstream openclaw
pnpm add -g openclaw           # pnpm → upstream openclaw
# or run once with no install:
npx openclaw chat
```

```bash
openclaw onboard          # add a provider + messaging channels
openclaw gateway          # start the gateway (foreground)
openclaw chat             # chat from another window
```

**Upgrade:**

```bash
npm update -g openclaw     # npm
pnpm update -g openclaw    # pnpm
```

The tradeoff: it runs as **your user** with full filesystem and network access — no sandbox, no read-only root, no dropped capabilities, no Keychain token. That hardening is exactly what this fork adds.

### This fork from source (hardened code, no container)

This fork is **not published to npm**. To run its code on your host without the Apple Container, build it from source (needs Node 22.19+ and pnpm):

```bash
git clone https://github.com/markfietje/openclaw && cd openclaw
corepack enable                       # enables the pinned pnpm
pnpm install
pnpm build
pnpm openclaw onboard                 # add a provider + channels
pnpm openclaw gateway                 # start the gateway
pnpm openclaw chat                    # chat from another window
```

**Upgrade:**

```bash
git pull
pnpm install
pnpm build
```

> You get the fork's code, but **without** the OS-level isolation. The read-only root, dropped caps, loopback-only bind, resource caps, and off-disk Keychain token only exist in the container image. Running from source on the host is a middle ground: hardened gateway logic, ordinary process privileges.

---

## Build the image from source (optional)

The one-liner pulls a **prebuilt** image from GitHub Container Registry. If you'd rather build the image yourself — to audit the build, pin a custom version, or run behind a reverse proxy — the repo ships `scripts/apple-container/setup.sh` + `run.sh`, which:

- **Build the image locally** from source (10–20 minutes, you verify everything)
- **Deliver the token over a localhost Keychain bridge** — a tiny HTTP server on the host reads the token from macOS Keychain and serves it to the container via bearer-authenticated HTTP, so the token never sits on disk inside the container
- **Support running behind a reverse proxy** ([Caddy](https://github.com/markfietje/openclaw/blob/main/docs/gateway/caddy-proxy.md) or [Tailscale Serve](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/examples/secure-tailscale-serve.json)) while preserving untrusted-proxy-header rejection and origin validation

```bash
git clone https://github.com/markfietje/openclaw && cd openclaw
scripts/apple-container/setup.sh    # build the image + write config
scripts/apple-container/run.sh      # start (seeds host config + Keychain bridge)
```

With the build-from-source path, config edits work differently: `run.sh` copies your **host** `~/.openclaw/openclaw.json` into the container's state volume on each start, so you edit the host file and re-run. Both paths share the same container hardening (`--read-only`, `--cap-drop ALL`, non-root, loopback-only port, 2 CPU / 1 GB caps).

### Quick comparison

- **Image** — one-liner pulls a prebuilt image from GHCR; build-from-source compiles it locally (10–20 min).
- **Setup time** — ~2–5 minutes (one-liner) vs 10–20 minutes (build-from-source).
- **Token delivery** — one-liner stages it in a token volume (on disk); build-from-source uses the Keychain bridge over localhost HTTP.
- **Config editing** — one-liner: `container exec … onboard` (writes to an in-container volume); build-from-source: edit host `~/.openclaw/openclaw.json` and re-run.
- **Requires repo clone** — no (one-liner) vs yes (build-from-source).
- **Requires `node` on host** — no (one-liner) vs yes (build-from-source).
- **Reverse proxy support** — manual (one-liner) vs auto-detects Tailscale and syncs `trustedProxies` (build-from-source).

> **Which one?** Use the **one-liner** for a personal Mac on loopback — it's the path this post is about. Use **build-from-source** if you want to verify the image, need an off-disk token, or are exposing the gateway through a reverse proxy, VPS, or Tailscale.

---

## What's hardened (audit summary)

Every feature below exists in the codebase. The status reflects whether it's active in the production gateway or requires explicit opt-in.

**Container**

- ✅ **Read-only root, `--cap-drop ALL`, `umask 0027`** — always on (Dockerfile + both scripts). Source: `Dockerfile.apple_arm64`, `scripts/apple-container/{bootstrap,run}.sh`.
- ✅ **Non-root process (`USER node`)** — always on (Dockerfile); `run.sh` also passes explicit `--user 1000:1000`.

**Credential storage**

- ⚙️ **AES-256-GCM + scrypt encryption at rest** — opt-in, requires the `OPENCLAW_PASSPHRASE` env var. Source: `src/infra/sealed-json-file.ts`.
- ✅ **HMAC-SHA256 config file integrity** — always on when a gateway token exists. Source: `src/config/io.hmac-integrity.ts`.

**Auth**

- ✅ **Token / password / Tailscale auth, plus credential-strength logging** — always on. Source: `src/gateway/auth.ts`.

**Startup checks**

- ✅ **TLS required, token ≥ 32, password ≥ 12, no-auth warns, bind-all warns** — runs on every start, logs all findings, and **blocks startup on critical findings** via `assertStartupSecurityFindingsAllowed`. Source: `packages/gateway-security-core/src/startup-security-checks.ts` (called from `src/gateway/server.impl.ts`).

**Pre-handshake**

- ✅ **verifyClient pipeline: connection limits, strict header validation, untrusted-proxy rejection, origin, IP allow/block, subprotocol** — always on, runs on every upgrade before the HTTP 101. Sources: `src/gateway/server/verify-client.ts`, wired via `src/gateway/server-runtime-state.ts` (`createRuntimeVerifyClient`) → `src/gateway/server-http.ts` (`runGatewayUpgradePreflight`).

**WebSocket**

- ✅ **Preauth payload cap (64 KB) + malformed-frame counter (3 strikes)** — always on. Source: `src/gateway/server/ws-connection/message-handler.ts`.

**HTTP**

- ✅ **Per-IP request rate limit (120/60s), healthz short-circuit, auto-HSTS** — always on. Source: `src/gateway/server-http.ts`.

**Connection**

- ✅ **Per-IP rate (30/10s) + per-device budget (8/identity)** — always on. Source: `packages/gateway-security-core/src/connection-rate-limit.ts`, `src/gateway/server/authenticated-connection-budget.ts`.

**Exec approval**

- ✅ **Allowlist + deny-path (glob) + heredoc + inline-eval + suppression detection** — always on. Source: `packages/gateway-security-core/src/exec-deny-paths.ts`, `src/infra/exec-approvals.ts`.

**Audit**

- ⚙️ **HMAC-signed auth + tool audit (per-entry, not chained)** — opt-in via `OPENCLAW_AUTH_AUDIT=1` or `gateway.security.toolAudit.enabled`. Source: `packages/gateway-security-core/src/{auth-audit-log,tool-audit}.ts`.

**Outbound**

- ✅ **Regex-based secret stripping (API keys, tokens, private keys)** — enabled by default, wired into the chat delivery path. Sources: `src/security/outbound-redact.ts`, `src/infra/outbound/redaction.ts`, called from `src/gateway/server-chat.ts` (`createOutboundDeliveryPayloadRedactor`).

**Origin**

- ✅ **Wildcard `*` rejected, signed origin tokens, browser Origin matching** — always on. Source: `src/gateway/origin-check.ts`.

**Forwarded headers**

- ✅ **Sensitive-header validation, cross-header consistency, proxy trust** — always on. Source: `src/gateway/forwarded-headers.ts`, `src/gateway/net.ts`.

**Per-message auth**

- ⚙️ **Capability checks for `secrets.*` / `config.set_protected` / `node.*`** — opt-in via `gateway.security.messageAuth.enabled`. Source: `src/gateway/message-auth.ts`.

> **Earlier drafts of this post listed three hardening items as "not yet wired" (pre-handshake verifyClient, outbound redaction, and startup security gating). All three are now live:** verifyClient runs on every upgrade via `server-runtime-state.ts` → `server-http.ts`; outbound redaction runs on every chat payload via `server-chat.ts`; and `server.impl.ts` calls `assertStartupSecurityFindingsAllowed(...)` so critical startup findings (e.g. missing TLS on a network-exposed bind) now block startup unless explicitly allowed via env.

For a deep dive on the threat model, attacker surface, and proof-of-concept exploits this hardening closes, see:

- [Fork Security Overview](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/FORK_SECURITY.md)
- [Fork Hardening Deep-Dive](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/fork-hardening-deep-dive.md)
- [Property-Based Evidence](https://github.com/markfietje/openclaw/blob/main/docs/gateway/security/PROPERTY-EVIDENCE.md)
- [CWE-290 TUI Client Spoofing Advisory](https://github.com/markfietje/openclaw/blob/main/docs/security/ADVISORY-CWE-290-TUI-CLIENT-SPOOFING.md)

---

## What is OpenClaw?

[OpenClaw](https://github.com/openclaw/openclaw) is an open-source AI gateway. It connects AI models (OpenAI, Anthropic, Google) to your messaging apps (Telegram, Discord, WhatsApp). You run it on your own Mac — no cloud, no third-party servers, your API keys stay local.

## How this build differs from upstream `openclaw/openclaw`

Upstream OpenClaw is the CLI/gateway you get from `npm install -g openclaw`. It does **not** ship an Apple Container image or these defaults. This fork adds the packaging and hardening layer:

- **Isolation** — upstream runs as your user with full host access; this build runs in a sandboxed Linux container, read-only root, `--cap-drop ALL`, non-root (`1000:1000`).
- **Network** — upstream binds however you configure it; this build is loopback-only (`127.0.0.1:18789`) by default.
- **Gateway token** — upstream stores it in config/env on disk; this build generates it, stores it in the **macOS Keychain**, and stages it in a container volume (the build-from-source path keeps it off disk via a localhost Keychain bridge).
- **Resource limits** — upstream has none; this build caps CPU at 2 cores and memory at 1 GB.
- **Image base** — n/a upstream; this build uses `node:24-bookworm-slim`, pinned by **SHA256 digest** (not a floating tag).
- **Install** — upstream is `npm install -g openclaw` + manual gateway setup; this build is one curl pipe with auto preflight, token, volumes, and container create.
- **Config integrity** — upstream is standard; this build adds HMAC-SHA256 config verification and optional AES-256-GCM secrets at rest (`OPENCLAW_PASSPHRASE`).
- **Hardening defaults** — upstream makes you opt in; this build turns on `--read-only`, dropped caps, `umask 0027`, and an init process by default.

Same OpenClaw inside; the value is the **hardened, zero-Docker, Keychain-backed packaging** for a personal Mac.

## Disclaimer

This is **not** the official OpenClaw project. The container image and hardening are my own build — the official OpenClaw repository does not ship a dedicated Apple Silicon Apple Container image. Use at your own risk, no warranties included.

If you'd like to see this upstreamed or want to chat about it, find me at [linkedin.com/in/markfietje](https://linkedin.com/in/markfietje).

## Full documentation

→ [Apple Container guide](https://github.com/markfietje/openclaw/blob/main/docs/install/apple-container.md)
→ [OpenClaw docs](https://docs.openclaw.ai)
