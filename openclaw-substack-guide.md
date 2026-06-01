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
| **Idle memory**  | ~80–120 MB RSS (Node.js 24, heap capped at 256 MB)                           |
| **Under load**   | ~200–300 MB RSS (streaming, tool calls, multiple agents)                     |
| **Base image**   | `node:24-bookworm-slim`                                                      |
| **Exposed port** | 18789 (localhost only)                                                       |

### Security

The container is hardened by default — these aren't optional toggles, they're always on:

- **Read-only filesystem** — nothing can modify the container image at runtime
- **All Linux capabilities dropped** (`--cap-drop ALL`) — zero kernel capabilities
- **Non-root process** — runs as `node` user, never root
- **Strict file permissions** — `umask 0027`, credentials directory `0700`
- **Gateway token in macOS Keychain** — not stored on disk, resolved at runtime via a localhost bridge
- **Outbound redaction** — API keys, tokens, private keys, and passwords are stripped from AI responses before they reach you
- **Exec filesystem policy** — sandbox-aware tool access control prevents agents from reading `.env`, SSH keys, or credential files
- **Encrypted credential storage** — AES-256-GCM for API keys and channel tokens at rest
- **Auth audit logging** — HMAC-authenticated, tamper-evident audit trail
- **Connection rate limiting** — 30 connections per 10 seconds per IP
- **IP allowlist/blocklist** — CIDR-aware access control

## What is OpenClaw?

[OpenClaw](https://github.com/markfietje/openclaw) is an open-source AI gateway. It connects AI models (OpenAI, Anthropic, Google) to your messaging apps (Telegram, Discord, WhatsApp). You run it on your own Mac — no cloud, no third-party servers, your API keys stay local.

## Disclaimer

This is **not** the official OpenClaw project. The container image and hardening are my own build — the official OpenClaw repository does not ship a dedicated Apple Silicon Apple Container image. Use at your own risk, no warranties included.

If you'd like to see this upstreamed or want to chat about it, find me at [linkedin.com/in/markfietje](https://linkedin.com/in/markfietje).

## Full documentation

→ [Apple Container guide](https://github.com/markfietje/openclaw/blob/main/docs/install/apple-container.md)
