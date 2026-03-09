---
summary: "OpenClaw Gateway in Apple Container on macOS with persistent state and hardened security"
read_when:
  - Running OpenClaw in Apple's container CLI on macOS
title: "Apple Container"
---

# Apple Container

OpenClaw can run inside Apple's [container](https://github.com/apple/container) CLI on macOS 26+.

## Quick start (recommended - secure + persistent)

The base image doesn't include required packages for Tailscale or SSH. Build a custom image:

```bash
# Create persistent storage directories
mkdir -p ~/.openclaw-container ~/.openclaw-tailscale-state

# Build custom image (includes Tailscale + hardened SSH)
cd /Users/mark/Sites/openclaw-build
container build -t openclaw-container:latest -f Dockerfile.openclaw-container .

# Run container with persistent storage
container run -d --name openclaw \
  -v ~/.openclaw-container:/home/node/.openclaw \
  -v ~/.openclaw-tailscale-state:/var/lib/tailscale \
  -e GATEWAY_BIND=loopback \
  -m 4G \
  --network default \
  openclaw-container:latest
```

## Key differences from Docker

Apple Container's `--network host` works differently from Docker:

- **Docker**: `--network host` shares the host's network namespace, so `127.0.0.1` inside the container = host's loopback
- **Apple Container**: `--network host` routes through the host but maintains separate network namespaces. The container's `127.0.0.1` is **not** the Mac's loopback

This means binding to `127.0.0.1` inside the container will NOT be accessible from the Mac at `127.0.0.1:18789`.

## Accessing the Gateway

### Option A: Tailscale Serve (recommended)

The custom image includes Tailscale pre-installed. After first start:

```bash
# Authenticate Tailscale (one-time)
container exec openclaw tailscale up --auth-key=<your-key>

# Serve to localhost (secure, loopback only)
container exec openclaw tailscale serve --bg --https 8443 localhost:18789
```

Then access from your Mac:

- Control UI: `https://openclaw.tail13961f.ts.net:8443/`

### Option B: SSH access (key-only, maximum security)

The custom image includes hardened SSH with maximum security:

```bash
# SSH from Mac (key-only, no password)
ssh openclaw
```

## Security features

The custom image includes maximum SSH hardening:

✓ **Root login disabled** - No SSH as root
✓ **Password auth disabled** - Key-only authentication required
✓ **Strongest ciphers** - Ed25519, ChaCha20-Poly1305, AES-256-GCM
✓ **KEX hardening** - Curve25519, DH groups with SHA-512
✓ **User restriction** - Only 'node' user can SSH
✓ **No port forwarding** - Prevents tunneling attacks
✓ **X11 forwarding disabled** - Prevents X11 attacks
✓ **Client keepalive** - Detects zombie sessions
✓ **Max auth attempts** - Only 3 tries before lockout
✓ **Strict directory permissions** - Enforces .ssh security

## Persistent storage

The following volumes are persisted:

| Volume                        | Container path         | Purpose                        |
| ----------------------------- | ---------------------- | ------------------------------ |
| `~/.openclaw-container`       | `/home/node/.openclaw` | OpenClaw config, SSH keys      |
| `~/.openclaw-tailscale-state` | `/var/lib/tailscale`   | Tailscale authentication state |

All data survives container restarts. SSH keys are automatically backed up to `~/.openclaw-container/.ssh`.

## Health check

```bash
# Check gateway is running
container exec openclaw curl -s http://127.0.0.1:18789/healthz

# Check Tailscale status
container exec openclaw tailscale status
```

## Troubleshooting

### Can't reach 127.0.0.1:18789 from Mac

This is expected. Apple Container isolates loopback. Use:

- Tailscale Serve: `https://openclaw.tail13961f.ts.net:8443/`
- SSH: `ssh openclaw`

### Tailscale not working

Make sure you've authenticated with your auth key:

```bash
container exec openclaw tailscale up --auth-key=<your-key>
```

### Container IP changes

The container's local IP may change on restart. Always check `container list` for the current IP if using direct IP access.

### Need to rebuild the image

After changing `Dockerfile.openclaw-container`:

```bash
cd /Users/mark/Sites/openclaw-build
container build -t openclaw-container:latest -f Dockerfile.openclaw-container .

container delete openclaw --force
container run -d --name openclaw \
  -v ~/.openclaw-container:/home/node/.openclaw \
  -v ~/.openclaw-tailscale-state:/var/lib/tailscale \
  -e GATEWAY_BIND=loopback \
  -m 4G \
  --network default \
  openclaw-container:latest
```
