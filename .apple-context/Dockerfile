FROM node:24-bookworm-slim AS build
WORKDIR /app

# Enable Corepack
RUN corepack enable

# Copy package files first for better caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./

# Pre-install pnpm via npm to avoid Corepack network issues during build
RUN npm install -g pnpm@10.23.0 --registry=https://registry.npmjs.org || \
    (echo "npm install failed, trying Corepack..." && \
     corepack prepare "$(node -p "require('./package.json').packageManager")" --activate)

# Copy configuration files
COPY tsconfig.json tsconfig.plugin-sdk.dts.json ./

# Copy UI package.json separately for better layer caching
COPY ui/package.json ./ui/package.json

# Copy patches and scripts
COPY patches ./patches
COPY scripts ./scripts

# Install dependencies (optimized for ARM64 with memory limits)
RUN NODE_OPTIONS=--max-old-space-size=2048 pnpm install --frozen-lockfile

# Copy all source code
COPY src ./src
COPY ui ./ui
COPY extensions ./extensions
COPY skills ./skills
COPY apps ./apps
COPY docs ./docs
COPY openclaw.mjs .

# Build A2UI bundle (non-fatal if it fails)
RUN pnpm canvas:a2ui:bundle || \
    (mkdir -p src/canvas-host/a2ui && \
     echo "/* A2UI stub */" > src/canvas-host/a2ui/a2ui.bundle.js && \
     echo "stub" > src/canvas-host/a2ui/.bundle.hash)

# Build OpenClaw (with increased memory limit)
RUN NODE_OPTIONS=--max-old-space-size=3072 pnpm build

# Build UI (force pnpm usage, set memory limit)
ENV OPENCLAW_PREFER_PNPM=1
RUN NODE_OPTIONS=--max-old-space-size=2048 pnpm ui:build

FROM node:24-bookworm-slim AS runtime
WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        procps hostname curl git openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

# Copy built artifacts from build stage
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/package.json .
COPY --from=build --chown=node:node /app/openclaw.mjs .
COPY --from=build --chown=node:node /app/extensions ./extensions
COPY --from=build --chown=node:node /app/skills ./skills
COPY --from=build --chown=node:node /app/docs ./docs

# Set up Corepack for pnpm availability
RUN corepack enable && \
    corepack prepare "$(node -p "require('./package.json').packageManager")" --activate

# Create symlink and set permissions
RUN ln -sf /app/openclaw.mjs /usr/local/bin/openclaw && \
    chmod 755 /app/openclaw.mjs

# Set proper permissions for extensions/skills
RUN for dir in /app/extensions /app/skills; do \
      if [ -d "$dir" ]; then \
        find "$dir" -type d -exec chmod 755 {} +; \
        find "$dir" -type f -exec chmod 644 {} +; \
      fi; \
    done

# Add OCI metadata labels
LABEL org.opencontainers.image.source=https://github.com/openclaw/openclaw \
      org.opencontainers.image.url=https://openclaw.ai \
      org.opencontainers.image.documentation=https://docs.openclaw.ai/install/docker \
      org.opencontainers.image.licenses=MIT \
      org.opencontainers.image.title=OpenClaw \
      org.opencontainers.image.description="OpenClaw gateway and CLI runtime container image (Apple Container optimized, Node 24 ARM64)" \
      org.opencontainers.image.version=2026.3.9 \
      org.opencontainers.image.base.name=docker.io/library/node:24-bookworm-slim

ENV NODE_ENV=production
USER node

EXPOSE 18789

HEALTHCHECK --interval=3m --timeout=10s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:18789/healthz').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "openclaw.mjs", "gateway", "--allow-unconfigured"]
