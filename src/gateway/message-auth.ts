import {
  ADMIN_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  APPROVALS_SCOPE,
  PAIRING_SCOPE,
} from "./method-scopes.js";

// ---------------------------------------------------------------------------
// Operator scope → capability translation
// macOS app sends operator.* scopes; translate them into capability strings.
// operator.admin does NOT grant secrets:* or admin:config — those require
// explicit opt-in via direct capability scopes.
// ---------------------------------------------------------------------------

const OPERATOR_SCOPE_CAPABILITIES: Record<string, readonly string[]> = {
  [ADMIN_SCOPE]: ["admin:read", "admin:write"],
  [READ_SCOPE]: ["admin:read"],
  [WRITE_SCOPE]: ["admin:read", "admin:write"], // write implies read
  [APPROVALS_SCOPE]: ["admin:write"],
  [PAIRING_SCOPE]: ["admin:write"],
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

// ---------------------------------------------------------------------------
// Method → capability mapping (built from real gateway method names)
// ---------------------------------------------------------------------------

const METHODS_BY_CAPABILITY: Record<string, readonly string[]> = {
  "admin:read": [
    // READ_SCOPE
    "health",
    "doctor.memory.status",
    "logs.tail",
    "channels.status",
    "status",
    "usage.status",
    "usage.cost",
    "tts.status",
    "tts.providers",
    "models.list",
    "tools.catalog",
    "agents.list",
    "agent.identity.get",
    "skills.status",
    "voicewake.get",
    "sessions.list",
    "sessions.get",
    "sessions.preview",
    "sessions.resolve",
    "sessions.subscribe",
    "sessions.unsubscribe",
    "sessions.messages.subscribe",
    "sessions.messages.unsubscribe",
    "sessions.usage",
    "sessions.usage.timeseries",
    "sessions.usage.logs",
    "cron.list",
    "cron.status",
    "cron.runs",
    "gateway.identity.get",
    "system-presence",
    "last-heartbeat",
    "node.list",
    "node.describe",
    "chat.history",
    "config.get",
    "config.schema.lookup",
    "talk.config",
    "web.login.wait",
    "agents.files.list",
    "agents.files.get",
    // Read-only queries not covered by prefixes
    "tools.effective",
    "skills.bins",
    "commands.list",
    "node.invoke.result",
    // Missing from BASE_METHODS read-only
    "exec.approvals.get",
    "exec.approvals.node.get",
    "exec.approval.get",
    "exec.approval.list",
    "plugin.approval.list",
    "models.authStatus",
    "skills.search",
    "skills.detail",
    "sessions.compaction.list",
    "sessions.compaction.get",
    "sessions.compaction.branch",
    "sessions.compaction.restore",
    // Doctor memory read
    "doctor.memory.dreamDiary",
  ],
  "admin:write": [
    // WRITE_SCOPE
    "send",
    "poll",
    "agent",
    "agent.wait",
    "wake",
    "talk.mode",
    "talk.speak",
    "tts.enable",
    "tts.disable",
    "tts.convert",
    "tts.setProvider",
    "voicewake.set",
    "node.invoke",
    "chat.send",
    "chat.abort",
    "sessions.create",
    "sessions.send",
    "sessions.steer",
    "sessions.abort",
    "browser.request",
    "push.test",
    "node.pending.enqueue",
    // ADMIN_SCOPE (secrets.* handled separately below)
    "channels.logout",
    "agents.create",
    "agents.update",
    "agents.delete",
    "skills.install",
    "skills.update",
    "cron.add",
    "cron.update",
    "cron.remove",
    "cron.run",
    "sessions.patch",
    "sessions.reset",
    "sessions.delete",
    "sessions.compact",
    "connect",
    "chat.inject",
    "web.login.start",
    "set-heartbeats",
    "system-event",
    "agents.files.set",
    // APPROVALS_SCOPE
    "exec.approval.request",
    "exec.approval.waitDecision",
    "exec.approval.resolve",
    "exec.approvals.set",
    "exec.approvals.node.set",
    // Missing from BASE_METHODS write
    "config.set",
    "config.apply",
    "config.patch",
    "config.schema",
    "channels.start",
    "skills.install",
    "skills.update",
    "update.run",
    "secrets.reload",
    "wizard.start",
    "wizard.next",
    "wizard.cancel",
    "wizard.status",
    "message.action",
    // Doctor memory write
    "doctor.memory.backfillDreamDiary",
    "doctor.memory.resetDreamDiary",
    "doctor.memory.resetGroundedShortTerm",
    "doctor.memory.repairDreamingArtifacts",
    "doctor.memory.dedupeDreamDiary",
    // PAIRING_SCOPE
    "node.pair.request",
    "node.pair.list",
    "node.pair.approve",
    "node.pair.reject",
    "node.pair.verify",
    "device.pair.list",
    "device.pair.approve",
    "device.pair.reject",
    "device.pair.remove",
    "device.token.rotate",
    "device.token.revoke",
    "node.rename",
    // Plugin approval operations (mirrors exec.approval.* above)
    "plugin.approval.request",
    "plugin.approval.waitDecision",
    "plugin.approval.resolve",
    // Node pending/event operations (node.pending.enqueue already listed above)
    "node.pending.drain",
    "node.pending.pull",
    "node.pending.ack",
    "node.event",
    "node.canvas.capability.refresh",
  ],
  "secrets:read": ["secrets.resolve"],
  "secrets:manage": ["secrets.reload"],
  "admin:config": ["config.set_protected"],
};

// Prefix fallback for unlisted methods (matches ADMIN_METHOD_PREFIXES in method-scopes.ts)
const CAPABILITY_PREFIXES: readonly [string, string][] = [
  ["exec.approvals.", "admin:write"],
  ["plugin.approval.", "admin:write"],
  ["config.", "admin:write"],
  ["wizard.", "admin:write"],
  ["update.", "admin:write"],
];

function buildCapabilitiesMap(): Record<string, string> {
  const map: Record<string, string> = {};
  for (const [cap, methods] of Object.entries(METHODS_BY_CAPABILITY)) {
    for (const method of methods) {
      map[`gateway.method.${method}`] = cap;
    }
  }
  return map;
}

const DEFAULT_MESSAGE_CAPABILITIES = buildCapabilitiesMap();

const METHOD_PREFIX = "gateway.method." as const;

function resolveMessageCapability(
  messageType: string,
  overrides?: Map<string, string>,
): string | undefined {
  if (overrides) {
    const v = overrides.get(messageType);
    if (v) {
      return v;
    }
  }
  const exact = DEFAULT_MESSAGE_CAPABILITIES[messageType];
  if (exact) {
    return exact;
  }
  if (messageType.startsWith(METHOD_PREFIX)) {
    const method = messageType.slice(METHOD_PREFIX.length);
    for (const [prefix, cap] of CAPABILITY_PREFIXES) {
      if (method.startsWith(prefix)) {
        return cap;
      }
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface MessageAuthorizationContext {
  clientId: string;
  role?: string;
  scopes: Set<string>;
  endpoint: string;
  connectedAt: number;
  resolvedCapabilities: Set<string>;
}

export interface MessageAuthorizationResult {
  ok: true;
  capability: string;
}
export interface MessageAuthorizationDenied {
  ok: false;
  reason: string;
  missingCapability: string;
}
export type MessageAuthorization = MessageAuthorizationResult | MessageAuthorizationDenied;

export interface MessageAuthConfig {
  messageCapabilities: Map<string, string>;
  requireCapabilityForAll: boolean;
  logDenied: boolean;
}

export function createMessageAuthContext(params: {
  clientId: string;
  role?: string;
  scopes?: string[];
  endpoint: string;
}): MessageAuthorizationContext {
  const scopes = new Set(params.scopes ?? []);
  return {
    clientId: params.clientId,
    role: params.role,
    scopes,
    endpoint: params.endpoint,
    connectedAt: Date.now(),
    resolvedCapabilities: resolveCapabilitiesFromScopes(scopes),
  };
}

export function hasMessageCapability(ctx: MessageAuthorizationContext, required: string): boolean {
  const caps = ctx.resolvedCapabilities;
  if (caps.has("*")) {
    return true;
  }
  if (caps.has(required)) {
    return true;
  }
  const [namespace] = required.split(":");
  if (caps.has(`${namespace}:*`)) {
    return true;
  }
  return false;
}

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
    return { ok: true, capability: "none" };
  }

  if (hasMessageCapability(ctx, messageCapability)) {
    return { ok: true, capability: messageCapability };
  }

  if (config?.logDenied) {
    console.warn(
      `[MessageAuth] Denied: client=${ctx.clientId} type=${messageType} required=${messageCapability}`,
    );
  }

  return {
    ok: false,
    reason: `Capability denied: ${messageCapability} required for ${messageType}`,
    missingCapability: messageCapability,
  };
}
