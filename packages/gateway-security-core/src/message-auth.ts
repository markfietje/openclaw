import {
  ADMIN_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  APPROVALS_SCOPE,
  PAIRING_SCOPE,
  TALK_SECRETS_SCOPE,
  resolveRequiredOperatorScopeForMethod,
  type OperatorScope,
} from "../../../src/gateway/method-scopes.js";
import { resolveCoreGatewayMethodScope } from "../../../src/gateway/methods/core-descriptors.js";
import {
  DYNAMIC_GATEWAY_METHOD_SCOPE,
  NODE_GATEWAY_METHOD_SCOPE,
  type GatewayMethodRegistryView,
  type GatewayMethodScope,
} from "../../../src/gateway/methods/descriptor.js";

// ---------------------------------------------------------------------------
// Operator scope → capability translation
// macOS app sends operator.* scopes; translate them into capability strings.
// operator.admin does NOT grant secrets:* or admin:config — those require
// explicit opt-in via direct capability scopes.
// ---------------------------------------------------------------------------

const OPERATOR_SCOPE_CAPABILITIES: Record<OperatorScope, readonly string[]> = {
  [ADMIN_SCOPE]: ["admin:read", "admin:write"],
  [READ_SCOPE]: ["admin:read"],
  [WRITE_SCOPE]: ["admin:read", "admin:write"], // write implies read
  [APPROVALS_SCOPE]: ["admin:write"],
  [PAIRING_SCOPE]: ["admin:write"],
  [TALK_SECRETS_SCOPE]: ["talk:secrets"],
};

function resolveCapabilitiesFromScopes(scopes: ReadonlySet<string>): Set<string> {
  const caps = new Set<string>();
  for (const scope of scopes) {
    if (scope === "*") {
      caps.add("*");
      continue;
    }
    const translated = OPERATOR_SCOPE_CAPABILITIES[scope as OperatorScope];
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
// Message → authorization decision resolver
// ---------------------------------------------------------------------------

const METHOD_PREFIX = "gateway.method." as const;

const DIRECT_MESSAGE_CAPABILITIES: ReadonlyMap<string, string> = new Map([
  // Secrets are intentionally stricter than operator.admin. Operator default
  // scopes may administer the gateway but must opt into secret read/manage.
  ["gateway.method.secrets.resolve", "secrets:read"],
  ["gateway.method.secrets.reload", "secrets:manage"],
  // Synthetic message used by the protected config path check in the WS handler.
  ["gateway.method.config.set_protected", "admin:config"],
]);

export type MessageAuthorizationDecision =
  | { kind: "capability"; capability: string }
  | { kind: "role"; role: "node" };

function operatorScopeToMessageCapability(scope: OperatorScope): string {
  switch (scope) {
    case READ_SCOPE:
      return "admin:read";
    case ADMIN_SCOPE:
    case WRITE_SCOPE:
    case APPROVALS_SCOPE:
    case PAIRING_SCOPE:
      return "admin:write";
    case TALK_SECRETS_SCOPE:
      return "talk:secrets";
  }
}

function gatewayMethodScopeToDecision(
  scope: GatewayMethodScope | undefined,
): MessageAuthorizationDecision | undefined {
  if (!scope) {
    return undefined;
  }
  if (scope === NODE_GATEWAY_METHOD_SCOPE) {
    return { kind: "role", role: "node" };
  }
  if (scope === DYNAMIC_GATEWAY_METHOD_SCOPE) {
    // Dynamic method-specific authorization still runs in server-methods with
    // params available. Message auth only applies the coarse operator write gate.
    return { kind: "capability", capability: "admin:write" };
  }
  return { kind: "capability", capability: operatorScopeToMessageCapability(scope) };
}

function resolveGatewayMethodScope(params: {
  method: string;
  methodRegistry?: Pick<GatewayMethodRegistryView, "getScope">;
}): GatewayMethodScope | undefined {
  return (
    params.methodRegistry?.getScope(params.method) ??
    resolveCoreGatewayMethodScope(params.method) ??
    resolveRequiredOperatorScopeForMethod(params.method)
  );
}

export function resolveMessageAuthorizationDecision(
  messageType: string,
  config?: Partial<Pick<MessageAuthConfig, "messageCapabilities" | "methodRegistry">>,
): MessageAuthorizationDecision | undefined {
  const override = config?.messageCapabilities?.get(messageType);
  if (override) {
    return { kind: "capability", capability: override };
  }
  const directCapability = DIRECT_MESSAGE_CAPABILITIES.get(messageType);
  if (directCapability) {
    return { kind: "capability", capability: directCapability };
  }
  if (!messageType.startsWith(METHOD_PREFIX)) {
    return undefined;
  }
  const method = messageType.slice(METHOD_PREFIX.length);
  return gatewayMethodScopeToDecision(
    resolveGatewayMethodScope({ method, methodRegistry: config?.methodRegistry }),
  );
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
  methodRegistry: Pick<GatewayMethodRegistryView, "getScope">;
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

function messageDecisionAllowed(
  ctx: MessageAuthorizationContext,
  decision: MessageAuthorizationDecision,
): boolean {
  switch (decision.kind) {
    case "capability":
      return hasMessageCapability(ctx, decision.capability);
    case "role":
      return ctx.role === decision.role;
  }
}

function formatMissingAuthorization(decision: MessageAuthorizationDecision): string {
  switch (decision.kind) {
    case "capability":
      return decision.capability;
    case "role":
      return `role:${decision.role}`;
  }
}

export function authorizeMessage(
  ctx: MessageAuthorizationContext,
  messageType: string,
  config?: Partial<MessageAuthConfig>,
): MessageAuthorization {
  const decision = resolveMessageAuthorizationDecision(messageType, config);

  if (!decision) {
    if (config?.requireCapabilityForAll) {
      return {
        ok: false,
        reason: `No capability defined for message type: ${messageType}`,
        missingCapability: "unknown",
      };
    }
    return { ok: true, capability: "none" };
  }

  const missingAuthorization = formatMissingAuthorization(decision);
  if (messageDecisionAllowed(ctx, decision)) {
    return { ok: true, capability: missingAuthorization };
  }

  if (config?.logDenied) {
    console.warn(
      `[MessageAuth] Denied: client=${ctx.clientId} type=${messageType} required=${missingAuthorization}`,
    );
  }

  return {
    ok: false,
    reason: `Capability denied: ${missingAuthorization} required for ${messageType}`,
    missingCapability: missingAuthorization,
  };
}
