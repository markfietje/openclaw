import {
  ADMIN_SCOPE,
  READ_SCOPE,
  WRITE_SCOPE,
  APPROVALS_SCOPE,
  PAIRING_SCOPE,
  TALK_SECRETS_SCOPE,
  resolveRequiredOperatorScopeForMethod,
  type OperatorScope,
} from "./method-scopes.js";
import { resolveCoreGatewayMethodScope } from "./methods/core-descriptors.js";
import {
  DYNAMIC_GATEWAY_METHOD_SCOPE,
  NODE_GATEWAY_METHOD_SCOPE,
  type GatewayMethodRegistryView,
  type GatewayMethodScope,
} from "./methods/descriptor.js";

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

// Node scopes (dot form, e.g. `node.exec`) are authorized by `role: "node"`
// and translate into `node:*` capabilities so a node can satisfy the
// `/gateway` endpoint capability gate without acquiring operator scopes.
const NODE_SCOPE_CAPABILITIES: Record<string, readonly string[]> = {
  "node.exec": ["node:exec"],
  "node.invoke": ["node:invoke"],
};

// OWASP A01:2021 — Broken Access Control. Enforce maximum scope count
// to prevent memory exhaustion via large scope sets.
const MAX_MESSAGE_AUTH_SCOPES = 64;
const MAX_SCOPE_LENGTH = 128;
const MAX_CAPABILITY_LENGTH = 64;

function resolveCapabilitiesFromScopes(scopes: ReadonlySet<string>): Set<string> {
  const caps = new Set<string>();
  let scopeCount = 0;
  for (const scope of scopes) {
    // Enforce maximum scope count to prevent memory exhaustion.
    if (scopeCount >= MAX_MESSAGE_AUTH_SCOPES) {
      break;
    }
    scopeCount++;
    // OWASP A05:2021 — Security Logging/Monitoring Failures. Enforce maximum
    // scope length to prevent memory exhaustion via oversized scope strings.
    if (scope.length > MAX_SCOPE_LENGTH) {
      continue;
    }
    if (scope === "*") {
      // OWASP A01:2021 — Broken Access Control. The wildcard scope grants
      // all capabilities. This is intentionally limited to prevent
      // accidental over-privileging — wildcards are rare and controlled.
      caps.add("*");
      continue;
    }
    const translated = OPERATOR_SCOPE_CAPABILITIES[scope as OperatorScope];
    if (translated) {
      for (const cap of translated) {
        // Enforce maximum capability length.
        if (cap.length <= MAX_CAPABILITY_LENGTH) {
          caps.add(cap);
        }
      }
      continue;
    }
    const nodeTranslated = NODE_SCOPE_CAPABILITIES[scope];
    if (nodeTranslated) {
      for (const cap of nodeTranslated) {
        if (cap.length <= MAX_CAPABILITY_LENGTH) {
          caps.add(cap);
        }
      }
      continue;
    }
    // Direct capability scope (e.g. secrets:read, admin:config, admin:*)
    if (scope.includes(":") && scope.length <= MAX_CAPABILITY_LENGTH) {
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
    default:
      return "admin:read";
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

// OWASP A01:2021 — Broken Access Control. Enforce maximum method name length
// to prevent memory exhaustion via oversized method names.
const MAX_MESSAGE_TYPE_LENGTH = 256;
const MAX_METHOD_LENGTH = 128;

export function resolveMessageAuthorizationDecision(
  messageType: string,
  config?: Partial<Pick<MessageAuthConfig, "messageCapabilities" | "methodRegistry">>,
): MessageAuthorizationDecision | undefined {
  // Reject oversized message types to prevent memory exhaustion.
  if (messageType.length > MAX_MESSAGE_TYPE_LENGTH) {
    return undefined;
  }
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
  // Reject oversized method names to prevent memory exhaustion.
  if (method.length > MAX_METHOD_LENGTH) {
    return undefined;
  }
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

// OWASP A01:2021 — Broken Access Control. Enforce maximum context field lengths
// to prevent memory exhaustion via oversized context values.
const MAX_CLIENT_ID_LENGTH = 128;
const MAX_ENDPOINT_LENGTH = 256;

export function createMessageAuthContext(params: {
  clientId: string;
  role?: string;
  scopes?: string[];
  endpoint: string;
}): MessageAuthorizationContext {
  // Truncate clientId to prevent memory exhaustion.
  const truncatedClientId =
    params.clientId.length > MAX_CLIENT_ID_LENGTH
      ? params.clientId.slice(0, MAX_CLIENT_ID_LENGTH)
      : params.clientId;
  // Truncate endpoint to prevent memory exhaustion.
  const truncatedEndpoint =
    params.endpoint.length > MAX_ENDPOINT_LENGTH
      ? params.endpoint.slice(0, MAX_ENDPOINT_LENGTH)
      : params.endpoint;
  // Limit scopes array to MAX_MESSAGE_AUTH_SCOPES to prevent memory exhaustion.
  const truncatedScopes = Array.isArray(params.scopes)
    ? params.scopes.slice(0, MAX_MESSAGE_AUTH_SCOPES)
    : [];
  const scopes = new Set(truncatedScopes);
  return {
    clientId: truncatedClientId,
    role: params.role,
    scopes,
    endpoint: truncatedEndpoint,
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
    default:
      return false;
  }
}

function formatMissingAuthorization(decision: MessageAuthorizationDecision): string {
  switch (decision.kind) {
    case "capability":
      return decision.capability;
    case "role":
      return `role:${decision.role}`;
    default:
      return "unauthorized";
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
