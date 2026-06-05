// Node invocation forwarding sanitizer.
// Strips or validates gateway-only control fields before node transport.
import type { ExecApprovalManager } from "./exec-approval-manager.js";
import { sanitizeSystemRunParamsForForwarding } from "./node-invoke-system-run-approval.js";
import type { GatewayClient } from "./server-methods/types.js";

// Gateway-only control fields that must never reach a node host.
// These are set by the gateway during approval routing and could
// confuse or bypass node-side policy if forwarded.
const GATEWAY_CONTROL_FIELDS: ReadonlySet<string> = new Set([
  "approved",
  "approvalDecision",
  "approvalId",
  "approvalRequired",
  "__gatewayInternal",
]);

/** Strips gateway control fields from arbitrary command params. */
function stripGatewayControlFields(params: unknown): unknown {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    return params;
  }
  const record = params as Record<string, unknown>;
  let changed = false;
  for (const key of Object.keys(record)) {
    if (GATEWAY_CONTROL_FIELDS.has(key)) {
      delete record[key];
      changed = true;
    }
  }
  // Return the same object reference when nothing changed to avoid
  // unnecessary allocations on the hot path.
  return changed ? record : params;
}

// Node invoke forwarding sanitizes command-specific payloads before they leave
// the gateway. system.run carries approval bindings and therefore needs special
// handling; other commands get a generic control-field strip pass.
/** Sanitizes node.invoke params before forwarding them to a connected node. */
export function sanitizeNodeInvokeParamsForForwarding(opts: {
  nodeId: string;
  command: string;
  rawParams: unknown;
  client: GatewayClient | null;
  execApprovalManager?: ExecApprovalManager;
}):
  | { ok: true; params: unknown }
  | { ok: false; message: string; details?: Record<string, unknown> } {
  if (opts.command === "system.run") {
    return sanitizeSystemRunParamsForForwarding({
      nodeId: opts.nodeId,
      rawParams: opts.rawParams,
      client: opts.client,
      execApprovalManager: opts.execApprovalManager,
    });
  }
  return { ok: true, params: stripGatewayControlFields(opts.rawParams) };
}
