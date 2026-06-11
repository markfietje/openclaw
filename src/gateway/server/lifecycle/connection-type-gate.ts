// Connection-type capability gate for gateway RPC dispatch.
// Restricts methods to specific client connection types when defined.

import { CORE_GATEWAY_METHOD_SPECS } from "../../methods/core-descriptors.js";

export type ConnectionType =
  | "webchat"
  | "cli"
  | "ui"
  | "backend"
  | "node"
  | "probe"
  | "test"
  | "mcp-loopback";

// Node-only methods are restricted to node connections to prevent scope spoofing
// (#64993). A browser WS client cannot call node.invoke.result to impersonate a node.
const NODE_ONLY = new Set<ConnectionType>(["node"]);

const METHOD_CAPABILITY_MATRIX: ReadonlyMap<string, ReadonlySet<ConnectionType>> = new Map(
  CORE_GATEWAY_METHOD_SPECS.filter((spec) => spec.scope === "node").map(
    (spec) => [spec.name, NODE_ONLY] as const,
  ),
);

const VALID_CONNECTION_TYPES: ReadonlySet<string> = new Set<string>([
  "webchat",
  "cli",
  "ui",
  "backend",
  "node",
  "probe",
  "test",
  "mcp-loopback",
]);

export function resolveConnectionType(params: {
  clientMode?: string | null;
  clientId?: string | null;
}): ConnectionType {
  const raw = typeof params.clientMode === "string" ? params.clientMode.toLowerCase().trim() : "";
  return VALID_CONNECTION_TYPES.has(raw) ? (raw as ConnectionType) : "cli";
}

export function isMethodAllowedForConnectionType(
  method: string,
  connectionType: ConnectionType,
): boolean {
  for (const [prefix, allowedTypes] of METHOD_CAPABILITY_MATRIX) {
    if (method === prefix || method.startsWith(`${prefix}.`)) {
      return allowedTypes.has(connectionType);
    }
  }
  return true;
}
