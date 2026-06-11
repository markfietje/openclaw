// Connection-type capability gate for gateway RPC dispatch.
// Restricts methods to specific client connection types when defined.

export type ConnectionType =
  | "webchat"
  | "cli"
  | "ui"
  | "backend"
  | "node"
  | "probe"
  | "test"
  | "mcp-loopback";

const METHOD_CAPABILITY_MATRIX: ReadonlyMap<string, ReadonlySet<ConnectionType>> = new Map([
  // Conservative starting matrix. Expand as specific method restrictions are needed.
]);

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
