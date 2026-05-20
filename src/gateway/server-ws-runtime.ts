import type { createSubsystemLogger } from "../logging/subsystem.js";
import type { GatewayMethodRegistry } from "./methods/registry.js";
import type { GatewayRequestContext, GatewayRequestHandlers } from "./server-methods/types.js";
import type { AuthenticatedConnectionBudget } from "./server/authenticated-connection-budget.js";
import {
  attachGatewayWsConnectionHandler,
  type GatewayWsSharedHandlerParams,
} from "./server/ws-connection.js";
import type { ToolAuditLogger } from "./tool-audit.js";

type GatewayWsRuntimeParams = Omit<GatewayWsSharedHandlerParams, "refreshHealthSnapshot"> & {
  authenticatedConnectionBudget: AuthenticatedConnectionBudget;
  logGateway: ReturnType<typeof createSubsystemLogger>;
  logHealth: ReturnType<typeof createSubsystemLogger>;
  logWsControl: ReturnType<typeof createSubsystemLogger>;
  extraHandlers: GatewayRequestHandlers;
  getMethodRegistry?: () => GatewayMethodRegistry;
  broadcast: (
    event: string,
    payload: unknown,
    opts?: {
      dropIfSlow?: boolean;
      stateVersion?: { presence?: number; health?: number };
    },
  ) => void;
  context: GatewayRequestContext;
  /** Optional tool audit logger for structured tool call forensics. */
  toolAuditLogger?: ToolAuditLogger;
};

export function attachGatewayWsHandlers(params: GatewayWsRuntimeParams) {
  attachGatewayWsConnectionHandler({
    wss: params.wss,
    clients: params.clients,
    preauthConnectionBudget: params.preauthConnectionBudget,
    authenticatedConnectionBudget: params.authenticatedConnectionBudget,
    port: params.port,
    gatewayHost: params.gatewayHost,
    pluginSurfaceScheme: params.pluginSurfaceScheme,
    getPluginNodeCapabilities: params.getPluginNodeCapabilities,
    resolvedAuth: params.resolvedAuth,
    getResolvedAuth: params.getResolvedAuth,
    getRequiredSharedGatewaySessionGeneration: params.getRequiredSharedGatewaySessionGeneration,
    rateLimiter: params.rateLimiter,
    browserRateLimiter: params.browserRateLimiter,
    preauthHandshakeTimeoutMs: params.preauthHandshakeTimeoutMs,
    isStartupPending: params.isStartupPending,
    gatewayMethods: params.gatewayMethods,
    events: params.events,
    refreshHealthSnapshot: params.context.refreshHealthSnapshot,
    logGateway: params.logGateway,
    logHealth: params.logHealth,
    logWsControl: params.logWsControl,
    extraHandlers: params.extraHandlers,
    getMethodRegistry: params.getMethodRegistry,
    broadcast: params.broadcast,
    buildRequestContext: () => params.context,
    toolAuditLogger: params.toolAuditLogger,
  });
}
