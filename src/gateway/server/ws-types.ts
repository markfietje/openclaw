import type { WebSocket } from "ws";
import type { ConnectParams } from "../../../packages/gateway-protocol/src/index.js";
import type { DeviceSessionAuthoritySnapshot } from "../device-session-authority.js";
import type { PluginNodeCapabilityClient } from "../plugin-node-capability.js";

export type GatewayWsClient = PluginNodeCapabilityClient & {
  socket: WebSocket;
  connect: ConnectParams;
  connId: string;
  isDeviceTokenAuth?: boolean;
  deviceSessionAuthority?: DeviceSessionAuthoritySnapshot;
  invalidated?: boolean;
  invalidatedReason?: string;
  usesSharedGatewayAuth: boolean;
  sharedGatewaySessionGeneration?: string;
  presenceKey?: string;
  clientIp?: string;
  internal?: {
    approvalRuntime?: boolean;
  };
  canvasHostUrl?: string;
  canvasCapability?: string;
  canvasCapabilityExpiresAtMs?: number;
};
