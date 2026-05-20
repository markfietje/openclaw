import { afterEach, describe, expect, it } from "vitest";
import { createEmptyPluginRegistry } from "../plugins/registry.js";
import {
  getActivePluginChannelRegistry,
  pinActivePluginHttpRouteRegistry,
  pinActivePluginChannelRegistry,
  releasePinnedPluginChannelRegistry,
  releasePinnedPluginHttpRouteRegistry,
  resetPluginRuntimeStateForTest,
  resolveActivePluginHttpRouteRegistry,
  setActivePluginRegistry,
} from "../plugins/runtime.js";
import { createGatewayRuntimeState } from "./server-runtime-state.js";

function createRegistryWithRoute(path: string) {
  const registry = createEmptyPluginRegistry();
  registry.httpRoutes.push({
    path,
    auth: "plugin",
    match: "exact",
    handler: () => true,
    pluginId: "demo",
    source: "test",
  });
  return registry;
}

describe("createGatewayRuntimeState", () => {
  afterEach(() => {
    releasePinnedPluginHttpRouteRegistry();
    releasePinnedPluginChannelRegistry();
    resetPluginRuntimeStateForTest();
  });

  it("releases post-bootstrap repinned plugin registries on cleanup", async () => {
    const startupRegistry = createRegistryWithRoute("/startup");
    const loadedRegistry = createRegistryWithRoute("/loaded");
    const fallbackRegistry = createRegistryWithRoute("/fallback");

    setActivePluginRegistry(startupRegistry);
    const runtimeState = await createGatewayRuntimeState({
      cfg: {},
      bindHost: "127.0.0.1",
      port: 0,
      controlUiEnabled: false,
      controlUiBasePath: "/",
      openAiChatCompletionsEnabled: false,
      openResponsesEnabled: false,
      resolvedAuth: {} as never,
      getResolvedAuth: () => ({}) as never,
      hooksConfig: () => null,
      getHookClientIpConfig: () => ({}) as never,
      pluginRegistry: startupRegistry,
      deps: {} as never,
      log: { info: () => {}, warn: () => {} },
      logHooks: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
      logPlugins: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
    });

    pinActivePluginHttpRouteRegistry(loadedRegistry);
    pinActivePluginChannelRegistry(loadedRegistry);
    expect(resolveActivePluginHttpRouteRegistry(fallbackRegistry)).toBe(loadedRegistry);
    expect(getActivePluginChannelRegistry()).toBe(loadedRegistry);

    runtimeState.releasePluginRouteRegistry();

    expect(resolveActivePluginHttpRouteRegistry(fallbackRegistry)).toBe(startupRegistry);
    expect(getActivePluginChannelRegistry()).toBe(startupRegistry);
  });

  it("wires configured pre-handshake connection rate limits", async () => {
    const startupRegistry = createRegistryWithRoute("/startup");

    setActivePluginRegistry(startupRegistry);
    const runtimeState = await createGatewayRuntimeState({
      cfg: {
        gateway: {
          security: {
            connectionRateLimit: {
              maxAttempts: 1,
              windowMs: 60_000,
              lockoutMs: 60_000,
              exemptLoopback: false,
              ipv6SubnetMask: 0,
            },
          },
        },
      },
      bindHost: "127.0.0.1",
      port: 0,
      controlUiEnabled: false,
      controlUiBasePath: "/",
      openAiChatCompletionsEnabled: false,
      openResponsesEnabled: false,
      resolvedAuth: {} as never,
      getResolvedAuth: () => ({}) as never,
      hooksConfig: () => null,
      getHookClientIpConfig: () => ({}) as never,
      pluginRegistry: startupRegistry,
      deps: {} as never,
      canvasRuntime: {} as never,
      canvasHostEnabled: false,
      logCanvas: { info: () => {}, warn: () => {} },
      log: { info: () => {}, warn: () => {} },
      logHooks: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
      logPlugins: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
    });

    try {
      expect(runtimeState.connectionRateLimiter.check("198.51.100.10").allowed).toBe(true);
      runtimeState.connectionRateLimiter.recordAttempt("198.51.100.10");
      expect(runtimeState.connectionRateLimiter.check("198.51.100.10").allowed).toBe(false);
    } finally {
      runtimeState.connectionRateLimiter.dispose();
      runtimeState.releasePluginRouteRegistry();
    }
  });

  it("creates the canvas host without logging it before HTTP bind", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "openclaw-canvas-runtime-"));
    tempDirs.push(root);
    const registry = createEmptyPluginRegistry();
    const logCanvas = { info: vi.fn(), warn: vi.fn() };

    const runtimeState = await createGatewayRuntimeState({
      cfg: { canvasHost: { root, liveReload: false } },
      bindHost: "127.0.0.1",
      port: 18789,
      controlUiEnabled: false,
      controlUiBasePath: "/",
      openAiChatCompletionsEnabled: false,
      openResponsesEnabled: false,
      resolvedAuth: {} as never,
      getResolvedAuth: () => ({}) as never,
      hooksConfig: () => null,
      getHookClientIpConfig: () => ({}) as never,
      pluginRegistry: registry,
      deps: {} as never,
      canvasRuntime: { log: () => {} } as never,
      canvasHostEnabled: true,
      allowCanvasHostInTests: true,
      logCanvas,
      log: { info: () => {}, warn: () => {} },
      logHooks: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
      logPlugins: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} } as never,
    });

    expect(runtimeState.canvasHost?.rootDir).toBe(root);
    expect(logCanvas.info).not.toHaveBeenCalled();
    await runtimeState.canvasHost?.close();
  });
});
