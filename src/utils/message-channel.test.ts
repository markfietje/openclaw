// Message channel tests cover channel id normalization and routing helpers.
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ChannelPlugin } from "../channels/plugins/types.js";
import { setActivePluginRegistry } from "../plugins/runtime.js";
import { createChannelTestPluginBase, createTestRegistry } from "../test-utils/channel-plugins.js";
import {
  INTERNAL_NON_DELIVERY_CHANNELS,
  isBrowserOperatorUiClient,
  isInternalNonDeliveryChannel,
  isMarkdownCapableMessageChannel,
  isOperatorUiClient,
  isWebchatClient,
  resolveGatewayMessageChannel,
} from "./message-channel.js";

const emptyRegistry = createTestRegistry([]);
const demoAliasPlugin: ChannelPlugin = {
  ...createChannelTestPluginBase({
    id: "demo-alias-channel",
    label: "Demo Alias Channel",
    docsPath: "/channels/demo-alias-channel",
  }),
  meta: {
    ...createChannelTestPluginBase({
      id: "demo-alias-channel",
      label: "Demo Alias Channel",
      docsPath: "/channels/demo-alias-channel",
    }).meta,
    aliases: ["workspace-chat"],
  },
};

const demoMarkdownPlugin: ChannelPlugin = {
  ...createChannelTestPluginBase({
    id: "demo-markdown-channel",
    label: "Demo Markdown Channel",
    docsPath: "/channels/demo-markdown-channel",
    markdownCapable: true,
  }),
};

describe("message-channel", () => {
  beforeEach(() => {
    setActivePluginRegistry(emptyRegistry);
  });

  afterEach(() => {
    setActivePluginRegistry(emptyRegistry);
  });

  it("normalizes gateway message channels and rejects unknown values", () => {
    expect(resolveGatewayMessageChannel("discord")).toBe("discord");
    expect(resolveGatewayMessageChannel(" imsg ")).toBe("imessage");
    expect(resolveGatewayMessageChannel("web")).toBeUndefined();
    expect(resolveGatewayMessageChannel("nope")).toBeUndefined();
  });

  it("normalizes plugin aliases when registered", () => {
    setActivePluginRegistry(
      createTestRegistry([
        { pluginId: "demo-alias-channel", plugin: demoAliasPlugin, source: "test" },
      ]),
    );
    expect(resolveGatewayMessageChannel("workspace-chat")).toBe("demo-alias-channel");
  });

  it("recognises internal non-delivery channel sources", () => {
    for (const channel of INTERNAL_NON_DELIVERY_CHANNELS) {
      expect(isInternalNonDeliveryChannel(channel)).toBe(true);
    }
    expect(isInternalNonDeliveryChannel("telegram")).toBe(false);
    expect(isInternalNonDeliveryChannel("webchat")).toBe(false);
    expect(isInternalNonDeliveryChannel("")).toBe(false);
    expect(isInternalNonDeliveryChannel("HEARTBEAT")).toBe(false);
  });

  it("reads markdown capability from channel metadata", () => {
    expect(isMarkdownCapableMessageChannel("telegram")).toBe(true);
    expect(isMarkdownCapableMessageChannel("whatsapp")).toBe(false);
    setActivePluginRegistry(
      createTestRegistry([
        { pluginId: "demo-markdown-channel", plugin: demoMarkdownPlugin, source: "test" },
      ]),
    );
    expect(isMarkdownCapableMessageChannel("demo-markdown-channel")).toBe(true);
  });

  it("reads Matrix markdown capability from bundled channel catalog metadata", async () => {
    const previousBundledPluginsDir = process.env.OPENCLAW_BUNDLED_PLUGINS_DIR;
    process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = path.resolve("extensions");
    vi.resetModules();
    try {
      const module = await import("./message-channel.js");
      expect(module.isMarkdownCapableMessageChannel("matrix")).toBe(true);
    } finally {
      if (previousBundledPluginsDir === undefined) {
        delete process.env.OPENCLAW_BUNDLED_PLUGINS_DIR;
      } else {
        process.env.OPENCLAW_BUNDLED_PLUGINS_DIR = previousBundledPluginsDir;
      }
      vi.resetModules();
    }
  });

  it("treats registered plugin channels without markdown metadata as plain text", () => {
    setActivePluginRegistry(
      createTestRegistry([
        {
          pluginId: "qa-channel",
          plugin: createChannelTestPluginBase({
            id: "qa-channel",
            label: "QA Channel",
            docsPath: "/channels/qa-channel",
          }),
          source: "test",
        },
      ]),
    );

    expect(isMarkdownCapableMessageChannel("qa-channel")).toBe(false);
  });

  describe("client classification (CWE-290 contract)", () => {
    it("isOperatorUiClient matches both CONTROL_UI and TUI", () => {
      expect(isOperatorUiClient({ id: "openclaw-control-ui" })).toBe(true);
      expect(isOperatorUiClient({ id: "openclaw-tui" })).toBe(true);
      expect(isOperatorUiClient({ id: "webchat-ui" })).toBe(false);
      expect(isOperatorUiClient({ id: "cli" })).toBe(false);
      expect(isOperatorUiClient({ id: "node-host" })).toBe(false);
    });

    it("isBrowserOperatorUiClient matches only CONTROL_UI, never TUI", () => {
      expect(isBrowserOperatorUiClient({ id: "openclaw-control-ui" })).toBe(true);
      expect(isBrowserOperatorUiClient({ id: "openclaw-tui" })).toBe(false);
      expect(isBrowserOperatorUiClient({ id: "webchat-ui" })).toBe(false);
      expect(isBrowserOperatorUiClient({ id: "cli" })).toBe(false);
    });

    it("isWebchatClient matches WEBCHAT mode and WEBCHAT_UI id", () => {
      expect(isWebchatClient({ mode: "webchat" })).toBe(true);
      expect(isWebchatClient({ id: "webchat-ui" })).toBe(true);
      expect(isWebchatClient({ id: "openclaw-tui" })).toBe(false);
      expect(isWebchatClient({ id: "openclaw-control-ui" })).toBe(false);
    });

    it("normalizes whitespace and case before matching", () => {
      expect(isBrowserOperatorUiClient({ id: "  OpenClaw-TUI  " })).toBe(false);
      expect(isBrowserOperatorUiClient({ id: "  OpenClaw-Control-UI  " })).toBe(true);
      expect(isOperatorUiClient({ id: "  OpenClaw-TUI  " })).toBe(true);
    });

    it("rejects empty, null, undefined, and unknown client info", () => {
      expect(isOperatorUiClient(undefined)).toBe(false);
      expect(isOperatorUiClient(null)).toBe(false);
      expect(isOperatorUiClient({})).toBe(false);
      expect(isOperatorUiClient({ id: "" })).toBe(false);
      expect(isOperatorUiClient({ id: "  " })).toBe(false);
      expect(isOperatorUiClient({ id: "garbage" })).toBe(false);
      expect(isBrowserOperatorUiClient(undefined)).toBe(false);
      expect(isBrowserOperatorUiClient(null)).toBe(false);
      expect(isBrowserOperatorUiClient({})).toBe(false);
      expect(isBrowserOperatorUiClient({ id: "" })).toBe(false);
      expect(isBrowserOperatorUiClient({ id: "  " })).toBe(false);
      expect(isBrowserOperatorUiClient({ id: "garbage" })).toBe(false);
    });

    it("does not trust spoofed client id even when mode is omitted", () => {
      // A bare id is enough to compute isControlUi; the security gate at
      // message-handler.ts:698 must use isBrowserOperatorUiClient, not
      // isOperatorUiClient, so TUI never inherits Control UI bypass.
      expect(isBrowserOperatorUiClient({ id: "openclaw-tui" })).toBe(false);
      expect(isOperatorUiClient({ id: "openclaw-tui" })).toBe(true);
    });
  });
});
