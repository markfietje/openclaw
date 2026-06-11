import type { ReplyPayload, ReplyPayloadTtsSupplement } from "../../auto-reply/reply-payload.js";
import { copyReplyPayloadMetadata } from "../../auto-reply/reply-payload.js";
import type { OpenClawConfig } from "../../config/types.openclaw.js";
import type {
  InteractiveReply,
  InteractiveReplyBlock,
  MessagePresentation,
  MessagePresentationBlock,
  MessagePresentationButton,
  MessagePresentationOption,
} from "../../interactive/payload.js";
import {
  createOutboundRedactor,
  isOutboundRedactionEnabled,
  type OutboundRedactor,
} from "../../security/outbound-redact.js";

function collectPlaintextGatewaySecrets(config: OpenClawConfig): string[] {
  const auth = config.gateway?.auth;
  const secrets: string[] = [];
  if (typeof auth?.token === "string") {
    secrets.push(auth.token);
  }
  if (typeof auth?.password === "string") {
    secrets.push(auth.password);
  }

  // Channel API keys — collect non-empty string values from channel configs.
  // Channel configs are typed but plugin-owned, so enumerate string values defensively.
  const channels = config.channels;
  if (channels && typeof channels === "object") {
    for (const channelValue of Object.values(channels)) {
      if (channelValue && typeof channelValue === "object") {
        collectStringValues(channelValue as Record<string, unknown>, secrets);
      }
    }
  }

  return secrets;
}

function collectStringValues(obj: Record<string, unknown>, out: string[]): void {
  for (const value of Object.values(obj)) {
    if (typeof value === "string" && value.length > 0) {
      out.push(value);
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      collectStringValues(value as Record<string, unknown>, out);
    }
  }
}

function redactButton(button: MessagePresentationButton, redact: (text: string) => string) {
  return {
    ...button,
    label: redact(button.label),
  };
}

function redactOption(option: MessagePresentationOption, redact: (text: string) => string) {
  return {
    ...option,
    label: redact(option.label),
  };
}

function redactPresentationBlock(
  block: MessagePresentationBlock,
  redact: (text: string) => string,
): MessagePresentationBlock {
  switch (block.type) {
    case "text":
    case "context":
      return { ...block, text: redact(block.text) };
    case "buttons":
      return {
        ...block,
        buttons: block.buttons.map((button) => redactButton(button, redact)),
      };
    case "select":
      return {
        ...block,
        ...(block.placeholder !== undefined ? { placeholder: redact(block.placeholder) } : {}),
        options: block.options.map((option) => redactOption(option, redact)),
      };
    case "divider":
      return block;
    default:
      return block;
  }
}

function redactPresentation(
  presentation: MessagePresentation,
  redact: (text: string) => string,
): MessagePresentation {
  return {
    ...presentation,
    ...(presentation.title !== undefined ? { title: redact(presentation.title) } : {}),
    blocks: presentation.blocks.map((block) => redactPresentationBlock(block, redact)),
  };
}

function redactInteractiveBlock(
  block: InteractiveReplyBlock,
  redact: (text: string) => string,
): InteractiveReplyBlock {
  switch (block.type) {
    case "text":
      return { ...block, text: redact(block.text) };
    case "buttons":
      return {
        ...block,
        buttons: block.buttons.map((button) => redactButton(button, redact)),
      };
    case "select":
      return {
        ...block,
        ...(block.placeholder !== undefined ? { placeholder: redact(block.placeholder) } : {}),
        options: block.options.map((option) => redactOption(option, redact)),
      };
    default:
      return block;
  }
}

function redactInteractive(
  interactive: InteractiveReply,
  redact: (text: string) => string,
): InteractiveReply {
  return {
    ...interactive,
    blocks: interactive.blocks.map((block) => redactInteractiveBlock(block, redact)),
  };
}

function redactTtsSupplement(
  supplement: ReplyPayloadTtsSupplement,
  redact: (text: string) => string,
): ReplyPayloadTtsSupplement {
  return {
    ...supplement,
    spokenText: redact(supplement.spokenText),
  };
}

function redactReplyPayload(payload: ReplyPayload, redactor: OutboundRedactor): ReplyPayload {
  const redact = redactor.redact.bind(redactor);
  const redacted: ReplyPayload = {
    ...payload,
    ...(payload.text !== undefined ? { text: redact(payload.text) } : {}),
    ...(payload.spokenText !== undefined ? { spokenText: redact(payload.spokenText) } : {}),
    ...(payload.ttsSupplement !== undefined
      ? { ttsSupplement: redactTtsSupplement(payload.ttsSupplement, redact) }
      : {}),
    ...(payload.btw !== undefined ? { btw: { question: redact(payload.btw.question) } } : {}),
    ...(payload.presentation !== undefined
      ? { presentation: redactPresentation(payload.presentation, redact) }
      : {}),
    ...(payload.interactive !== undefined
      ? { interactive: redactInteractive(payload.interactive, redact) }
      : {}),
  };
  return copyReplyPayloadMetadata(payload, redacted);
}

export function createOutboundDeliveryPayloadRedactor(config: OpenClawConfig) {
  if (!isOutboundRedactionEnabled(config)) {
    return (payload: ReplyPayload): ReplyPayload => payload;
  }
  const redactor = createOutboundRedactor({
    knownSecrets: collectPlaintextGatewaySecrets(config),
  });
  return (payload: ReplyPayload): ReplyPayload => redactReplyPayload(payload, redactor);
}
