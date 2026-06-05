// Chat send input sanitizer for Gateway message payloads.

/** Drop disallowed control characters while preserving tab and line breaks. */
function stripDisallowedChatControlChars(message: string): string {
  const chars: string[] = [];
  for (const char of message) {
    const code = char.charCodeAt(0);
    if (code === 9 || code === 10 || code === 13 || (code >= 32 && code !== 127)) {
      chars.push(char);
    }
  }
  return chars.join("");
}

const MAX_CHAT_MESSAGE_LENGTH = 100_000;

/** Normalize chat text and reject null bytes before routing to channels. */
export function sanitizeChatSendMessageInput(
  message: string,
): { ok: true; message: string } | { ok: false; error: string } {
  const normalized = message.normalize("NFC");
  if (normalized.includes("\u0000")) {
    return { ok: false, error: "message must not contain null bytes" };
  }
  if (normalized.length > MAX_CHAT_MESSAGE_LENGTH) {
    return {
      ok: false,
      error: `message exceeds maximum length (${MAX_CHAT_MESSAGE_LENGTH} characters)`,
    };
  }
  return { ok: true, message: stripDisallowedChatControlChars(normalized) };
}
