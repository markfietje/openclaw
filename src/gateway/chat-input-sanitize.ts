// Chat send input sanitizer for Gateway message payloads.

/** Drop disallowed control characters while preserving tab and line breaks.
 *  Also strips Unicode zero-width characters that enable homoglyph attacks. */
function stripDisallowedChatControlChars(message: string): string {
  const chars: string[] = [];
  for (const char of message) {
    const code = char.codePointAt(0)!;
    if (code === 9 || code === 10 || code === 13) {
      chars.push(char);
      continue;
    }
    if (code >= 32 && code !== 127 && code < 0x80) {
      chars.push(char);
      continue;
    }
    if (code >= 0x80) {
      // Strip zero-width characters: ZW space/joiner/non-joiner, BOM,
      // directional overrides (U+202A–202E, U+2066–2069), Arabic Letter Mark
      // (U+061C, an invisible bidi control), and the word-joiner ranges.
      if (
        code === 0x061c ||
        (code >= 0x200b && code <= 0x200f) ||
        code === 0xfeff ||
        (code >= 0x202a && code <= 0x202e) ||
        (code >= 0x2060 && code <= 0x2069)
      ) {
        continue;
      }
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
