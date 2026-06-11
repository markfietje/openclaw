// Safe JSON serialization for WebSocket frames.
// Strips U+2028/U+2029 line/paragraph separators that break JSON-in-HTML contexts.

export function safeWsJsonStringify(data: unknown): string {
  return JSON.stringify(data)
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}
