// Boot-run echo guard: tracks the active boot prompt per session key so that
// downstream user-visible delivery paths (currently the message tool) can
// suppress fallback-model echoes that copy substantial portions of the boot
// prompt without preserving the internal-runtime-context delimiters.
//
// The marker-based strip in `stripInternalRuntimeContext` only catches
// echoes that include the delimiter lines verbatim. A model that paraphrases
// out the wrapper but reproduces a long contiguous chunk of the BOOT.md
// content would slip past the marker strip and reach the user. This module
// adds a defense-in-depth substantial-echo check using the active boot prompt
// as the comparison source. Refs #53732.

const MIN_ECHO_CHARS = 80;
const MAX_BOOT_CHUNK_PROMPTS = 64;
const MAX_BOOT_CONTEXT_SESSIONS = 512;

type BootEchoContext = {
  bootPrompt: string;
  normalizedBootPrompt: string;
};

const bootContextBySessionKey = new Map<string, BootEchoContext>();
const bootChunksByNormalizedPrompt = new Map<string, Map<number, Set<string>>>();
// Reference count for shared chunk entries so chunks are only freed when all
// sessions using that normalized prompt are cleared.
const bootChunksRefByNormalizedPrompt = new Map<string, number>();

function normalizeEchoComparisonText(text: string): string {
  return text.replace(/\s+/gu, " ").trim();
}

function getBootPromptChunks(normalizedBootPrompt: string, minLen: number): Set<string> {
  let chunksByLength = bootChunksByNormalizedPrompt.get(normalizedBootPrompt);
  if (!chunksByLength) {
    chunksByLength = new Map();
    bootChunksByNormalizedPrompt.set(normalizedBootPrompt, chunksByLength);
  }
  const cached = chunksByLength.get(minLen);
  if (cached) {
    return cached;
  }
  const chunks = new Set<string>();
  for (let i = 0; i <= normalizedBootPrompt.length - minLen; i += 1) {
    chunks.add(normalizedBootPrompt.slice(i, i + minLen));
  }
  chunksByLength.set(minLen, chunks);
  return chunks;
}

export function setBootEchoContextForSession(sessionKey: string, bootPrompt: string): void {
  if (!sessionKey || !bootPrompt) {
    return;
  }
  // Evict oldest entries when the session map exceeds the cap.
  if (bootContextBySessionKey.size >= MAX_BOOT_CONTEXT_SESSIONS) {
    const oldestKey = bootContextBySessionKey.keys().next().value;
    if (oldestKey !== undefined) {
      clearBootEchoContextForSession(oldestKey);
    }
  }
  const normalizedBootPrompt = normalizeEchoComparisonText(bootPrompt);
  if (normalizedBootPrompt.length >= MIN_ECHO_CHARS) {
    // Evict oldest chunk entries when the chunk map exceeds the cap.
    if (bootChunksByNormalizedPrompt.size >= MAX_BOOT_CHUNK_PROMPTS) {
      const oldestChunkKey = bootChunksByNormalizedPrompt.keys().next().value;
      if (oldestChunkKey !== undefined) {
        bootChunksByNormalizedPrompt.delete(oldestChunkKey);
        bootChunksRefByNormalizedPrompt.delete(oldestChunkKey);
      }
    }
    getBootPromptChunks(normalizedBootPrompt, MIN_ECHO_CHARS);
  }
  // Increment ref count for shared chunk deduplication.
  const currentRefCount = bootChunksRefByNormalizedPrompt.get(normalizedBootPrompt) ?? 0;
  bootChunksRefByNormalizedPrompt.set(normalizedBootPrompt, currentRefCount + 1);
  bootContextBySessionKey.set(sessionKey, { bootPrompt, normalizedBootPrompt });
}

export function clearBootEchoContextForSession(sessionKey: string): void {
  if (!sessionKey) {
    return;
  }
  const context = bootContextBySessionKey.get(sessionKey);
  if (context) {
    // Decrement ref count; only free chunks when the last session using them clears.
    const refCount = bootChunksRefByNormalizedPrompt.get(context.normalizedBootPrompt);
    if (refCount !== undefined && refCount <= 1) {
      bootChunksByNormalizedPrompt.delete(context.normalizedBootPrompt);
      bootChunksRefByNormalizedPrompt.delete(context.normalizedBootPrompt);
    } else if (refCount !== undefined) {
      bootChunksRefByNormalizedPrompt.set(context.normalizedBootPrompt, refCount - 1);
    }
  }
  bootContextBySessionKey.delete(sessionKey);
}

export function getBootEchoContextForSession(sessionKey: string | undefined): string | undefined {
  if (!sessionKey) {
    return undefined;
  }
  return bootContextBySessionKey.get(sessionKey)?.bootPrompt;
}

/**
 * Returns true if `outboundText` contains a contiguous substring of
 * `bootPrompt` of at least `minLen` characters, ignoring leading/trailing
 * whitespace on the boot prompt itself. Short boot prompts (< minLen chars)
 * never trigger to avoid suppressing legitimate short BOOT.md-directed
 * sends like a literal "good morning".
 */
export function containsSubstantialBootEcho(
  outboundText: string,
  bootPrompt: string,
  minLen: number = MIN_ECHO_CHARS,
): boolean {
  const haystack = normalizeEchoComparisonText(outboundText ?? "");
  const needle = normalizeEchoComparisonText(bootPrompt ?? "");
  if (haystack.length < minLen || needle.length < minLen) {
    return false;
  }
  const bootChunks = getBootPromptChunks(needle, minLen);
  for (let i = 0; i <= haystack.length - minLen; i += 1) {
    if (bootChunks.has(haystack.slice(i, i + minLen))) {
      return true;
    }
  }
  return false;
}

/**
 * Removes any user-supplied outbound text that substantially echoes the
 * active boot prompt. Returns an empty string when an echo is detected so
 * the caller can either drop the send entirely or treat the outbound text
 * as empty. The boot prompt itself is unchanged.
 */
export function stripBootEchoFromOutboundText(
  outboundText: string,
  bootPrompt: string | undefined,
): string {
  if (!bootPrompt) {
    return outboundText;
  }
  return containsSubstantialBootEcho(outboundText, bootPrompt) ? "" : outboundText;
}

export function resetBootEchoContextForTests(): void {
  bootContextBySessionKey.clear();
  bootChunksByNormalizedPrompt.clear();
  bootChunksRefByNormalizedPrompt.clear();
}
