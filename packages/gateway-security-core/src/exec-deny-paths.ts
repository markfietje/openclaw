/* eslint-disable @typescript-eslint/no-unnecessary-type-assertion, curly -- explicit string indices simplify the segment-vs-pattern comparison loop; parser uses early-return guards throughout */
/**
 * Exec deny-path gate — prevents agents from reading sensitive files via the exec tool.
 *
 * Provides a configurable deny-list of filesystem glob patterns. When a command
 * attempts to access a path matching a deny pattern, the gate returns the matched
 * pattern so the caller can block the command.
 *
 * @module exec-deny-paths
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ExecDenyPathsConfig {
  /** Glob patterns for paths that exec should be denied from reading.
   *  Overrides the built-in defaults. Pass an empty array to disable all deny checks. */
  denyPathPatterns?: string[];
}

/** Default deny patterns — blocks common secret/credential locations. */
export const DEFAULT_EXEC_DENY_PATTERNS: readonly string[] = [
  "**/.openclaw/secrets/**",
  "**/.openclaw/credentials/**",
  "**/.env",
  "**/.env.*",
  "**/*secret*",
  "**/*credential*",
  "**/*token*.env",
  "**/ssh/id_*",
  "**/.ssh/id_*",
  "**/.gnupg/**",
] as const;

// ---------------------------------------------------------------------------
// Simple glob matcher (no external dependency)
// ---------------------------------------------------------------------------

/**
 * Matches a single path segment against a single glob segment.
 * Supports `*` (any chars except `/`) and `?` (single char).
 */
function matchSegment(segment: string, pattern: string): boolean {
  // Fast path: literal match
  if (pattern === segment) return true;
  if (!pattern.includes("*") && !pattern.includes("?")) return pattern === segment;

  // Walk both strings simultaneously
  let si = 0;
  let pi = 0;
  let starIdx = -1;
  let segBacktrack = -1;

  while (si < segment.length) {
    if (pi < pattern.length) {
      const pc = pattern[pi]!;
      if (pc === "*") {
        starIdx = pi;
        segBacktrack = si;
        pi++;
        continue;
      }
      if (pc === "?" || pc === segment[si]) {
        si++;
        pi++;
        continue;
      }
    }
    // Backtrack to last star
    if (starIdx !== -1) {
      pi = starIdx + 1;
      segBacktrack++;
      si = segBacktrack;
      continue;
    }
    return false;
  }

  // Consume trailing stars
  while (pi < pattern.length && pattern[pi] === "*") {
    pi++;
  }

  return pi === pattern.length;
}

/**
 * Lightweight glob match supporting `*` (any non-slash) and `**` (any depth).
 * Does not support character classes or brace expansion.
 */
function globMatch(path: string, pattern: string): boolean {
  // Normalize — collapse duplicate slashes, strip trailing slash
  const normalizedPath = path.replace(/\/+/g, "/").replace(/\/$/, "");
  const normalizedPattern = pattern.replace(/\/+/g, "/").replace(/\/$/, "");

  // Exact match shortcut
  if (normalizedPattern === normalizedPath) return true;

  // Split into segments
  const pathParts = normalizedPath.split("/").filter(Boolean);
  const patternParts = normalizedPattern.split("/").filter(Boolean);

  return globMatchParts(pathParts, 0, patternParts, 0);
}

function globMatchParts(
  pathParts: string[],
  pi: number,
  patternParts: string[],
  gi: number,
): boolean {
  // Both exhausted → match
  if (gi === patternParts.length && pi === pathParts.length) return true;
  // Pattern exhausted but path remains → no match
  if (gi === patternParts.length) return false;

  const pat = patternParts[gi]!;

  // `**` — match zero or more path segments
  if (pat === "**") {
    // Consecutive `**` are redundant — skip
    let nextGi = gi + 1;
    while (nextGi < patternParts.length && patternParts[nextGi] === "**") {
      nextGi++;
    }
    // If `**` is the last pattern segment, it matches everything remaining
    if (nextGi === patternParts.length) {
      return true;
    }
    // Try matching the remainder of the pattern at every remaining position
    for (let i = pi; i <= pathParts.length; i++) {
      if (globMatchParts(pathParts, i, patternParts, nextGi)) {
        return true;
      }
    }
    return false;
  }

  // Path exhausted but pattern still has non-`**` segments → no match
  if (pi === pathParts.length) return false;

  // Current segment must match
  if (!matchSegment(pathParts[pi]!, pat)) return false;

  // Recurse
  return globMatchParts(pathParts, pi + 1, patternParts, gi + 1);
}

// ---------------------------------------------------------------------------
// Path extraction from shell commands (best-effort)
// ---------------------------------------------------------------------------

/** Commands whose first non-flag arguments are treated as file paths. */
const PATH_COMMANDS: ReadonlySet<string> = new Set([
  "cat",
  "less",
  "more",
  "head",
  "tail",
  "cp",
  "mv",
  "rm",
  "rmdir",
  "vim",
  "vi",
  "nano",
  "open",
  "touch",
  "chmod",
  "chown",
  "file",
  "stat",
  "wc",
  "diff",
  "sort",
  "uniq",
  "tee",
  "dd",
  "ln",
  "mkdir",
  "find",
  "grep",
  "sed",
  "awk",
  "xz",
  "gzip",
  "gunzip",
  "tar",
  "zip",
  "unzip",
  "base64",
  "md5",
  "shasum",
  "sha256sum",
  "xxd",
  "od",
  "strings",
  "curl",
  "wget",
  "git",
]);

/** Short flags that take a value argument (the next token is consumed, not treated as a path). */
const VALUE_FLAGS: ReadonlySet<string> = new Set([
  "n", // tail -n, head -n
  "c", // tail -c, head -c
  "s", // split -s, etc.
  "l", // wc -l, etc. (value-like but uncommon)
  "f", // cut -f, sort -f, etc.
  "d", // cut -d, etc.
  "b", // split -b, etc.
  "A", // some tools -A
  "B", // some tools -B
  "C", // grep -C, etc.
  "e", // sed -e, etc.
]);

/**
 * Expand a tilde prefix to the home directory marker.
 * We keep it as `~/` for consistent glob matching rather than resolving to an
 * actual filesystem path, since deny patterns should match semantically.
 */
function expandTilde(token: string): string {
  if (token === "~" || token.startsWith("~/")) {
    return token; // Keep tilde form — patterns can match `~/**` or `**/.ssh/**`
  }
  return token;
}

/**
 * Quick heuristic: does a token look like a filesystem path?
 * Matches tokens starting with `/`, `./`, `~`, or containing at least one `/`.
 */
function looksLikePath(token: string): boolean {
  if (token.length === 0) {
    return false;
  }
  // Starts with / ./ ~
  if (token[0] === "/" || token.startsWith("./") || token[0] === "~") {
    return true;
  }
  // Contains a slash somewhere (but not just a lone `/` in a flag like `-r/path`)
  if (token.includes("/") && !token.startsWith("-")) {
    return true;
  }
  return false;
}

/**
 * Strip leading short/long flags from an argument.
 * Returns `null` if the argument is a pure flag (e.g. `-la`, `--verbose`).
 */
function stripFlag(token: string): string | null {
  if (token === "--") {
    return null; // end-of-flags sentinel
  }
  if (token.startsWith("--")) {
    // `--option=value` → extract value portion
    const eqIdx = token.indexOf("=");
    if (eqIdx !== -1) {
      return token.slice(eqIdx + 1);
    }
    return null; // bare long flag
  }
  if (token.startsWith("-") && token.length >= 2) {
    // Combined short flags like `-la` are flags, not paths
    return null;
  }
  return token;
}

/**
 * Extract file paths from a shell command string. Best-effort — does not
 * implement a full shell parser.
 *
 * Recognised patterns:
 * - Arguments to known file-reading/operating commands (`cat`, `head`, `less`, …)
 * - Redirect targets (`< path`, `> path`, `>> path`)
 * - Bare arguments that look like filesystem paths
 */
export function extractPathsFromCommand(command: string): string[] {
  const paths: string[] = [];

  // Tokenize — naive whitespace split, then trim surrounding quotes
  const rawTokens = command.trim().split(/\s+/);
  const tokens: string[] = [];
  for (const raw of rawTokens) {
    // Strip matching surrounding quotes
    let t = raw;
    if ((t.startsWith('"') && t.endsWith('"')) || (t.startsWith("'") && t.endsWith("'"))) {
      t = t.slice(1, -1);
    }
    tokens.push(t);
  }

  if (tokens.length === 0) {
    return paths;
  }

  // Detect the command name (first token, possibly with a path prefix)
  const commandName = tokens[0]!.split("/").pop() ?? tokens[0]!;
  const isKnownCommand = PATH_COMMANDS.has(commandName);
  let pastEndOfFlags = false;
  let skipNext = false; // true when previous token was a flag that takes a value

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i]!;

    // If previous flag consumed this token as its value, skip it
    if (skipNext) {
      skipNext = false;
      continue;
    }

    // Handle redirect operators
    if (token === "<" || token === ">" || token === ">>") {
      // Next token is the redirect target
      const next = tokens[i + 1];
      if (next) {
        const target = expandTilde(stripQuotes(next));
        if (target.length > 0) {
          paths.push(target);
        }
        i++; // consume the next token
      }
      continue;
    }

    // Combined redirect like `>file`
    if (token.startsWith(">") || token.startsWith(">>")) {
      const redirectPath = token.startsWith(">>")
        ? token.slice(2)
        : token.startsWith(">")
          ? token.slice(1)
          : null;
      if (redirectPath && redirectPath.length > 0) {
        paths.push(expandTilde(stripQuotes(redirectPath)));
      }
      continue;
    }

    // Process-redirect `2>&1` etc — skip
    if (/^\d*>&\d*$/.test(token)) {
      continue;
    }

    // Pipeline / command separators — reset command context
    if (token === "|" || token === "&&" || token === "||" || token === ";") {
      pastEndOfFlags = false;
      skipNext = false;
      continue;
    }

    // End-of-flags sentinel
    if (token === "--") {
      pastEndOfFlags = true;
      continue;
    }

    // If we haven't passed the end-of-flags sentinel, try to strip flags
    let candidate = token;
    if (!pastEndOfFlags) {
      const stripped = stripFlag(token);
      if (stripped === null) {
        // Pure flag — check if it takes a value (short flag with known value-arg)
        if (token.startsWith("-") && !token.startsWith("--") && token.length === 2) {
          const flagChar = token[1];
          if (flagChar && VALUE_FLAGS.has(flagChar)) {
            skipNext = true;
          }
        }
        continue;
      }
      candidate = stripped;
    }

    candidate = expandTilde(stripQuotes(candidate));

    // For known path-operating commands, treat positional args as paths
    if (isKnownCommand && candidate.length > 0) {
      paths.push(candidate);
      continue;
    }

    // For any command, if the argument looks like a path, include it
    if (looksLikePath(candidate)) {
      paths.push(candidate);
    }
  }

  return paths;
}

function stripQuotes(s: string): string {
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

// ---------------------------------------------------------------------------
// Deny-path check
// ---------------------------------------------------------------------------

/**
 * Check if a command string attempts to access a denied path.
 *
 * @returns The first matched deny pattern, or `undefined` if the command is allowed.
 */
export function checkExecDenyPath(
  command: string,
  config?: ExecDenyPathsConfig,
): string | undefined {
  // Resolve effective patterns — empty array means "disable all checks"
  const patterns: readonly string[] =
    config?.denyPathPatterns !== undefined ? config.denyPathPatterns : DEFAULT_EXEC_DENY_PATTERNS;

  if (patterns.length === 0) {
    return undefined;
  }

  const extractedPaths = extractPathsFromCommand(command);

  for (const path of extractedPaths) {
    for (const pattern of patterns) {
      if (globMatch(path, pattern)) {
        return pattern;
      }
    }
  }

  return undefined;
}
