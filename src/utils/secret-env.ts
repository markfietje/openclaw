import { readFileSync } from "node:fs";

/**
 * Resolved value for a secret that may come from an environment variable
 * or a file path referenced by a `*_FILE` companion variable.
 *
 * Follows the Docker/Kubernetes secret-mount convention:
 * - `MY_SECRET` → inline value from the environment
 * - `MY_SECRET_FILE` → path to a file containing the secret
 */
export interface SecretEnvValue {
  readonly value: string;
  readonly source: "env" | "file";
  readonly envVar: string;
}

/**
 * Resolve a secret from the environment using the `*_FILE` fallback pattern.
 *
 * 1. If `env[envVar]` is a non-empty string, return it directly.
 * 2. Otherwise, if `env[${envVar}_FILE]` is set, read the file at that path
 *    synchronously and return the trimmed contents.
 * 3. Return `null` if neither resolves.
 *
 * File reads are intentionally synchronous — this runs at startup, not on a
 * hot path. If the file does not exist or cannot be read, returns `null`
 * instead of throwing so the caller can decide how to report the missing key.
 */
export function resolveSecretEnvValue(
  envVar: string,
  env: NodeJS.ProcessEnv = process.env,
): SecretEnvValue | null {
  const directValue = env[envVar];
  if (typeof directValue === "string" && directValue.length > 0) {
    return { value: directValue, source: "env", envVar };
  }

  const filePath = env[`${envVar}_FILE`];
  if (typeof filePath === "string" && filePath.length > 0) {
    try {
      const contents = readFileSync(filePath, "utf8");
      return { value: contents.trim(), source: "file", envVar };
    } catch {
      return null;
    }
  }

  return null;
}

/**
 * Same as {@link resolveSecretEnvValue} but throws if neither the direct env
 * var nor the `*_FILE` companion resolves.
 */
export function resolveSecretEnvValueOrThrow(
  envVar: string,
  env: NodeJS.ProcessEnv = process.env,
): SecretEnvValue {
  const result = resolveSecretEnvValue(envVar, env);
  if (result === null) {
    throw new Error(
      `Required secret not found: set ${envVar} or ${envVar}_FILE in the environment`,
    );
  }
  return result;
}

/**
 * Returns `true` when `key` ends with `_FILE`, indicating it is a file-path
 * companion variable in the Docker/Kubernetes secret-mount convention.
 */
export function isSecretEnvFileVar(key: string): boolean {
  return key.endsWith("_FILE");
}
