// Gateway auth resolver.
// Combines configured auth, overrides, environment credentials, and Tailscale policy.
import type {
  GatewayAuthConfig,
  GatewayTailscaleMode,
  GatewayTrustedProxyConfig,
} from "../config/types.gateway.js";
import { resolveSecretInputRef } from "../config/types.secrets.js";
import { logWarn } from "../logger.js";
import { resolveGatewayCredentialsFromValues } from "./credentials.js";

const DANGEROUSLY_ALLOW_NO_AUTH_ENV = "OPENCLAW_DANGEROUSLY_ALLOW_NO_AUTH";

export type ResolvedGatewayAuthMode = "none" | "token" | "password" | "trusted-proxy";
export type ResolvedGatewayAuthModeSource =
  | "override"
  | "config"
  | "password"
  | "token"
  | "default";

export type ResolvedGatewayAuth = {
  mode: ResolvedGatewayAuthMode;
  modeSource?: ResolvedGatewayAuthModeSource;
  token?: string;
  password?: string;
  allowTailscale: boolean;
  dangerouslyAllowNoAuth?: boolean;
  /**
   * When `mode = "none"`, allow loopback direct-local requests to authenticate
   * without credentials. Default: true for back-compat; set to false via
   * `gateway.auth.allowLocalDirectNoAuth` to require auth even on loopback.
   */
  allowLocalDirectNoAuth: boolean;
  /** Max body bytes for `/tools/invoke` (HTTP). Default 262144 (256 KiB). */
  toolsInvokeMaxBodyBytes: number;
  trustedProxy?: GatewayTrustedProxyConfig;
};

export type EffectiveSharedGatewayAuth = {
  mode: "token" | "password";
  secret: string | undefined;
};

const TOOLS_INVOKE_DEFAULT_MAX_BODY_BYTES = 256 * 1024;
const TOOLS_INVOKE_HARD_MAX_BODY_BYTES = 1024 * 1024;
const MAX_CREDENTIAL_LENGTH = 1024;

function resolveToolsInvokeMaxBodyBytes(value: number | undefined): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return TOOLS_INVOKE_DEFAULT_MAX_BODY_BYTES;
  }
  return Math.min(Math.floor(value), TOOLS_INVOKE_HARD_MAX_BODY_BYTES);
}

export function resolveGatewayAuth(params: {
  authConfig?: GatewayAuthConfig | null;
  authOverride?: GatewayAuthConfig | null;
  env?: NodeJS.ProcessEnv;
  tailscaleMode?: GatewayTailscaleMode;
}): ResolvedGatewayAuth {
  const baseAuthConfig = params.authConfig ?? {};
  const authOverride = params.authOverride ?? undefined;
  const authConfig: GatewayAuthConfig = { ...baseAuthConfig };
  if (authOverride) {
    if (authOverride.mode !== undefined) {
      authConfig.mode = authOverride.mode;
    }
    if (authOverride.token !== undefined) {
      authConfig.token = authOverride.token;
    }
    if (authOverride.password !== undefined) {
      authConfig.password = authOverride.password;
    }
    if (authOverride.allowTailscale !== undefined) {
      authConfig.allowTailscale = authOverride.allowTailscale;
    }
    if (authOverride.rateLimit !== undefined) {
      authConfig.rateLimit = authOverride.rateLimit;
    }
    if (authOverride.trustedProxy !== undefined) {
      authConfig.trustedProxy = authOverride.trustedProxy;
    }
    if (authOverride.dangerouslyAllowNoAuth !== undefined) {
      authConfig.dangerouslyAllowNoAuth = authOverride.dangerouslyAllowNoAuth;
    }
    if (authOverride.allowLocalDirectNoAuth !== undefined) {
      authConfig.allowLocalDirectNoAuth = authOverride.allowLocalDirectNoAuth;
    }
    if (authOverride.toolsInvokeMaxBodyBytes !== undefined) {
      authConfig.toolsInvokeMaxBodyBytes = authOverride.toolsInvokeMaxBodyBytes;
    }
  }
  const env = params.env ?? process.env;
  const tokenRef = resolveSecretInputRef({ value: authConfig.token }).ref;
  const passwordRef = resolveSecretInputRef({ value: authConfig.password }).ref;
  const resolvedCredentials = resolveGatewayCredentialsFromValues({
    configToken: tokenRef ? undefined : authConfig.token,
    configPassword: passwordRef ? undefined : authConfig.password,
    env,
    tokenPrecedence: "config-first",
    passwordPrecedence: "config-first", // pragma: allowlist secret
  });
  const token = resolvedCredentials.token;
  const password = resolvedCredentials.password;
  if (token && token.length > MAX_CREDENTIAL_LENGTH) {
    throw new Error(
      `Gateway auth token exceeds maximum length (${token.length} > ${MAX_CREDENTIAL_LENGTH}). ` +
        "Check your configuration for accidentally pasted long values.",
    );
  }
  if (password && password.length > MAX_CREDENTIAL_LENGTH) {
    throw new Error(
      `Gateway auth password exceeds maximum length (${password.length} > ${MAX_CREDENTIAL_LENGTH}). ` +
        "Check your configuration for accidentally pasted long values.",
    );
  }
  const trustedProxy = authConfig.trustedProxy;

  let mode: ResolvedGatewayAuth["mode"];
  let modeSource: ResolvedGatewayAuth["modeSource"];
  if (authOverride?.mode !== undefined) {
    mode = authOverride.mode;
    modeSource = "override";
  } else if (authConfig.mode) {
    mode = authConfig.mode;
    modeSource = "config";
  } else if (password) {
    mode = "password";
    modeSource = "password";
  } else if (token) {
    mode = "token";
    modeSource = "token";
  } else {
    mode = "token";
    modeSource = "default";
  }

  const allowTailscale =
    authConfig.allowTailscale ??
    (params.tailscaleMode === "serve" && mode !== "password" && mode !== "trusted-proxy");

  // Config takes precedence; env-var remains as a deprecated fallback so
  // existing dev setups keep working but log a one-shot deprecation notice.
  let dangerouslyAllowNoAuth = authConfig.dangerouslyAllowNoAuth === true;
  if (!dangerouslyAllowNoAuth && env[DANGEROUSLY_ALLOW_NO_AUTH_ENV] === "1") {
    dangerouslyAllowNoAuth = true;
    logWarn(
      `Gateway: ${DANGEROUSLY_ALLOW_NO_AUTH_ENV}=1 is deprecated; set gateway.auth.dangerouslyAllowNoAuth: true in openclaw.json instead.`,
    );
  }

  return {
    mode,
    modeSource,
    token,
    password,
    allowTailscale,
    ...(dangerouslyAllowNoAuth ? { dangerouslyAllowNoAuth: true } : {}),
    allowLocalDirectNoAuth: authConfig.allowLocalDirectNoAuth !== false,
    toolsInvokeMaxBodyBytes: resolveToolsInvokeMaxBodyBytes(authConfig.toolsInvokeMaxBodyBytes),
    trustedProxy,
  };
}

export function resolveEffectiveSharedGatewayAuth(params: {
  authConfig?: GatewayAuthConfig | null;
  authOverride?: GatewayAuthConfig | null;
  env?: NodeJS.ProcessEnv;
  tailscaleMode?: GatewayTailscaleMode;
}): EffectiveSharedGatewayAuth | null {
  const resolvedAuth = resolveGatewayAuth(params);
  if (resolvedAuth.mode === "token") {
    return {
      mode: "token",
      secret: resolvedAuth.token,
    };
  }
  if (resolvedAuth.mode === "password") {
    return {
      mode: "password",
      secret: resolvedAuth.password,
    };
  }
  return null;
}
