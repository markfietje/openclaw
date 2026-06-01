/**
 * Startup security checks for gateway network exposure.
 *
 * Runs a battery of checks at gateway startup to detect insecure
 * configurations that would be dangerous on public networks:
 * - TLS enforcement (network-exposed without TLS)
 * - Credential strength (weak token/password when exposed)
 * - Bind address safety (0.0.0.0 fallback detection)
 */

export interface StartupSecurityCheckResult {
  /** Unique check identifier for programmatic handling. */
  id: string;
  /** Severity level. */
  severity: "critical" | "warn";
  /** Human-readable description of the issue. */
  message: string;
}

export const DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE_ENV =
  "OPENCLAW_DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE";

export interface StartupSecurityCheckParams {
  /** Whether the gateway is accessible from non-loopback networks. */
  isNetworkExposed: boolean;
  /** Whether TLS is active on the listening socket. */
  hasTls: boolean;
  /** Whether TLS is terminated upstream (reverse proxy). */
  terminatedUpstream: boolean;
  /** Resolved auth mode: "token", "password", "tailscale", "none". */
  authMode: string;
  /** Bind address the gateway is listening on. */
  bindAddress?: string;
  /** Length of the resolved gateway token (if token auth). */
  tokenLength?: number;
  /** Length of the resolved gateway password (if password auth). */
  passwordLength?: number;
}

/**
 * Run startup security checks and return findings.
 *
 * Returns an empty array when everything looks good.
 * Findings are ordered by severity (critical first).
 */
export function runStartupSecurityChecks(
  params: StartupSecurityCheckParams,
): StartupSecurityCheckResult[] {
  const results: StartupSecurityCheckResult[] = [];

  // Check 1: Network-exposed without TLS and no upstream termination
  if (params.isNetworkExposed && !params.hasTls && !params.terminatedUpstream) {
    results.push({
      id: "gateway.no_tls_network_exposed",
      severity: "critical",
      message:
        "Gateway is network-exposed without TLS. Traffic is unencrypted. " +
        "Enable TLS (wss://) or use a reverse proxy with TLS termination.",
    });
  }

  // Check 2: Network-exposed with short token
  if (params.isNetworkExposed && params.authMode === "token" && params.tokenLength !== undefined) {
    if (params.tokenLength < 32) {
      results.push({
        id: "gateway.token_too_short",
        severity: "critical",
        message:
          `Gateway auth token is ${params.tokenLength} characters (minimum 32 for network exposure). ` +
          "Generate a stronger token: openssl rand -hex 32",
      });
    }
  }

  // Check 3: Network-exposed with weak password
  if (
    params.isNetworkExposed &&
    params.authMode === "password" &&
    params.passwordLength !== undefined
  ) {
    if (params.passwordLength < 12) {
      results.push({
        id: "gateway.password_too_short",
        severity: "critical",
        message:
          `Gateway auth password is ${params.passwordLength} characters (minimum 12 for network exposure). ` +
          "Choose a stronger password.",
      });
    }
  }

  // Check 4: Network-exposed without auth
  if (params.isNetworkExposed && params.authMode === "none") {
    results.push({
      id: "gateway.no_auth_network_exposed",
      severity: "critical",
      message:
        "Gateway is network-exposed with no authentication. " +
        "Set gateway.auth.mode to 'token' or 'password'.",
    });
  }

  // Check 5: Bound to all interfaces (0.0.0.0 / ::)
  const bindLower = (params.bindAddress ?? "").toLowerCase();
  if (bindLower === "0.0.0.0" || bindLower === "::" || bindLower === "[::]") {
    results.push({
      id: "gateway.bind_all_interfaces",
      severity: "warn",
      message:
        "Gateway is bound to all network interfaces (0.0.0.0/::). " +
        "Consider binding to a specific address or loopback for local-only access.",
    });
  }

  // Sort: critical first, then warn
  results.sort((a, b) => {
    if (a.severity === b.severity) {
      return 0;
    }
    return a.severity === "critical" ? -1 : 1;
  });

  return results;
}

export function hasCriticalStartupSecurityFindings(
  findings: readonly StartupSecurityCheckResult[],
): boolean {
  return findings.some((finding) => finding.severity === "critical");
}

export function isDangerousInsecureGatewayExposureOverrideEnabled(
  env: Readonly<Record<string, string | undefined>>,
): boolean {
  return env[DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE_ENV] === "1";
}

export function formatCriticalStartupSecurityFindingsError(
  findings: readonly StartupSecurityCheckResult[],
): string {
  const criticalMessages = findings
    .filter((finding) => finding.severity === "critical")
    .map((finding) => `${finding.id}: ${finding.message}`);

  return [
    "Refusing to start network-exposed gateway with critical security findings.",
    ...criticalMessages,
    `Set ${DANGEROUSLY_ALLOW_INSECURE_GATEWAY_EXPOSURE_ENV}=1 only for an explicit break-glass startup.`,
  ].join("\n");
}

export function assertStartupSecurityFindingsAllowed(
  findings: readonly StartupSecurityCheckResult[],
  env: Readonly<Record<string, string | undefined>>,
): void {
  if (!hasCriticalStartupSecurityFindings(findings)) {
    return;
  }
  if (isDangerousInsecureGatewayExposureOverrideEnabled(env)) {
    return;
  }

  throw new Error(formatCriticalStartupSecurityFindingsError(findings));
}
