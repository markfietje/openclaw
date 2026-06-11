// Exec output sanitizer redacts credential paths and secret values from
// command output before it reaches the model or transcript.
// OWASP LLM02 — Insecure Output Handling + A01:2025 — Broken Access Control (info disclosure).

// Paths that should never appear in exec output exposed to the model.
const CREDENTIAL_PATH_PATTERN =
  /(?:\/\.openclaw\/credentials\/|\/proc\/|\/etc\/shadow|\/etc\/passwd)[^\s]*/gi;

// Environment variable assignments where the value should be redacted.
// Matches: API_KEY=sk-abc, SECRET="value", TOKEN=value, etc.
const ENV_SECRET_PATTERN =
  /(?<=\b(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|CREDENTIAL|AUTH|ACCESS_KEY|SESSION_KEY|DATABASE_URL|DB_PASSWORD|CONNECTION_STRING|OPENAI_API_KEY|ANTHROPIC_API_KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|STRIPE_SECRET|SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|GITHUB_TOKEN|GITLAB_TOKEN|SLACK_TOKEN|DISCORD_TOKEN|MAILGUN_API_KEY|ENCRYPTION_KEY|SIGNING_KEY)\s*[:=]\s*)[^\s"']+/gi;

const REDACTED = "[REDACTED]";

/** Redact credential paths and secret values from exec tool output. */
export function sanitizeExecOutput(output: string | undefined): string {
  if (!output) {
    return "";
  }
  return output.replace(CREDENTIAL_PATH_PATTERN, REDACTED).replace(ENV_SECRET_PATTERN, REDACTED);
}
