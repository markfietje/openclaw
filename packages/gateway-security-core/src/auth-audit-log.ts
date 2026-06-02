import { createAuditLogBase, verifyAuditLine, type AuditLogConfig } from "./audit-log-base.js";

export type AuthAuditEventType = "auth_failure" | "auth_success" | "rate_limited" | "ip_blocked";

export type AuthAuditEntry = {
  ts: string;
  event: AuthAuditEventType;
  clientIp?: string;
  method?: string;
  reason?: string;
  user?: string;
  actorId?: string;
};

export interface AuthAuditLogger {
  log(entry: Omit<AuthAuditEntry, "ts">): void;
  flush(): Promise<void>;
}

export type AuthAuditLogConfig = AuditLogConfig & {
  maxBytes?: number;
  maxFiles?: number;
  logDir?: string;
  token?: string;
};

export function verifyLine(
  line: string,
  token: string,
): { valid: boolean; entry?: AuthAuditEntry } {
  return verifyAuditLine<AuthAuditEntry>(line, token);
}

export function createAuthAuditLogger(config?: AuthAuditLogConfig): AuthAuditLogger {
  return createAuditLogBase<AuthAuditEntry>({
    config,
    baseFilename: "gateway-auth",
    stampEntry: (entry) => entry,
  });
}
