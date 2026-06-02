import { createAuditLogBase, verifyAuditLine, type AuditLogConfig } from "./audit-log-base.js";

export type ToolAuditEventType = "tool.call" | "tool.result" | "tool.error";

export type ToolAuditEntry = {
  ts: string;
  source: "gateway";
  event: ToolAuditEventType;
  surface: string;
  tool: string;
  actorId?: string;
  session?: string;
  channel?: string;
  model?: string;
  runId?: string;
  toolCallId?: string;
  resultStatus?: "success" | "failure" | "denied";
  durationMs?: number;
};

export interface ToolAuditLogger {
  log(entry: Omit<ToolAuditEntry, "ts" | "source">): void;
  flush(): Promise<void>;
}

export type ToolAuditLogConfig = AuditLogConfig & {
  maxBytes?: number;
  maxFiles?: number;
  logDir?: string;
  token?: string;
};

export function verifyToolAuditLine(
  line: string,
  token: string,
): { valid: boolean; entry?: ToolAuditEntry } {
  return verifyAuditLine<ToolAuditEntry>(line, token);
}

export function createToolAuditLogger(config?: ToolAuditLogConfig): ToolAuditLogger {
  return createAuditLogBase<ToolAuditEntry>({
    config,
    baseFilename: "gateway-tool-audit",
    stampEntry: (entry) => ({ ...entry, source: "gateway" as const }),
  });
}
