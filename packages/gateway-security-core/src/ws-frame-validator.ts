import { z } from "zod";

// --- Frame schemas (mirrors TypeBox schemas in gateway-protocol for defense-in-depth) ---

const ErrorShapeSchema = z
  .object({
    code: z.string().min(1),
    message: z.string().min(1),
    details: z.unknown().optional(),
    retryable: z.boolean().optional(),
    retryAfterMs: z.number().int().min(0).optional(),
  })
  .strict();

export const RequestFrameSchema = z
  .object({
    type: z.literal("req"),
    id: z.string().min(1),
    method: z.string().min(1),
    params: z.unknown().optional(),
  })
  .strict();

export const ResponseFrameSchema = z
  .object({
    type: z.literal("res"),
    id: z.string().min(1),
    ok: z.boolean(),
    payload: z.unknown().optional(),
    error: ErrorShapeSchema.optional(),
  })
  .strict();

export const EventFrameSchema = z
  .object({
    type: z.literal("event"),
    event: z.string().min(1),
    payload: z.unknown().optional(),
    seq: z.number().int().min(0).optional(),
    stateVersion: z.unknown().optional(),
  })
  .strict();

export const GatewayFrameSchema: z.ZodTypeAny = z.discriminatedUnion("type", [
  RequestFrameSchema,
  ResponseFrameSchema,
  EventFrameSchema,
]);

export type InboundRequestFrame = z.infer<typeof RequestFrameSchema>;
export type GatewayFrame = z.infer<typeof GatewayFrameSchema>;

export interface FrameValidationResult {
  ok: boolean;
  frameType?: "req" | "res" | "event";
  method?: string;
  id?: string;
  error?: string;
}

/**
 * Validate an inbound WebSocket frame against the gateway frame schema.
 * Defense-in-depth: catches malformed frames even if protocol-level validation is bypassed.
 * Returns a structured result — never throws.
 */
export function validateInboundFrame(raw: unknown): FrameValidationResult {
  if (raw === null || raw === undefined || typeof raw !== "object" || Array.isArray(raw)) {
    return { ok: false, error: "frame must be a non-null object" };
  }

  const obj = raw as Record<string, unknown>;

  // Extract type for fast-path before full schema validation
  if (typeof obj.type !== "string") {
    return { ok: false, error: "frame.type must be a string" };
  }

  const frameType = obj.type as "req" | "res" | "event";

  // Select schema based on type for better error messages
  let schema: z.ZodTypeAny;
  switch (frameType) {
    case "req":
      schema = RequestFrameSchema;
      break;
    case "res":
      schema = ResponseFrameSchema;
      break;
    case "event":
      schema = EventFrameSchema;
      break;
    default:
      return { ok: false, error: `unknown frame type: "${obj.type}"` };
  }

  const result = schema.safeParse(raw);
  if (!result.success) {
    const firstIssue = result.error.issues[0];
    const path = firstIssue?.path.join(".") ?? "?";
    const message = firstIssue?.message ?? "validation failed";
    return { ok: false, error: `frame validation failed at ${path}: ${message}` };
  }

  // Extract metadata for capability gating
  const validated = result.data as Record<string, unknown>;
  return {
    ok: true,
    frameType,
    method: typeof validated.method === "string" ? validated.method : undefined,
    id: typeof validated.id === "string" ? validated.id : undefined,
  };
}
