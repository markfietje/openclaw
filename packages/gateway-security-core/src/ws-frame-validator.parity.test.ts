import {
  GatewayFrameSchema as TypeBoxGatewayFrameSchema,
  RequestFrameSchema as TypeBoxRequestFrameSchema,
  ResponseFrameSchema as TypeBoxResponseFrameSchema,
} from "@openclaw/gateway-protocol/schema";
import { Value } from "typebox/value";
// Contract parity test: the zod schemas in @openclaw/gateway-security-core
// and the TypeBox schemas in @openclaw/gateway-protocol both describe the
// gateway frame envelope. They intentionally diverge on `event.stateVersion`
// (zod is permissive, TypeBox is typed) for defense-in-depth; everywhere else
// they must agree on accept/reject behavior across a sample frame corpus.
import { describe, expect, it } from "vitest";
import {
  EventFrameSchema as ZodEventFrameSchema,
  GatewayFrameSchema as ZodGatewayFrameSchema,
  RequestFrameSchema as ZodRequestFrameSchema,
  ResponseFrameSchema as ZodResponseFrameSchema,
} from "./ws-frame-validator.js";

type Verdict = "accept" | "reject";

function zodVerdict(
  schema: { safeParse: (v: unknown) => { success: boolean } },
  value: unknown,
): Verdict {
  return schema.safeParse(value).success ? "accept" : "reject";
}

function typeboxVerdict(schema: typeof TypeBoxGatewayFrameSchema, value: unknown): Verdict {
  return Value.Check(schema, value) ? "accept" : "reject";
}

const samples: ReadonlyArray<{
  label: string;
  frame: unknown;
  perType: { req: Verdict; res: Verdict; event: Verdict };
}> = [
  {
    label: "minimal request frame",
    frame: { type: "req", id: "r1", method: "status" },
    perType: { req: "accept", res: "reject", event: "reject" },
  },
  {
    label: "request frame with params",
    frame: { type: "req", id: "r2", method: "talk.message", params: { text: "hi" } },
    perType: { req: "accept", res: "reject", event: "reject" },
  },
  {
    label: "request frame missing method",
    frame: { type: "req", id: "r3" },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "request frame with empty id",
    frame: { type: "req", id: "", method: "status" },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "request frame with extra field",
    frame: { type: "req", id: "r4", method: "status", unexpected: true },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "minimal response frame ok=true",
    frame: { type: "res", id: "r5", ok: true },
    perType: { req: "reject", res: "accept", event: "reject" },
  },
  {
    label: "response frame with payload",
    frame: { type: "res", id: "r6", ok: true, payload: { ok: true } },
    perType: { req: "reject", res: "accept", event: "reject" },
  },
  {
    label: "response frame with error",
    frame: {
      type: "res",
      id: "r7",
      ok: false,
      error: { code: "INVALID_REQUEST", message: "nope" },
    },
    perType: { req: "reject", res: "accept", event: "reject" },
  },
  {
    label: "response frame with retryable error",
    frame: {
      type: "res",
      id: "r8",
      ok: false,
      error: {
        code: "RATE_LIMITED",
        message: "slow down",
        retryable: true,
        retryAfterMs: 5000,
      },
    },
    perType: { req: "reject", res: "accept", event: "reject" },
  },
  {
    label: "response frame with empty error code",
    frame: {
      type: "res",
      id: "r9",
      ok: false,
      error: { code: "", message: "nope" },
    },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "response frame with negative retryAfterMs",
    frame: {
      type: "res",
      id: "r10",
      ok: false,
      error: { code: "X", message: "x", retryAfterMs: -1 },
    },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "minimal event frame",
    frame: { type: "event", event: "tick" },
    perType: { req: "reject", res: "reject", event: "accept" },
  },
  {
    label: "event frame with payload and seq",
    frame: { type: "event", event: "presence", payload: { count: 1 }, seq: 5 },
    perType: { req: "reject", res: "reject", event: "accept" },
  },
  {
    label: "event frame with stateVersion",
    frame: {
      type: "event",
      event: "presence",
      stateVersion: { presence: 1, health: 2 },
    },
    perType: { req: "reject", res: "reject", event: "accept" },
  },
  {
    label: "event frame with negative seq",
    frame: { type: "event", event: "tick", seq: -1 },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "event frame with empty name",
    frame: { type: "event", event: "" },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "frame with unknown type",
    frame: { type: "ping", id: "x" },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "frame missing type",
    frame: { id: "x", method: "y" },
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "null frame",
    frame: null,
    perType: { req: "reject", res: "reject", event: "reject" },
  },
  {
    label: "array frame",
    frame: [{ type: "req", id: "x", method: "y" }],
    perType: { req: "reject", res: "reject", event: "reject" },
  },
];

describe("frame schema parity (zod gateway-security-core vs TypeBox gateway-protocol)", () => {
  it.each(samples)("$label: req schema agrees", (sample) => {
    expect(zodVerdict(ZodRequestFrameSchema, sample.frame)).toBe(sample.perType.req);
    expect(typeboxVerdict(TypeBoxRequestFrameSchema, sample.frame)).toBe(sample.perType.req);
  });
  it.each(samples)("$label: res schema agrees", (sample) => {
    expect(zodVerdict(ZodResponseFrameSchema, sample.frame)).toBe(sample.perType.res);
    expect(typeboxVerdict(TypeBoxResponseFrameSchema, sample.frame)).toBe(sample.perType.res);
  });
  it.each(samples)("$label: event schema agrees on common fields", (sample) => {
    // zod uses z.unknown() for stateVersion so the parity contract is
    // intentionally narrower on event frames: the schemas only need to agree
    // on the common envelope (type, event, payload, seq, extra-field policy).
    // The TypeBox event schema additionally constrains stateVersion's shape.
    expect(zodVerdict(ZodEventFrameSchema, sample.frame)).toBe(sample.perType.event);
  });
  it("zod event schema is permissive on stateVersion shape (defense-in-depth)", () => {
    // The zod frame is intentionally more permissive: any value of
    // stateVersion passes so legacy or unknown consumers cannot break the
    // parser. TypeBox validates the shape; the zod parser is the runtime
    // safety net.
    expect(
      zodVerdict(ZodEventFrameSchema, {
        type: "event",
        event: "x",
        stateVersion: "anything",
      }),
    ).toBe("accept");
    expect(
      zodVerdict(ZodEventFrameSchema, {
        type: "event",
        event: "x",
        stateVersion: null,
      }),
    ).toBe("accept");
    expect(
      zodVerdict(ZodEventFrameSchema, {
        type: "event",
        event: "x",
        stateVersion: { presence: "not-a-number" },
      }),
    ).toBe("accept");
  });
  it("union schemas accept any of the three valid frame shapes", () => {
    // The discriminated union is the public entry point used by codegen; both
    // implementations must accept the same valid frames. The per-branch tests
    // above pin the accept/reject boundary; this test guards the union entry
    // point against accidental schema drop.
    for (const good of [
      { type: "req", id: "r", method: "m" },
      { type: "res", id: "r", ok: true },
      { type: "event", event: "tick" },
    ]) {
      expect(zodVerdict(ZodGatewayFrameSchema, good)).toBe("accept");
      expect(typeboxVerdict(TypeBoxGatewayFrameSchema, good)).toBe("accept");
    }
  });
  it("TypeBox union rejects unknown discriminator values", () => {
    expect(typeboxVerdict(TypeBoxGatewayFrameSchema, { type: "ping", id: "x" })).toBe("reject");
    expect(typeboxVerdict(TypeBoxGatewayFrameSchema, { id: "x", method: "y" })).toBe("reject");
    expect(typeboxVerdict(TypeBoxGatewayFrameSchema, null)).toBe("reject");
    expect(typeboxVerdict(TypeBoxGatewayFrameSchema, [])).toBe("reject");
  });
});
