// Chat input sanitizer tests: bidi/zero-width control stripping and basic
// validation (null bytes, length cap) for gateway chat send payloads.
import { describe, expect, it } from "vitest";
import { sanitizeChatSendMessageInput } from "./chat-input-sanitize.js";

describe("sanitizeChatSendMessageInput", () => {
  it("passes through normal text", () => {
    const result = sanitizeChatSendMessageInput("hello world");
    expect(result).toEqual({ ok: true, message: "hello world" });
  });

  it("preserves tab, LF, CR", () => {
    const result = sanitizeChatSendMessageInput("a\tb\nc\rd");
    expect(result).toEqual({ ok: true, message: "a\tb\nc\rd" });
  });

  it("rejects null bytes", () => {
    const result = sanitizeChatSendMessageInput("ab\u0000cd");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/null bytes/);
    }
  });

  it("rejects messages over the max length", () => {
    const result = sanitizeChatSendMessageInput("x".repeat(100_001));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toMatch(/maximum length/);
    }
  });

  it("strips zero-width and bidi override characters", () => {
    // U+200B ZW space, U+202E RLO override, U+2066 LRI, U+FEFF BOM
    const input = "a\u200Bb\u202Ec\u2066d\uFEFFe";
    const result = sanitizeChatSendMessageInput(input);
    expect(result).toEqual({ ok: true, message: "abcde" });
  });

  it("strips U+061C Arabic Letter Mark (invisible bidi control)", () => {
    const input = "a\u061Cb";
    const result = sanitizeChatSendMessageInput(input);
    expect(result).toEqual({ ok: true, message: "ab" });
  });

  it("strips a U+061C-based spoofing attempt while keeping visible text", () => {
    const input = "user\u061C@example.com";
    const result = sanitizeChatSendMessageInput(input);
    expect(result).toEqual({ ok: true, message: "user@example.com" });
  });
});
