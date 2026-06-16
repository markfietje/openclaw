// Chat input sanitizer tests: bidi/zero-width control stripping and basic
// validation (null bytes, length cap) for gateway chat send payloads.
import { describe, expect, it } from "vitest";
import { sanitizeChatSendMessageInput } from "./chat-input-sanitize.js";

describe("sanitizeChatSendMessageInput", () => {
  it("rejects null bytes before filtering", () => {
    expect(sanitizeChatSendMessageInput("before\u0000after")).toEqual({
      ok: false,
      error: "message must not contain null bytes",
    });
  });

  it("strips every disallowed C0 character and DEL", () => {
    const disallowed = [
      ...Array.from({ length: 8 }, (_, index) => String.fromCharCode(index + 1)),
      String.fromCharCode(0x0b, 0x0c),
      ...Array.from({ length: 18 }, (_, index) => String.fromCharCode(index + 0x0e)),
      String.fromCharCode(0x7f),
    ].join("");
    expect(sanitizeChatSendMessageInput(`before${disallowed}after`)).toEqual({
      ok: true,
      message: "beforeafter",
    });
  });

  it("preserves whitespace, printable text, C1 boundaries, and Unicode", () => {
    const input = `\t\n\r ~${String.fromCharCode(0x80)}${String.fromCharCode(0x9f)}世界😀`;
    expect(sanitizeChatSendMessageInput(input)).toEqual({ ok: true, message: input });
  });

  it("normalizes Unicode to NFC", () => {
    expect(sanitizeChatSendMessageInput("Cafe\u0301")).toEqual({
      ok: true,
      message: "Café",
    });
  });

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
