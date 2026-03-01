import { describe, expect, it } from "vitest";
import { sortSuggestions } from "../../ui/src/ui/sort-suggestions.ts";

describe("sortSuggestions", () => {
  it("sorts values with locale ordering and does not mutate input arrays", () => {
    const input = ["gamma", "beta", "alpha"];

    const sorted = sortSuggestions(input);

    expect(sorted).toEqual(["alpha", "beta", "gamma"]);
    expect(input).toEqual(["gamma", "beta", "alpha"]);
  });

  it("supports iterable values such as Set", () => {
    expect(sortSuggestions(new Set(["z", "a", "m"]))).toEqual(["a", "m", "z"]);
  });
});
