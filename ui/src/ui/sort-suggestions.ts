type StringArrayWithToSorted = string[] & {
  toSorted?: (compareFn?: (left: string, right: string) => number) => string[];
};

export function sortSuggestions(values: Iterable<string>): string[] {
  const list = Array.from(values);
  const withToSorted = list as StringArrayWithToSorted;
  if (typeof withToSorted.toSorted === "function") {
    return withToSorted.toSorted((left, right) => left.localeCompare(right));
  }
  // eslint-disable-next-line unicorn/no-array-sort -- fallback for browsers that do not implement Array.prototype.toSorted.
  return [...list].sort((left, right) => left.localeCompare(right));
}
