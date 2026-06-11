// Bounded map that evicts the oldest entry when size exceeds maxEntries.
// Replaces .clear()-on-overflow patterns that lose all data at once.

export class MapGauge<K, V> {
  private readonly map = new Map<K, V>();
  private readonly maxEntries: number;

  constructor(maxEntries: number, _opts?: { label?: string }) {
    this.maxEntries = maxEntries;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) {
      this.map.delete(key);
    }
    this.map.set(key, value);
    if (this.map.size > this.maxEntries) {
      const oldest = this.map.keys().next().value;
      if (oldest !== undefined) {
        this.map.delete(oldest);
      }
    }
  }

  get(key: K): V | undefined {
    return this.map.get(key);
  }

  delete(key: K): boolean {
    return this.map.delete(key);
  }

  get size(): number {
    return this.map.size;
  }

  keys(): IterableIterator<K> {
    return this.map.keys();
  }

  values(): IterableIterator<V> {
    return this.map.values();
  }

  entries(): IterableIterator<[K, V]> {
    return this.map.entries();
  }

  [Symbol.iterator](): IterableIterator<[K, V]> {
    return this.map[Symbol.iterator]();
  }

  has(key: K): boolean {
    return this.map.has(key);
  }

  forEach(callback: (value: V, key: K, map: Map<K, V>) => void): void {
    this.map.forEach(callback);
  }

  clear(): void {
    this.map.clear();
  }

  dispose(): void {
    this.map.clear();
  }
}
