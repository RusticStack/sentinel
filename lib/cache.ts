/** In-memory TTL cache for GitHub, Vigil, and membership responses. */

type Entry<T> = {
  value: T;
  expiresAt: number;
};

export class TtlCache {
  #store = new Map<string, Entry<unknown>>();

  get<T>(key: string): T | undefined {
    const entry = this.#store.get(key);
    if (!entry) return undefined;
    if (Date.now() >= entry.expiresAt) {
      this.#store.delete(key);
      return undefined;
    }
    return entry.value as T;
  }

  set<T>(key: string, value: T, ttlMs: number): void {
    this.#store.set(key, { value, expiresAt: Date.now() + ttlMs });
  }

  delete(key: string): void {
    this.#store.delete(key);
  }

  clear(): void {
    this.#store.clear();
  }
}

export const cache = new TtlCache();
