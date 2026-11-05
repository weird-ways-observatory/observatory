// Durable Object storage in memory, shared by the recorder tests. Like the real one: a `put` of several
// keys lands together, values are copied in and out, and `transaction` lands all of its writes or none
// (copy-on-write: writes go to a private copy that replaces the map only if `fn` returns; a throw
// discards it). The real runtime's behaviour is proven in test/recorder.workerd.test.ts.
// `fault(key)` makes the next write touching `key` throw, to model a crash at that exact point.
import type { Storage, Txn } from "../src/recorder/ledger.ts";

export function storage() {
  let m = new Map<string, unknown>();
  let faultOn: string | undefined;
  const trip = (k: string) => {
    if (faultOn === k) {
      faultOn = undefined;
      throw new Error(`injected storage fault at ${k}`);
    }
  };
  const over = (map: () => Map<string, unknown>): Txn => ({
    async get<T>(k: string) { return structuredClone(map().get(k)) as T | undefined; },
    async put(e: Record<string, unknown>) {
      for (const k of Object.keys(e)) trip(k);
      for (const [k, v] of Object.entries(e)) map().set(k, structuredClone(v));
    },
    async delete(k: string) { trip(k); return map().delete(k); },
  });
  const s: Storage & { readonly m: Map<string, unknown>; fault(key: string): void } = {
    ...over(() => m),
    get m() { return m; },
    fault(key: string) { faultOn = key; },
    async transaction<T>(fn: (txn: Txn) => Promise<T>): Promise<T> {
      const copy = new Map([...m].map(([k, v]) => [k, structuredClone(v)]));
      const out = await fn(over(() => copy));
      m = copy;
      return out;
    },
  };
  return s;
}
