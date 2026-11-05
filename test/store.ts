// Durable Object storage in memory, shared by the recorder tests. Like the real one: a `put` of several
// keys lands together, values are copied in and out, and `transaction` lands all of its writes or none
// (copy-on-write: writes go to a private copy that replaces the map only if `fn` returns; a throw
// discards it). The real runtime's behaviour is proven in test/recorder.workerd.test.ts.
// `fault(key, skip)` makes a write touching `key` throw, after `skip` such writes pass, to model a crash
// at that exact point.
import type { Storage, Txn } from "../src/recorder/ledger.ts";

export function storage() {
  let m = new Map<string, unknown>();
  let faultOn: string | undefined, skips = 0;
  const trip = (k: string) => {
    if (faultOn === k && skips-- <= 0) {
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
  const s: Storage & { readonly m: Map<string, unknown>; fault(key: string, skip?: number): void } = {
    ...over(() => m),
    get m() { return m; },
    fault(key: string, skip = 0) { faultOn = key; skips = skip; },
    async transaction<T>(fn: (txn: Txn) => Promise<T>): Promise<T> {
      const copy = new Map([...m].map(([k, v]) => [k, structuredClone(v)]));
      const out = await fn(over(() => copy));
      m = copy;
      return out;
    },
  };
  return s;
}

// The records bucket in memory: get, head, list and put, with a switch to make the next puts fail.
export function bucket() {
  const store = new Map<string, { body: string; sha?: string; raw?: Uint8Array }>();
  let failPuts = 0;
  return {
    store,
    failNext(n = 1) { failPuts = n; },
    async head(k: string) { const v = store.get(k); return v ? ({ key: k, customMetadata: { sha256: v.sha } } as unknown as R2Object) : null; },
    async get(k: string) { const v = store.get(k); return v ? ({ key: k, text: async () => v.body, arrayBuffer: async () => (v.raw ?? new TextEncoder().encode(v.body)).buffer } as unknown as R2ObjectBody) : null; },
    async list(o: { prefix?: string; limit?: number }) { return { objects: [...store.keys()].sort().filter((k) => k.startsWith(o.prefix ?? "")).slice(0, o.limit ?? 1000).map((key) => ({ key })), truncated: false, delimitedPrefixes: [] } as unknown as R2Objects; },
    async put(k: string, body: string, o?: R2PutOptions) {
      if (failPuts > 0) { failPuts--; throw new Error("R2 down"); }
      store.set(k, { body, sha: o?.customMetadata?.sha256 });
      return {} as R2Object;
    },
  };
}
