// Test-only Worker for test/recorder.workerd.test.ts: the recorder's Storage adapter (Cloudflare's own
// ctx.storage, passed exactly as src/recorder/index.ts passes it) inside a real SQLite Durable Object, so
// the all-or-nothing behaviour of `transaction` is proven on workerd itself, not on the in-memory copy.
// Never deployed: bundled by the test into a temp dir and loaded into Miniflare. Commands: POST {method, args}.
import { DurableObject } from "cloudflare:workers";
import type { Storage } from "../../src/recorder/ledger.ts";

export class TxnBox extends DurableObject {
  // The same cast the live Recorder makes (src/recorder/index.ts).
  private get s() { return this.ctx.storage as unknown as Storage; }
  async seed() {
    await this.s.put({ meta: { seq: 7, used: 4, bytes: 900 }, pending: { key: "k7", seq: 7 } });
  }
  // The withdrawal shape (REFINE v11 AE1): the accounting put and delete("pending") in one transaction.
  // `faultAfterPut` throws between the two, as a crash inside the step would.
  async withdraw(faultAfterPut: boolean) {
    try {
      await this.s.transaction(async (t) => {
        const m = (await t.get<{ seq: number; used: number; bytes: number }>("meta"))!;
        await t.put({ meta: { ...m, seq: m.seq - 1, used: m.used - 1, bytes: m.bytes - 100 } });
        if (faultAfterPut) throw new Error("injected fault after the put");
        await t.delete("pending");
      });
      return "committed";
    } catch (e) {
      return `threw: ${(e as Error).message}`;
    }
  }
  async dump() {
    return { meta: (await this.s.get("meta")) ?? null, pending: (await this.s.get("pending")) ?? null };
  }
}

export default {
  async fetch(request: Request, env: { BOX: DurableObjectNamespace<TxnBox> }) {
    const stub = env.BOX.get(env.BOX.idFromName("v1")) as unknown as Record<string, (...a: unknown[]) => Promise<unknown>>;
    const out: unknown[] = [];
    for (const c of (await request.json()) as { method: string; args: unknown[] }[]) out.push(await stub[c.method]!(...c.args));
    return Response.json(out);
  },
};
