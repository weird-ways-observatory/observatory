// Test-only Worker for test/cfaudit.workerd.test.ts (card beec640b, REFINE 5.5): runs the real
// runCfAudit against workerd's own R2 binding, so chained conditional saves are proven on the runtime,
// not on the in-memory fake. Cloudflare's API and the alert channels are the same fakes as the unit
// tests. Never deployed: bundled by the test into a temp dir and loaded into Miniflare.
// POST {cmd, ...}: "seed" (a log), "run" ({at, n, rival}): n runs at once; `rival` = k makes a second
// writer change the state object just before the run's k-th save, so R2 itself refuses that save.
import { runCfAudit, START, STATE_KEY } from "../../src/cfaudit.ts";
import { cloudflare, env, ev, OTHER, shapes } from "../cfaudit-fakes.ts";

const H = 3_600_000, T0 = START + H;
let cf = cloudflare([]), now = T0;

export default {
  async fetch(req: Request, e: { STATE: R2Bucket }): Promise<Response> {
    const c = (await req.json()) as { cmd: string; at?: number; n?: number; rival?: number; log?: string };
    if (c.cmd === "seed") {
      // 300 changes at one millisecond: run 1 judges a page of 200, run 2 steps one skip-only page, then judges.
      const log = c.log === "tie" ? Array.from({ length: 300 }, (_, n) => ev(`t${String(n).padStart(3, "0")}`, T0, { token: OTHER })) : [ev("x1", T0, { token: OTHER }), shapes.systemDns("s1", T0 + 1000)];
      cf = cloudflare(log, { clock: () => now });
      return Response.json({ ok: true });
    }
    if (c.cmd === "run") {
      now = c.at!;
      let puts = 0;
      const bucket: Pick<R2Bucket, "get" | "put"> = {
        get: (k: string) => e.STATE.get(k),
        put: async (k: string, v: any, o?: R2PutOptions) => {
          if (++puts === c.rival) {
            const cur = await e.STATE.get(k);
            // A rival run's write. R2's etag is the content's MD5, so it must differ in bytes to change the
            // etag; a byte-identical rival is invisible to the condition and harmless (same state).
            await e.STATE.put(k, cur ? `${await cur.text()} ` : "{}");
          }
          return e.STATE.put(k, v, o);
        },
      };
      const runs = await Promise.all(Array.from({ length: c.n ?? 1 }, () => runCfAudit(env(bucket), cf.fetch, new Date(now))));
      const s = await e.STATE.get(STATE_KEY);
      return Response.json({ runs, puts, alerts: cf.alerts.length, state: s ? JSON.parse(await s.text()) : null });
    }
    return new Response("unknown", { status: 400 });
  },
};
