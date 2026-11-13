// Card beec640b, REFINE 5.5 and THREATS D3: chained conditional saves on workerd's own R2 binding
// (wrangler's Miniflare, offline). Harness: test/workerd/cfaudit-harness.ts, bundled with esbuild into
// a temp dir; never deployed. Production R2 returning null on a failed condition is FROM DOCS.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { START } from "../src/cfaudit.ts";

const H = 3_600_000, T0 = START + H;
const dir = mkdtempSync(join(tmpdir(), "obs-cfaudit-"));
after(() => rmSync(dir, { recursive: true, force: true }));
let bundled: string | undefined;

async function start() {
  if (!bundled) {
    const out = join(dir, "bundle");
    await build({ entryPoints: [new URL("./workerd/cfaudit-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", outdir: out, logLevel: "silent" });
    bundled = readFileSync(join(out, "cfaudit-harness.js"), "utf8");
  }
  const mf = new Miniflare(convertV4MiniflareOptions({ modules: true, script: bundled, compatibilityDate: "2026-10-01", r2Buckets: ["STATE"] }));
  const send = async (body: object) => (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(body) })).json()) as any;
  return { mf, send };
}
const holds = (r: any) => /another run holds the state/.test(String(r.reason));

test("workerd: two runs at once -- one wins and alerts; the other stops at its first save and sends nothing", { timeout: 60_000 }, async () => {
  const { mf, send } = await start();
  try {
    await send({ cmd: "seed" });
    await send({ cmd: "run", at: T0 + H }); // creates state
    const r = await send({ cmd: "run", at: T0 + 2 * H, n: 2 });
    assert.equal(r.runs.filter(holds).length, 1, JSON.stringify(r.runs.map((x: any) => x.reason)));
    assert.equal(r.alerts, 1, "the first run's alert only");
  } finally {
    await mf.dispose();
  }
});

test("workerd: a full multi-page run completes every save in its chain (skip-only page, judging page, untold, told)", { timeout: 60_000 }, async () => {
  const { mf, send } = await start();
  try {
    await send({ cmd: "seed", log: "tie" });
    const r1 = await send({ cmd: "run", at: T0 + H });
    assert.equal(r1.runs[0].cfaudit, "ran");
    const r2 = await send({ cmd: "run", at: T0 + 2 * H });
    assert.equal(r2.runs[0].cfaudit, "ran", r2.runs[0].reason);
    assert.equal(r2.puts, 4, "skip-only page, judging page, untold, told");
    const changes = r2.state.incidents.filter((i: any) => i.id.startsWith("change:")).length;
    assert.equal(changes + r2.state.dropped, 300, "all 300 at one millisecond judged once, listed or counted");
    assert.ok(r2.state.bm.t > T0, "stepped past the tie");
    assert.ok(r2.state.incidents.every((i: any) => i.told));
  } finally {
    await mf.dispose();
  }
});

test("workerd: a rival write before each save makes R2 refuse it; the run stops, nothing after it is sent or marked told", { timeout: 120_000 }, async () => {
  for (const k of [1, 2, 3]) {
    const { mf, send } = await start();
    try {
      await send({ cmd: "seed" });
      const r = await send({ cmd: "run", at: T0 + H, rival: k });
      assert.ok(holds(r.runs[0]), `save ${k}: ${r.runs[0].reason}`);
      assert.equal(r.puts, k, `save ${k}: no save after the refused one`);
      if (k <= 2) assert.equal(r.alerts, 0, `save ${k}: refused before sending`);
      else assert.equal(r.alerts, 1, "save 3 is the told-save: the alert went, and stays untold for the next run");
      if (r.state?.incidents) assert.ok(r.state.incidents.every((i: any) => !i.told), `save ${k}: nothing marked told`);
    } finally {
      await mf.dispose();
    }
  }
});
