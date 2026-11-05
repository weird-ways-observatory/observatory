// B1's start gate (REFINE-observatory-ops.md v11 AE1, v12): Durable Object `transaction` is all-or-nothing
// in the real runtime -- workerd from wrangler's own Miniflare, offline, on a SQLite-backed object, through
// the same Storage cast the live recorder uses. If this fails, the withdrawal design does not hold.
// Harness: test/workerd/txn-harness.ts (bundled with esbuild into a temp dir; never deployed).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const dir = mkdtempSync(join(tmpdir(), "obs-txn-"));
after(() => rmSync(dir, { recursive: true, force: true }));

async function start(name: string) {
  const out = join(dir, `bundle-${name}`);
  await build({ entryPoints: [new URL("./workerd/txn-harness.ts", import.meta.url).pathname], bundle: true, format: "esm", platform: "neutral", external: ["cloudflare:workers"], outdir: out, logLevel: "silent" });
  const mf = new Miniflare(convertV4MiniflareOptions({
    modules: true, script: readFileSync(join(out, "txn-harness.js"), "utf8"), compatibilityDate: "2026-10-01",
    durableObjects: { BOX: { className: "TxnBox", useSQLite: true } }, resourcePersistencePath: join(dir, name),
  }));
  const send = async (...cmds: { method: string; args?: unknown[] }[]) =>
    (await (await mf.dispatchFetch("http://x/", { method: "POST", body: JSON.stringify(cmds.map((c) => ({ args: [], ...c }))) })).json()) as any[];
  return { mf, send };
}

test("workerd transaction: a throw after the put leaves the accounting and pending exactly as before", { timeout: 60_000 }, async () => {
  const { mf, send } = await start("fault");
  try {
    const [, r, d] = await send({ method: "seed" }, { method: "withdraw", args: [true] }, { method: "dump" });
    assert.equal(r, "threw: injected fault after the put");
    assert.deepEqual(d, { meta: { seq: 7, used: 4, bytes: 900 }, pending: { key: "k7", seq: 7 } }, "workerd transaction kept a write from a thrown closure");
  } finally {
    await mf.dispose();
  }
});

test("workerd transaction: a committed withdrawal lands the accounting and removes pending together, and survives a restart", { timeout: 60_000 }, async () => {
  const first = await start("commit");
  try {
    const [, r] = await first.send({ method: "seed" }, { method: "withdraw", args: [false] });
    assert.equal(r, "committed");
  } finally {
    await first.mf.dispose(); // every workerd started here is stopped, pass or fail (B0 limit: bound processes)
  }
  const second = await start("commit");
  try {
    const [d] = await second.send({ method: "dump" });
    assert.deepEqual(d, { meta: { seq: 6, used: 3, bytes: 800 }, pending: null });
  } finally {
    await second.mf.dispose();
  }
});
