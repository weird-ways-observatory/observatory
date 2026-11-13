// Card beec640b build b, the consumer (studio-os docs/specifications/trust-but-verify/REFINE-beec640b-build-b.md v3.3:
// sections 4.4-4.7 as overridden by 12 and 13). cfaudit judges each master-key create or delete against the `effects`
// the records check publishes. Most rows write `effects` straight into state/records.json (the records side's own
// projection is proven in effects.test.ts); rows 10, 26 and 27 run the production path, runRecords then runCfAudit.
// Test names carry their evidence-matrix row. Every id is synthetic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runCfAudit, STATE_KEY, SETTLE_MS } from "../src/cfaudit.ts";
import { EPOCHS_KEY, MAX_PENDING, RESULT_WAIT_MS, WARM_MS } from "../src/cfmatch.ts";
import { b64, keyFor, sealed, sha256, type Envelope, type Stage } from "../src/contract.ts";
import { CF_FROM } from "../src/card.ts";
import { runRecords, STATE_KEY as RECORDS_KEY, type Pin, type RecordsEnv } from "../src/records.ts";
import { grantHashOf } from "../src/recorder/passkey.ts";
import { bucket, cloudflare, env, MASTER, shapes, state } from "./cfaudit-fakes.ts";

const MIN = 60_000, H = 60 * MIN;
const S = CF_FROM + H; // effects.since in the hand-written rows
const ON = S + WARM_MS; // B_FROM
const T = ON + 2 * H; // taps in the active period
const id = (n: number) => n.toString(16).padStart(32, "0");
type Ev = Record<string, any>;

/** A master create naming its new key as Cloudflare does (resource.response.id), with name and expiry. */
function mc(eid: string, t: number, key: string, o: { name?: string; exp?: number | null; result?: string } = {}): Ev {
  const e = shapes.masterCreate(eid, t);
  e.resource.response = { id: key, name: o.name ?? "front-desk probe x", ...(o.exp === null ? {} : { expires_on: new Date(o.exp ?? t + 5 * MIN).toISOString() }) };
  if (o.result) e.action.result = o.result;
  return e;
}
function md(eid: string, t: number, key: string, result?: string): Ev {
  const e = shapes.masterDelete(eid, t);
  e.resource.id = key;
  if (result) e.action.result = result;
  return e;
}
/** The headcount key's own nightly read, logged under its token id. */
const hcRead = (eid: string, t: number, key: string) => { const e = shapes.view(eid, t, key); e.action.description = "List Tokens"; e.resource = { product: "tokens" }; return e; };

const st = (n: number, at: number) => ({ n, sha: "s".repeat(64), at });
let rn = 0;
/** One effects entry: approved at `t`, result recorded at `t + len`. */
function grant(job: string, t: number, cf: unknown, o: { len?: number; tainted?: string; path?: string } = {}) {
  rn += 3;
  return { job, path: o.path ?? "ordinary", req: st(rn - 2, t - MIN), appr: st(rn - 1, t), res: st(rn, t + (o.len ?? 2 * MIN)), cf, ...(o.tainted ? { tainted: o.tainted } : {}) };
}

function world(grants: Record<string, unknown> = {}, over: Record<string, unknown> = {}) {
  let now = 0;
  const b = bucket(), log: Ev[] = [], cf = cloudflare(log, { clock: () => now });
  let gen = 1;
  const fx = { gen, since: S, covered_to: 0, grants, retired: {} as Record<string, number>, index: {}, revoked: {} as Record<string, string>, ...over };
  const publish = () => b.store.set(RECORDS_KEY, { body: JSON.stringify({ effects: { ...fx, gen: gen++ } }), etag: `r${gen}` });
  publish();
  const run = async (t: number, coveredTo = t - 15 * MIN) => {
    fx.covered_to = Math.max(fx.covered_to, coveredTo);
    publish();
    now = t;
    return runCfAudit(env(b), cf.fetch, new Date(t), ON - 2 * H);
  };
  const inc = () => (state(b).incidents as { id: string; text: string; told: boolean }[]);
  const has = (p: string) => inc().filter((i) => i.id.startsWith(p));
  const m = () => state(b).m;
  return { b, log, cf, fx, publish, run, inc, has, m };
}
const add = (w: ReturnType<typeof world>, ...e: Ev[]) => { w.log.push(...e); w.log.sort((x, y) => Date.parse(x.action.time) - Date.parse(y.action.time)); };

test("row 1: an honest trace per job is matched with no unmatched alert and a clean reverse check", async () => {
  const hcOld = id(90), hcNew = id(91);
  const w = world({
    "aaaaaaaa-dns": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [id(1), id(2)] }, { path: "card" }),
    "bbbbbbbb-aud": grant("cf.audit.read", T + 10 * MIN, { made: [id(3)], deleted: [id(3), id(9)] }),
    "cccccccc-acc": grant("cf.token.accept", T + 20 * MIN, { made: [], deleted: [id(10), id(11)] }),
    "dddddddd-hc": grant("cf.token.headcount.setup", T + 30 * MIN, { made: [hcNew], deleted: [hcOld] }),
    "eeeeeeee-zon": grant("cf.zone.read", T + 40 * MIN, { made: [id(4), id(5)], deleted: [id(4), id(5)] }),
  });
  add(w, mc("e1", T + 10_000, id(1)), md("e2", T + 11_000, id(1)), mc("e3", T + 12_000, id(2)), md("e4", T + 13_000, id(2)));
  add(w, mc("e5", T + 10 * MIN + 10_000, id(3)), md("e6", T + 10 * MIN + 11_000, id(3)), md("e7", T + 10 * MIN + 12_000, id(9)));
  add(w, md("e8", T + 20 * MIN + 10_000, id(10)), md("e9", T + 20 * MIN + 11_000, id(11)));
  add(w, mc("e10", T + 30 * MIN + 10_000, hcNew, { name: "front-desk headcount 2026", exp: null }), md("e11", T + 30 * MIN + 12_000, hcOld));
  add(w, mc("e12", T + 40 * MIN + 10_000, id(4)), md("e13", T + 40 * MIN + 11_000, id(4)), mc("e14", T + 40 * MIN + 12_000, id(5)), md("e15", T + 40 * MIN + 13_000, id(5)));
  add(w, hcRead("r1", T + 50 * MIN, hcNew));
  const r = await w.run(T + 3 * H);
  assert.equal(r.cfaudit, "ran", String(r.reason));
  assert.deepEqual(w.has("change:").map((i) => i.id), [], "an honest master write alerted as unmatched");
  assert.deepEqual(w.has("reverse:"), [], "the reverse check flagged an honest tap");
  assert.equal(w.m().expl.length, 15, "not every honest master write was matched");
  assert.equal(w.m().pend.length, 0, "an honest write is still pending");
});

test("row 2: a create and a delete no tap names alert once coverage passes; held before", async () => {
  const w = world();
  add(w, mc("x1", T, id(1)), md("x2", T + 1000, id(2)));
  await w.run(T + 25 * MIN, T + RESULT_WAIT_MS - 1);
  assert.equal(w.has("change:").length, 0, "an event alerted before its result could have been recorded");
  assert.equal(w.m().pend.length, 2, "the unexplained events were not held pending");
  await w.run(T + 85 * MIN, T + 1000 + RESULT_WAIT_MS);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:x1", "change:x2"], "an unnamed create or delete did not alert");
  assert.match(w.has("change:x1")[0].text, /master key that no approved tap names/, "the alert does not say what it is");
  assert.doesNotMatch(w.has("change:x1")[0].text, new RegExp(id(1)), "the alert names the key");
});

test("row 2: a master-key update alerts at once", async () => {
  const w = world();
  const u = shapes.masterCreate("u1", T); u.action.type = "update";
  add(w, u);
  await w.run(T + 25 * MIN, 0);
  assert.equal(w.has("change:u1").length, 1, "a master update did not alert at once");
});

test("row 3: one key named twice for the same action alerts; made by one tap and deleted by another is clean", async () => {
  const w = world({
    "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1), id(7)], deleted: [] }),
    "bbbbbbbb-2": grant("cf.dns.list", T, { made: [id(1)], deleted: [id(7)] }),
  });
  add(w, mc("d1", T + 10_000, id(1)), mc("d2", T + 11_000, id(7)), md("d3", T + 12_000, id(7)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id), ["change:d1"], "a doubly named key matched, or made-here deleted-there alerted");
  assert.match(w.has("change:d1")[0].text, /two taps name/, "the alert does not say two taps name the key");
});

test("row 3: a second event for the same key and action is an incident, never a second match", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [] }) });
  add(w, mc("s1", T + 10_000, id(1)), mc("s2", T + 11_000, id(1)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id), ["change:s2"], "a second event id for one key action was matched");
});

test("row 4: an event before the approval or after the result alerts", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [] }) });
  add(w, mc("w1", T - 1, id(1)), mc("w2", T + 2 * MIN + 1, id(2)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:w1", "change:w2"], "an event outside its tap's window matched");
});

test("row 5: creates over the job's count alert (two for audit.read, any for accept)", async () => {
  const w = world({
    "aaaaaaaa-1": grant("cf.audit.read", T, { made: [id(1), id(2)], deleted: [] }),
    "bbbbbbbb-2": grant("cf.token.accept", T, { made: [id(3)], deleted: [] }),
  });
  add(w, mc("c1", T + 10_000, id(1)), mc("c2", T + 11_000, id(2)), mc("c3", T + 12_000, id(3)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:c2", "change:c3"], "a create over the job's count matched");
});

test("row 5: deletes over the job's count alert", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.token.accept", T, { made: [], deleted: [id(1), id(2), id(3)] }) });
  add(w, md("k1", T + 10_000, id(1)), md("k2", T + 11_000, id(2)), md("k3", T + 12_000, id(3)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id), ["change:k3"], "a delete over the job's count matched");
});

test("row 6: a create whose name, expiry or kind does not fit its job alerts", async () => {
  const w = world({
    "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [] }),
    "bbbbbbbb-2": grant("cf.token.headcount.setup", T, { made: [id(3)], deleted: [] }),
    "cccccccc-3": grant("cf.zone.read", T, { made: [id(4)], deleted: [] }),
  });
  add(w, mc("h1", T + 10_000, id(1), { name: "something else" }), mc("h2", T + 11_000, id(2), { exp: T + 11_000 + 2 * H }));
  add(w, mc("h3", T + 12_000, id(3), { name: "front-desk headcount x", exp: T + H }), mc("h4", T + 13_000, id(4), { exp: null }));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:h1", "change:h2", "change:h3", "change:h4"], "a misshapen create matched");
  assert.match(w.has("change:h1")[0].text, /shape/, "the alert does not say the shape is wrong");
});

test("row 7: a tap with cf unknown, legacy none, or tainted explains nothing, with the right words", async () => {
  const w = world({
    "aaaaaaaa-un": grant("cf.dns.list", T, "unknown"),
    "bbbbbbbb-no": grant("cf.dns.list", T + 10 * MIN, "none"),
    "cccccccc-ta": grant("cf.dns.list", T + 20 * MIN, { made: [id(3)], deleted: [] }, { tainted: "bad" }),
  });
  add(w, mc("u1", T + 10_000, id(1)), mc("u2", T + 10 * MIN + 10_000, id(2)), mc("u3", T + 20 * MIN + 10_000, id(3)));
  await w.run(T + 2 * H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:u1", "change:u2", "change:u3"], "an unknown, none or tainted tap explained a key");
  assert.match(w.has("change:u1")[0].text, /a front-desk tap could not say which keys it touched.*aaaaaaaa/, "the unknown words or grant are missing");
});

test("row 8: a named id with no event, or with its event outside the window, is one reverse incident; taps before B_FROM are not checked", async () => {
  const w = world({
    "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [] }),
    "bbbbbbbb-2": grant("cf.dns.list", T + 10 * MIN, { made: [id(3)], deleted: [] }),
    "cccccccc-0": grant("cf.dns.list", ON - H, { made: [id(5)], deleted: [] }),
  });
  add(w, mc("v1", T + 10_000, id(1)), mc("v3", T + 13 * MIN, id(3)));
  await w.run(T + 2 * H);
  assert.deepEqual(w.has("reverse:").map((i) => i.id).sort(), ["reverse:aaaaaaaa-1", "reverse:bbbbbbbb-2"], "a reverse miss was not one incident per tap, or a pre-activation tap was checked");
  await w.run(T + 3 * H);
  assert.equal(w.has("reverse:").length, 2, "the reverse check ran twice");
});

test("row 9: a helper outliving 24 h is an incident; the installed headcount key with an in-use read is not; a leftover candidate is", async () => {
  const cand = id(20), inst = id(21);
  const w = world({
    "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }),
    "bbbbbbbb-hc": grant("cf.token.headcount.setup", T + 10 * MIN, { made: [inst], deleted: [] }),
    "cccccccc-hc": grant("cf.token.headcount.setup", T + 20 * MIN, { made: [cand], deleted: [] }),
  });
  add(w, mc("o1", T + 10_000, id(1)), mc("o2", T + 10 * MIN + 10_000, inst, { name: "front-desk headcount a", exp: null }), mc("o3", T + 20 * MIN + 10_000, cand, { name: "front-desk headcount b", exp: null }));
  add(w, hcRead("rd", T + 26 * H, inst));
  await w.run(T + 2 * H);
  await w.run(T + 26 * H);
  assert.deepEqual(w.has("outlived:").map((i) => i.id), ["outlived:o1"], "a 24 h helper was not flagged, or a headcount key was decided early");
  await w.run(T + 50 * H);
  assert.deepEqual(w.has("outlived:").map((i) => i.id).sort(), ["outlived:o1", "outlived:o3"], "a never-read candidate was exempt, or the installed key was flagged");
});

test("row 11: records 1 h behind holds; 6 h raises one incomplete incident; recovery judges once", async () => {
  const w = world();
  add(w, mc("p1", T, id(1)));
  await w.run(T + H, T - 2 * H);
  assert.equal(w.has("change:").length + w.has("incomplete").length, 0, "a held event alerted or went incomplete within the hour");
  await w.run(T + 7 * H, T - 2 * H);
  await w.run(T + 8 * H, T - 2 * H);
  assert.equal(w.has("incomplete").length, 1, "six hours pending did not raise exactly one incomplete incident");
  await w.run(T + 9 * H);
  await w.run(T + 10 * H);
  assert.equal(w.has("change:p1").length, 1, "a recovered event was not judged exactly once");
});

test("row 11: the 501st pending event holds the bookmark; nothing is dropped", async () => {
  const w = world();
  for (let n = 0; n < MAX_PENDING + 1; n++) add(w, mc(`q${String(n).padStart(4, "0")}`, T + n, id(n + 1)));
  let r: Record<string, unknown> = {};
  for (let n = 0; n < 4; n++) r = await w.run(T + H + n * MIN, 0);
  assert.equal(w.m().pend.length, MAX_PENDING, "pending grew past its bound");
  assert.equal(state(w.b).bm.ids.at(-1), `q${String(MAX_PENDING - 1).padStart(4, "0")}`, "the bookmark moved past the event that found no room");
  assert.equal(r.cfaudit, "did not finish", "a full pending list did not turn the light red");
});

test("row 13: effects missing, malformed or with coverage going backwards explain nothing and raise one incident", async () => {
  const g1 = grant("cf.dns.list", T, { made: [id(1)], deleted: [] });
  const back = { gen: 9, since: S, covered_to: 1, grants: { "aaaaaaaa-1": g1 }, retired: {}, index: {}, revoked: {} };
  for (const bad of [undefined, { gen: 1, since: S, covered_to: 0, grants: { x: { job: 7 } }, retired: {}, index: {}, revoked: {} }, back]) {
    const w = world({ "aaaaaaaa-1": g1 });
    await w.run(T); // matching active on good effects first
    add(w, mc("m1", T + 10_000, id(1)));
    w.b.store.set(RECORDS_KEY, { body: JSON.stringify(bad === undefined ? {} : { effects: bad }), etag: "x" });
    await runCfAudit(env(w.b), w.cf.fetch, new Date(T + H), ON - 2 * H);
    await runCfAudit(env(w.b), w.cf.fetch, new Date(T + 2 * H), ON - 2 * H);
    assert.equal(w.m().expl.length, 0, "an event was explained from missing or malformed effects");
    assert.equal(w.has("effects:").length, 1, "missing or malformed effects did not raise one incident");
  }
});

test("row 14: an explained event whose tap is later tainted is re-judged once", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }) });
  add(w, mc("t1", T + 10_000, id(1)));
  await w.run(T + H);
  assert.equal(w.m().expl.length, 1);
  (w.fx.grants as any)["aaaaaaaa-1"].tainted = "sweep";
  await w.run(T + 2 * H);
  await w.run(T + 3 * H);
  assert.equal(w.has("unexplained-after:t1").length, 1, "a revoked explanation was not re-judged exactly once");
});

test("row 15: a result recorded after the wait alerts, then sends one explained-after-the-alert follow-up", async () => {
  const w = world();
  add(w, mc("l1", T + 10_000, id(1)));
  await w.run(T + H);
  assert.equal(w.has("change:l1").length, 1, "the late event did not alert first");
  (w.fx.grants as any)["aaaaaaaa-late"] = grant("cf.dns.list", T, { made: [id(1)], deleted: [] }, { len: 50 * MIN });
  await w.run(T + 2 * H);
  await w.run(T + 3 * H);
  assert.equal(w.has("explained-after:l1").length, 1, "the late explanation did not send exactly one follow-up");
  assert.equal(w.has("change:l1").length, 1, "the first alert was retracted");
  assert.match(w.has("explained-after:l1")[0].text, /aaaaaaaa/, "the follow-up does not name the tap");
});

test("row 16: before B_FROM master writes are counted apart; the first active run pushes matching on, once", async () => {
  const w = world();
  add(w, mc("b1", ON - 90 * MIN, id(1)));
  await w.run(ON - H);
  assert.equal(w.m().ep, 0, "matching activated before B_FROM");
  assert.equal(state(w.b).week.counts[`master writes, not yet matched (before ${new Date(ON).toISOString()})`], 1, "a pre-activation write was not counted apart");
  await w.run(ON + H);
  assert.equal(w.has("on:").length, 1, "the first active run did not raise one matching-on line");
  assert.match(w.has("on:")[0].text, /matching on/, "the matching-on words are missing");
  assert.deepEqual(JSON.parse(w.b.store.get(EPOCHS_KEY)!.body).epochs.map((e: any) => e.boundary), [ON], "the epoch was not appended once at B_FROM");
  await w.run(ON + 2 * H);
  assert.equal(w.has("on:").length, 1);
});

test("row 21: a tap with unfinished matching is not acknowledged done; once finished it is", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [id(1)] }) });
  add(w, mc("a1", T + 10_000, id(1)));
  await w.run(T + 5 * H);
  assert.ok(!w.m().done.includes("aaaaaaaa-1"), "a tap with a missing delete and its helper check open was acknowledged");
  const w2 = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [id(1)] }) });
  add(w2, mc("a1", T + 10_000, id(1)), md("a2", T + 11_000, id(1)));
  await w2.run(T + 2 * H);
  assert.ok(w2.m().done.includes("aaaaaaaa-1"), "a finished tap was not acknowledged done");
});

test("row 22: a finding on a retired record re-judges its events from the monthly index, at any age", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [id(1)] }) });
  add(w, mc("i1", T + 10_000, id(1)), md("i2", T + 11_000, id(1)));
  await w.run(T + 2 * H);
  const g = (w.fx.grants as any)["aaaaaaaa-1"];
  delete (w.fx.grants as any)["aaaaaaaa-1"];
  w.fx.retired["aaaaaaaa-1"] = T + 80 * H;
  await w.run(T + 81 * H);
  assert.equal(w.m().expl.length, 0, "retired associations stayed in working state");
  const month = new Date(T + 80 * H).toISOString().slice(0, 7);
  assert.ok(w.b.store.get(`state/cfindex/${month}.json`), "the monthly index was not written");
  delete w.fx.retired["aaaaaaaa-1"]; // 31+ days on: the records side no longer keeps the retirement time
  w.fx.revoked[String(g.res.n)] = "aaaaaaaa-1";
  await w.run(T + 32 * 24 * H);
  await w.run(T + 33 * 24 * H);
  assert.deepEqual(w.has("unexplained-after:").map((i) => i.id).sort(), ["unexplained-after:i1", "unexplained-after:i2"], "a retired tap's events were not re-judged once from the index");
});

test("row 23: failed events carrying named ids explain nothing and satisfy nothing", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }) });
  add(w, mc("f1", T + 10_000, id(1), { result: "failure" }));
  await w.run(T + 2 * H);
  assert.equal(w.has("change:f1").length, 1, "a failed event was explained");
  assert.equal(w.has("reverse:aaaaaaaa-1").length, 1, "a failed event satisfied the reverse check");
});

test("row 24: a candidate's own setup probe before its result never makes it current", async () => {
  const cand = id(30);
  const w = world({ "bbbbbbbb-hc": grant("cf.token.headcount.setup", T, { made: [cand], deleted: [] }) });
  add(w, mc("g1", T + 10_000, cand, { name: "front-desk headcount c", exp: null }), hcRead("probe", T + 20_000, cand));
  await w.run(T + 2 * H);
  await w.run(T + 50 * H);
  assert.equal(w.has("outlived:g1").length, 1, "a candidate whose only read was its setup probe was treated as current");
});

test("row 20: a lost save sends nothing and loses no pending event", async () => {
  const w = world();
  add(w, mc("z1", T, id(1)));
  await w.run(T + 30 * MIN, 0);
  assert.equal(w.m().pend.length, 1);
  const before = w.cf.alerts.length;
  add(w, mc("z2", T + 10 * MIN, id(2)));
  w.b.nullOn(1);
  const r = await w.run(T + 2 * H);
  assert.equal(r.cfaudit, "did not finish");
  assert.equal(w.cf.alerts.length, before, "the losing run sent an alert");
  assert.equal(w.m().pend.length, 1, "the stored pending list changed after a lost save");
  await w.run(T + 3 * H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:z1", "change:z2"], "a pending event was lost after the race");
});

test("row 25: revert with a pending event, build a advancing the bookmark, then re-enable: all judged, gap incident in addition", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T + 2 * H, { made: [id(2)], deleted: [] }) });
  add(w, mc("y1", T, id(1)));
  await w.run(T + 30 * MIN, 0);
  assert.equal(w.m().pend.length, 1);
  // Build a runs while b is off: it keeps `m` as it is and moves only the bookmark.
  add(w, mc("y2", T + 2 * H + 10_000, id(2)), mc("y3", T + 2 * H + 20_000, id(3)));
  const s = state(w.b);
  s.bm = { t: T + 3 * H, ids: ["y3"] };
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "builda" });
  await w.run(T + 4 * H);
  await w.run(T + 5 * H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:y1", "change:y3"], "an event pending or ingested while off was not judged");
  assert.ok(w.m().expl.some((e: any) => e.id === "y2"), "an honest event ingested while off was not matched");
  assert.equal(w.has("gap:").length, 1, "no gap incident was raised in addition");
  assert.match(w.has("gap:")[0].text, /3 master writes/, "the gap incident does not count the writes");
});

test("row 25: matching state lost while epochs exist is a recovery: replayed from the last epoch, gap incident raised", async () => {
  const w = world();
  w.b.store.set(EPOCHS_KEY, { body: JSON.stringify({ epochs: [{ n: 1, boundary: ON }] }), etag: "ep" });
  add(w, mc("n1", T, id(1)));
  const s0 = { v: 1, bm: { t: T + H, ids: [] }, recent: [], incidents: [], dropped: 0, week: { counts: {}, lag: 0 } };
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s0), etag: "lost" });
  await w.run(T + 2 * H);
  await w.run(T + 3 * H);
  assert.equal(w.has("change:n1").length, 1, "an event from before the loss was not judged");
  assert.equal(w.has("gap:").length, 1, "no gap incident");
});

test("row 28: a replay range Cloudflare no longer returns raises evidence unavailable; matching stays incomplete", async () => {
  const w = world();
  add(w, mc("y1", T, id(1)));
  await w.run(T + 30 * MIN, 0);
  const s = state(w.b);
  s.bm = { t: T + 3 * H, ids: [] };
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "builda" });
  w.cf.fail["/logs/audit"] = () => Response.json({ success: false }, { status: 400 });
  const r = await w.run(T + 4 * H);
  assert.equal(w.has("unavailable:").length, 1, "unreadable evidence was not named");
  assert.equal(r.matching, "incomplete", "matching reported clean over unavailable evidence");
});

// ---- production path: signed records through runRecords, then runCfAudit ----

function listBucket() {
  const store = new Map<string, { body: string; uploaded: Date }>();
  return {
    store,
    async list(o: { prefix?: string; delimiter?: string; cursor?: string; startAfter?: string; limit?: number }) {
      const prefix = o.prefix ?? "", start = Number(o.cursor ?? 0), limit = o.limit ?? 1000, prefixes = new Set<string>(), objects: R2Object[] = [];
      for (const k of [...store.keys()].sort().filter((x) => x.startsWith(prefix) && (!o.startAfter || x > o.startAfter))) {
        const rest = k.slice(prefix.length), cut = o.delimiter ? rest.indexOf(o.delimiter) : -1;
        if (cut >= 0) prefixes.add(prefix + rest.slice(0, cut + 1));
        else objects.push({ key: k, size: store.get(k)!.body.length, uploaded: store.get(k)!.uploaded } as R2Object);
      }
      const page = objects.slice(start, start + limit), more = start + limit < objects.length;
      return { objects: page, delimitedPrefixes: [...prefixes], truncated: more, cursor: more ? String(start + limit) : undefined } as R2Objects;
    },
    async get(k: string) { const v = store.get(k); return v ? ({ text: async () => v.body } as R2ObjectBody) : null; },
  };
}
async function signedWorld() {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
  const pin: Pin = { key: b64((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer), from: 1 };
  let now = 0;
  const recs = listBucket(), b = bucket(), log: Ev[] = [], cf = cloudflare(log, { clock: () => now });
  let seq = 0;
  const put = async (grant: string, stage: Stage, rec: object, t: number) => {
    const body = JSON.stringify({ v: 1, grant, stage, ...rec }), sha = await sha256(body), n = ++seq;
    const e: Envelope = { v: 2, seq: n, grant, stage, recorded_at: new Date(t).toISOString(), sha256: sha, body };
    recs.store.set(keyFor(n, grant, stage), { body: JSON.stringify({ ...e, sig: b64(await crypto.subtle.sign("Ed25519", pair.privateKey, sealed(e))) }), uploaded: new Date(t) });
    return sha;
  };
  const tap = async (grant: string, job: string, t: number, cf: unknown) => {
    const f = { v: 1 as const, grant, stage: "request" as const, job, params: {}, requester: "c-box agent", expires_at: t + 10 * MIN };
    const req = await put(grant, "request", { ...f, grant_hash: (await grantHashOf(f))! }, t);
    await put(grant, "approval", { job, request: req }, t + MIN);
    await put(grant, "result", { job, request: req, outcome: "done", cf }, t + 2 * MIN);
  };
  const renv = { RECORDS: recs, COPY: b } as unknown as RecordsEnv;
  const records = (t: number) => runRecords(renv, async () => new Response("", { status: 500 }), new Date(t), pin, undefined, CF_FROM);
  const audit = (t: number) => (now = t, runCfAudit(env(b), cf.fetch, new Date(t), CF_FROM));
  /** Runs the real crons, records at :30 and cfaudit at :45, from `from` to `to`; returns cfaudit's run times. */
  const crons = async (from: number, to: number) => {
    const runs: number[] = [];
    for (let h = Math.floor(from / H) * H; h <= to; h += H) {
      if (h + 30 * MIN >= from && h + 30 * MIN <= to) await records(h + 30 * MIN);
      if (h + 45 * MIN >= from && h + 45 * MIN <= to) { await audit(h + 45 * MIN); runs.push(h + 45 * MIN); }
    }
    return runs;
  };
  const inc = () => (state(b).incidents as { id: string; text: string; told: boolean }[]);
  return { b, log, cf, tap, records, audit, crons, inc };
}
const since = (w: Awaited<ReturnType<typeof signedWorld>>) => JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.since as number;

test("row 10: production path, quiet records for 5 h: an unexplained master create still alerts", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, ev = Math.floor(on / H) * H + 3 * H + 26 * MIN;
  w.log.push(mc("quiet1", ev, id(1)));
  await w.crons(t0 + H, ev + 5 * H);
  assert.ok(w.inc().some((i) => i.id === "change:quiet1"), "a quiet records check starved the unexplained create");
});

test("row 26: detection time with the real :30/:45 crons: a create at :26 alerts within 2 h 20 min", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, ev = Math.floor(on / H) * H + 3 * H + 26 * MIN;
  await w.crons(t0 + H, ev - 1);
  w.log.push(mc("late26", ev, id(1)));
  let alertedAt: number | undefined;
  for (let h = Math.floor(ev / H) * H; !alertedAt && h < ev + 4 * H; h += H) {
    await w.records(h + 30 * MIN);
    await w.audit(h + 45 * MIN);
    if (h + 45 * MIN > ev && w.inc().some((i) => i.id === "change:late26")) alertedAt = h + 45 * MIN;
  }
  assert.ok(alertedAt, "the create never alerted");
  const minutes = (alertedAt! - ev) / MIN;
  assert.ok(minutes <= 140, `detection took ${minutes} minutes, over 140`);
  assert.equal(minutes, 79, `detection took ${minutes} minutes, not the computed 79`);
});

test("row 27: production path: an honest tap after activation matches, and the weekly line names its tap and count", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, t = Math.floor(on / H) * H + 2 * H + 5 * MIN;
  const g = "5ca1ab1e-0000-4000-8000-000000000027";
  await w.tap(g, "cf.dns.list", t, { made: [id(1), id(2)], deleted: [id(1), id(2)] });
  w.log.push(mc("p1", t + MIN + 1000, id(1)), md("p2", t + MIN + 2000, id(1)), mc("p3", t + MIN + 3000, id(2)), md("p4", t + MIN + 4000, id(2)));
  await w.crons(t0 + H, t + 4 * H);
  assert.deepEqual(w.inc().filter((i) => /^(change|reverse|outlived):/.test(i.id)), [], "an honest production-path tap alerted");
  assert.equal(state(w.b).week.counts["master writes matched to tap 5ca1ab1e"], 4, "the weekly counts do not name the tap and its matched count");
  assert.ok(w.inc().some((i) => i.id.startsWith("on:")), "no matching-on line on the production path");
});

test("settle: SETTLE_MS is the 20 minutes the detection bound assumes", () => assert.equal(SETTLE_MS, 20 * MIN));
