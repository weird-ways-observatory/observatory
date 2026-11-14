// Card beec640b build b, the consumer (studio-os docs/specifications/trust-but-verify/REFINE-beec640b-build-b.md v3.3:
// sections 4.4-4.7 as overridden by 12 and 13). cfaudit judges each master-key create or delete against the `effects`
// the records check publishes. Most rows write `effects` straight into state/records.json (the records side's own
// projection is proven in effects.test.ts); rows 10, 26 and 27 run the production path, runRecords then runCfAudit.
// Test names carry their evidence-matrix row. Every id is synthetic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { runCfAudit, STATE_KEY, SETTLE_MS } from "../src/cfaudit.ts";
import { EPOCHS_KEY, MAX_PENDING, REPLAY_RUNS, RESULT_WAIT_MS, WARM_MS } from "../src/cfmatch.ts";
import { b64, GRANT_TTL_MS, keyFor, sealed, sha256, type Envelope, type Stage } from "../src/contract.ts";
import { CARD_RUN_MS, cardHashOf, CF_FROM, type Manifest } from "../src/card.ts";
import { softKey } from "./softkey.ts";
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
/** `pg`: the permission group names on the new key (claim: Cloudflare's create response shape, policies[].permission_groups[].name). */
function mc(eid: string, t: number, key: string, o: { name?: string; exp?: number | null; result?: string; pg?: string[] } = {}): Ev {
  const e = shapes.masterCreate(eid, t);
  const pg = o.pg ?? ((o.name ?? "").startsWith("front-desk headcount") ? ["Account API Tokens Read"] : ["Zone Read"]);
  e.resource.response = { id: key, name: o.name ?? "front-desk probe x", policies: [{ effect: "allow", permission_groups: pg.map((name) => ({ id: "f".repeat(32), name })) }], ...(o.exp === null ? {} : { expires_on: new Date(o.exp ?? t + 5 * MIN).toISOString() }) };
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
    "cccccccc-acc": grant("cf.token.accept", T + 20 * MIN, { made: [], deleted: [id(10)] }),
    "dddddddd-hc": grant("cf.token.headcount.setup", T + 30 * MIN, { made: [hcNew], deleted: [hcOld] }),
    "eeeeeeee-zon": grant("cf.zone.read", T + 40 * MIN, { made: [id(4), id(5)], deleted: [id(4), id(5)] }),
  });
  add(w, mc("e1", T + 10_000, id(1)), md("e2", T + 11_000, id(1)), mc("e3", T + 12_000, id(2)), md("e4", T + 13_000, id(2)));
  add(w, mc("e5", T + 10 * MIN + 10_000, id(3), { pg: ["Account Settings Read"] }), md("e6", T + 10 * MIN + 11_000, id(3)), md("e7", T + 10 * MIN + 12_000, id(9)));
  add(w, md("e8", T + 20 * MIN + 10_000, id(10)));
  add(w, mc("e10", T + 30 * MIN + 10_000, hcNew, { name: "front-desk headcount 2026", exp: null }), md("e11", T + 30 * MIN + 12_000, hcOld));
  add(w, mc("e12", T + 40 * MIN + 10_000, id(4)), md("e13", T + 40 * MIN + 11_000, id(4)), mc("e14", T + 40 * MIN + 12_000, id(5)), md("e15", T + 40 * MIN + 13_000, id(5)));
  add(w, hcRead("r1", T + 50 * MIN, hcNew));
  const r = await w.run(T + 3 * H);
  assert.equal(r.cfaudit, "ran", String(r.reason));
  assert.deepEqual(w.has("change:").map((i) => i.id), [], "an honest master write alerted as unmatched");
  assert.deepEqual(w.has("reverse:"), [], "the reverse check flagged an honest tap");
  assert.equal(w.m().expl.length, 14, "not every honest master write was matched");
  assert.equal(w.m().pend.length, 0, "an honest write is still pending");
  assert.equal(w.m().t, state(w.b).bm.t, "the matching checkpoint did not move with the bookmark");
  assert.deepEqual(w.m().ids, state(w.b).bm.ids, "the matching checkpoint's ids did not move with the bookmark");
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
  await w.run(T + 90 * H);
  assert.equal(w.m().late.length, 2, "alerted events were dropped by elapsed time, before records' coverage passed their grants' life");
  await w.run(T + 100 * H);
  assert.equal(w.m().late.length, 0, "alerted events were kept after records' coverage passed their grants' life and margin");
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
  add(w, mc("c1", T + 10_000, id(1), { pg: ["Account Settings Read"] }), mc("c2", T + 11_000, id(2), { pg: ["Account Settings Read"] }), mc("c3", T + 12_000, id(3)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:c2", "change:c3"], "a create over the job's count matched");
});

test("row 5: deletes over the job's count alert", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.token.accept", T, { made: [], deleted: [id(1), id(2)] }) });
  add(w, md("k1", T + 10_000, id(1)), md("k2", T + 11_000, id(2)));
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id), ["change:k2"], "a delete over the job's count matched");
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
  assert.deepEqual(w.has("outlived:"), [], "a helper was flagged before 24 h");
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

test("row 13: tap records held back at capacity (replay_from) explain nothing and report matching incomplete", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }) });
  await w.run(T);
  add(w, mc("h1", T + 10_000, id(1)));
  (w.fx as any).replay_from = 5;
  const r = await w.run(T + H);
  assert.equal(w.m().expl.length, 0, "an event was explained while the tap records were held back");
  assert.equal(r.matching, "incomplete", "held-back tap records did not report matching incomplete");
});

test("row 25: tap records that restart (a new since) are a recovery: a write before the new warm-up alerts as unmatchable", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }) });
  await w.run(T);
  add(w, mc("rs1", T + 10_000, id(1)));
  w.fx.since = T - H; // the records state was lost and restarted
  await w.run(T + H);
  assert.equal(w.has("reset:").length, 1, "a restart of the tap records was not raised");
  assert.match(w.has("change:rs1")[0]?.text ?? "", /restarted/, "a write the restarted records cannot cover was matched or held");
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
  const w2 = world(); // behind: a write from before B_FROM is first read after activation
  add(w2, mc("b2", ON - 30 * MIN, id(2)));
  await w2.run(ON + H);
  assert.equal(w2.m().pend.length + w2.m().expl.length + w2.has("change:").length, 0, "a pre-activation write read after activation was judged");
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
  const w3 = world({ "aaaaaaaa-1": grant("cf.token.accept", T, { made: [], deleted: [] }) });
  add(w3, mc("a3", T + 10_000, id(3)));
  await w3.run(T + 2 * H, T);
  assert.ok(!w3.m().done.includes("aaaaaaaa-1"), "a tap with a pending event in its window was acknowledged done");
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

/** Build a ran while b was off: `m` kept, the bookmark moved to `to`. */
function revert(w: ReturnType<typeof world>, to: number) {
  const s = state(w.b);
  s.bm = { t: to, ids: [] };
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: `builda${to}` });
}
const views = (w: ReturnType<typeof world>, from: number, n: number) => { for (let i = 0; i < n; i++) w.log.push(shapes.view(`v${from}-${i}`, from + i, id(77))); };

test("security a: a replay range of more pages than one run reads, with no master write on them, still progresses and finishes", async () => {
  const w = world();
  await w.run(T, 0);
  views(w, T + MIN, 700); // more than one run's replay pages, none a master write
  add(w, mc("ra1", T + 2 * H, id(1)));
  revert(w, T + 3 * H);
  for (let n = 1; n <= 3; n++) await w.run(T + 3 * H + n * MIN);
  assert.equal(w.has("gap:").length, 1, "a replay with no master writes on its pages never finished");
  assert.ok(w.m().pend.some((e: any) => e.id === "ra1") || w.has("change:ra1").length, "the master write after the quiet pages was never read");
});

test("security b: a cursor is never paired with a changed since: no event in the replay range is skipped", async () => {
  const w = world();
  await w.run(T, 0);
  for (let i = 0; i < 450; i++) w.log.push(i === 100 ? mc("rb1", T + MIN + i, id(1)) : i === 250 ? mc("rb2", T + MIN + i, id(2)) : shapes.view(`w${i}`, T + MIN + i, id(77)));
  add(w);
  revert(w, T + 3 * H);
  await w.run(T + 4 * H);
  const seen = (e: string) => w.m().pend.some((x: any) => x.id === e) || w.has(`change:${e}`).length > 0;
  assert.ok(seen("rb1") && seen("rb2"), "a master write was skipped by a cursor paired with a moved since");
});

test("security c: a replay still unfinished after REPLAY_RUNS runs turns the light red", async () => {
  const w = world();
  await w.run(T, 0);
  for (let i = 0; i < 3 * 200 * (REPLAY_RUNS + 1); i++) w.log.push(shapes.view(`x${i}`, T + MIN + i, id(77)));
  add(w);
  revert(w, T + 3 * H);
  let r: Record<string, unknown> = {};
  for (let n = 1; n < REPLAY_RUNS; n++) r = await w.run(T + 3 * H + n * MIN);
  assert.equal(r.cfaudit, "ran", `a replay within its runs turned red: ${r.reason}`);
  r = await w.run(T + 3 * H + REPLAY_RUNS * MIN);
  assert.equal(r.cfaudit, "did not finish", "a replay unfinished after its runs left the light green");
  assert.match(String(r.reason), /replay/, "the red reason does not name the replay");
});

test("row 28 (#10): a replay answer that is not a clean page keeps the range; matching stays incomplete and red, never lost by inference", async () => {
  const w = world();
  add(w, mc("y1", T, id(1)));
  await w.run(T + 30 * MIN, 0);
  revert(w, T + 3 * H);
  w.cf.fail["/logs/audit"] = () => Response.json({ success: false }, { status: 400 });
  const r = await w.run(T + 4 * H);
  assert.ok(w.m().rp, "an unclean replay answer deleted the replay range");
  assert.equal(r.matching, "incomplete", "matching reported clean over an unread range");
  assert.equal(r.cfaudit, "did not finish", "an unread replay range left the light green");
  assert.equal(w.has("gap:").length, 0, "the gap was closed over an unread range");
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
    return { n, sha };
  };
  const key = await softKey();
  /** A whole tap, as effects.test.ts records it: `card` gives a real card/v1 approval; `verdict` adds a verdict record. */
  const tap = async (grant: string, job: string, t: number, cf: unknown, o: { card?: boolean; verdict?: boolean } = {}) => {
    const f = { v: 1 as const, grant, stage: "request" as const, job, params: {}, requester: "c-box agent", expires_at: t + 10 * MIN, ...(o.card ? { card: `card-${grant}` } : {}) };
    const hash = (await grantHashOf(f))!;
    const req = await put(grant, "request", { ...f, grant_hash: hash }, t);
    const mf: Manifest = { kind: "card/v1", card: `card-${grant}`, requester: "c-box agent", entries: [hash], deadline: t + 10 * MIN + CARD_RUN_MS, jobs_version: 1 };
    const cardMark = o.card ? { grant_hash: hash, approval_kind: "card/v1", manifest: mf, assertion: await key.answer(await cardHashOf(mf)) } : {};
    const appr = await put(grant, "approval", { job, request: req.sha, ...cardMark }, t + MIN);
    const vd = o.verdict ? await put(grant, "verdict", { job, request: req.sha }, t + MIN + 30_000) : undefined;
    const res = await put(grant, "result", { job, request: req.sha, outcome: "done", cf }, t + 2 * MIN);
    return { req: req.n, appr: appr.n, res: res.n, vd: vd?.n };
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
  return { b, recs, log, cf, tap, records, audit, crons, inc, seq: () => seq };
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

test("row 22: end to end, a records finding 32 days after retirement on a retired tap's record re-judges its matched events from the monthly index", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, t = Math.floor(on / H) * H + 2 * H + 5 * MIN, g = "5ca1ab1e-0000-4000-8000-000000000022";
  const s = await w.tap(g, "cf.dns.list", t, { made: [id(1)], deleted: [id(1)] });
  w.log.push(mc("j1", t + MIN + 1000, id(1)), md("j2", t + MIN + 2000, id(1)));
  await w.crons(t0 + H, t + 4 * H);
  assert.ok(state(w.b).m.done.includes(g), "the honest tap was not acknowledged done");
  await w.records(t + 80 * H);
  await w.audit(t + 80 * H + 15 * MIN);
  assert.equal(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.grants[g], undefined, "the done tap was not retired");
  assert.equal(state(w.b).m.expl.length, 0, "retired associations stayed in working state");
  const late = Date.UTC(new Date(t + 35 * 24 * H).getUTCFullYear(), new Date(t + 35 * 24 * H).getUTCMonth(), new Date(t + 35 * 24 * H).getUTCDate(), 4, 30);
  await w.records(late - 2 * H); // the records index for this tap has expired by now
  assert.equal(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.index[String(s.res)], undefined, "test setup: the records index still held the record");
  w.recs.store.set(keyFor(s.res, g, "result", "0123456789abcdef"), { body: "{}", uploaded: new Date(late - H) }); // written around the recorder
  await w.records(late);
  await w.audit(late + 15 * MIN);
  await w.audit(late + 75 * MIN);
  assert.deepEqual(w.inc().filter((i) => i.id.startsWith("unexplained-after:")).map((i) => i.id).sort(), ["unexplained-after:j1", "unexplained-after:j2"], "a retired tap's events were not re-judged once at 32 days");
  assert.equal(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.index[String(s.res)], undefined, "test setup: the records index still held the record");
  assert.ok(state(w.b).m.rj.includes(String(s.res)), "the re-judged record was not remembered, so it would be re-judged again");
  await w.records(late + 90 * MIN);
  assert.ok(Object.hasOwn(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.revoked, String(s.res)), "a confirmed number that is still raised was dropped, so it would be re-judged again");
});

test("row 22: a tap is acknowledged done only once its index entry landed", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, t = Math.floor(on / H) * H + 2 * H + 5 * MIN, g = "5ca1ab1e-0000-4000-8000-000000000122";
  await w.tap(g, "cf.dns.list", t, { made: [id(1)], deleted: [id(1)] });
  w.log.push(mc("jj1", t + MIN + 1000, id(1)), md("jj2", t + MIN + 2000, id(1)));
  const put = w.b.put.bind(w.b);
  (w.b as any).put = async (k: string, ...a: any[]) => (k.startsWith("state/cfindex/") && k !== "state/cfindex/by-record.json" ? null : put(k, ...(a as [any, any])));
  await w.crons(t0 + H, t + 4 * H);
  assert.ok(!state(w.b).m.done.includes(g), "a tap was acknowledged done while its index entry could not be saved");
});

test("row 25 / 12.5: end to end, effects lost in a revert are rebuilt from the records: honest taps made while off match, an unnamed write still alerts", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS;
  await w.crons(t0 + H, on + 2 * H);
  // Build b is reverted for a few hours: build a's records check reads the new records and its save drops `effects`;
  // build a's cfaudit moves the bookmark and keeps `m` as it is.
  const t = on + 3 * H, g = "5ca1ab1e-0000-4000-8000-000000000025";
  await w.tap(g, "cf.dns.list", t, { made: [id(1)], deleted: [id(1)] });
  w.log.push(mc("k1", t + MIN + 1000, id(1)), md("k2", t + MIN + 2000, id(1)), mc("k3", t + MIN + 3000, id(9)));
  const rs = JSON.parse(w.b.store.get(RECORDS_KEY)!.body);
  rs.seq = w.seq(); if (rs.sealed) rs.sealed.to = w.seq(); delete rs.effects; delete rs.open?.[g];
  w.b.store.set(RECORDS_KEY, { body: JSON.stringify(rs), etag: "builda-records" });
  const cs = state(w.b);
  cs.bm = { t: t + 2 * H, ids: [] };
  w.b.store.set(STATE_KEY, { body: JSON.stringify(cs), etag: "builda-cfaudit" });
  await w.records(t + 2 * H + 30 * MIN);
  const fx = JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects;
  assert.ok(fx.grants[g]?.res, "the tap made while off was not rebuilt from the records");
  assert.ok(fx.since + WARM_MS <= t, "the rebuilt effects do not cover the off period");
  await w.crons(t + 2 * H + 40 * MIN, t + 6 * H);
  const ch = w.inc().filter((i) => i.id.startsWith("change:"));
  assert.deepEqual(ch.map((i) => i.id), ["change:k3"], "an honest write made while off was not matched after the rebuild, or the unnamed one did not alert");
  assert.match(ch[0].text, /no approved tap names it/, "the unnamed write was called unmatchable instead of judged");
  assert.ok(w.inc().some((i) => i.id.startsWith("gap:")), "no gap incident");
});

test("12.5: the rebuild starts at the first record at or after the floor, not at record one", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  for (let i = 0; i < 6; i++) await w.tap(`5ca1ab1e-0000-4000-8000-00000000010${i}`, "cf.dns.list", t0 + 3 * H + i * MIN, "unknown");
  const on = since(w) + WARM_MS, after = "5ca1ab1e-0000-4000-8000-000000000199";
  await w.crons(t0 + H, on + 20 * H);
  await w.tap(after, "cf.dns.list", on + 20 * H + 5 * MIN, "unknown");
  await w.crons(on + 20 * H, on + 30 * H);
  const rs = JSON.parse(w.b.store.get(RECORDS_KEY)!.body);
  delete rs.effects;
  w.b.store.set(RECORDS_KEY, { body: JSON.stringify(rs), etag: "builda-records" });
  const floor = state(w.b).m.t - GRANT_TTL_MS;
  const reads: string[] = [], get = w.recs.get.bind(w.recs);
  (w.recs as any).get = async (k: string) => (reads.push(k), get(k));
  await w.records(on + 31 * H);
  const first = JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects;
  assert.ok(floor > t0 + 2 * H && floor < on + 20 * H, "test setup: the floor is not after the early taps");
  assert.ok(first.grants[after], "a tap after the floor was not rebuilt");
  assert.equal(Object.keys(first.grants).filter((k) => k.startsWith("5ca1ab1e-0000-4000-8000-00000000010")).length, 0, "records before the floor were rebuilt");
});

test("12.5: a records state older than cfaudit last saw (gen behind) is a recovery, not a silent restart", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS;
  await w.crons(t0 + H, on + H);
  const old = w.b.store.get(RECORDS_KEY)!;
  await w.crons(on + H, on + 5 * H);
  const seen = state(w.b).m;
  w.b.store.set(RECORDS_KEY, { body: JSON.parse(JSON.stringify(old)).body, etag: "rolled-back" });
  await w.records(on + 5 * H + 30 * MIN);
  const fx = JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects;
  assert.ok(fx.gen > seen.gen && fx.since === seen.t - GRANT_TTL_MS - H, "an older records state was not treated as a recovery");
});

test("12.5: effects and matching state both lost: records rebuilds from the last epoch boundary", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, g = "5ca1ab1e-0000-4000-8000-000000000125";
  await w.crons(t0 + H, on + H);
  await w.tap(g, "cf.dns.list", on + H + 5 * MIN, "unknown");
  await w.crons(on + H, on + 3 * H);
  const rs = JSON.parse(w.b.store.get(RECORDS_KEY)!.body), cs = state(w.b);
  delete rs.effects; delete cs.m;
  w.b.store.set(RECORDS_KEY, { body: JSON.stringify(rs), etag: "lost-r" });
  w.b.store.set(STATE_KEY, { body: JSON.stringify(cs), etag: "lost-c" });
  await w.records(on + 3 * H + 30 * MIN);
  const fx = JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects;
  assert.ok(fx.grants[g] && fx.since === on - GRANT_TTL_MS - H, "lost effects with no matching state were not rebuilt from the last epoch");
});

// ---- Codex build r1 (#1-#15) and security review S1-S3 ----

test("#1: a create whose permission groups do not fit the job, or cannot be read, is not explained", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [] }), "bbbbbbbb-2": grant("cf.zone.read", T, { made: [id(3)], deleted: [] }) });
  const noPolicies = mc("pg2", T + 11_000, id(2)); delete noPolicies.resource.response.policies;
  const empty = mc("pg4", T + 13_000, id(4)); empty.resource.response.policies = [];
  (w.fx.grants as any)["cccccccc-4"] = grant("cf.zone.read", T, { made: [id(4)], deleted: [] });
  add(w, mc("pg1", T + 10_000, id(1), { pg: ["Zone Read", "DNS Write"] }), noPolicies, mc("pg3", T + 12_000, id(3), { pg: ["DNS Read"] }), empty);
  await w.run(T + H);
  assert.deepEqual(w.has("change:").map((i) => i.id).sort(), ["change:pg1", "change:pg2", "change:pg3", "change:pg4"], "a key with the wrong or unreadable permissions matched");
  assert.match(w.has("change:pg1")[0].text, /permissions/, "the alert does not say the permissions are wrong");
});

test("#3: build a extending the bookmark at the same instant is a recovery; the event is judged", async () => {
  const w = world();
  add(w, mc("i1", T, id(1)));
  await w.run(T + 30 * MIN, 0);
  add(w, mc("i2", T, id(2))); // build a reads it at the same millisecond
  const s = state(w.b);
  s.bm = { t: s.bm.t, ids: [...s.bm.ids, "i2"] };
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "builda-tie" });
  await w.run(T + 2 * H);
  assert.ok(w.has("change:i2").length || w.m().pend.some((e: any) => e.id === "i2"), "a write build a read at the checkpoint's instant was never judged");
});

test("#4: an activated matching state without its boundary is a recovery, not pre-activation forever", async () => {
  const w = world();
  await w.run(T, 0);
  const s = state(w.b);
  delete s.m.from;
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "corrupt" });
  add(w, mc("cf1", T + 10 * MIN, id(1)));
  await w.run(T + H);
  await w.run(T + 2 * H);
  assert.equal(w.has("change:cf1").length, 1, "a write after a corrupt matching state was counted as before activation");
});

test("#4: lost matching state replays from the first epoch, where unresolved work may start", async () => {
  const w = world();
  w.b.store.set(EPOCHS_KEY, { body: JSON.stringify({ epochs: [{ n: 1, boundary: ON }, { n: 2, boundary: T + H }] }), etag: "ep" });
  add(w, mc("fe1", T, id(1)));
  w.b.store.set(STATE_KEY, { body: JSON.stringify({ v: 1, bm: { t: T + 2 * H, ids: [] }, recent: [], incidents: [], dropped: 0, week: { counts: {}, lag: 0 } }), etag: "lost" });
  await w.run(T + 3 * H);
  await w.run(T + 4 * H);
  assert.equal(w.has("change:fe1").length, 1, "an event before the latest epoch was not judged after matching state was lost");
});

test("#4: an unreadable activation record explains nothing and is raised", async () => {
  const w = world({ "aaaaaaaa-1": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }) });
  await w.run(T);
  w.b.store.set(EPOCHS_KEY, { body: JSON.stringify({ epochs: "x" }), etag: "bad" });
  add(w, mc("ur1", T + 10_000, id(1)));
  await w.run(T + H);
  assert.equal(w.m().expl.length, 0, "an event was matched while the activation record was unreadable");
  assert.equal(w.has("effects:").length, 1, "an unreadable activation record was not raised");
});

test("#6: an unfinished replay never judges absence or acknowledges a tap it has not read", async () => {
  const w = world({ "aaaaaaaa-6": grant("cf.dns.list", T + 2 * H, { made: [id(1)], deleted: [id(1)] }) });
  await w.run(T, 0);
  views(w, T + MIN, 700);
  add(w, mc("u61", T + 2 * H + 10_000, id(1)), md("u62", T + 2 * H + 11_000, id(1)));
  revert(w, T + 3 * H);
  await w.run(T + 4 * H);
  assert.ok(w.m().rp, "test setup: the replay finished in one run");
  assert.equal(w.has("reverse:").length, 0, "the reverse check judged events the replay had not read yet");
  assert.ok(!w.m().done.includes("aaaaaaaa-6"), "a tap was acknowledged before the replay read its events");
  await w.run(T + 5 * H);
  await w.run(T + 6 * H);
  assert.equal(w.has("reverse:").length, 0, "the honest tap failed the reverse check after the replay");
  assert.ok(w.m().done.includes("aaaaaaaa-6"), "the honest tap was not acknowledged once the replay read it");
});

test("#7: a lookup of a revoked record has no age cap, and an unreadable index keeps matching incomplete", async () => {
  const w = world();
  await w.run(T, 0);
  w.b.store.set("state/cfindex/by-record.json", { body: JSON.stringify({ complete_from: ON, n: { "41": { g: "old-tap-1", mo: ["2023-01"] }, "42": { g: "old-tap-2", mo: ["2023-02"] } } }), etag: "br" });
  w.b.store.set("state/cfindex/2023-01.json", { body: JSON.stringify({ "old-tap-1": [{ id: "anc1", a: "create", k: id(1), t: T - 1000 * 86_400_000, ok: true, ep: 1, g: "old-tap-1", i: 1 }] }), etag: "m1" });
  w.fx.revoked["41"] = "";
  w.fx.revoked["42"] = ""; // its month file is gone: unreadable
  const r = await w.run(T + H);
  assert.equal(w.has("unexplained-after:anc1").length, 1, "an association older than any cap was not re-judged");
  assert.ok(!w.m().rj.includes("42"), "an unreadable index entry was marked handled");
  assert.equal(r.matching, "incomplete", "an unreadable index entry left matching reported complete");
});

test("#7/S1: acknowledging a tap writes every record number of its chain, verdicts and taps with no matched event included", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS, t = Math.floor(on / H) * H + 2 * H + 5 * MIN;
  const a = await w.tap("5ca1ab1e-0000-4000-8000-0000000007a1", "cf.dns.list", t, { made: [id(1)], deleted: [id(1)] }, { verdict: true });
  const u = await w.tap("5ca1ab1e-0000-4000-8000-0000000007a2", "cf.zone.read", t + 10 * MIN, "unknown");
  w.log.push(mc("v71", t + MIN + 1000, id(1)), md("v72", t + MIN + 2000, id(1)));
  await w.crons(t0 + H, t + 4 * H);
  const br = JSON.parse(w.b.store.get("state/cfindex/by-record.json")?.body ?? "{}").n ?? {};
  for (const n of [a.req, a.appr, a.vd!, a.res, u.req, u.appr, u.res]) assert.ok(br[String(n)], `record ${n} of an acknowledged tap is not in the index`);
});

test("S1/S2: a revoked number is settled as never matched only by a complete index; missing, malformed or late-started is unknown", async () => {
  const w = world();
  await w.run(T, 0);
  assert.equal(JSON.parse(w.b.store.get("state/cfindex/by-record.json")?.body ?? "{}").complete_from, ON, "activation did not create the index complete from the first epoch");
  w.fx.revoked["77"] = "";
  let r = await w.run(T + H);
  assert.ok(w.m().rj.includes("77"), "a number the complete index never names was not settled");
  assert.equal(r.matching, "active");
  for (const [name, body] of [["missing", undefined], ["malformed", "{\"n\": 5}"], ["late-started", JSON.stringify({ complete_from: T + H, n: {} })], ["entry", JSON.stringify({ complete_from: ON, n: { "85": 5 } })]] as const) {
    const n = `8${name.length}`;
    if (body === undefined) w.b.store.delete("state/cfindex/by-record.json"); else w.b.store.set("state/cfindex/by-record.json", { body, etag: name });
    w.fx.revoked[n] = "";
    r = await w.run(T + 2 * H);
    assert.ok(!w.m().rj.includes(n), `a ${name} index settled a revoked number as never matched`);
    assert.equal(r.matching, "incomplete", `a ${name} index left matching reported complete`);
    assert.equal(w.has("unavailable:index").length, 1, `a ${name} index did not raise one incident`);
    delete w.fx.revoked[n];
  }
});

test("#8: the headcount key is re-checked every run: 48 h without a read raises it", async () => {
  const inst = id(21);
  const w = world({ "bbbbbbbb-hc": grant("cf.token.headcount.setup", T, { made: [inst], deleted: [] }) });
  add(w, mc("hh1", T + 10_000, inst, { name: "front-desk headcount a", exp: null }), hcRead("hr1", T + 25 * H, inst));
  await w.run(T + 26 * H);
  assert.equal(w.has("outlived:").length, 0, "test setup: the read key was flagged");
  await w.run(T + 80 * H);
  assert.equal(w.has("outlived:hh1").length, 1, "a headcount key not read for 48 h stayed exempt");
});

test("#8: a failed candidate's setup probe never displaces the installed key as newest", async () => {
  const inst = id(22), cand = id(23);
  const w = world({ "bbbbbbbb-hc": grant("cf.token.headcount.setup", T, { made: [inst], deleted: [] }), "cccccccc-hc": grant("cf.token.headcount.setup", T + 30 * H, { made: [cand], deleted: [] }) });
  add(w, mc("hn1", T + 10_000, inst, { name: "front-desk headcount a", exp: null }), hcRead("hn2", T + 29 * H, inst));
  add(w, mc("hn3", T + 30 * H + 10_000, cand, { name: "front-desk headcount b", exp: null }), hcRead("hn4", T + 30 * H + 20_000, cand));
  await w.run(T + 31 * H);
  assert.equal(w.has("outlived:hn1").length, 0, "a failed candidate's setup probe displaced the installed key");
});

test("#8: an unconfirmed candidate past 48 h is raised but stays pending (still watched)", async () => {
  const cand = id(24);
  const w = world({ "cccccccc-hc": grant("cf.token.headcount.setup", T, { made: [cand], deleted: [] }) });
  add(w, mc("hu1", T + 10_000, cand, { name: "front-desk headcount b", exp: null }));
  await w.run(T + 50 * H);
  assert.equal(w.has("outlived:hu1").length, 1);
  assert.ok(!w.m().expl.find((e: any) => e.id === "hu1").o, "an unconfirmed headcount candidate was marked decided");
});

test("#9: a replay never puts more than MAX_PENDING master writes in the pending list; it holds its place", async () => {
  const w = world();
  await w.run(T, 0);
  for (let i = 0; i < MAX_PENDING + 20; i++) w.log.push(mc(`rq${i}`, T + MIN + i, id(i + 1)));
  add(w);
  revert(w, T + 3 * H);
  for (let n = 1; n <= 3; n++) await w.run(T + 3 * H + n * MIN, 0);
  assert.ok(w.m().pend.length <= MAX_PENDING, `the replay grew pending to ${w.m().pend.length}`);
  assert.ok(w.m().rp, "the replay dropped its place when pending was full");
});

test("#12: an echo waits while its key event is matched, then says approved by your tap", async () => {
  const w = world();
  add(w, mc("k12", T + 10_000, id(1), {}), shapes.echo("e12", T + 12_000)); // a pair: same address, within 5 s
  await w.run(T + H, 0); // no tap result yet: the key event is pending
  assert.equal(w.has("echo:e12").length, 0, "the echo was told before its key event was judged");
  (w.fx.grants as any)["aaaaaaaa-12"] = grant("cf.dns.list", T, { made: [id(1)], deleted: [] });
  await w.run(T + 2 * H);
  assert.match(w.has("echo:e12")[0]?.text ?? "", /approved by your tap aaaaaaaa/, "the echo of a matched write does not say approved by your tap");
});

test("#13: the weekly counts name at most five taps; the rest are counted together", async () => {
  const gs: Record<string, unknown> = {};
  for (let i = 0; i < 8; i++) gs[`${String(i).repeat(8)}-t`] = grant("cf.token.accept", T + i * 10 * MIN, { made: [], deleted: [id(i + 1)] });
  const w = world(gs);
  for (let i = 0; i < 8; i++) add(w, md(`wk${i}`, T + i * 10 * MIN + 10_000, id(i + 1)));
  await w.run(T + 3 * H);
  const c = state(w.b).week.counts, named = Object.keys(c).filter((k) => k.startsWith("master writes matched to tap "));
  assert.equal(named.length, 5, "the weekly counts are not bounded to five named taps");
  assert.equal(c["master writes matched to other taps"], 3, "the other taps were not counted together");
});

test("#14: matching is reported active again once the pending work it waited on is judged", async () => {
  const w = world();
  add(w, mc("st1", T, id(1)));
  await w.run(T + 7 * H, T - 2 * H);
  assert.equal((await w.run(T + 8 * H, T - 2 * H)).matching, "incomplete", "stale pending work did not report matching incomplete");
  const r = await w.run(T + 9 * H);
  assert.equal(w.has("incomplete").length, 1, "test setup: the historical incident left the list");
  assert.equal(r.matching, "active", "a resolved incident kept matching reported incomplete");
});

test("S3: records keeps a bare revoked number until cfaudit confirms it handled it", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.records(t0 + 30 * MIN);
  const rs = JSON.parse(w.b.store.get(RECORDS_KEY)!.body);
  rs.effects.revoked = { "9": "" };
  w.b.store.set(RECORDS_KEY, { body: JSON.stringify(rs), etag: "s3" });
  await w.records(t0 + 90 * MIN);
  assert.ok(Object.hasOwn(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.revoked, "9"), "a bare number was dropped before cfaudit confirmed it");
  w.b.store.set(STATE_KEY, { body: JSON.stringify({ v: 1, m: { rj: ["9"] } }), etag: "s3c" });
  await w.records(t0 + 150 * MIN);
  assert.ok(!Object.hasOwn(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.revoked, "9"), "a confirmed, no longer raised number was kept");
});

test("#5: the rebuild floor covers late and not-yet-indexed matched events, not only the checkpoint", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS;
  await w.crons(t0 + H, on + 30 * H);
  const rs = JSON.parse(w.b.store.get(RECORDS_KEY)!.body), cs = state(w.b);
  const lateT = cs.m.t - 10 * H;
  cs.m.late = [{ id: "lt1", a: "create", k: id(1), t: lateT, ok: true, ep: 1 }];
  delete rs.effects;
  w.b.store.set(RECORDS_KEY, { body: JSON.stringify(rs), etag: "f5" });
  w.b.store.set(STATE_KEY, { body: JSON.stringify(cs), etag: "f5c" });
  await w.records(on + 31 * H);
  assert.equal(JSON.parse(w.b.store.get(RECORDS_KEY)!.body).effects.since, lateT - GRANT_TTL_MS - H, "the rebuild floor ignored a late event's needs");
});

// ---- #15: the six conditions that had no distinguishing test ----

test("#15 epoch: two runs activating at the same boundary append one epoch", async () => {
  const w = world();
  await w.run(ON - H, 0); // saved, still warming up
  w.b.store.set(EPOCHS_KEY, { body: JSON.stringify({ epochs: [{ n: 1, boundary: ON }] }), etag: "raced" }); // a rival run activated first
  await w.run(ON + H, 0);
  assert.equal(JSON.parse(w.b.store.get(EPOCHS_KEY)!.body).epochs.length, 1, "a repeated activation appended a second epoch");
});

test("#15 headcount-read filter: only the key's own List Tokens read counts as in use", async () => {
  const inst = id(25);
  const w = world({ "bbbbbbbb-hc": grant("cf.token.headcount.setup", T, { made: [inst], deleted: [] }) });
  const other = shapes.view("hf2", T + 25 * H, inst); other.action.description = "Get Token"; other.resource = { product: "tokens" };
  add(w, mc("hf1", T + 10_000, inst, { name: "front-desk headcount a", exp: null }), other);
  await w.run(T + 50 * H);
  assert.equal(w.has("outlived:hf1").length, 1, "a read other than List Tokens confirmed the headcount key");
});

test("#15 reverse dedupe: a reverse miss is raised once, never again after its incident leaves the list", async () => {
  const w = world({ "aaaaaaaa-rd": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }) });
  await w.run(T + 2 * H);
  assert.equal(w.has("reverse:").length, 1);
  await w.run(T + 31 * 24 * H);
  assert.equal(w.has("reverse:").length, 0, "a reverse miss was raised again after its incident left the list");
});

test("#15 replay tie: ids already read at the replay's instant are skipped, so the position never repeats them", async () => {
  const w = world();
  await w.run(T, 0);
  for (let i = 0; i < 1300; i++) w.log.push(shapes.view(`tv${i}`, T + MIN + (i < 590 ? i : 590), id(77)));
  add(w);
  revert(w, T + 3 * H);
  await w.run(T + 3 * H + MIN);
  await w.run(T + 3 * H + 2 * MIN);
  const ids = w.m().rp?.ids ?? [];
  assert.equal(new Set(ids).size, ids.length, "the replay re-read ids at its instant");
});

test("#15 delete deadline: a helper deleted after 24 h is still an outlived helper", async () => {
  const w = world({ "aaaaaaaa-dl": grant("cf.dns.list", T, { made: [id(1)], deleted: [] }), "bbbbbbbb-dl": grant("cf.token.accept", T + 25 * H, { made: [], deleted: [id(1)] }) });
  add(w, mc("dl1", T + 10_000, id(1)), md("dl2", T + 25 * H + 10_000, id(1)));
  await w.run(T + 27 * H);
  assert.equal(w.has("outlived:dl1").length, 1, "a delete after 24 h counted as in time");
});

test("M1: production path, an honest trace per permitted job and path matches with no unmatched alert", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS;
  let t = Math.floor(on / H) * H + 2 * H + 5 * MIN, k = 100;
  const jobs: [string, boolean, string[], number][] = [["cf.dns.list", false, ["Zone Read", "DNS Read"], 2], ["cf.dns.list", true, ["Zone Read", "DNS Read"], 2], ["cf.zone.read", false, ["Zone Read"], 2], ["cf.zone.read", true, ["Zone Read"], 2], ["cf.audit.read", false, ["Account Settings Read"], 1], ["cf.audit.read", true, ["Account Settings Read"], 1]];
  for (const [job, card, pg, n] of jobs) {
    const keys = Array.from({ length: n }, () => id(++k)), g = `5ca1ab1e-0000-4000-8000-${String(k).padStart(12, "0")}`;
    await w.tap(g, job, t, { made: keys, deleted: keys }, { card });
    keys.forEach((key, i) => w.log.push(mc(`m1c${k}${i}`, t + MIN + 1000 + i * 2000, key, { pg: [pg[i % pg.length]] }), md(`m1d${k}${i}`, t + MIN + 2000 + i * 2000, key)));
    t += 10 * MIN;
  }
  const hcOld = id(++k), hcNew = id(++k), sweep = id(++k);
  await w.tap("5ca1ab1e-0000-4000-8000-0000000000h1".replace("h", "a"), "cf.token.headcount.setup", t, { made: [hcNew], deleted: [hcOld] });
  w.log.push(mc("m1hc", t + MIN + 1000, hcNew, { name: "front-desk headcount 2026", exp: null }), md("m1ho", t + MIN + 2000, hcOld), hcRead("m1hr", t + 30 * MIN, hcNew));
  t += 10 * MIN;
  await w.tap("5ca1ab1e-0000-4000-8000-0000000000a2", "cf.token.accept", t, { made: [], deleted: [sweep] });
  w.log.push(md("m1sw", t + MIN + 1000, sweep));
  w.log.sort((x, y) => Date.parse(x.action.time) - Date.parse(y.action.time));
  await w.crons(t0 + H, t + 4 * H);
  assert.deepEqual(w.inc().filter((i) => /^(change|reverse|outlived):/.test(i.id)), [], "an honest production-path trace alerted");
  assert.equal(state(w.b).m.pend.length, 0, "an honest write is still pending");
});

test("#15 dedupe: an event read by both the replay and the main read is judged once", async () => {
  const w = world();
  add(w, mc("dd1", T, id(1)));
  await w.run(T + 30 * MIN, 0);
  add(w, mc("dd2", T + 2 * H, id(2)), mc("dd3", T + 2 * H, id(3))); // build a judged dd2; dd3 at the same instant it had not
  revert(w, T + 2 * H);
  const s = state(w.b); s.bm.ids = ["dd2"]; w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "dd" });
  await w.run(T + 3 * H, 0);
  const ids = [...w.m().pend, ...w.m().late, ...w.m().expl].map((e: any) => e.id);
  assert.equal(new Set(ids).size, ids.length, "an event read twice was queued twice");
});

test("r2 #4/#5: effects and matching state both lost across two epochs: an honest event between them matches, never 'restarted'", async () => {
  const w = await signedWorld();
  const t0 = Math.floor(CF_FROM / H) * H + H;
  await w.crons(t0, t0 + H);
  const on = since(w) + WARM_MS;
  await w.crons(t0 + H, on + 2 * H);
  const t = on + 3 * H, g = "5ca1ab1e-0000-4000-8000-0000000002e2";
  await w.tap(g, "cf.dns.list", t, { made: [id(1)], deleted: [id(1)] });
  w.log.push(mc("ce1", t + MIN + 1000, id(1)), md("ce2", t + MIN + 2000, id(1)));
  const ep = JSON.parse(w.b.store.get(EPOCHS_KEY)!.body);
  ep.epochs.push({ n: 2, boundary: on + 5 * H }); // a later re-enable
  w.b.store.set(EPOCHS_KEY, { body: JSON.stringify(ep), etag: "ep2" });
  const rs = JSON.parse(w.b.store.get(RECORDS_KEY)!.body), cs = state(w.b);
  rs.seq = w.seq(); if (rs.sealed) rs.sealed.to = w.seq(); delete rs.effects; delete rs.open?.[g];
  delete cs.m; cs.bm = { t: on + 7 * H, ids: [] };
  w.b.store.set(RECORDS_KEY, { body: JSON.stringify(rs), etag: "lost-r" });
  w.b.store.set(STATE_KEY, { body: JSON.stringify(cs), etag: "lost-c" });
  await w.crons(on + 7 * H, on + 11 * H);
  assert.deepEqual(w.inc().filter((i) => i.id.startsWith("change:ce")), [], "an honest event between the epochs alerted after both states were lost");
  assert.ok(state(w.b).m.expl.some((e: any) => e.id === "ce1"), "the honest event was not matched");
});

test("r2 N1: a headcount key replaced after 72 h ends its watch: the create is decided, the tap done, no outlived incident", async () => {
  const k1 = id(31), k2 = id(32);
  const w = world({ "aaaaaaaa-h1": grant("cf.token.headcount.setup", T, { made: [k1], deleted: [] }), "bbbbbbbb-h2": grant("cf.token.headcount.setup", T + 72 * H, { made: [k2], deleted: [k1] }) });
  add(w, mc("n1c", T + 10_000, k1, { name: "front-desk headcount a", exp: null }), hcRead("n1r", T + 25 * H, k1), hcRead("n1r2", T + 49 * H, k1), hcRead("n1r3", T + 71 * H, k1));
  add(w, mc("n2c", T + 72 * H + 10_000, k2, { name: "front-desk headcount b", exp: null }), md("n2d", T + 72 * H + 20_000, k1));
  await w.run(T + 74 * H);
  assert.ok(w.m().done.includes("aaaaaaaa-h1"), "a replaced headcount tap was not acknowledged done");
  assert.ok(w.m().expl.find((e: any) => e.id === "n1c")?.o, "a replaced headcount key's create stayed undecided");
  assert.equal(w.has("outlived:n1c").length, 0, "a headcount key deleted after 72 h was raised as outlived");
});

test("r2 #10: a replay range starting past 17 months is kept, red and incomplete, with one retention incident", async () => {
  const w = world();
  await w.run(T, 0);
  const s = state(w.b);
  s.m.t = T - 600 * 86_400_000; s.m.ids = [];
  w.b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "old" });
  const r = await w.run(T + H);
  await w.run(T + 2 * H);
  assert.ok(w.m().rp, "a replay past the retention bound was closed as complete");
  assert.equal(r.cfaudit, "did not finish", "a replay past the retention bound left the light green");
  assert.equal(r.matching, "incomplete");
  assert.equal(w.has("unavailable:retention:").length, 1, "the retention limit was not raised once");
  assert.equal(w.has("gap:").length, 0, "a gap was closed over a range past retention");
});

test("r2 #1: each run counts master creates and how many had readable permission groups, and raises the shape once", async () => {
  const w = world({ "aaaaaaaa-sh": grant("cf.dns.list", T, { made: [id(1), id(2)], deleted: [] }) });
  const bare = mc("sh2", T + 11_000, id(2)); delete bare.resource.response.policies;
  add(w, mc("sh1", T + 10_000, id(1)), bare);
  await w.run(T + H);
  const c = state(w.b).week.counts;
  assert.equal(c["master key creates seen"], 2, "master creates were not counted");
  assert.equal(c["master key creates with readable permission groups"], 1, "creates with readable groups were not counted");
  add(w, (() => { const e = mc("sh3", T + 2 * H, id(3)); delete e.resource.response.policies; return e; })());
  await w.run(T + 3 * H);
  assert.equal(w.has("shape:create").length, 1, "an unreadable create shape was not raised once");
  assert.equal(w.m().sh, true, "the shape flag was not kept");
});

test("r2 #7: an index recreated after a loss is complete only from its recreation", async () => {
  const w = world({ "aaaaaaaa-rc": grant("cf.dns.list", T, { made: [id(1)], deleted: [id(1)] }) });
  await w.run(T, 0);
  w.b.store.delete("state/cfindex/by-record.json");
  add(w, mc("rc1", T + 10_000, id(1)), md("rc2", T + 11_000, id(1)));
  await w.run(T + 2 * H);
  assert.ok(w.m().done.includes("aaaaaaaa-rc"), "test setup: the tap was not acknowledged");
  assert.ok(JSON.parse(w.b.store.get("state/cfindex/by-record.json")!.body).complete_from > ON, "a recreated index claimed completeness from the first epoch");
});
