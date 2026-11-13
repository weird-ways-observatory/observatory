// Card 139071ea (studio-os REFINE-139071ea-cf-keys-in-results.md v2.1 R6, R7, E2): a result of a job that opens the
// Cloudflare master names the keys its tap made and deleted, `cf`, so the hourly audit check can tie master-key events
// to Ben's taps. The recorder refuses a record that breaks the rule and the hourly checker re-reads every tap record
// against it, card or ordinary. The rule binds only grants whose request was recorded at or after CF_FROM.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, keyFor, sealed, sha256, validate, type Envelope, type Stage } from "../src/contract.ts";
import { CARD_RUN_MS, cardHashOf, CF_FROM, CF_JOBS, CF_LIST_MAX, cfRefusal, type Manifest } from "../src/card.ts";
import { Ledger, type Bucket, type Storage } from "../src/recorder/ledger.ts";
import { grantHashOf } from "../src/recorder/passkey.ts";
import { runRecords, STATE_KEY, type Pin, type RecordsEnv } from "../src/records.ts";
import { softKey } from "./softkey.ts";
import { bucket, storage } from "./store.ts";

const MIN = 60_000, HOUR = 60 * MIN;
const at = (ms: number) => () => new Date(ms);
const id = (n: number) => n.toString(16).padStart(32, "0");
const ids = (k: number, from = 1) => Array.from({ length: k }, (_, i) => id(from + i));
const LISTS = { made: [id(1), id(2)], deleted: [id(1), id(2), id(3)] };
const CARD_JOBS = ["cf.zone.read", "cf.dns.list", "cf.audit.read"]; // the master jobs a card may hold (card.ts CARD_ELIGIBLE)
/** Every malformed `cf`, each with why it is wrong. */
const MALFORMED: [string, unknown][] = [
  ["null", null], ["an empty object", {}], ["a list", [id(1)]], ["the wrong word", "Unknown"], ["a number", 0],
  ["made only", { made: [] }], ["an extra key", { made: [], deleted: [], kept: [] }],
  ["a list that is not a list", { made: id(1), deleted: [] }], ["an upper-case id", { made: [id(1).toUpperCase().replace(/0/g, "A")], deleted: [] }],
  ["a 31-hex id", { made: [id(1).slice(1)], deleted: [] }], ["a number id", { made: [1], deleted: [] }],
  ["17 made", { made: ids(CF_LIST_MAX + 1), deleted: [] }], ["17 deleted", { made: [], deleted: ids(CF_LIST_MAX + 1) }],
];

test("rule: only a Cloudflare-master result carries cf; from CF_FROM it must, well formed; 0 and 16 ids pass, 17 do not", () => {
  const r = (over: object) => ({ v: 1, grant: "grant-cf-01", stage: "result", job: "cf.dns.list", request: "a".repeat(64), outcome: "done", ...over });
  for (const job of CF_JOBS) {
    assert.equal(cfRefusal(r({ job, cf: LISTS }), CF_FROM), undefined, `${job}: well-formed lists were refused`);
    assert.equal(cfRefusal(r({ job, cf: "unknown" }), CF_FROM), undefined, `${job}: "unknown" was refused`);
    assert.equal(cfRefusal(r({ job }), CF_FROM), "a Cloudflare-master result must carry cf", `${job}: a result without cf was admitted`);
  }
  assert.equal(cfRefusal(r({ cf: { made: [], deleted: [] } }), CF_FROM), undefined, "empty lists were refused");
  assert.equal(cfRefusal(r({ cf: { made: ids(16), deleted: ids(16, 20) } }), CF_FROM), undefined, "16 ids were refused");
  for (const [what, cf] of MALFORMED) assert.match(cfRefusal(r({ cf }), CF_FROM) ?? "admitted", /^cf must be/, `malformed cf admitted: ${what}`);
  for (const stage of ["request", "approval", "verdict"]) assert.equal(cfRefusal(r({ stage, cf: LISTS }), CF_FROM), "only a result may carry cf", `cf on a ${stage} was admitted`);
  for (const job of ["test.echo", "gh.repo.create", "cf.token.canary"]) assert.equal(cfRefusal(r({ job, cf: LISTS }), CF_FROM - HOUR), "only a Cloudflare-master job's result may carry cf", `cf on a ${job} result was admitted`);
  assert.equal(cfRefusal(r({ job: "test.echo" }), CF_FROM), undefined, "a non-master result was asked for cf");
  // Activation by the request's recorded time: 1 ms before is legacy, exactly at is bound.
  assert.equal(cfRefusal(r({}), CF_FROM - 1), undefined, "a legacy result without cf was refused");
  assert.equal(cfRefusal(r({}), CF_FROM), "a Cloudflare-master result must carry cf", "a result opened exactly at CF_FROM was not bound");
  assert.match(cfRefusal(r({ cf: { made: [] } }), CF_FROM - 1) ?? "admitted", /^cf must be/, "a legacy result's malformed cf was admitted");
  // The writer's own reasons are never repeated back.
  assert.ok(!(cfRefusal(r({ cf: { made: ["MARKER"], deleted: [] } }), CF_FROM) ?? "").includes("MARKER"));
});

test("R5: whole desk-shaped result bodies with cf pass the recorder's contract (names, size)", () => {
  const body = (cf: unknown) => JSON.stringify({ v: 1, grant: "grant-cf-01", stage: "result", job: "cf.token.headcount.setup", request: "a".repeat(64), outcome: "done", at: CF_FROM, cf });
  assert.equal(validate(body({ made: ids(16), deleted: ids(16, 20) })).ok, true, "a full-bound body failed the contract");
  assert.equal(validate(body("unknown")).ok, true);
});

// ---- The recorder, through its real admission path ----

/** A recorder whose ordinary passkey check passes (passkey.test.ts tests it); card checks (a)-(e) run for real. */
class TestLedger extends Ledger {
  constructor(s: Storage, b: Bucket, cfFrom = CF_FROM) { super(s, b, undefined, async () => undefined, cfFrom); }
}
function recorder(cfFrom = CF_FROM) {
  const st = storage(), b = bucket();
  return { st, b, l: new TestLedger(st, b, cfFrom) };
}
type L = TestLedger;
const why = (o: Awaited<ReturnType<Ledger["accept"]>>) => [o.status, "why" in o ? o.why : "", "why" in o ? o.word : undefined];

/** Request and approval of one grant, ordinary or on a card, its request recorded at `t`. */
async function opened(l: L, grant: string, job: string, t: number, card = false, extra: object = {}) {
  const f = { v: 1 as const, grant, stage: "request" as const, job, params: {}, requester: "c-box agent", expires_at: t + 10 * MIN, ...(card ? { card: `card-${grant}` } : {}), ...extra };
  const hash = (await grantHashOf(f))!, req = JSON.stringify({ ...f, grant_hash: hash });
  assert.equal((await l.accept(req, at(t))).status, 201, `request ${grant}`);
  const request = await sha256(req);
  const manifest = { kind: "card/v1", card: `card-${grant}`, requester: "c-box agent", entries: [hash], deadline: t + 10 * MIN + CARD_RUN_MS, jobs_version: 1 };
  const appr = JSON.stringify({ v: 1, grant, stage: "approval", job, request, grant_hash: hash, approved_at: t + MIN, ...(card ? { approval_kind: "card/v1", manifest, assertion: {} } : {}) });
  assert.equal((await l.accept(appr, at(t + MIN))).status, 201, `approval ${grant}`);
  return { request, result: (over: object = {}) => JSON.stringify({ v: 1, grant, stage: "result", job, request, outcome: "done", ...over }) };
}
/** Refused with this reason, nothing stored, no number taken. */
async function refused(s: ReturnType<typeof recorder>, body: string, t: number, reason: string | RegExp, msg: string) {
  const before = s.b.store.size, seq = (s.st.m.get("meta") as { seq: number }).seq;
  const [status, w] = why(await s.l.accept(body, at(t)));
  assert.equal(status, 409, `${msg} (status ${status}: ${w})`);
  if (typeof reason === "string") assert.equal(w, reason, msg);
  else assert.match(String(w), reason, msg);
  assert.equal(s.b.store.size, before, "a refused record was stored");
  assert.equal((s.st.m.get("meta") as { seq: number }).seq, seq, "a refused record took a number");
}

test("recorder: every master job, card and ordinary, opened at CF_FROM: lists and unknown stored; missing, malformed or 17 ids refused", async () => {
  const combos = [...CF_JOBS.map((j) => [j, false] as const), ...CARD_JOBS.map((j) => [j, true] as const)];
  let n = 0;
  for (const [job, card] of combos) {
    const s = recorder(), t = CF_FROM;
    const g = await opened(s.l, `grant-rm-${String(++n).padStart(2, "0")}`, job, t, card);
    await refused(s, g.result(), t + 2 * MIN, "a Cloudflare-master result must carry cf", `${job}${card ? " (card)" : ""}: a result without cf was stored`);
    for (const [what, cf] of MALFORMED) await refused(s, g.result({ cf }), t + 2 * MIN, /^cf must be/, `${job}${card ? " (card)" : ""}: malformed cf stored: ${what}`);
    if (card) assert.equal(why(await s.l.accept(g.result(), at(t + 2 * MIN)))[2], "card_refused", "a card entry's cf refusal was not counted as card_refused");
    const ok = await s.l.accept(g.result({ cf: { made: ids(16), deleted: [] } }), at(t + 2 * MIN));
    assert.equal(ok.status, 201, `${job}: a well-formed result was refused`);
    const u = await opened(s.l, `grant-ru-${String(n).padStart(2, "0")}`, job, t, card);
    assert.equal((await s.l.accept(u.result({ cf: "unknown", outcome: "failed" }), at(t + 2 * MIN))).status, 201, `${job}: an unknown result was refused`);
  }
});

test("recorder: cf on a request, approval or verdict is refused, and on a non-master job's result, before or after CF_FROM", async () => {
  for (const t of [CF_FROM - HOUR, CF_FROM + HOUR]) {
    const s = recorder();
    const f = { v: 1, grant: "grant-st-01", stage: "request", job: "cf.dns.list", params: {}, cf: LISTS };
    await s.l.accept(JSON.stringify({ v: 1, grant: "grant-st-00", stage: "request", job: "test.echo" }), at(t)); // a first record, so meta exists
    await refused(s, JSON.stringify(f), t, "only a result may carry cf", "cf on a request was stored");
    const req = JSON.stringify({ v: 1, grant: "grant-st-02", stage: "request", job: "cf.dns.list" }), h = await sha256(req);
    assert.equal((await s.l.accept(req, at(t))).status, 201);
    await refused(s, JSON.stringify({ v: 1, grant: "grant-st-02", stage: "approval", job: "cf.dns.list", request: h, cf: LISTS }), t + MIN, "only a result may carry cf", "cf on an approval was stored");
    await refused(s, JSON.stringify({ v: 1, grant: "grant-st-02", stage: "verdict", job: "cf.dns.list", request: h, cf: LISTS }), t + MIN, "only a result may carry cf", "cf on a verdict was stored");
    for (const job of ["test.echo", "gh.repo.create"]) {
      const g = await opened(s.l, `grant-nm-${job === "test.echo" ? "01" : "02"}`, job, t);
      await refused(s, g.result({ cf: LISTS, ...(job === "gh.repo.create" ? { repo_id: "12345" } : {}) }), t + 2 * MIN, "only a Cloudflare-master job's result may carry cf", `cf on a ${job} result was stored`);
    }
  }
});

test("recorder: activation by the stored request time -- 1 ms before CF_FROM is legacy (resend admitted), exactly at is bound, a writer's earlier time is ignored", async () => {
  const s = recorder();
  const legacy = await opened(s.l, "grant-ac-01", "cf.zone.read", CF_FROM - 1, true);
  const frozen = legacy.result({ outcome: "done" });
  assert.equal((await s.l.accept(frozen, at(CF_FROM + HOUR))).status, 201, "a legacy result without cf was refused after CF_FROM");
  assert.equal((await s.l.accept(frozen, at(CF_FROM + 2 * HOUR))).status, 200, "a resend of a legacy frozen body was not answered with its receipt");
  const bound = await opened(s.l, "grant-ac-02", "cf.zone.read", CF_FROM);
  await refused(s, bound.result(), CF_FROM + MIN, "a Cloudflare-master result must carry cf", "a request recorded exactly at CF_FROM was not bound");
  // The writer claims an earlier time in every field it controls; the recorder's own stored time decides.
  const claim = { at: CF_FROM - HOUR, created_at: CF_FROM - HOUR, approved_at: CF_FROM - HOUR };
  const g = await opened(s.l, "grant-ac-03", "cf.dns.list", CF_FROM + MIN);
  await refused(s, g.result(claim), CF_FROM + 2 * MIN, "a Cloudflare-master result must carry cf", "a writer-supplied earlier time exempted a bound grant");
});

// ---- The hourly checker, over signed records ----

/** An R2 bucket that lists, as cards-checker.test.ts fakes it. */
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
    async put(k: string, b: string) { store.set(k, { body: b, uploaded: new Date(0) }); return {} as R2Object; },
  };
}

async function world(cfFrom = CF_FROM) {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair, key = await softKey();
  const pin: Pin = { key: b64((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer), from: 1 };
  const b = listBucket(), copy = listBucket();
  let seq = 0;
  const put = async (grant: string, stage: Stage, rec: object, t: number) => {
    const body = JSON.stringify({ v: 1, grant, stage, ...rec }), sha = await sha256(body), n = ++seq;
    const e: Envelope = { v: 2, seq: n, grant, stage, recorded_at: new Date(t).toISOString(), sha256: sha, body };
    b.store.set(keyFor(n, grant, stage), { body: JSON.stringify({ ...e, sig: b64(await crypto.subtle.sign("Ed25519", pair.privateKey, sealed(e))) }), uploaded: new Date(t) });
    return { sha, body, n };
  };
  /** A whole tap: request at t, approval, then a result with `over`; card grants carry a card mark (card checks are cards-checker.test.ts's). */
  // A card grant gets a real card/v1 approval (Ben's software passkey over the card hash), so the card checks pass
  // and any finding left is the cf rule's. `request`: extra request fields (a writer-claimed time); `verdict`: a
  // verdict record's extra fields, stored between approval and result.
  const tap = async (grant: string, job: string, t: number, over: object = {}, { card = false, approval = {} as object, request = {} as object, verdict = undefined as object | undefined } = {}) => {
    const f = { v: 1 as const, grant, stage: "request" as const, job, params: {}, requester: "c-box agent", expires_at: t + 10 * MIN, ...(card ? { card: `card-${grant}` } : {}), ...request };
    const hash = (await grantHashOf(f))!;
    const r = await put(grant, "request", { ...f, grant_hash: hash }, t);
    const m: Manifest = { kind: "card/v1", card: `card-${grant}`, requester: "c-box agent", entries: [hash], deadline: t + 10 * MIN + CARD_RUN_MS, jobs_version: 1 };
    const cardMark = card ? { grant_hash: hash, approval_kind: "card/v1", manifest: m, assertion: await key.answer(await cardHashOf(m)) } : {};
    await put(grant, "approval", { job, request: r.sha, ...cardMark, ...approval }, t + MIN);
    if (verdict) await put(grant, "verdict", { job, request: r.sha, ...verdict }, t + MIN + 30_000);
    return put(grant, "result", { job, request: r.sha, outcome: "done", ...over }, t + 2 * MIN);
  };
  const env = { RECORDS: b, COPY: copy } as unknown as RecordsEnv;
  // Every incident but the bucket-lock setup one: the fake bucket has no retention lock (lock.ts), unrelated to cf.
  const allIds = () => (copy.store.has(STATE_KEY) ? (JSON.parse(copy.store.get(STATE_KEY)!.body).incidents as { id: string }[]).map((i) => i.id).filter((i) => !i.startsWith("lock:")) : []);
  const run = (t: number, from = cfFrom) => runRecords(env, async () => new Response("", { status: 500 }), new Date(t), pin, undefined, from);
  const cfIds = () => (copy.store.has(STATE_KEY) ? (JSON.parse(copy.store.get(STATE_KEY)!.body).incidents as { id: string }[]).map((i) => i.id).filter((i) => i.startsWith("cf-bad:")) : []);
  /** A rebuild: the checker's saved state is dropped and every record is read again from the first. */
  const rebuild = (t: number, from = cfFrom) => (copy.store.delete(STATE_KEY), run(t, from));
  return { b, put, tap, run, rebuild, cfIds, allIds };
}

test("checker: every master job, card and ordinary tap, at CF_FROM: a missing or malformed cf is flagged in the shared step; lists, 0, 16 and unknown are not", async () => {
  const w = await world();
  const combos = [...CF_JOBS.map((j) => [j, false] as const), ...CARD_JOBS.map((j) => [j, true] as const)];
  const want: string[] = [];
  let n = 0;
  for (const [job, card] of combos) {
    const k = String(++n).padStart(2, "0");
    await w.tap(`grant-ok-${k}`, job, CF_FROM, { cf: LISTS }, { card });
    await w.tap(`grant-un-${k}`, job, CF_FROM, { cf: "unknown", outcome: card ? "failed" : "done" }, { card });
    await w.tap(`grant-ze-${k}`, job, CF_FROM, { cf: { made: [], deleted: [] } }, { card });
    await w.tap(`grant-16-${k}`, job, CF_FROM, { cf: { made: ids(16), deleted: ids(16, 20) } }, { card });
    want.push(`cf-bad:grant-no-${k}:${(await w.tap(`grant-no-${k}`, job, CF_FROM, {}, { card })).n}`);
    for (const [i, [, cf]] of MALFORMED.entries()) {
      const g = `grant-m${String(i).padStart(2, "0")}-${k}`;
      want.push(`cf-bad:${g}:${(await w.tap(g, job, CF_FROM, { cf }, { card })).n}`);
    }
  }
  await w.run(CF_FROM + HOUR);
  assert.deepEqual(w.cfIds().sort(), want.sort(), "the checker's cf findings are not exactly the missing and malformed results");
});

test("checker: cf on a request, approval or verdict, or on a non-master result, is flagged, before or after CF_FROM", async () => {
  const w = await world(), want: string[] = [];
  const combos = [...CF_JOBS.map((j) => [j, false] as const), ...CARD_JOBS.map((j) => [j, true] as const)];
  for (const [t, k] of [[CF_FROM - HOUR, "a"], [CF_FROM + HOUR, "b"]] as const) {
    let n = 0;
    // Every supported master job, ordinary and (where eligible) card, with cf on each non-result stage in turn (Codex obs r2 #2).
    for (const [job, card] of combos) {
      const c = `${k}${String(++n).padStart(2, "0")}`;
      const rq = await w.tap(`grant-rq-${c}`, job, t, { cf: LISTS }, { card, request: { cf: LISTS } });
      want.push(`cf-bad:grant-rq-${c}:${rq.n - 2}`);
      const ap = await w.tap(`grant-ap-${c}`, job, t, { cf: LISTS }, { card, approval: { cf: LISTS } });
      want.push(`cf-bad:grant-ap-${c}:${ap.n - 1}`);
      const vd = await w.tap(`grant-vd-${c}`, job, t, { cf: LISTS }, { card, verdict: { cf: LISTS } });
      want.push(`cf-bad:grant-vd-${c}:${vd.n - 1}`);
    }
    for (const [job, card] of [["test.echo", false], ["test.echo", true], ["gh.repo.create", true]] as const) {
      const g = `grant-nm-${job === "test.echo" ? "e" : "r"}${card ? "c" : "o"}${k}`;
      want.push(`cf-bad:${g}:${(await w.tap(g, job, t, { cf: LISTS, ...(job === "gh.repo.create" ? { repo_id: "12345" } : {}) }, { card })).n}`);
    }
  }
  await w.run(CF_FROM + 2 * HOUR);
  assert.deepEqual(w.cfIds().sort(), want.sort(), "cf findings differ from the request, approval, verdict and non-master records");
});

test("E2 spoof: a request recorded exactly at CF_FROM that claims an earlier time is bound -- recorder refuses, checker flags its result without cf", async () => {
  const claim = { at: CF_FROM - HOUR, created_at: CF_FROM - HOUR };
  const s = recorder();
  for (const card of [false, true]) {
    const g = await opened(s.l, `grant-sp-0${card ? 2 : 1}`, "cf.audit.read", CF_FROM, card, claim);
    await refused(s, g.result(), CF_FROM + MIN, "a Cloudflare-master result must carry cf", `a request claiming an earlier time exempted its ${card ? "card" : "ordinary"} result`);
  }
  const w = await world();
  const o = await w.tap("grant-sp-01", "cf.audit.read", CF_FROM, {}, { request: claim });
  const c = await w.tap("grant-sp-02", "cf.audit.read", CF_FROM, {}, { request: claim, card: true });
  await w.run(CF_FROM + HOUR);
  assert.deepEqual(w.cfIds().sort(), [`cf-bad:grant-sp-01:${o.n}`, `cf-bad:grant-sp-02:${c.n}`].sort(), "the checker exempted a request that claimed an earlier time");
});

test("checker: legacy grants (card and ordinary, every master job) without cf raise nothing, and a rebuild over them runs green with no incident", async () => {
  const w = await world();
  let n = 0;
  for (const [job, card] of [...CF_JOBS.map((j) => [j, false] as const), ...CARD_JOBS.map((j) => [j, true] as const)]) {
    await w.tap(`grant-lg-${String(++n).padStart(2, "0")}`, job, n % 2 ? CF_FROM - 1 : CF_FROM - HOUR, {}, { card });
  }
  const first = await w.run(CF_FROM + HOUR);
  assert.equal(first.records, "ran", `the first read did not run: ${first.reason}`);
  assert.deepEqual(w.allIds(), [], "legacy results without cf raised an incident");
  const again = await w.rebuild(CF_FROM + 2 * HOUR);
  assert.equal(again.records, "ran", `the rebuild did not run: ${again.reason}`);
  assert.equal(again.checked, 3 * n, "the rebuild did not re-read every record");
  assert.deepEqual(w.allIds(), [], "a rebuild over legacy results without cf raised an incident");
});

test("R7 rollback: rule on, rule reverted while an old desk writes no cf, then on again with a fresh CF_FROM -- earlier bodies unchanged, rollback-period results never refused or flagged", async () => {
  const w = await world(), FRESH = CF_FROM + 6 * HOUR;
  // One recorder's storage across three code versions: rule on, rule reverted, rule on again with a fresh time.
  const st = storage(), b = bucket();
  const on1 = { st, b, l: new TestLedger(st, b) }, off = { st, b, l: new TestLedger(st, b, Infinity) }, on2 = { st, b, l: new TestLedger(st, b, FRESH) };
  // 1. Rule active: a result with lists is stored and read.
  const g1 = await opened(on1.l, "grant-rb-01", "cf.dns.list", CF_FROM + MIN);
  const kept = g1.result({ cf: LISTS });
  assert.equal((await on1.l.accept(kept, at(CF_FROM + 2 * MIN))).status, 201);
  await w.tap("grant-rb-01", "cf.dns.list", CF_FROM + MIN, { cf: LISTS });
  // 2. Rolled back, Observatory first: the old desk writes results without cf. Reverting removes the rule, shown
  //    here by a rule time no record reaches.
  const g2 = await opened(off.l, "grant-rb-02", "cf.audit.read", CF_FROM + 3 * HOUR);
  const rolled = g2.result();
  assert.equal((await off.l.accept(rolled, at(CF_FROM + 3 * HOUR + 2 * MIN))).status, 201, "the reverted recorder refused an old desk's result");
  await w.tap("grant-rb-02", "cf.audit.read", CF_FROM + 3 * HOUR);
  // 3. On again with a fresh time, chosen after the cf-writing desk is live again.
  assert.equal((await on2.l.accept(rolled, at(FRESH + MIN))).status, 200, "a rollback-period frozen body's resend was not answered with its receipt");
  assert.equal((await on2.l.accept(kept, at(FRESH + MIN))).status, 200, "an earlier body with cf was not answered with its receipt");
  const g3 = await opened(on2.l, "grant-rb-03", "cf.audit.read", FRESH - MIN);
  assert.equal((await on2.l.accept(g3.result(), at(FRESH + MIN))).status, 201, "a request from before the fresh time was refused for lacking cf");
  const g4 = await opened(on2.l, "grant-rb-04", "cf.dns.list", FRESH);
  await refused(on2, g4.result(), FRESH + MIN, "a Cloudflare-master result must carry cf", "re-activation did not bind a later request");
  await w.tap("grant-rb-04", "cf.dns.list", FRESH, { cf: "unknown" });
  const before = [...w.b.store.entries()].map(([k, v]) => [k, v.body]);
  await w.rebuild(FRESH + HOUR, FRESH);
  assert.deepEqual(w.cfIds(), [], "a rebuild with the fresh CF_FROM flagged a rollback-period result");
  assert.deepEqual([...w.b.store.entries()].map(([k, v]) => [k, v.body]), before, "a replay changed a stored body");
  // Why the old time is never reused: it would flag the rollback-period result.
  await w.rebuild(FRESH + HOUR, CF_FROM);
  assert.equal(w.cfIds().length, 1, "reusing the old CF_FROM did not flag the rollback-period result");
});
