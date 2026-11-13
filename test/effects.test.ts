// Card beec640b build b, the records side (studio-os docs/specifications/trust-but-verify/REFINE-beec640b-build-b.md
// v3.2, sections 4.1-4.3, 4.6, 12.2): the hourly records check keeps `effects`, the eligible request-approval-result
// chain of every Cloudflare-master tap, inside state/records.json, saved in the same conditional save as its bookmark.
// Records are signed by a test key, as the recorder signs them; COPY is the R2 fake that honours conditions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, keyFor, sealed, sha256, SKEW_MS, type Envelope, type Stage } from "../src/contract.ts";
import { CARD_RUN_MS, cardHashOf, CF_FROM, CF_JOBS, type Manifest } from "../src/card.ts";
import { STATE_KEY as CFAUDIT_KEY } from "../src/cfaudit.ts";
import { grantHashOf } from "../src/recorder/passkey.ts";
import { EFFECTS_KEEP_MS, INDEX_KEEP_MS, MAX_EFFECTS, PAGE, runRecords, STATE_KEY, WRITE_MARGIN_MS, type Pin, type RecordsEnv } from "../src/records.ts";
import { bucket as copyBucket } from "./cfaudit-fakes.ts";
import { softKey } from "./softkey.ts";

const MIN = 60_000, HOUR = 60 * MIN, DAY = 24 * HOUR;
const T = CF_FROM + HOUR; // taps after CF_FROM: cf is required
const id = (n: number) => n.toString(16).padStart(32, "0");
const LISTS = { made: [id(1), id(2)], deleted: [id(3)] };
const CARD_JOBS = ["cf.zone.read", "cf.dns.list", "cf.audit.read"];
const ORDINARY_ONLY = ["cf.token.headcount.setup", "cf.token.accept"];

function listBucket() {
  const store = new Map<string, { body: string; uploaded: Date }>();
  let failList = false;
  return {
    store,
    failList(on = true) { failList = on; },
    async list(o: { prefix?: string; delimiter?: string; cursor?: string; startAfter?: string; limit?: number }) {
      if (failList) throw new Error("R2 down");
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

interface Stamp { n: number; sha: string; at: number }
interface Entry { job: string; path: string; req?: Stamp; appr?: Stamp; res?: Stamp; cf?: unknown; tainted?: string }
interface Fx { gen: number; since: number; covered_to: number; grants: Record<string, Entry>; retired: Record<string, number>; index: Record<string, string>; replay_from?: number }

async function world() {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair, key = await softKey();
  const pin: Pin = { key: b64((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer), from: 1 };
  const b = listBucket(), copy = copyBucket();
  let seq = 0;
  const put = async (grant: string, stage: Stage, rec: object, t: number): Promise<Stamp> => {
    const body = JSON.stringify({ v: 1, grant, stage, ...rec }), sha = await sha256(body), n = ++seq;
    const e: Envelope = { v: 2, seq: n, grant, stage, recorded_at: new Date(t).toISOString(), sha256: sha, body };
    b.store.set(keyFor(n, grant, stage), { body: JSON.stringify({ ...e, sig: b64(await crypto.subtle.sign("Ed25519", pair.privateKey, sealed(e))) }), uploaded: new Date(t) });
    return { n, sha, at: t };
  };
  /** A whole tap: request at t, approval at t+1m, optional verdict, result at t+2m. A card grant gets a real card/v1 approval. */
  const tap = async (grant: string, job: string, t: number, over: object = {}, { card = false, approval = {} as object, request = {} as object, verdict = undefined as object | undefined, result = true } = {}) => {
    const f = { v: 1 as const, grant, stage: "request" as const, job, params: {}, requester: "c-box agent", expires_at: t + 10 * MIN, ...(card ? { card: `card-${grant}` } : {}), ...request };
    const hash = (await grantHashOf(f))!;
    const req = await put(grant, "request", { ...f, grant_hash: hash }, t);
    const m: Manifest = { kind: "card/v1", card: `card-${grant}`, requester: "c-box agent", entries: [hash], deadline: t + 10 * MIN + CARD_RUN_MS, jobs_version: 1 };
    const cardMark = card ? { grant_hash: hash, approval_kind: "card/v1", manifest: m, assertion: await key.answer(await cardHashOf(m)) } : {};
    const appr = await put(grant, "approval", { job, request: req.sha, ...cardMark, ...approval }, t + MIN);
    if (verdict) await put(grant, "verdict", { job, request: req.sha, ...verdict }, t + MIN + 30_000);
    const res = result ? await put(grant, "result", { job, request: req.sha, outcome: "done", ...over }, t + 2 * MIN) : undefined;
    return { req, appr, res };
  };
  const env = { RECORDS: b, COPY: copy } as unknown as RecordsEnv;
  const run = (t: number, e: RecordsEnv = env) => runRecords(e, async () => new Response("", { status: 500 }), new Date(t), pin, undefined, CF_FROM);
  const runWith = (e: RecordsEnv, f: (r: Request) => Promise<Response>, t: number) => runRecords(e, f, new Date(t), pin, undefined, CF_FROM);
  const state = () => JSON.parse(copy.store.get(STATE_KEY)!.body);
  const fx = (): Fx => state().effects;
  /** cfaudit's matching acknowledgement (12.2): `m.done` inside state/cfaudit.json. */
  const done = (grants: string[]) => copy.store.set(CFAUDIT_KEY, { body: JSON.stringify({ v: 1, m: { done: grants } }), etag: "cfaudit" });
  return { b, copy, put, tap, run, runWith, env, state, fx, done, seq: () => seq };
}

test("effects: an honest tap per Cloudflare-master job and path is kept whole; other jobs get no entry", async () => {
  const w = await world();
  const want: Record<string, Entry> = {};
  let k = 0;
  const combos = [...CF_JOBS.map((j) => [j, false] as const), ...CARD_JOBS.map((j) => [j, true] as const)];
  for (const [job, card] of combos) {
    const g = `grant-ok-${String(++k).padStart(2, "0")}`;
    const s = await w.tap(g, job, T + k * MIN, { cf: LISTS }, { card });
    want[g] = { job, path: card ? "card" : "ordinary", req: s.req, appr: s.appr, res: s.res, cf: LISTS };
  }
  for (const [job, card] of [["test.echo", false], ["test.echo", true], ["gh.repo.create", true], ["cf.token.canary", false]] as const) {
    await w.tap(`grant-no-${job.replace(/\./g, "")}${card ? "c" : "o"}`, job, T, job === "gh.repo.create" ? { repo_id: "123" } : {}, { card });
  }
  const r = await w.run(T + HOUR);
  assert.equal(r.records, "ran", r.reason);
  assert.deepEqual(w.fx().grants, want, "the effects entries are not exactly the honest master taps");
  for (const [job] of ORDINARY_ONLY.map((j) => [j])) assert.ok(Object.values(w.fx().grants).some((e) => e.job === job && e.path === "ordinary"));
  assert.equal(w.fx().index[String(want["grant-ok-01"].res!.n)], "grant-ok-01", "the index does not map a result's record number to its grant");
});

test("effects: legacy results without cf are kept as none; cf unknown is kept as unknown", async () => {
  const w = await world();
  await w.tap("grant-lg-01", "cf.dns.list", CF_FROM - HOUR, {});
  await w.tap("grant-lg-02", "cf.zone.read", CF_FROM - HOUR, {}, { card: true });
  await w.tap("grant-un-01", "cf.token.accept", T, { cf: "unknown" });
  await w.tap("grant-un-02", "cf.audit.read", T, { cf: "unknown", outcome: "failed" }, { card: true });
  await w.run(T + HOUR);
  const g = w.fx().grants;
  assert.deepEqual([g["grant-lg-01"].cf, g["grant-lg-02"].cf, g["grant-un-01"].cf, g["grant-un-02"].cf], ["none", "none", "unknown", "unknown"], "legacy or unknown cf was not kept as none or unknown");
  for (const e of Object.values(g)) assert.ok(e.res && !e.tainted, "a legacy or unknown result was not eligible");
});

test("effects: a finding at any stage taints the grant and stops its later stages; a bad request gets no entry", async () => {
  const w = await world();
  await w.tap("grant-rq-01", "cf.dns.list", T, { cf: LISTS }, { request: { cf: LISTS } }); // cf on a request
  await w.tap("grant-ap-01", "cf.zone.read", T, { cf: LISTS }, { card: true, approval: { assertion: {} } }); // card-bad approval
  await w.tap("grant-vd-01", "cf.audit.read", T, { cf: LISTS }, { verdict: { cf: LISTS } }); // cf on a verdict
  await w.tap("grant-rs-01", "cf.token.accept", T, {}); // a bound result without cf
  await w.run(T + HOUR);
  const g = w.fx().grants;
  assert.equal(g["grant-rq-01"], undefined, "a request with a finding made an entry");
  assert.match(g["grant-ap-01"]?.tainted ?? "", /card-bad/, "a card-bad approval did not taint");
  assert.ok(g["grant-ap-01"].req && !g["grant-ap-01"].appr && !g["grant-ap-01"].res, "a stage after a bad approval was kept");
  assert.match(g["grant-vd-01"]?.tainted ?? "", /cf-bad/, "a bad verdict did not taint");
  assert.ok(g["grant-vd-01"].appr && !g["grant-vd-01"].res, "a result after a bad verdict was kept");
  assert.match(g["grant-rs-01"]?.tainted ?? "", /cf-bad/, "a bad result did not taint");
  assert.ok(!g["grant-rs-01"].res && g["grant-rs-01"].cf === undefined, "a bad result was kept");
});

test("effects: a cf list with a repeated key id taints the grant", async () => {
  const w = await world();
  await w.tap("grant-dp-01", "cf.dns.list", T, { cf: { made: [id(1), id(1)], deleted: [] } });
  await w.tap("grant-dp-02", "cf.dns.list", T, { cf: { made: [], deleted: [id(4), id(5), id(4)] } });
  await w.run(T + HOUR);
  for (const g of ["grant-dp-01", "grant-dp-02"]) {
    const e = w.fx().grants[g];
    assert.ok(e.tainted && !e.res, `a repeated key id in a cf list did not taint ${g}`);
  }
});

test("effects: a later daily-count finding on a kept record number taints its grant", async () => {
  const w = await world();
  const s = await w.tap("grant-sw-01", "cf.dns.list", T, { cf: LISTS });
  await w.tap("grant-sw-02", "cf.dns.list", T, { cf: LISTS });
  await w.run(T + HOUR);
  assert.equal(w.fx().grants["grant-sw-01"].tainted, undefined);
  // Something writes around the recorder at the result's number; the daily count (04:xx UTC) reads it.
  w.b.store.set(keyFor(s.res!.n, "grant-sw-01", "result", "0123456789abcdef"), { body: "{}", uploaded: new Date(T + 2 * HOUR) });
  const sweep = Date.parse("2026-11-14T04:30:00.000Z");
  await w.run(sweep);
  assert.match(w.fx().grants["grant-sw-01"].tainted ?? "", /foreign/, "a later sweep finding on the result's number did not taint the grant");
  assert.equal(w.fx().grants["grant-sw-02"].tainted, undefined, "an untouched grant was tainted");
});

test("covered_to: a quiet run moves it to run start - skew - margin; an unverified or backlog run does not; it never moves back", async () => {
  const w = await world();
  await w.tap("grant-cv-01", "cf.dns.list", T, { cf: LISTS });
  const t1 = T + HOUR, t2 = T + 2 * HOUR;
  await w.run(t1);
  assert.equal(w.fx().covered_to, t1 - SKEW_MS - WRITE_MARGIN_MS, "a run that read to the end did not set covered_to");
  assert.equal(WRITE_MARGIN_MS, 2 * MIN);
  await w.run(t2); // no new records
  assert.equal(w.fx().covered_to, t2 - SKEW_MS - WRITE_MARGIN_MS, "a quiet run did not advance covered_to");
  await w.run(t1 + 30 * MIN);
  assert.equal(w.fx().covered_to, t2 - SKEW_MS - WRITE_MARGIN_MS, "covered_to moved backwards");
  w.b.failList();
  const u = await w.run(t2 + HOUR);
  assert.equal(u.records, "unverified");
  assert.equal(w.fx().covered_to, t2 - SKEW_MS - WRITE_MARGIN_MS, "an unverified run moved covered_to");
  w.b.failList(false);
  // A run that read to the end of the bookmark but saw a higher number (a gap): ran, yet not covered.
  const gap = keyFor(w.seq() + 2, "grant-gp-0001", "request");
  w.b.store.set(gap, { body: "{}", uploaded: new Date(t2) });
  const g = await w.run(t2 + 90 * MIN);
  assert.equal(g.records, "ran", g.reason);
  assert.equal(w.fx().covered_to, t2 - SKEW_MS - WRITE_MARGIN_MS, "a run that saw a higher number moved covered_to");
  w.b.store.delete(gap);
  // The daily count cannot finish (too many objects at one number): unverified though the hourly read reached the end.
  for (let i = 0; i < 21; i++) w.b.store.set(keyFor(1, "grant-cv-01", "request", i.toString(16).padStart(16, "0")), { body: "{}", uploaded: new Date(t2) });
  const day = Date.parse("2026-11-14T04:30:00.000Z"), c = await w.run(day);
  assert.equal(c.records, "unverified", c.reason);
  assert.equal(w.fx().covered_to, t2 - SKEW_MS - WRITE_MARGIN_MS, "an unverified daily-count run moved covered_to");
  for (let i = 0; i < 21; i++) w.b.store.delete(keyFor(1, "grant-cv-01", "request", i.toString(16).padStart(16, "0")));
  for (let i = 0; i < PAGE; i++) await w.put(`grant-bl-${String(i).padStart(4, "0")}`, "request", { job: "test.echo" }, t2 + HOUR + i);
  const back = await w.run(day + HOUR);
  assert.equal(back.checked, PAGE);
  assert.equal(w.fx().covered_to, t2 - SKEW_MS - WRITE_MARGIN_MS, "a backlog run moved covered_to");
});

test("save: gen counts saves; a throw or a null at the save leaves effects and bookmark unchanged, and the next run rebuilds the same", async () => {
  const w = await world();
  await w.tap("grant-cr-01", "cf.dns.list", T, { cf: LISTS });
  await w.run(T + HOUR);
  const first = w.fx();
  assert.equal(first.gen, 1, "gen is not 1 after the first save");
  assert.equal(first.since, T + HOUR, "since is not the first save's time");
  await w.tap("grant-cr-02", "cf.zone.read", T + 3 * HOUR, { cf: LISTS }, { card: true });
  for (const fail of ["throw", "null"] as const) {
    const before = w.copy.store.get(STATE_KEY)!.body;
    if (fail === "throw") w.copy.throwOn(1);
    else w.copy.nullOn(1);
    const r = await w.run(T + 4 * HOUR);
    assert.equal(r.records, "unverified", `a ${fail} at the save was reported as ran`);
    assert.equal(w.copy.store.get(STATE_KEY)!.body, before, `a ${fail} at the save changed the saved state`);
  }
  await w.run(T + 4 * HOUR);
  const s = w.state();
  assert.equal(s.seq, w.seq());
  assert.equal(s.effects.gen, 2, "gen did not count only successful saves");
  assert.equal(s.effects.since, T + HOUR, "since moved");
  assert.ok(s.effects.grants["grant-cr-02"].res, "the next run did not rebuild the entry the failed saves lost");
});

test("save: two runs racing -- the loser writes nothing and the winner's state stands", async () => {
  const w = await world();
  await w.tap("grant-rc-01", "cf.dns.list", T, { cf: LISTS });
  await w.run(T + HOUR);
  const stale = w.copy.store.get(STATE_KEY)!;
  await w.tap("grant-rc-02", "cf.dns.list", T + HOUR, { cf: LISTS });
  await w.run(T + 2 * HOUR); // the winner
  const won = w.copy.store.get(STATE_KEY)!.body;
  // The loser read the state before the winner saved (its etag is the old one).
  const lagging = { ...w.env, COPY: { get: async (k: string) => (k === STATE_KEY ? { etag: stale.etag, text: async () => stale.body } : w.copy.get(k)), put: w.copy.put } } as unknown as RecordsEnv;
  await w.tap("grant-rc-03", "cf.dns.list", T + 2 * HOUR, { cf: LISTS });
  const lost = await w.run(T + 3 * HOUR, lagging);
  assert.equal(lost.records, "unverified", "the losing run reported ran");
  assert.equal(w.copy.store.get(STATE_KEY)!.body, won, "the losing run's save overwrote the winner's state");
});

test("save: the first save creates state only if none exists", async () => {
  const w = await world();
  await w.tap("grant-cf-01", "cf.dns.list", T, { cf: LISTS });
  const blind = { ...w.env, COPY: { get: async () => null, put: w.copy.put } } as unknown as RecordsEnv;
  await w.run(T + HOUR);
  const kept = w.copy.store.get(STATE_KEY)!.body;
  assert.equal((await w.run(T + 2 * HOUR, blind)).records, "unverified", "a run that saw no state overwrote existing state");
  assert.equal(w.copy.store.get(STATE_KEY)!.body, kept);
});

test("retention: an entry is retired only after res.at + 72 h AND cfaudit's m.done names it; its index lasts 30 days more", async () => {
  const w = await world();
  const s = await w.tap("grant-rt-01", "cf.dns.list", T, { cf: LISTS });
  await w.run(T + HOUR);
  const end = s.res!.at;
  w.done(["grant-rt-01"]);
  await w.run(end + EFFECTS_KEEP_MS - MIN);
  assert.ok(w.fx().grants["grant-rt-01"], "an entry was retired before 72 h");
  w.done([]);
  await w.run(end + EFFECTS_KEEP_MS + HOUR);
  assert.ok(w.fx().grants["grant-rt-01"], "an entry was retired without cfaudit's acknowledgement");
  w.copy.store.delete(CFAUDIT_KEY);
  await w.run(end + EFFECTS_KEEP_MS + 2 * HOUR);
  assert.ok(w.fx().grants["grant-rt-01"], "an entry was retired with no cfaudit state");
  w.done(["grant-rt-01"]);
  const at = end + EFFECTS_KEEP_MS + 3 * HOUR;
  await w.run(at);
  assert.equal(w.fx().grants["grant-rt-01"], undefined, "an acknowledged entry past 72 h was not retired");
  assert.equal(w.fx().retired["grant-rt-01"], at, "the retirement was not recorded");
  assert.equal(w.fx().index[String(s.res!.n)], "grant-rt-01", "the index was dropped at retirement");
  await w.run(at + INDEX_KEEP_MS - HOUR);
  assert.equal(w.fx().index[String(s.res!.n)], "grant-rt-01", "the index was dropped before 30 days");
  await w.run(at + INDEX_KEEP_MS + HOUR);
  assert.equal(w.fx().index[String(s.res!.n)], undefined, "the index outlived 30 days after retirement");
  assert.equal(w.fx().retired["grant-rt-01"], undefined);
});

test("cap: at MAX_EFFECTS live entries replay_from marks the first record not kept, the bookmark advances, and nothing is lost when room returns", async () => {
  const w = await world();
  const old = T - 10 * DAY, stamp = { n: 0, sha: "0".repeat(64), at: old };
  const grants = Object.fromEntries(Array.from({ length: MAX_EFFECTS }, (_, i) => [`grant-ful-${String(i).padStart(4, "0")}`, { job: "cf.dns.list", path: "ordinary", req: stamp, appr: stamp, res: stamp, cf: "none" }]));
  w.copy.store.set(STATE_KEY, { body: JSON.stringify({ seq: 0, effects: { gen: 7, since: old, covered_to: 0, grants, retired: {}, index: {} } }), etag: "seed" });
  const a = await w.tap("grant-cap-01", "cf.dns.list", T, { cf: LISTS });
  const b2 = await w.tap("grant-cap-02", "cf.zone.read", T, { cf: LISTS }, { card: true });
  await w.run(T + HOUR);
  assert.equal(w.state().seq, w.seq(), "the records bookmark stopped at the cap");
  assert.equal(w.fx().replay_from, a.req.n, "replay_from does not name the first record not kept");
  assert.equal(w.fx().grants["grant-cap-01"], undefined);
  // cfaudit acknowledges one old entry: room for one; projection resumes from replay_from.
  w.done(["grant-ful-0000"]);
  await w.run(T + 2 * HOUR);
  assert.deepEqual(w.fx().grants["grant-cap-01"], { job: "cf.dns.list", path: "ordinary", req: a.req, appr: a.appr, res: a.res, cf: LISTS }, "the replayed entry is not whole");
  assert.equal(w.fx().replay_from, b2.req.n, "replay_from did not stop at the next record with no room");
  w.done(["grant-ful-0001"]);
  await w.run(T + 3 * HOUR);
  assert.deepEqual(w.fx().grants["grant-cap-02"], { job: "cf.zone.read", path: "card", req: b2.req, appr: b2.appr, res: b2.res, cf: LISTS }, "a record was lost at the cap");
  assert.equal(w.fx().replay_from, undefined, "replay_from stayed set after the replay caught up");
});

test("cap: a replayed record with a standing finding is tainted, as if read live", async () => {
  const w = await world();
  const stamp = { n: 0, sha: "0".repeat(64), at: T - 10 * DAY };
  const grants = Object.fromEntries(Array.from({ length: MAX_EFFECTS }, (_, i) => [`grant-ful-${String(i).padStart(4, "0")}`, { job: "cf.dns.list", path: "ordinary", req: stamp, appr: stamp, res: stamp, cf: "none" }]));
  w.copy.store.set(STATE_KEY, { body: JSON.stringify({ seq: 0, effects: { gen: 1, since: 0, covered_to: 0, grants, retired: {}, index: {} } }), etag: "seed" });
  const s = await w.tap("grant-cpb-01", "cf.dns.list", T, { cf: LISTS });
  // Something wrote around the recorder at the approval's number: the finding names only that number.
  w.b.store.set(keyFor(s.appr.n, "grant-cpb-01", "approval", "0123456789abcdef"), { body: "{}", uploaded: new Date(T + MIN) });
  await w.tap("grant-cpb-02", "cf.dns.list", T, { cf: LISTS }, { verdict: { request: "f".repeat(64) } }); // mismatch names only the grant
  await w.run(T + HOUR);
  w.done(["grant-ful-0000", "grant-ful-0001"]);
  await w.run(T + 2 * HOUR);
  const e = w.fx().grants["grant-cpb-01"], f = w.fx().grants["grant-cpb-02"];
  assert.ok(e && e.tainted && !e.res, "a replayed record with a standing finding on its number was not tainted");
  assert.ok(f && f.tainted, "a replayed grant with a standing finding on the grant was not tainted");
});

test("retired: a finding on a retired grant's record raises one incident and is kept for re-judging; the run does not throw", async () => {
  const w = await world();
  const s = await w.tap("grant-rv-01", "cf.dns.list", T, { cf: LISTS });
  await w.run(T + HOUR);
  w.done(["grant-rv-01"]);
  const retiredAt = Date.parse("2026-11-17T03:30:00.000Z"); // past res.at + 72 h
  await w.run(retiredAt);
  assert.equal(w.fx().grants["grant-rv-01"], undefined);
  w.b.store.set(keyFor(s.res!.n, "grant-rv-01", "result", "0123456789abcdef"), { body: "{}", uploaded: new Date(retiredAt) });
  const r = await w.run(Date.parse("2026-11-18T04:30:00.000Z")).catch((x) => assert.fail(`effects threw out of the run: ${x}`)); // the daily count reads the plant
  assert.equal(r.records, "ran", `a finding on a retired record broke the run: ${r.reason}`);
  const ids = (w.state().incidents as { id: string; text: string }[]);
  assert.ok(ids.some((i) => i.id === `retired-bad:${s.res!.n}` && i.text.includes(`a record found bad after its judgments were retired: record ${s.res!.n}`)), "no retired-record incident was raised");
  assert.equal((w.fx() as Fx & { revoked: Record<string, string> }).revoked[String(s.res!.n)], "grant-rv-01", "the retired record was not kept for re-judging");
});

test("guard: a throw inside the effects bookkeeping marks the run unverified, and existing findings are still alerted and saved", async () => {
  for (const [where, bad] of [["the main read", "x"], ["after the read", null]] as const) {
    const w = await world();
    // A saved entry that is not an object: "x" throws when the read projects its request, null when retention reads it.
    w.copy.store.set(STATE_KEY, { body: JSON.stringify({ seq: 0, effects: { gen: 1, since: 0, covered_to: 0, grants: { "grant-str-01": bad }, retired: {}, index: {} } }), etag: "seed" });
    if (bad === "x") await w.put("grant-str-01", "request", { job: "cf.dns.list" }, T);
    await w.put("grant-ur-01", "result", { job: "test.echo", request: "a".repeat(64), outcome: "done" }, T + MIN); // ran unrecorded
    const pushes: string[] = [];
    const fetch = async (req: Request) => { const u = new URL(req.url); if (u.hostname === "api.pushover.net") pushes.push(new URLSearchParams(await req.text()).get("message") ?? ""); return new Response("{}", { status: u.hostname === "api.cloudflare.com" ? 500 : 200 }); };
    const e = { ...w.env, PING_URL: "https://hc.example/main", PING_URL_RECORDS: "https://hc.example/rec", PUSHOVER_TOKEN: "t".repeat(30), PUSHOVER_USER: "u".repeat(30) } as RecordsEnv;
    const r2 = await w.runWith(e, fetch, T + HOUR).catch((x) => assert.fail(`effects threw out of the run (${where}): ${x}`));
    assert.equal(r2.records, "unverified", `a throw in effects ${where} did not mark the run unverified`);
    assert.match(r2.reason, /effects/, `the unverified reason does not name effects (${where})`);
    assert.ok((w.state().incidents as { id: string }[]).some((i) => i.id === "unrecorded:grant-ur-01"), `an existing finding was not saved when effects threw ${where}`);
    assert.ok(pushes.some((p) => p.includes("ran unrecorded")), `an existing finding was not alerted when effects threw ${where}`);
  }
});
