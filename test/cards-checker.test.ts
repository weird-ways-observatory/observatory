// Card 586da182, the checker side (REFINE-586da182 Outcome 7, S2, S3, T3, D3): it re-reads card requests,
// card/v1 approvals and card results; raises card-bad, card-incomplete (only after a complete read passes
// deadline + 1 h), card-late and card-unknown (once); and a reverted checker's lost state shows as card-bad.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, keyFor, sealed, sha256, type Envelope, type Stage } from "../src/contract.ts";
import { CARD_RESULT_MS, CARD_RUN_MS, cardHashOf, type Manifest } from "../src/card.ts";
import { grantHashOf } from "../src/recorder/passkey.ts";
import { runRecords, STATE_KEY, type Pin, type RecordsEnv } from "../src/records.ts";
import { runRecords as oldRunRecords } from "./fixtures/old/records-7ddcffe.ts";
import { softKey } from "./softkey.ts";

const T0 = Date.parse("2026-11-08T12:00:00.000Z");
const MIN = 60_000, HOUR = 60 * MIN;
const EXP = T0 + 10 * MIN, DEADLINE = EXP + CARD_RUN_MS, CARD = "card-00000001";

function bucket() {
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
    async put(k: string, b: string) { store.set(k, { body: b, uploaded: new Date(T0) }); return {} as R2Object; },
  };
}

/** Records signed as the recorder signs them, at chosen times; a software passkey for Ben's answers. */
async function world() {
  const pair = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair, key = await softKey();
  const pin: Pin = { key: b64((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer), from: 1 };
  const b = bucket(), copy = bucket();
  let seq = 0;
  const put = async (grant: string, stage: Stage, rec: object, at: number) => {
    const body = JSON.stringify({ v: 1, grant, stage, job: "test.echo", ...rec }), sha = await sha256(body), n = ++seq;
    const e: Envelope = { v: 2, seq: n, grant, stage, recorded_at: new Date(at).toISOString(), sha256: sha, body };
    b.store.set(keyFor(n, grant, stage), { body: JSON.stringify({ ...e, sig: b64(await crypto.subtle.sign("Ed25519", pair.privateKey, sealed(e))) }), uploaded: new Date(at) });
    return sha;
  };
  /** A card request as the desk sends it; `claim` replaces its grant_hash (a false one). */
  const request = async (grant: string, at = T0, over: object = {}, claim?: string) => {
    const f = { v: 1 as const, grant, stage: "request" as const, job: "test.echo", params: { word: "hi" }, requester: "c-box agent", expires_at: EXP, card: CARD, ...over };
    const hash = (await grantHashOf(f))!;
    return { hash, sha: await put(grant, "request", { ...f, grant_hash: claim ?? hash }, at) };
  };
  const manifest = (entries: string[], over: Partial<Manifest> = {}): Manifest => ({ kind: "card/v1", card: CARD, requester: "c-box agent", entries, deadline: DEADLINE, jobs_version: 1, ...over });
  const approve = async (grant: string, req: string, m: Manifest | object, at = T0 + MIN, signed = m as Manifest) =>
    put(grant, "approval", { request: req, grant_hash: "x", approval_kind: "card/v1", manifest: m, assertion: await key.answer(await cardHashOf(signed)) }, at);
  const result = (grant: string, req: string, outcome: unknown, at: number) => put(grant, "result", { request: req, outcome }, at);
  const env = { RECORDS: b, COPY: copy } as unknown as RecordsEnv;
  const fetch = async () => new Response("", { status: 500 });
  const run = (t: number) => runRecords(env, fetch, new Date(t), pin);
  const runOld = (t: number) => oldRunRecords(env, fetch, new Date(t), pin);
  const ids = () => (JSON.parse(copy.store.get(STATE_KEY)!.body).incidents as { id: string }[]).map((i) => i.id);
  const cardIds = () => ids().filter((i) => i.startsWith("card-"));
  return { b, put, request, manifest, approve, result, run, runOld, ids, cardIds, key, skip: () => ++seq };
}
const AFTER = DEADLINE + CARD_RESULT_MS; // the missing-result time

test("a card read in separate runs, with the state saved and reloaded between, gives no card finding when its result comes", async () => {
  const w = await world();
  const A = await w.request("grant-ck-01");
  await w.run(T0 + 30_000);
  await w.approve("grant-ck-01", A.sha, w.manifest([A.hash]));
  await w.run(T0 + 2 * MIN);
  await w.result("grant-ck-01", A.sha, "done", T0 + 3 * MIN);
  await w.run(AFTER + 20 * MIN);
  assert.deepEqual(w.cardIds(), []);
});

test("missing result: raised only once a complete read passes deadline + 1 h; never on a stalled read; cleared by done, failed or unknown", async () => {
  const w = await world();
  const A = await w.request("grant-mr-01"), B = await w.request("grant-mr-02");
  await w.approve("grant-mr-01", A.sha, w.manifest([A.hash, B.hash]));
  await w.approve("grant-mr-02", B.sha, w.manifest([A.hash, B.hash]));
  await w.run(AFTER); // the watermark is the run's start minus 10 minutes: not past yet
  assert.deepEqual(w.cardIds(), []);
  // A stalled read: an unsigned object at the next number holds the bookmark, so no read is complete.
  w.b.store.set(keyFor(5, "grant-zz-01", "request"), { body: "{}", uploaded: new Date(AFTER) });
  await w.run(AFTER + 3 * HOUR);
  assert.deepEqual(w.cardIds(), [], "a stalled read raised a missing result");
  w.b.store.delete(keyFor(5, "grant-zz-01", "request"));
  await w.result("grant-mr-02", B.sha, "failed", T0 + 5 * MIN); // number 5, early: B is cleared
  await w.run(AFTER + 4 * HOUR);
  const ids = w.cardIds();
  assert.ok(ids.includes("card-incomplete:grant-mr-01"), `missing result not raised: ${ids}`);
  assert.ok(!ids.some((i) => i.includes("grant-mr-02")), "a failed result did not clear its entry");
});

test("card-late for a result after deadline + 1 h; card-unknown once and not repeated; done and failed raise nothing", async () => {
  const w = await world();
  const g = ["grant-lt-01", "grant-lt-02", "grant-lt-03", "grant-lt-04"], r: { hash: string; sha: string }[] = [];
  for (const x of g) r.push(await w.request(x));
  const m = w.manifest(r.map((x) => x.hash).slice(0, 4));
  for (let i = 0; i < 4; i++) await w.approve(g[i], r[i].sha, m);
  await w.result(g[0], r[0].sha, "done", T0 + 2 * MIN);
  await w.result(g[1], r[1].sha, "failed", T0 + 2 * MIN);
  await w.result(g[2], r[2].sha, "unknown", T0 + 2 * MIN);
  await w.result(g[3], r[3].sha, "done", AFTER + 1);
  await w.run(AFTER + 30 * MIN);
  assert.deepEqual(w.cardIds().sort(), [`card-late:${g[3]}:12`, `card-unknown:${g[2]}`].sort());
  const told = w.ids().length;
  await w.run(AFTER + 90 * MIN);
  assert.equal(w.ids().filter((i) => i === `card-unknown:${g[2]}`).length, 1, "the unknown result was raised twice");
  assert.equal(w.ids().length, told);
});

test("card-bad: a card approval stored around the recorder with a bad manifest, a deadline past expiry, or an answer not over the card hash", async () => {
  const w = await world();
  const A = await w.request("grant-cb-01"), B = await w.request("grant-cb-02"), C = await w.request("grant-cb-03"), D = await w.request("grant-cb-04");
  await w.approve("grant-cb-01", A.sha, w.manifest([B.hash])); // not on the card
  await w.approve("grant-cb-02", B.sha, w.manifest([B.hash], { deadline: EXP + CARD_RUN_MS + 1 })); // past expiry + 15 min
  await w.approve("grant-cb-03", C.sha, w.manifest([C.hash]), T0 + MIN, w.manifest([C.hash, A.hash])); // answer over another card
  await w.approve("grant-cb-04", D.sha, w.manifest([D.hash]), DEADLINE + 1); // stored after the deadline, by its signed time
  await w.run(T0 + HOUR);
  assert.deepEqual(w.cardIds().map((i) => i.split(":").slice(0, 2).join(":")).sort(), ["card-bad:grant-cb-01", "card-bad:grant-cb-02", "card-bad:grant-cb-03", "card-bad:grant-cb-04"]);
});

test("S3: a request whose grant_hash is false keeps no grant hash, so its card approval is card-bad; an outcome outside the three is card-bad", async () => {
  const w = await world();
  const A = await w.request("grant-fh-01", T0, {}, "f".repeat(64));
  await w.approve("grant-fh-01", A.sha, w.manifest(["f".repeat(64)]));
  const B = await w.request("grant-fh-02");
  await w.approve("grant-fh-02", B.sha, w.manifest([B.hash]));
  await w.result("grant-fh-02", B.sha, "maybe", T0 + 2 * MIN);
  await w.request("grant-fh-03", T0, { job: "cbox.key.enroll" });
  await w.run(T0 + HOUR);
  assert.deepEqual(w.cardIds().sort(), ["card-bad:grant-fh-01:2", "card-bad:grant-fh-02:5", "card-bad:grant-fh-03:6"]);
});

test("S2: new -> old -> new checker with an old-checker save between a card request and its approval: card-bad (no request context), nothing else lost", async () => {
  const w = await world();
  const A = await w.request("grant-s2-01");
  await w.run(T0 + 30_000); // new checker holds the card request
  await w.runOld(T0 + HOUR); // the reverted checker reads nothing new and saves its state without `cards`
  await w.approve("grant-s2-01", A.sha, w.manifest([A.hash]), T0 + HOUR + MIN);
  await w.result("grant-s2-01", A.sha, "done", T0 + HOUR + 2 * MIN);
  await w.run(T0 + 2 * HOUR);
  assert.deepEqual(w.cardIds(), ["card-bad:grant-s2-01:2"]);
  assert.deepEqual(w.ids().filter((i) => !i.startsWith("card-") && !i.startsWith("lock:")), [], "the change-over lost or doubled other findings");
});

test("today's records (no card mark, no approval_kind) give no card finding", async () => {
  const w = await world();
  const f = { params: { word: "hi" }, requester: "c-box agent", expires_at: EXP };
  const sha = await w.put("grant-pl-01", "request", f, T0);
  await w.put("grant-pl-01", "approval", { request: sha, grant_hash: "x", assertion: {} }, T0 + MIN);
  await w.put("grant-pl-01", "result", { request: sha, outcome: "maybe" }, T0 + 2 * MIN);
  await w.run(AFTER + HOUR);
  assert.deepEqual(w.cardIds(), []);
});
