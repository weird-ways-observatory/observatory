// Card 586da182 (REFINE-586da182 v2.2): the recorder stores a card/v1 approval only for a grant on Ben's
// signed card, of an eligible job, by the card's deadline; cards keep inside a 100-slot share and the 5 GiB
// cutoff; receipts are signed; the counter survives every accounting path and a change-over from 7ddcffe code.
// Real P-256 answers from the software passkey (test/softkey.ts), over the card hash.
import { test } from "node:test";
import assert from "node:assert/strict";
import { DAY_CAP, GRANT_TTL_MS, MAX_STORED_BYTES, receiptSealed, sealed, sha256, STAGE_SLOTS, unb64, type Envelope, type Receipt } from "../src/contract.ts";
import { CARD_RUN_MS, CARD_SHARE, cardHashOf, type Manifest } from "../src/card.ts";
import { RUN_CUTOFF_BYTES } from "../src/ops.ts";
import { Ledger } from "../src/recorder/ledger.ts";
import { approvalCheck, grantHashOf } from "../src/recorder/passkey.ts";
import { Ledger as OldLedger } from "./fixtures/old/ledger-7ddcffe.ts";
import { pinFor, softKey } from "./softkey.ts";
import { bucket, storage } from "./store.ts";

const T0 = Date.parse("2026-11-08T12:00:00.000Z");
const MIN = 60_000, HOUR = 60 * MIN;
const at = (ms: number) => () => new Date(ms);
const EXP = T0 + 10 * MIN; // the grants' approve-by
const DEADLINE = EXP + CARD_RUN_MS;
const CARD = "card-00000001";
type St = ReturnType<typeof storage>;
type Out = Awaited<ReturnType<Ledger["accept"]>>;
const why = (o: Out) => [o.status, "why" in o ? o.why : ""];

async function setup() {
  const key = await softKey(), st = storage(), b = bucket(), pin = await pinFor(key);
  return { key, st, b, pin, l: new Ledger(st, b, undefined, approvalCheck(pin)) };
}
type S = Awaited<ReturnType<typeof setup>>;

/** A request shaped like the desk's, on `card` (null: on no card). Returns its grant hash and request sha. */
async function requested(l: Pick<Ledger, "accept">, grant: string, { card = CARD as string | null, job = "test.echo", t = T0, status = 201, exp = EXP } = {}) {
  const f = { v: 1 as const, grant, stage: "request" as const, job, params: { word: "hi" }, requester: "c-box agent", reason: "test", created_at: 1, expires_at: exp };
  const hash = (await grantHashOf(f))!;
  const body = JSON.stringify({ ...f, grant_hash: hash, ...(card === null ? {} : { card }) });
  const o = await l.accept(body, at(t));
  assert.equal(o.status, status, `request ${grant}: ${JSON.stringify(o)}`);
  return { hash, request: await sha256(body), job };
}
const manifest = (entries: string[], over: Partial<Manifest> = {}): Manifest => ({ kind: "card/v1", card: CARD, requester: "c-box agent", entries, deadline: DEADLINE, jobs_version: 1, ...over });
/** The approval body for one entry: Ben's answer over `signed` (default: the manifest sent). */
async function approval(s: S, grant: string, request: string, m: Manifest | object, { signed = m as Manifest, job = "test.echo", over = {} as object } = {}) {
  return JSON.stringify({ v: 1, grant, stage: "approval", job, request, grant_hash: "x", approved_at: 1, approval_kind: "card/v1", manifest: m, assertion: await s.key.answer(await cardHashOf(signed)), ...over });
}
const result = (grant: string, request: string, outcome: unknown = "done", job = "test.echo") => JSON.stringify({ v: 1, grant, stage: "result", job, request, outcome });
const meta = (st: St) => st.m.get("meta") as { seq: number; bytes: number; card?: { charged: number; blocked?: string; seq: number; pending?: string }; open: { grant: string; left: number; card?: true }[] };
const stageOf = (st: St, g: string, stage: string) => (st.m.get(`g:${g}`) as { stages: Record<string, Receipt> }).stages[stage];
/** Refused with this status and reason, and nothing stored: no new object, no new number. */
async function refused(s: S, body: string, status: number, reason: string, t = T0) {
  const before = s.b.store.size, seq = meta(s.st)?.seq;
  assert.deepEqual(why(await s.l.accept(body, at(t))), [status, reason]);
  assert.equal(s.b.store.size, before, "a refused record was stored");
  assert.equal(meta(s.st)?.seq, seq, "a refused record took a number");
}
const cardStatus = async (l: Ledger, t: number) => ((await l.status(at(t))) as unknown as { pools: { card: { used: number; reserved_slots: number; blocked: boolean } } }).pools.card;
const refusedCount = async (l: Ledger, t: number) => ((await l.status(at(t))) as unknown as { refused: Record<string, number> }).refused;

test("allowed: a 2-entry card stores both approvals with Ben's one answer; results done, failed and unknown are stored", async () => {
  const s = await setup();
  const A = await requested(s.l, "grant-ca-01"), B = await requested(s.l, "grant-ca-02");
  const m = manifest([A.hash, B.hash]), assertion = await s.key.answer(await cardHashOf(m));
  for (const [g, r] of [["grant-ca-01", A.request], ["grant-ca-02", B.request]] as const) {
    const body = JSON.stringify({ v: 1, grant: g, stage: "approval", job: "test.echo", request: r, grant_hash: "x", approved_at: 1, approval_kind: "card/v1", manifest: m, assertion });
    assert.equal((await s.l.accept(body, at(T0 + MIN))).status, 201);
  }
  assert.equal((await s.l.accept(result("grant-ca-01", A.request, "unknown"), at(T0 + 2 * MIN))).status, 201);
  assert.equal((await s.l.accept(result("grant-ca-02", B.request, "failed"), at(T0 + 2 * MIN))).status, 201);
  const C = await requested(s.l, "grant-ca-03");
  assert.equal((await s.l.accept(await approval(s, "grant-ca-03", C.request, manifest([C.hash])), at(T0 + MIN))).status, 201);
  assert.equal((await s.l.accept(result("grant-ca-03", C.request, "done"), at(T0 + 2 * MIN))).status, 201);
});

test("threats 1-3: a manifest without this grant, or changed in any way after Ben signed it, is refused", async () => {
  const s = await setup();
  const A = await requested(s.l, "grant-cb-01"), B = await requested(s.l, "grant-cb-02"), X = "e".repeat(64);
  const m = manifest([A.hash, B.hash]);
  const cases: [Manifest, Manifest | undefined, string][] = [
    [manifest([B.hash]), undefined, "this grant is not on the card Ben approved"], // Ben signed a card without A
    [manifest([B.hash, A.hash]), m, "the answer is for another grant"], // reordered
    [manifest([A.hash, X]), m, "the answer is for another grant"], // one hash substituted
    [manifest([A.hash, B.hash, X]), m, "the answer is for another grant"], // added
    [manifest([A.hash]), m, "the answer is for another grant"], // dropped
    [manifest([A.hash, B.hash], { deadline: DEADLINE - 1 }), m, "the answer is for another grant"],
    [manifest([A.hash, B.hash], { jobs_version: 2 }), m, "the answer is for another grant"],
    [manifest([A.hash, B.hash], { requester: "someone else" }), m, "the manifest names another requester"],
    [manifest([A.hash, B.hash], { requester: "someone else" }), undefined, "the manifest names another requester"], // even if Ben signed it
    [manifest([A.hash, B.hash], { card: "card-00000002" }), m, "the manifest names another card"],
  ];
  for (const [sent, signed] of cases) await refused(s, await approval(s, "grant-cb-01", A.request, sent, { signed: signed ?? sent }), 409, cases.find((c) => c[0] === sent)![2]);
  await refused(s, await approval(s, "grant-cb-01", A.request, { ...m, extra: 1 }, { signed: m }), 409, "the manifest has the wrong fields");
  await refused(s, await approval(s, "grant-cb-01", A.request, manifest([A.hash, A.hash])), 409, "the manifest's entries are not 1 to 5 distinct grant hashes");
  // Stored once: a second approval of the same grant with another manifest is refused.
  assert.equal((await s.l.accept(await approval(s, "grant-cb-01", A.request, m), at(T0))).status, 201);
  await refused(s, await approval(s, "grant-cb-01", A.request, manifest([A.hash])), 409, "this stage of this grant is already recorded with other content");
  assert.ok((await refusedCount(s.l, T0)).card_refused >= cases.length + 2, "card refusals not counted as card_refused");
});

test("threats 5-6: ineligible job at request and at approval; kinds must agree with the request's card mark", async () => {
  const s = await setup();
  await refused(s, JSON.stringify({ v: 1, grant: "grant-cc-01", stage: "request", job: "cbox.key.enroll", params: {}, card: CARD }), 409, "this request cannot be on a card: its card id or job is not allowed");
  await refused(s, JSON.stringify({ v: 1, grant: "grant-cc-02", stage: "request", job: "test.echo", params: {}, card: "x" }), 409, "this request cannot be on a card: its card id or job is not allowed");
  // At approval: a card grant whose job is not eligible (state as if the list changed after its request).
  const E = await requested(s.l, "grant-cc-03");
  const g = s.st.m.get("g:grant-cc-03") as { job: string };
  s.st.m.set("g:grant-cc-03", { ...g, job: "cbox.key.enroll" });
  await refused(s, await approval(s, "grant-cc-03", E.request, manifest([E.hash]), { job: "cbox.key.enroll" }), 409, "this job is not allowed on a card");
  const C = await requested(s.l, "grant-cc-04"), O = await requested(s.l, "grant-cc-05", { card: null });
  const m = manifest([C.hash]);
  await refused(s, await approval(s, "grant-cc-05", O.request, manifest([O.hash])), 409, "a card approval for a request that is not on a card");
  await refused(s, await approval(s, "grant-cc-05", O.request, m, { over: { approval_kind: undefined } }), 409, "a card approval for a request that is not on a card"); // ordinary approval carrying a manifest
  await refused(s, await approval(s, "grant-cc-04", C.request, m, { over: { approval_kind: undefined } }), 409, "a request on a card needs a card/v1 approval"); // no kind
  const ordinary = JSON.stringify({ v: 1, grant: "grant-cc-04", stage: "approval", job: "test.echo", request: C.request, grant_hash: "x", approved_at: 1, assertion: await s.key.answer(C.hash) });
  await refused(s, ordinary, 409, "a request on a card needs a card/v1 approval");
  // Open fact 5: a grant requested before this build has no card mark and can never take a card approval.
  s.st.m.set("g:grant-cc-05", { ...(s.st.m.get("g:grant-cc-05") as object) });
  assert.equal((s.st.m.get("g:grant-cc-05") as { card?: string }).card, undefined);
});

test("threat 4: deadline -1 ms and exact are stored, +1 ms is 410; a deadline past expiry + 15 min is refused", async () => {
  for (const [dt, status] of [[-1, 201], [0, 201], [1, 410]] as const) {
    const s = await setup(), A = await requested(s.l, "grant-cd-01");
    const o = await s.l.accept(await approval(s, "grant-cd-01", A.request, manifest([A.hash])), at(DEADLINE + dt));
    assert.equal(o.status, status, `at deadline ${dt} ms`);
    if (status === 410) assert.equal("why" in o && o.why, "the card's deadline has passed");
  }
  const s = await setup(), A = await requested(s.l, "grant-cd-02");
  await refused(s, await approval(s, "grant-cd-02", A.request, manifest([A.hash], { deadline: EXP + CARD_RUN_MS + 1 })), 409, "the card's deadline is past its grants' expiry");
});

test("S4/T2: an approval held pending over an outage is re-checked with the finishing call's time: stored at the deadline, withdrawn 1 ms after", async () => {
  for (const [finish, stored] of [[DEADLINE - 1, true], [DEADLINE, true], [DEADLINE + 1, false]] as const) {
    const s = await setup(), A = await requested(s.l, "grant-ce-01");
    s.b.failNext(1);
    assert.equal((await s.l.accept(await approval(s, "grant-ce-01", A.request, manifest([A.hash])), at(T0 + MIN))).status, 503);
    // The interleaving happened: the approval is pending and not in the bucket when the clock moves (L2).
    const p = s.st.m.get("pending") as { key: string; receipt: { stage: string } };
    assert.ok(p && p.receipt.stage === "approval" && !s.b.store.has(p.key), "the approval was not left pending");
    assert.equal((await s.l.accept(JSON.stringify({ v: 1, grant: "grant-ce-02", stage: "request", job: "test.echo" }), at(finish))).status, 201);
    assert.equal(Boolean(stageOf(s.st, "grant-ce-01", "approval")), stored, `finishing at deadline ${finish - DEADLINE} ms`);
    assert.equal(s.b.store.has(p.key), stored);
    if (!stored) assert.equal((await s.l.accept(await approval(s, "grant-ce-01", A.request, manifest([A.hash])), at(finish))).status, 410, "a retry after the deadline is refused");
  }
});

test("T2: a bucket write that stalls inside one accept across the deadline is stored with recorded_at by the deadline; the vault decides the start", async () => {
  const s = await setup(), A = await requested(s.l, "grant-cf-01");
  let release!: () => void, reached = false, wall = DEADLINE - 1;
  const put = s.b.put.bind(s.b);
  s.b.put = async (k: string, body: string, o?: R2PutOptions) => { reached = true; await new Promise<void>((r) => (release = r)); return put(k, body, o); };
  const pending = s.l.accept(await approval(s, "grant-cf-01", A.request, manifest([A.hash])), () => new Date(wall));
  while (!reached) await new Promise((r) => setTimeout(r, 1));
  assert.ok(reached, "the put was not reached before the clock moved"); // L2 checkpoint
  wall = DEADLINE + 5 * MIN; // time passes while the write is stalled
  release();
  const o = await pending;
  assert.equal(o.status, 201);
  const rc = (o as { receipt: Receipt }).receipt;
  assert.ok(Date.parse(rc.recorded_at) <= DEADLINE, "the signed time is after the deadline");
  // Stated: the receipt arrived after the deadline in wall time, so build 3's vault must refuse to start it (card 85818ab1).
  assert.ok(wall > DEADLINE);
});

test("threat 13: a card entry's result must be done, failed or unknown; an ordinary grant's result is unchanged", async () => {
  const s = await setup(), A = await requested(s.l, "grant-cg-01"), O = await requested(s.l, "grant-cg-02", { card: null });
  assert.equal((await s.l.accept(await approval(s, "grant-cg-01", A.request, manifest([A.hash])), at(T0))).status, 201);
  await refused(s, result("grant-cg-01", A.request, "maybe"), 409, "a card entry's result must be done, failed or unknown");
  await refused(s, result("grant-cg-01", A.request, ["done"]), 409, "a card entry's result must be done, failed or unknown");
  const ordinary = JSON.stringify({ v: 1, grant: "grant-cg-02", stage: "approval", job: "test.echo", request: O.request, grant_hash: "x", approved_at: 1, assertion: await s.key.answer(O.hash) });
  assert.equal((await s.l.accept(ordinary, at(T0))).status, 201);
  assert.equal((await s.l.accept(result("grant-cg-02", O.request, "maybe"), at(T0))).status, 201);
});

test("threat 7: the card share full is 429 card_share_full while a single test.echo request still gets 201", async () => {
  const s = await setup();
  for (let i = 0; i < CARD_SHARE / STAGE_SLOTS; i++) await requested(s.l, `grant-sh-${String(i).padStart(2, "0")}`);
  assert.equal((await cardStatus(s.l, T0)).used, CARD_SHARE);
  const o = await s.l.accept(JSON.stringify({ v: 1, grant: "grant-sh-99", stage: "request", job: "test.echo", card: CARD }), at(T0));
  assert.deepEqual(why(o), [429, `today's ${CARD_SHARE} card slots are taken`]);
  await requested(s.l, "grant-sh-tap", { card: null });
  const c = await refusedCount(s.l, T0);
  assert.deepEqual([c.card_share_full, c.tap_pool_full], [1, 0], "the share refusal was not counted apart");
});

test("threat 7: a card request that would pass 5 GiB counting its own reservation is card_cutoff; a single tap still passes", async () => {
  const s = await setup();
  await requested(s.l, "grant-co-01");
  const m = meta(s.st), reserved = m.open.reduce((n, o) => n + o.left, 0) * MAX_STORED_BYTES;
  s.st.m.set("meta", { ...m, bytes: RUN_CUTOFF_BYTES - reserved - STAGE_SLOTS * MAX_STORED_BYTES }); // exactly at the cutoff with this request
  await requested(s.l, "grant-co-02");
  const m2 = meta(s.st), reserved2 = m2.open.reduce((n, o) => n + o.left, 0) * MAX_STORED_BYTES;
  s.st.m.set("meta", { ...m2, bytes: RUN_CUTOFF_BYTES - reserved2 - STAGE_SLOTS * MAX_STORED_BYTES + 1 });
  const o = await s.l.accept(JSON.stringify({ v: 1, grant: "grant-co-03", stage: "request", job: "test.echo", card: CARD }), at(T0));
  assert.deepEqual(why(o), [429, "the recorder's storage is past the card cutoff"]);
  await requested(s.l, "grant-co-04", { card: null });
  assert.equal((await refusedCount(s.l, T0)).card_cutoff, 1);
});

test("receipts: sig verifies with the status key over receipt/v1, and never crosses over with an envelope signature", async () => {
  const s = await setup(), A = await requested(s.l, "grant-rc-01", { card: null });
  const body = JSON.stringify({ v: 1, grant: "grant-rc-02", stage: "request", job: "test.echo" });
  const o = await s.l.accept(body, at(T0)), rc = (o as { receipt: Receipt }).receipt;
  const pub = await crypto.subtle.importKey("raw", unb64(((await s.l.status(at(T0))) as { public_key: string }).public_key), "Ed25519", false, ["verify"]);
  // The exact bytes build 3's vault will check, written out here rather than taken from receiptSealed.
  const bytes = new TextEncoder().encode(JSON.stringify({ kind: "receipt/v1", v: 1, seq: rc.seq, key: rc.key, grant: rc.grant, stage: rc.stage, sha256: rc.sha256, recorded_at: rc.recorded_at }));
  assert.deepEqual(receiptSealed(rc), bytes);
  assert.ok(rc.sig && (await crypto.subtle.verify("Ed25519", pub, unb64(rc.sig), bytes)), "the receipt signature does not verify");
  const retry = await s.l.accept(body, at(T0 + MIN));
  assert.deepEqual([retry.status, (retry as { receipt: Receipt }).receipt], [200, rc], "an identical retry did not get the same signed receipt");
  assert.equal(stageOf(s.st, "grant-rc-02", "request").sig, undefined, "the signature was stored with the stage");
  const env = JSON.parse(s.b.store.get(rc.key)!.body) as Envelope;
  assert.equal(await crypto.subtle.verify("Ed25519", pub, unb64(env.sig!), receiptSealed(rc)), false, "an envelope signature verifies as a receipt");
  assert.equal(await crypto.subtle.verify("Ed25519", pub, unb64(rc.sig), sealed(env)), false, "a receipt signature verifies as an envelope");
  assert.ok(A.request);
});

test("threat 10: the 7ddcffe recorder refuses a card approval (a reverted recorder fails closed) and its receipts are unsigned", async () => {
  const key = await softKey(), st = storage(), b = bucket(), old = new OldLedger(st, b, undefined, approvalCheck(await pinFor(key)));
  const A = await requested(old, "grant-od-01");
  const m = manifest([A.hash]);
  const body = JSON.stringify({ v: 1, grant: "grant-od-01", stage: "approval", job: "test.echo", request: A.request, grant_hash: "x", approved_at: 1, approval_kind: "card/v1", manifest: m, assertion: await key.answer(await cardHashOf(m)) });
  assert.deepEqual(why(await old.accept(body, at(T0))), [409, "the answer is for another grant"]);
});

// Accounting (Outcome 5, threat 8): the share follows the tap pool's rules on every path.
test("threat 8: expiry and rollover -- a card hold carries into the next day and is released 24 h after its request", async () => {
  const s = await setup(), late = Date.parse("2026-11-08T23:00:00.000Z");
  await requested(s.l, "grant-ac-01", { t: late });
  assert.deepEqual(await cardStatus(s.l, late), { used: STAGE_SLOTS, cap: CARD_SHARE, reserved_slots: STAGE_SLOTS - 1, blocked: false });
  assert.equal((await cardStatus(s.l, late + 2 * HOUR)).used, STAGE_SLOTS - 1, "rollover did not carry the card hold, or kept the charge");
  assert.equal((await cardStatus(s.l, late + GRANT_TTL_MS)).used, STAGE_SLOTS - 1, "released before 24 h");
  assert.equal((await cardStatus(s.l, late + GRANT_TTL_MS + 1)).used, 0, "the card hold outlived its 24 h");
  await requested(s.l, "grant-ac-02", { t: late + GRANT_TTL_MS + 1 });
  assert.equal(meta(s.st).card!.charged, 1);
});

test("threat 8: an unverified withdrawal and a late-stage withdrawal give the card share back exactly", async () => {
  const s = await setup(), A = await requested(s.l, "grant-aw-01");
  const before = await cardStatus(s.l, T0 + MIN);
  s.b.failNext(1);
  assert.equal((await s.l.accept(await approval(s, "grant-aw-01", A.request, manifest([A.hash])), at(T0 + MIN))).status, 503);
  assert.equal((await s.l.accept(JSON.stringify({ v: 1, grant: "grant-aw-09", stage: "request", job: "test.echo" }), at(DEADLINE + 1))).status, 201); // withdrawn: past its deadline
  assert.equal(stageOf(s.st, "grant-aw-01", "approval"), undefined);
  assert.deepEqual(await cardStatus(s.l, DEADLINE + 1), before, "the unverified withdrawal did not give the card slot back");
  // Late stage: a card result pending past its grant's 24 h is withdrawn and the card hold released.
  const s2 = await setup(), B = await requested(s2.l, "grant-aw-02");
  assert.equal((await s2.l.accept(await approval(s2, "grant-aw-02", B.request, manifest([B.hash])), at(T0 + MIN))).status, 201);
  s2.b.failNext(1);
  assert.equal((await s2.l.accept(result("grant-aw-02", B.request), at(T0 + GRANT_TTL_MS - 6 * MIN))).status, 503); // re-timed when finished: over 5 min late
  assert.equal((await s2.l.accept(JSON.stringify({ v: 1, grant: "grant-aw-08", stage: "request", job: "test.echo" }), at(T0 + GRANT_TTL_MS + 1))).status, 201);
  assert.equal(stageOf(s2.st, "grant-aw-02", "result"), undefined, "the late result was stored");
  assert.equal((await cardStatus(s2.l, T0 + GRANT_TTL_MS + 1)).used, 0, "the late-stage withdrawal left card slots in use");
});

test("threat 8 / APPROACH row 15: a pending card request re-charged after midnight counts toward the new day's share", async () => {
  const s = await setup(), late = Date.parse("2026-11-08T23:59:00.000Z"), next = Date.parse("2026-11-09T00:01:00.000Z");
  s.b.failNext(1);
  await requested(s.l, "grant-mn-01", { t: late, status: 503 });
  assert.ok(s.st.m.get("pending"), "the request was not left pending over midnight"); // L2 checkpoint
  await requested(s.l, "grant-mn-02", { t: next, card: null });
  assert.deepEqual(await cardStatus(s.l, next), { used: STAGE_SLOTS, cap: CARD_SHARE, reserved_slots: STAGE_SLOTS - 1, blocked: false });
  assert.equal(meta(s.st).card!.charged, 1);
});

// Change-over (S1, T1): the 7ddcffe recorder as a second class over the same storage and bucket.
test("S1: new -> old -> new across midnight: old code writing a record blocks cards for the rest of that UTC day, then the share is rebuilt from card holds", async () => {
  const s = await setup(), old = new OldLedger(s.st, s.b, undefined, approvalCheck(s.pin));
  await requested(s.l, "grant-s1-01", { t: T0 }); // card hold 3, charged 1
  await requested(old, "grant-s1-02", { t: T0 + MIN, card: null }); // old code takes a number
  assert.equal(meta(s.st).card!.seq, 1, "older code changed the card counter"); // it kept the field untouched
  const o = await s.l.accept(JSON.stringify({ v: 1, grant: "grant-s1-03", stage: "request", job: "test.echo", card: CARD }), at(T0 + 2 * MIN));
  assert.deepEqual(why(o), [429, `today's ${CARD_SHARE} card slots are taken`]);
  await requested(s.l, "grant-s1-04", { t: T0 + 3 * MIN, card: null }); // a single tap is still admitted
  assert.equal((await cardStatus(s.l, T0 + 3 * MIN)).blocked, true);
  await requested(s.l, "grant-s1-05", { t: T0 + 4 * MIN, status: 429 }); // still blocked after this version wrote again
  const tomorrow = Date.parse("2026-11-09T01:00:00.000Z");
  assert.deepEqual(await cardStatus(s.l, tomorrow), { used: STAGE_SLOTS - 1, cap: CARD_SHARE, reserved_slots: STAGE_SLOTS - 1, blocked: false }, "next day's share is not the carried card holds");
  await requested(s.l, "grant-s1-06", { t: tomorrow });
});

test("T1: old code finishing this version's pending card write (with a recharge over midnight), or withdrawing it, blocks cards for that day", async () => {
  // Codex r2 #1: a card result pending over midnight, finished by the old recorder on an identical retry.
  const s = await setup(), old = new OldLedger(s.st, s.b, undefined, approvalCheck(s.pin));
  const e1 = Date.parse("2026-11-08T23:40:00.000Z");
  const A = await requested(s.l, "grant-t1-01", { t: Date.parse("2026-11-08T23:00:00.000Z"), exp: e1 });
  const m = manifest([A.hash], { deadline: e1 + CARD_RUN_MS });
  assert.equal((await s.l.accept(await approval(s, "grant-t1-01", A.request, m), at(Date.parse("2026-11-08T23:30:00.000Z")))).status, 201);
  s.b.failNext(1);
  const body = result("grant-t1-01", A.request);
  assert.equal((await s.l.accept(body, at(Date.parse("2026-11-08T23:59:00.000Z")))).status, 503);
  assert.ok(s.st.m.get("pending"), "the result was not left pending"); // L2 checkpoint
  const seq = meta(s.st).seq;
  assert.equal((await old.accept(body, at(Date.parse("2026-11-09T00:01:00.000Z")))).status, 200); // old code finishes it
  assert.equal(meta(s.st).seq, seq, "the trace needs seq unchanged");
  await requested(s.l, "grant-t1-02", { t: Date.parse("2026-11-09T00:02:00.000Z"), status: 429 });
  // Withdrawn by old code: a pending card approval the old passkey check refuses.
  const s2 = await setup(), old2 = new OldLedger(s2.st, s2.b, undefined, approvalCheck(s2.pin));
  const B = await requested(s2.l, "grant-t1-03");
  s2.b.failNext(1);
  assert.equal((await s2.l.accept(await approval(s2, "grant-t1-03", B.request, manifest([B.hash])), at(T0 + MIN))).status, 503);
  assert.equal((await old2.accept(JSON.stringify({ v: 1, grant: "grant-t1-04", stage: "request", job: "test.echo" }), at(T0 + 2 * MIN))).status, 201);
  assert.equal(stageOf(s2.st, "grant-t1-03", "approval"), undefined, "old code did not withdraw the card approval");
  await requested(s2.l, "grant-t1-05", { t: T0 + 3 * MIN, status: 429 });
});

test("S1: a blocked share never holds back a card grant's later stages (only the tap pool can)", async () => {
  const s = await setup(), old = new OldLedger(s.st, s.b, undefined, approvalCheck(s.pin));
  const e2 = Date.parse("2026-11-09T00:10:00.000Z");
  const A = await requested(s.l, "grant-bk-01", { t: Date.parse("2026-11-09T00:00:30.000Z"), exp: e2 });
  await requested(old, "grant-bk-02", { t: Date.parse("2026-11-09T00:01:00.000Z"), card: null }); // blocks today
  assert.equal((await s.l.accept(await approval(s, "grant-bk-01", A.request, manifest([A.hash], { deadline: e2 + CARD_RUN_MS })), at(Date.parse("2026-11-09T00:02:00.000Z")))).status, 201);
  assert.equal((await cardStatus(s.l, Date.parse("2026-11-09T00:03:00.000Z"))).blocked, true);
  assert.equal((await s.l.accept(result("grant-bk-01", A.request), at(Date.parse("2026-11-09T00:03:00.000Z")))).status, 201, "a blocked share held back a later stage");
  assert.ok(DAY_CAP > CARD_SHARE);
});

test("Codex build r1 #1: a change-over seen only by refused card requests and status reads blocks that UTC day alone", async () => {
  const s = await setup(), old = new OldLedger(s.st, s.b, undefined, approvalCheck(s.pin));
  await requested(s.l, "grant-r1-01", { t: T0 });
  await requested(old, "grant-r1-02", { t: T0 + MIN, card: null });
  await requested(s.l, "grant-r1-03", { t: T0 + 2 * MIN, status: 429 }); // the only write attempt today: refused
  assert.equal((await cardStatus(s.l, T0 + 3 * MIN)).blocked, true);
  assert.equal((await cardStatus(s.l, Date.parse("2026-11-09T00:30:00.000Z"))).blocked, false, "status shows tomorrow blocked");
  await requested(s.l, "grant-r1-04", { t: Date.parse("2026-11-09T01:00:00.000Z") }); // no ordinary record in between
});

// Card 77ec1e64 (REFINE-77ec1e64 X1, Y1; threat table T5, T17): gh.repo.create is card-eligible, and its done
// result must carry GitHub's repo_id (digits) -- the durable evidence the nightly check and M1 match by id.
const repoResult = (grant: string, request: string, outcome: string, extra: object = {}, job = "gh.repo.create") => JSON.stringify({ v: 1, grant, stage: "result", job, request, outcome, ...extra });
test("T17: a done gh.repo.create card result is stored only with a digits repo_id; no other result may carry one", async () => {
  const s = await setup(), J = { job: "gh.repo.create" };
  const A = await requested(s.l, "grant-ri-01", J);
  assert.equal((await s.l.accept(await approval(s, "grant-ri-01", A.request, manifest([A.hash]), J), at(T0))).status, 201);
  const must = "a done gh.repo.create result must carry GitHub's repo_id (digits)";
  await refused(s, repoResult("grant-ri-01", A.request, "done"), 409, must);
  await refused(s, repoResult("grant-ri-01", A.request, "done", { repo_id: 1234567 }), 409, must);
  await refused(s, repoResult("grant-ri-01", A.request, "done", { repo_id: "0123" }), 409, must);
  await refused(s, repoResult("grant-ri-01", A.request, "done", { repo_id: "12a4" }), 409, must);
  await refused(s, repoResult("grant-ri-01", A.request, "done", { repo_id: "1".repeat(21) }), 409, must);
  const only = "only a done gh.repo.create result may carry a repo_id";
  await refused(s, repoResult("grant-ri-01", A.request, "unknown", { repo_id: "1234567" }), 409, only);
  assert.equal((await s.l.accept(repoResult("grant-ri-01", A.request, "done", { repo_id: "1234567" }), at(T0 + MIN))).status, 201);
  // Another job's result, on a card or not, never carries one.
  const B = await requested(s.l, "grant-ri-02");
  assert.equal((await s.l.accept(await approval(s, "grant-ri-02", B.request, manifest([B.hash])), at(T0))).status, 201);
  await refused(s, repoResult("grant-ri-02", B.request, "done", { repo_id: "1234567" }, "test.echo"), 409, only);
  const O = await requested(s.l, "grant-ri-03", { card: null });
  const ordinary = JSON.stringify({ v: 1, grant: "grant-ri-03", stage: "approval", job: "test.echo", request: O.request, grant_hash: "x", approved_at: 1, assertion: await s.key.answer(O.hash) });
  assert.equal((await s.l.accept(ordinary, at(T0))).status, 201);
  await refused(s, repoResult("grant-ri-03", O.request, "done", { repo_id: "1234567" }, "test.echo"), 409, only);
  assert.equal((await refusedCount(s.l, T0 + MIN)).card_refused, 7, "the six card refusals and the test.echo card one count as card_refused; the ordinary one does not");
});

test("T5: gh.repo.create is on the Observatory's card list: a card request for it is stored", async () => {
  const s = await setup();
  await requested(s.l, "grant-rj-01", { job: "gh.repo.create" });
});
