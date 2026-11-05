// The recorder's core (card feea07eb, route A). One instance runs inside one Durable Object
// (src/recorder/index.ts), so every write in the Observatory goes through this queue in turn.
// It decides, before anything is stored: is the record in the contract, is its stage in order for
// its grant, is there room today and in the storage budget. Then it saves the record as pending,
// writes it to the locked bucket, and only then answers with a receipt. A crash between those
// steps leaves the pending record, which the next call finishes first -- so sequence numbers never
// have gaps. Every envelope is signed (card 6a04908f) with a key made here on first use; the
// private half lives only in this Durable Object's storage and is never returned or logged.
// An `approval` is stored only if Ben's pinned passkey signed it for that grant (passkey.ts, card 7190ab0a).
import { b64, DAY_CAP, GRANT_TTL_MS, keyFor, MAX_STORED_BYTES, sealed, sha256, SKEW_MS, STAGE_SLOTS, STORE_BUDGET_BYTES, unb64, validate, type Envelope, type Receipt, type Stage } from "../contract.ts";
import { approvalCheck, grantHashOf, PASSKEY_PIN, type ApprovalCheck } from "./passkey.ts";
import { OP_DAY_CAP, RESULT_MS, RUN_CUTOFF_BYTES } from "../ops.ts";

/**
 * The slice of Durable Object storage used here; each put of several keys is one atomic write.
 * `transaction` runs `fn` so that every put and delete inside it lands together or not at all (a
 * throw inside `fn` discards them all). Used where two writes must never be seen apart: a withdrawal's
 * accounting and the removal of `pending` (REFINE-observatory-ops.md v11 AE1). The live object passes
 * Cloudflare's own `ctx.storage` (index.ts); test/recorder.workerd.test.ts proves the all-or-nothing
 * behaviour in the real runtime, and test/store.ts mirrors it for the fast tests.
 */
export interface Txn {
  get<T>(key: string): Promise<T | undefined>;
  put(entries: Record<string, unknown>): Promise<void>;
  delete(key: string): Promise<boolean>;
}
export interface Storage extends Txn {
  transaction<T>(fn: (txn: Txn) => Promise<T>): Promise<T>;
}
export type Bucket = Pick<R2Bucket, "get" | "put">;

// Two pools of DAY_CAP / OP_DAY_CAP slots a UTC day (card 509a5d85): taps (Ben's grants) and run ops,
// so run traffic can never take the room Ben's taps need. The state is additive over 43af20c: the tap
// pool keeps its old names (`used`, `open`), the op pool and counters are new optional fields, and old
// code ignores and keeps them (REFINE-observatory-ops.md v5 Y2, v6 Z6). B1 admits no op: `validate`
// still refuses op and op_result, so the op pool stays empty until B2.
//
// An open grant still holds `left` reserved slots for its later stages, whatever day they land on,
// until `opened` + 24 h (inclusive); an op holds 1 for its result until `at` + 24 h. A hold that runs
// out is released on the next accept or status read (`settle`), counted once in `expired`.
interface Open { grant: string; opened: number; left: number }
interface OpOpen { op: string; at: number; left: number }
// `used` / `op_used`: today's slots per pool = records charged today + every hold still open (carried
// in at rollover, released at expiry). `bytes`: every stored or pending envelope's size, for the budget.
interface Meta { seq: number; day: string; used: number; bytes: number; open: Open[]; op_used?: number; op_open?: OpOpen[]; expired?: { tap: number; op: number } }
// `grant_hash`: the front desk's hash of the grant, kept only if it matches the hash worked out here from
// the request's own fields (passkey.ts grantHashOf); Ben's passkey answer must carry it.
interface Grant { job: string; request: string; opened: number; grant_hash?: string; stages: Partial<Record<Stage, Receipt>> }
// `day`: the UTC day its slot was charged to. `pool`: absent = tap (every record before B2).
interface Pending { key: string; stored: string; storedSha: string; receipt: Receipt; day: string; pool?: "tap" | "op" }
interface Keys { priv: string; pub: string } // base64 PKCS#8 and raw Ed25519 public key
// Refusals by fixed reason word, and identical retries answered with the stored receipt (status only).
export const REFUSALS = ["invalid", "conflict", "late", "tap_pool_full", "budget_full", "stuck"] as const;
interface Counters { refused: Partial<Record<(typeof REFUSALS)[number], number>>; retries: number }

export type Outcome =
  | { status: 200 | 201; receipt: Receipt }
  | { status: 400 | 409 | 410 | 429 | 503; why: string };

const day = (ms: number) => new Date(ms).toISOString().slice(0, 10);
const len = (s: string) => new TextEncoder().encode(s).length;
const held = (m: Meta) => ({ tap: m.open.reduce((n, o) => n + o.left, 0), op: (m.op_open ?? []).reduce((n, o) => n + o.left, 0) });
const reservedBytes = (m: Meta) => (held(m).tap + held(m).op) * MAX_STORED_BYTES;

/**
 * Brings the counts to time `t`: holds past their 24 h are released (taken off today's pool and
 * counted once in `expired`), then a new UTC day starts with the holds still open, never at zero.
 * `keep` names the grant or op of the pending record, whose hold is never released while it is
 * pending (REFINE v6 Z4): it is re-timed or withdrawn by #finishPending instead.
 */
export function settle(m: Meta, t: number, keep?: string): Meta {
  const expired = { tap: m.expired?.tap ?? 0, op: m.expired?.op ?? 0 };
  let used = m.used, opUsed = m.op_used ?? 0;
  const open = m.open.filter((o) => {
    if (o.left <= 0 || o.grant === keep || t - o.opened <= GRANT_TTL_MS) return true;
    used -= o.left;
    expired.tap += 1;
    return false;
  });
  const opOpen = (m.op_open ?? []).filter((o) => {
    if (o.left <= 0 || o.op === keep || t - o.at <= RESULT_MS) return true;
    opUsed -= o.left;
    expired.op += 1;
    return false;
  });
  const next: Meta = { ...m, used, open, op_used: opUsed, op_open: opOpen, expired };
  // Never backwards: a clock reading from an earlier day (status now saves what it settles) keeps the day.
  if (day(t) <= m.day) return next;
  const carry = open.filter((o) => o.left > 0), opCarry = opOpen.filter((o) => o.left > 0);
  return { ...next, day: day(t), open: carry, used: held({ ...next, open: carry }).tap, op_open: opCarry, op_used: held({ ...next, op_open: opCarry }).op };
}

/** Admits, orders and stores records one at a time; see the file comment. */
export class Ledger {
  #queue: Promise<unknown> = Promise.resolve();
  #key?: { priv: CryptoKey; pub: string };
  private storage: Storage;
  private bucket: Bucket;
  private budget: number;
  private approvals: ApprovalCheck;
  constructor(storage: Storage, bucket: Bucket, budget = STORE_BUDGET_BYTES, approvals = approvalCheck(PASSKEY_PIN)) {
    this.storage = storage;
    this.bucket = bucket;
    this.budget = budget;
    this.approvals = approvals;
  }

  /**
   * One write at a time, in arrival order: a later call waits for the one before to finish. The
   * time is read when its turn comes, so recorded times rise with sequence numbers.
   */
  accept(body: string, clock: () => Date = () => new Date()): Promise<Outcome> {
    return this.#serial(async () => this.#count(await this.#accept(body, clock())));
  }

  /** Counts a refusal by its reason word, or an identical retry; returns the outcome unchanged. */
  async #count(out: Outcome): Promise<Outcome> {
    const reason = out.status === 400 ? "invalid" : out.status === 409 ? "conflict" : out.status === 410 ? "late" : out.status === 503 ? "stuck"
      : out.status === 429 ? (out.why.startsWith("the recorder's storage budget") ? "budget_full" : "tap_pool_full") : undefined;
    if (!reason && out.status !== 200) return out;
    const c = (await this.storage.get<Counters>("counters")) ?? { refused: {}, retries: 0 };
    if (reason) c.refused[reason] = (c.refused[reason] ?? 0) + 1;
    else c.retries += 1;
    await this.storage.put({ counters: c });
    return out;
  }

  /** Runs `fn` after every call queued before it: records, status and key creation never overlap. */
  #serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.#queue.then(fn);
    this.#queue = run.catch(() => undefined);
    return run;
  }

  /**
   * Today's use of each pool, holds, the storage budget, whether a write is pending, refusals, and
   * the public key the checker pins (made here if none exists yet, so it can be pinned before the
   * first record). The time is read when its turn comes (REFINE v6 Z5), and holds past their 24 h are
   * released here too, so status never shows a hold the checker has already let go. Older names stay
   * (`used_today` = the tap pool) so the front desk's reader is unchanged.
   */
  status(at: Date | (() => Date) = () => new Date()) {
    return this.#serial(async () => {
      const now = typeof at === "function" ? at() : at;
      const pending = await this.storage.get<Pending>("pending");
      const stored = await this.storage.get<Meta>("meta");
      const meta = stored ? settle(stored, now.getTime(), pending?.receipt.grant) : undefined;
      if (meta && JSON.stringify(meta) !== JSON.stringify(stored)) await this.storage.put({ meta });
      const c = (await this.storage.get<Counters>("counters")) ?? { refused: {}, retries: 0 };
      const h = meta ? held(meta) : { tap: 0, op: 0 };
      return {
        seq: meta?.seq ?? 0, used_today: meta?.used ?? 0, cap: DAY_CAP, stored_bytes: meta?.bytes ?? 0, budget_bytes: this.budget, pending: Boolean(pending), public_key: (await this.#keys()).pub,
        pools: {
          tap: { used: meta?.used ?? 0, cap: DAY_CAP, reserved_slots: h.tap, reserved_bytes: h.tap * MAX_STORED_BYTES },
          op: { used: meta?.op_used ?? 0, cap: OP_DAY_CAP, reserved_slots: h.op, reserved_bytes: h.op * MAX_STORED_BYTES },
        },
        op_cutoff_bytes: RUN_CUTOFF_BYTES, pending_bytes: pending ? len(pending.stored) : 0,
        refused: Object.fromEntries(REFUSALS.map((r) => [r, c.refused[r] ?? 0])), retries: c.retries, expired: meta?.expired ?? { tap: 0, op: 0 },
      };
    });
  }

  /** The signing key: loaded, or made once and kept. Only ever called inside the queue. */
  async #keys() {
    if (this.#key) return this.#key;
    let k = await this.storage.get<Keys>("signing");
    if (!k) {
      const made = (await crypto.subtle.generateKey("Ed25519", true, ["sign", "verify"])) as CryptoKeyPair;
      k = { priv: b64((await crypto.subtle.exportKey("pkcs8", made.privateKey)) as ArrayBuffer), pub: b64((await crypto.subtle.exportKey("raw", made.publicKey)) as ArrayBuffer) };
      await this.storage.put({ signing: k });
    }
    this.#key = { priv: await crypto.subtle.importKey("pkcs8", unb64(k.priv), "Ed25519", false, ["sign"]), pub: k.pub };
    return this.#key;
  }

  /** The envelope as stored: version 2, signed over every other field. */
  async #seal(e: Envelope): Promise<string> {
    const v2: Envelope = { ...e, v: 2 };
    const sig = await crypto.subtle.sign("Ed25519", (await this.#keys()).priv, sealed(v2));
    return JSON.stringify({ ...v2, sig: b64(sig) });
  }

  /** One record's turn: finish any pending write, check, reserve, queue, store, receipt. */
  async #accept(body: string, now: Date): Promise<Outcome> {
    // An unfinished write always goes first; until it is stored nothing new is taken.
    const stuck = await this.#finishPending(now);
    if (stuck) return { status: 503, why: stuck };

    const checked = validate(body);
    if (!checked.ok) return { status: 400, why: checked.why };
    const r = checked.record, sha = await sha256(body), t = now.getTime();
    const grant = await this.storage.get<Grant>(`g:${r.grant}`);

    const done = grant?.stages[r.stage];
    if (done) {
      // The same bytes again (a lost answer, retried) get the same receipt; anything else is refused.
      return done.sha256 === sha ? { status: 200, receipt: done } : { status: 409, why: "this stage of this grant is already recorded with other content" };
    }
    let meta = settle((await this.storage.get<Meta>("meta")) ?? { seq: 0, day: day(t), used: 0, bytes: 0, open: [] }, t);

    let next: Grant;
    if (r.stage === "request") {
      if (meta.used + STAGE_SLOTS > DAY_CAP) return { status: 429, why: `today's ${DAY_CAP} record slots are taken` };
      if (meta.bytes + reservedBytes(meta) + STAGE_SLOTS * MAX_STORED_BYTES > this.budget) return { status: 429, why: "the recorder's storage budget is full: Ben must decide" };
      meta = { ...meta, used: meta.used + STAGE_SLOTS, open: [...meta.open, { grant: r.grant, opened: t, left: STAGE_SLOTS - 1 }] };
      next = { job: r.job, request: sha, opened: t, ...(await grantHashOf(r).then((h) => (h && r.grant_hash === h ? { grant_hash: h } : {}))), stages: {} };
    } else {
      if (!grant) return { status: 409, why: "no request is recorded for this grant" };
      if (t - grant.opened > GRANT_TTL_MS) return { status: 410, why: "this grant's request is over 24 hours old" };
      if (r.request !== grant.request) return { status: 409, why: "the request hash does not match the recorded request" };
      if (r.job !== grant.job) return { status: 409, why: "the job does not match the recorded request" };
      if (r.stage === "result" && !grant.stages.approval) return { status: 409, why: "no approval is recorded for this grant" };
      if (r.stage === "approval") {
        const refused = await this.approvals(r, grant.grant_hash);
        if (refused) return { status: 409, why: refused };
      }
      // Its slot was reserved when the request was taken (and carried into today if need be).
      meta = { ...meta, open: meta.open.map((o) => (o.grant === r.grant ? { ...o, left: Math.max(0, o.left - 1) } : o)) };
      next = grant;
    }

    const seq = meta.seq + 1, key = keyFor(seq, r.grant, r.stage);
    const receipt: Receipt = { v: 1, seq, key, grant: r.grant, stage: r.stage, sha256: sha, recorded_at: now.toISOString() };
    const stored = await this.#seal({ v: 2, seq, grant: r.grant, stage: r.stage, recorded_at: receipt.recorded_at, sha256: sha, body });
    const pending: Pending = { key, stored, storedSha: await sha256(stored), receipt, day: meta.day };
    // Counted, ordered and queued in one atomic step, before the bucket is touched.
    await this.storage.put({
      meta: { ...meta, seq, bytes: meta.bytes + new TextEncoder().encode(stored).length },
      [`g:${r.grant}`]: { ...next, stages: { ...next.stages, [r.stage]: receipt } },
      pending,
    });
    const stuckNow = await this.#finishPending(now);
    if (stuckNow) return { status: 503, why: stuckNow };
    // Withdrawn by #finishPending instead of stored (it fell outside its grant's 24 h): never a receipt.
    const final = (await this.storage.get<Grant>(`g:${r.grant}`))?.stages[r.stage];
    return final ? { status: 201, receipt: final } : { status: 410, why: "this grant's request is over 24 hours old" };
  }

  /**
   * Withdraws a pending approval whose passkey answer fails the check: its number, bytes and grant
   * stage are given back, so the next record takes the number and no gap appears. No receipt has gone
   * out for it (receipts follow storage), so the desk has already stopped that grant. Returns true if
   * withdrawn. The accounting and the removal of `pending` are one transaction (REFINE v11 AE1): after
   * any crash the state is wholly before (pending still there, handled as today) or wholly after. Before
   * card 509a5d85 they were two writes, and a crash and a planted object between them let #retag put
   * back a receipt for a record never written (Codex r5 on B1's refinement).
   */
  async #withdrawUnverified(p: Pending, now: number): Promise<boolean> {
    const checked = validate((JSON.parse(p.stored) as Envelope).body);
    const g0 = (await this.storage.get<Grant>(`g:${p.receipt.grant}`))!;
    if (checked.ok && !(await this.approvals(checked.record, g0.grant_hash))) return false;
    await this.storage.transaction(async (txn) => {
      const m = settle((await txn.get<Meta>("meta"))!, now, p.receipt.grant), g = (await txn.get<Grant>(`g:${p.receipt.grant}`))!;
      if (m.seq === p.receipt.seq) {
        const { approval: _, ...stages } = g.stages, hold = m.open.some((o) => o.grant === p.receipt.grant);
        await txn.put({
          // Its slot goes back to the grant's hold. Charged on an earlier day, that hold is new to
          // today's pool, so today counts it (else today's pool reads one low; found writing B1).
          // With no hold left to return it to, today simply loses its charge if it was charged today.
          meta: { ...m, seq: m.seq - 1, bytes: Math.max(0, m.bytes - len(p.stored)), used: m.used + (hold ? (p.day === m.day ? 0 : 1) : (p.day === m.day ? -1 : 0)), open: m.open.map((o) => (o.grant === p.receipt.grant ? { ...o, left: o.left + 1 } : o)) },
          [`g:${p.receipt.grant}`]: { ...g, stages },
        });
      }
      await txn.delete("pending");
    });
    return true;
  }

  /**
   * Withdraws a pending later tap stage that would be stored past its grant's 24 h (REFINE v7 AA2, v8
   * AB2): the stage is taken off its grant, its number (when still the last) and bytes are given back
   * once, its charge comes off today's pool if it was charged today, and the grant's remaining hold is
   * released as expired (counted once), never restored. One transaction with the removal of `pending`
   * (v11 AE1). Called only once the bucket holds nothing under its exact name (W3).
   */
  async #withdrawLate(p: Pending, now: number): Promise<void> {
    await this.storage.transaction(async (txn) => {
      const m = settle((await txn.get<Meta>("meta"))!, now, p.receipt.grant), g = (await txn.get<Grant>(`g:${p.receipt.grant}`))!;
      const { [p.receipt.stage]: _, ...stages } = g.stages;
      const hold = m.open.find((o) => o.grant === p.receipt.grant);
      const expired = { ...m.expired!, tap: m.expired!.tap + (hold && hold.left > 0 ? 1 : 0) };
      await txn.put({
        meta: {
          ...m, expired,
          seq: m.seq === p.receipt.seq ? m.seq - 1 : m.seq,
          bytes: Math.max(0, m.bytes - len(p.stored)),
          used: m.used - (p.day === m.day ? 1 : 0) - (hold?.left ?? 0),
          open: m.open.filter((o) => o.grant !== p.receipt.grant),
        },
        [`g:${p.receipt.grant}`]: { ...g, stages },
      });
      await txn.delete("pending");
    });
  }

  /** The pending record under a new name at the same number, with a random tag, signed again; its receipt follows. */
  async #retag(p: Pending): Promise<Pending> {
    const tag = [...crypto.getRandomValues(new Uint8Array(8))].map((b) => b.toString(16).padStart(2, "0")).join("");
    const key = keyFor(p.receipt.seq, p.receipt.grant, p.receipt.stage, tag);
    // The tag is signed with the record, so the record verifies only under this one name.
    const stored = await this.#seal({ ...(JSON.parse(p.stored) as Envelope), tag });
    const moved: Pending = { ...p, key, stored, storedSha: await sha256(stored), receipt: { ...p.receipt, key } };
    const g = (await this.storage.get<Grant>(`g:${p.receipt.grant}`))!;
    // The signed tag makes the envelope longer: the storage budget is charged the difference (Codex r2).
    const m = (await this.storage.get<Meta>("meta"))!;
    await this.storage.put({ pending: moved, meta: { ...m, bytes: m.bytes + len(stored) - len(p.stored) }, [`g:${p.receipt.grant}`]: { ...g, stages: { ...g.stages, [p.receipt.stage]: moved.receipt } } });
    return moved;
  }

  /** Stores the pending record, if any. Returns why it could not, or undefined once it is stored. */
  async #finishPending(now: Date): Promise<string | undefined> {
    let p = await this.storage.get<Pending>("pending");
    if (!p) return undefined;
    try {
      // Other names under this number are not looked at: the record is written beside them, and the
      // checker reports anything the recorder did not sign as foreign (card 6f681cc1). Halting here
      // instead let any bucket writer stop every record, and locked plants cannot be deleted.
      let there = await this.bucket.get(p.key);
      // Its exact name holding other bytes (planted ahead; names are predictable): it moves to a name
      // at the same number that no one could plant ahead. Ours from before a crash keeps its name.
      if (there && (await sha256(new Uint8Array(await there.arrayBuffer()))) !== p.storedSha) {
        p = await this.#retag(p);
        there = null;
      }
      // An approval not yet in the bucket is checked again before it is stored: one queued by a
      // recorder from before the passkey check (or before a new pin) must not slip through (Codex r1 #1).
      if (!there && p.receipt.stage === "approval" && (await this.#withdrawUnverified(p, now.getTime()))) return undefined;
      if (!there) {
        const t = now.getTime(), late = t - Date.parse(p.receipt.recorded_at) > SKEW_MS / 2 || day(t) !== p.day;
        const g = (await this.storage.get<Grant>(`g:${p.receipt.grant}`))!;
        // A later stage re-timed past its grant's 24 h is withdrawn, never stored (REFINE v7 AA2). Its
        // grant's opening time never moves for it: only an opening record moves its own window.
        if (late && p.receipt.stage !== "request" && t - g.opened > GRANT_TTL_MS) {
          await this.#withdrawLate(p, t);
          return undefined;
        }
        if (late) {
          // Stored late (the bucket was down), or on a later UTC day however briefly: no receipt has
          // gone out, so it takes the time it is actually stored, and its receipt says the same.
          const receipt = { ...p.receipt, recorded_at: now.toISOString() };
          // A new time means a new signature: the old one covered the old time. A legacy unsigned
          // envelope is signed here too; either way the budget is charged the length change (Z5).
          const stored = await this.#seal({ ...(JSON.parse(p.stored) as Envelope), recorded_at: receipt.recorded_at });
          let m = settle((await this.storage.get<Meta>("meta"))!, t, p.receipt.grant), next: Grant = { ...g, stages: { ...g.stages, [receipt.stage]: receipt } };
          let charged = p.day;
          if (day(t) !== p.day) {
            // Stored on a later UTC day: it is charged to that day, in its own pool. Nothing else is
            // taken while a record is pending, so this is the day's first write, after the carried holds.
            if (p.pool === "op") {
              if ((m.op_used ?? 0) + 1 > OP_DAY_CAP) return `today's ${OP_DAY_CAP} op slots are taken; the pending record waits`;
              m = { ...m, op_used: (m.op_used ?? 0) + 1 };
            } else {
              if (m.used + 1 > DAY_CAP) return `today's ${DAY_CAP} record slots are taken; the pending record waits`;
              m = { ...m, used: m.used + 1 };
            }
            charged = m.day;
          }
          if (receipt.stage === "request") {
            // An opening record's window starts when it is stored (T11): the grant's `opened` and its
            // hold move together, so recorder and checker (which reads `recorded_at`) agree. A hold that
            // is somehow gone is made again in full, and counted in today's pool.
            next = { ...next, opened: t };
            const hold = m.open.find((o) => o.grant === receipt.grant);
            m = hold
              ? { ...m, open: m.open.map((o) => (o.grant === receipt.grant ? { ...o, opened: t } : o)) }
              : { ...m, used: m.used + STAGE_SLOTS - 1, open: [...m.open, { grant: receipt.grant, opened: t, left: STAGE_SLOTS - 1 }] };
          }
          m = { ...m, bytes: m.bytes + len(stored) - len(p.stored) };
          p = { ...p, stored, storedSha: await sha256(stored), receipt, day: charged };
          await this.storage.put({ meta: m, [`g:${receipt.grant}`]: next, pending: p });
        } else if ((JSON.parse(p.stored) as Envelope).v !== 2) {
          // Queued before this recorder signed records (card 6a04908f): signed now, before it is stored,
          // and the budget is charged the length change (Z5; before card 509a5d85 it was not).
          const stored = await this.#seal(JSON.parse(p.stored) as Envelope);
          const m = (await this.storage.get<Meta>("meta"))!;
          await this.storage.put({ meta: { ...m, bytes: m.bytes + len(stored) - len(p.stored) }, pending: (p = { ...p, stored, storedSha: await sha256(stored) }) });
        }
        await this.bucket.put(p.key, p.stored, { customMetadata: { sha256: p.storedSha }, httpMetadata: { contentType: "application/json" } });
      }
    } catch {
      return "the records bucket did not take the write; it will be retried";
    }
    await this.storage.delete("pending");
    return undefined;
  }
}
