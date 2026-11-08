// The hourly checker's view of run operations (card 1a272a5c build A; threat table studio-os
// docs/specifications/trust-but-verify/OPS-CHECKER-THREATS-1a272a5c.md). records.ts calls these as it
// reads each record in number order: a run-open request, its approval, each op, each op_result. Coverage
// rules and the op format live in ops.ts, shared with B's recorder. Nothing here refuses anything: it
// raises findings, and keeps run and op state in its own maps, apart from the grant map records.ts
// prunes (threat 11), so an op id equal to a grant id never collides (threat 10).
import { GRANT_TTL_MS, MAX_STORED_BYTES, SKEW_MS, sha256, STORE_BUDGET_BYTES, type WriterRecord } from "./contract.ts";
import { CARD_ELIGIBLE, CARD_OUTCOMES, CARD_RESULT_MS, cardApproval, challengeHash, isCardId } from "./card.ts";
import { grantHashOf } from "./recorder/passkey.ts";
import { OP_DAY_CAP, parseDescriptor, RESULT_MS, RUN_CUTOFF_BYTES, RUN_MAX_MS, RUN_OPEN_JOB, uncovered, type Op, type OpResult, type RunSeen } from "./ops.ts";
import type { Finding } from "./records.ts";

/**
 * How an id appears in alerts: the first 16 hex of its SHA-256, never the id itself, so a writer cannot
 * put words into Ben's alerts, and cannot make one id's fingerprint look like another's.
 */
export const fp = async (id: string) => `#${(await sha256(id)).slice(0, 16)}`;

const DAY_MS = 86_400_000;
/** How long run-op state waits for the watermark before it is let go (Codex r1 #4): a week of stalled reads. */
export const HOLD_MS = 7 * DAY_MS;

// `read`: when this checker first held the entry (its own clock), so a backlog read late is still held HOLD_MS.
interface Run extends RunSeen { at: number; first?: number; last?: number; read?: number }
interface Waiting { seq: number; sha: string; run: string; job: string; at: number; read?: number }
/** Kept in the checker's saved state under `ops`; every field defaults empty for a state from before A. */
export interface OpsState {
  runs: Record<string, Run>; // by run-open grant id, until deadline + 24 h is behind the watermark
  open: Record<string, Waiting>; // ops with no valid result yet, by op id
  seen: Record<string, { until: number; end: "open" | "result" | "expired"; read?: number }>; // every op id, for duplicates and late results
  through?: number; // complete_through (W4): every record recorded at or before it has been read
  days: Record<string, number>; // op-pool records by UTC day
  written: number; // bytes of stored objects, from the hourly reads; the daily count sets it exactly
  bytes: Record<string, number>; // written bytes by UTC day, for the runway
  first?: string; // the first UTC day this checker counted bytes: no runway alert for 7 full days after
  kinds: { tap: number; op: number }; // written bytes by kind
  incomplete: number; resolved: number; delay_max: number;
  unsettled: number; // ops let go as op-unsettled because no complete read came for HOLD_MS after they were read
}
const bare = <T>(o: unknown): Record<string, T> => Object.assign(Object.create(null), o && typeof o === "object" ? o : {});
const num = (v: unknown) => (Number.isFinite(v) ? (v as number) : 0);
/** The saved run-op state, or empty fields where it is missing or from before A (threat 18). */
export function loadOps(x: unknown): OpsState {
  const o = (x && typeof x === "object" ? x : {}) as Partial<OpsState>;
  return {
    runs: bare(o.runs), open: bare(o.open), seen: bare(o.seen), through: Number.isFinite(o.through) ? o.through : undefined,
    days: bare(o.days), written: num(o.written), bytes: bare(o.bytes), first: typeof o.first === "string" ? o.first : undefined,
    kinds: { tap: num(o.kinds?.tap), op: num(o.kinds?.op) }, incomplete: num(o.incomplete), resolved: num(o.resolved), delay_max: num(o.delay_max), unsettled: num(o.unsettled),
  };
}

/** A request that passed the order check: a run-open request becomes a run, with its descriptor parsed once. */
export function onRequest(s: OpsState, grant: string, seq: number, sha: string, job: string, record: Record<string, unknown>, at: number) {
  // A grant id seen again (possible only once the grant map has let the first go): the run covers nothing.
  if (Object.hasOwn(s.runs, grant)) return void Object.assign(s.runs[grant], { descriptor: "run-open grant id was used twice", approved: false });
  if (job !== RUN_OPEN_JOB) return;
  const p = record.params as Record<string, unknown> | undefined;
  const only = p && typeof p === "object" && !Array.isArray(p) && Object.keys(p).length === 1 && Object.hasOwn(p, "descriptor");
  s.runs[grant] = { seq, sha, descriptor: only ? parseDescriptor(p.descriptor, at) : "run-open request carries more than the descriptor", approved: false, ops: 0, at };
}
/** An approval that passed the order check (V7.4) and names the run's own request: only this marks a run approved. */
export function onApproval(s: OpsState, grant: string, request: string | undefined) {
  if (Object.hasOwn(s.runs, grant) && s.runs[grant].sha === request) s.runs[grant].approved = true;
}

/** An op record that failed its own checks (malformed, or stored over 10 minutes late, X1): never covered. */
export const badOp = async (seq: number, op: string): Promise<Finding> => ({ id: `op-uncovered:${op}:${seq}`, text: `run op ${await fp(op)} (record ${seq}) is not covered by a passkey-approved run: it was stored late or is malformed` });

/** One valid op, read in order. `grantJob` says whether a non-run grant of that id was read (threat 2). */
export async function onOp(s: OpsState, seq: number, op: Op, sha: string, at: number, grantJob: (g: string) => string | undefined, opsFrom: number | undefined): Promise<Finding[]> {
  const shown = `run op ${await fp(op.grant)} (record ${seq})`;
  if (Object.hasOwn(s.seen, op.grant)) return [{ id: `duplicate:o:${op.grant}:op`, text: `${shown} has a second op record` }];
  s.seen[op.grant] = { until: at + 2 * RESULT_MS, end: "open" };
  s.open[op.grant] = { seq, sha, run: op.run, job: op.job, at };
  const run = Object.hasOwn(s.runs, op.run_grant) ? s.runs[op.run_grant] : undefined;
  if (!run) {
    if (grantJob(op.run_grant) !== undefined) return [{ id: `op-uncovered:${op.grant}`, text: `${shown} is not covered by a passkey-approved run: it names a grant that is not a run-open request` }];
    return [{ id: `op-unlinked:${op.grant}`, text: `${shown} names no run-open request the checker has read` }];
  }
  const why = uncovered(op, run, at, opsFrom);
  run.ops++;
  run.first ??= at;
  run.last = at;
  return why ? [{ id: `op-uncovered:${op.grant}`, text: `${shown} is not covered by Ben's passkey-approved run ${await fp(op.run_grant)}: ${why}` }] : [];
}

/** One valid op_result. Only a result naming its op's exact bytes, run and job, within 24 hours, clears it (threat 13). */
export async function onResult(s: OpsState, seq: number, r: OpResult, at: number): Promise<Finding[]> {
  const shown = `the result of run op ${await fp(r.grant)} (record ${seq})`;
  const o = Object.hasOwn(s.open, r.grant) ? s.open[r.grant] : undefined;
  if (!o) {
    const end = Object.hasOwn(s.seen, r.grant) ? s.seen[r.grant].end : undefined;
    if (end === "result") return [{ id: `duplicate:o:${r.grant}:op_result`, text: `${shown} is a second result` }];
    if (end === "expired") return [{ id: `op-late:${r.grant}:${seq}`, text: `${shown} came after its op was already reported incomplete` }];
    return [{ id: `op-unlinked:${r.grant}:${seq}`, text: `${shown} names no op the checker has read` }];
  }
  if (r.op !== o.sha || r.run !== o.run || r.job !== o.job) return [{ id: `op-unlinked:${r.grant}:${seq}`, text: `${shown} names a different op, run or job than its op record; the op stays open` }];
  if (at - o.at > RESULT_MS) return [{ id: `op-late:${r.grant}:${seq}`, text: `${shown} was recorded over 24 hours after its op; the op stays open` }];
  delete s.open[r.grant];
  s.seen[r.grant].end = "result";
  s.resolved++;
  s.delay_max = Math.max(s.delay_max, at - o.at);
  return [];
}

/**
 * After the hour's read. A complete run (W4, X2) moves the watermark to its start minus the skew bound;
 * then every open op whose 24 hours ended before the watermark is incomplete, and state past its use is let go.
 */
export async function settle(s: OpsState, now: number, complete: boolean): Promise<Finding[]> {
  if (complete) s.through = Math.max(s.through ?? 0, now - SKEW_MS);
  const out: Finding[] = [];
  // A watermark held back (a planted higher number, a stuck read) must not hold state forever (Codex r1 #4):
  // past HOLD_MS, open ops are let go and counted as unsettled, never as incomplete, and the rest is pruned.
  // The hold runs from when this checker first held each entry, never from its recorded time (commit security review).
  for (const x of [...Object.values(s.open), ...Object.values(s.seen), ...Object.values(s.runs)]) x.read ??= now;
  const hold = now - HOLD_MS;
  for (const [id, o] of Object.entries(s.open)) {
    if (o.read! >= hold || (s.through ?? 0) > o.at + RESULT_MS) continue;
    out.push({ id: `op-unsettled:${id}`, text: `run op ${await fp(id)} (record ${o.seq}) could not be settled: no complete read of the records for 7 days after it was read` });
    delete s.open[id];
    s.unsettled++;
  }
  for (const [id, x] of Object.entries(s.seen)) if (x.read! < hold && x.until < now - RESULT_MS && !Object.hasOwn(s.open, id)) delete s.seen[id];
  for (const [g, r] of Object.entries(s.runs)) if (r.read! < hold && r.at + RUN_MAX_MS < now - RESULT_MS) delete s.runs[g];
  const through = s.through;
  if (through === undefined) return out;
  for (const [id, o] of Object.entries(s.open)) {
    if (o.at + RESULT_MS >= through) continue;
    out.push({ id: `op-incomplete:${id}`, text: `run op ${await fp(id)} (record ${o.seq}) has no result 24 hours after it was recorded` });
    delete s.open[id];
    if (Object.hasOwn(s.seen, id)) s.seen[id].end = "expired";
    s.incomplete++;
  }
  for (const [id, x] of Object.entries(s.seen)) if (x.until < through && !Object.hasOwn(s.open, id)) delete s.seen[id];
  for (const [g, r] of Object.entries(s.runs)) {
    const end = typeof r.descriptor === "string" ? r.at + RUN_MAX_MS : r.descriptor.deadline;
    if (end + RESULT_MS < through) delete s.runs[g];
  }
  return out;
}

const level = (used: number, cap: number) => (used >= 0.9 * cap ? 90 : used >= 0.8 * cap ? 80 : 0);
const GiB = (b: number) => (b / 1024 ** 3).toFixed(2);

/** Pool alerts (80 / 90% of each pool's 400 today, counting outstanding reservations) and the op day cap. */
export function poolFindings(s: OpsState, today: string, use: { tap: number; op: number }, tapCap: number): Finding[] {
  const out: Finding[] = [];
  for (const [pool, used, cap] of [["tap", use.tap, tapCap], ["op", use.op, OP_DAY_CAP]] as const) {
    const l = level(used, cap);
    if (l) out.push({ id: `pool:${pool}:${today}:${l}`, text: `the ${pool === "tap" ? "tap" : "run op"} pool is at ${used} of ${cap} slots today, counting reservations (${l}%+)` });
  }
  for (const [d, n] of Object.entries(s.days)) if (n > OP_DAY_CAP) out.push({ id: `cap:op:${d}`, text: `${n} run op records stored on ${d}, over the op pool's cap of ${OP_DAY_CAP}` });
  return out;
}

/**
 * Storage alerts for the run cutoff and the tap capacity separately (V8, W8): 80 / 90% used, and runway
 * under 60 (warning) or 30 (critical: Ben acts within 7 days) days at the last 7 full days' average rate.
 */
export function capacityFindings(s: OpsState, now: number, reserved: number, tapBudget = STORE_BUDGET_BYTES): Finding[] {
  const out: Finding[] = [], used = s.written + reserved;
  const days = s.first ? Math.floor((Date.parse(new Date(now).toISOString().slice(0, 10)) - Date.parse(s.first)) / DAY_MS) : 0;
  let rate = 0;
  for (let i = 1; i <= 7; i++) rate += num(s.bytes[new Date(now - i * DAY_MS).toISOString().slice(0, 10)]);
  rate /= 7;
  for (const [which, cap, name] of [["run", RUN_CUTOFF_BYTES, "run op cutoff"], ["tap", tapBudget, "tap capacity"]] as const) {
    const l = level(used, cap);
    if (l) out.push({ id: `capacity:${which}:${l}`, text: `records storage is at ${GiB(used)} of the ${GiB(cap)} GiB ${name}, counting reservations (${l}%+)` });
    if (days < 7 || rate <= 0) continue;
    const runway = (cap - used) / rate;
    if (runway < 30) out.push({ id: `runway:${which}:critical`, text: `the ${name} fills in about ${Math.max(0, Math.floor(runway))} days at the last week's rate: Ben acts within 7 days` });
    else if (runway < 60) out.push({ id: `runway:${which}:warning`, text: `the ${name} fills in about ${Math.floor(runway)} days at the last week's rate` });
  }
  return out;
}

/** Counts one stored object toward bytes written (by day and kind). */
export function countBytes(s: OpsState, d: string, size: number, op: boolean) {
  s.written += size;
  s.bytes[d] = num(s.bytes[d]) + size;
  s.kinds[op ? "op" : "tap"] += size;
  s.first ??= d;
}

/** Day counts and bytes by day past their use are let go: op days after three days, bytes after eight. */
export function pruneDays(s: OpsState, now: number) {
  for (const d of Object.keys(s.days)) if (d < new Date(now - 3 * DAY_MS).toISOString().slice(0, 10)) delete s.days[d];
  for (const d of Object.keys(s.bytes)) if (d < new Date(now - 8 * DAY_MS).toISOString().slice(0, 10)) delete s.bytes[d];
}

/** The measures (V8) the checker can rebuild from records, for the run report. */
export const measures = (s: OpsState, use: { tap: number; op: number; reserved_bytes: number }, today: string) => ({
  pools_today: { tap: use.tap, op: use.op }, op_records_today: num(s.days[today]), runs_open: Object.keys(s.runs).length, ops_open: Object.keys(s.open).length,
  ops_per_run: Object.values(s.runs).map((r) => ({ ops: r.ops, length_ms: r.last !== undefined && r.first !== undefined ? r.last - r.first : 0 })),
  ops_incomplete: s.incomplete, results: s.resolved, result_delay_max_ms: s.delay_max,
  bytes: { written: s.written, reserved: use.reserved_bytes, by_kind: s.kinds, per_slot_max: MAX_STORED_BYTES },
});

// Card approvals (card 586da182; REFINE-586da182 Outcome 7, S2, S3, T3, D3). Kept apart from the grant map
// records.ts prunes, under `cards` in the saved state. Per card grant, from its request: job, request hash,
// card id, expiry, and the grant hash only when this checker's own grantHashOf matches the request's (S3).
// A card approval re-runs the recorder's checks (card.ts cardApproval) timed by its signed recorded_at, and
// its challenge must carry the card hash; the passkey signature is not re-verified (the recorder did, as for
// ordinary approvals). Records without a card mark or `approval_kind` are untouched.
interface CardEntry { job: string; req: string; card: string; at: number; seq: number; exp?: number; by?: string; hash?: string; deadline?: number; end?: "result" | "incomplete"; read?: number }
export type CardsState = Record<string, CardEntry>;
/** True while a card grant may still need its request context: not yet resolved by a result or an incident. */
export const cardOpen = (s: CardsState, g: string) => Object.hasOwn(s, g) && !s[g].end;
/** The saved card state, or empty where it is missing or from before this card (a reverted checker drops it). */
export const loadCards = (x: unknown): CardsState => bare<CardEntry>(Object.fromEntries(Object.entries(x && typeof x === "object" ? x : {}).filter(([, v]) => v && typeof v === "object")));
/** A card-bad finding: one per record, the grant shown as a fingerprint, the reason a fixed phrase. */
const cardBad = async (grant: string, seq: number, why: string): Promise<Finding> => ({ id: `card-bad:${grant}:${seq}`, text: `card grant ${await fp(grant)} (record ${seq}): ${why}` });

/** A request that passed the order check: a card request is kept for its approval and result. */
export async function onCardRequest(s: CardsState, grant: string, seq: number, sha: string, job: string, record: Record<string, unknown>, at: number): Promise<Finding[]> {
  if (record.card === undefined) return [];
  const h = await grantHashOf(record as WriterRecord);
  s[grant] = { job, req: sha, card: String(record.card), at, seq, ...(Number.isSafeInteger(record.expires_at) ? { exp: record.expires_at as number } : {}), ...(typeof record.requester === "string" ? { by: record.requester } : {}), ...(h && record.grant_hash === h ? { hash: h } : {}) };
  return isCardId(record.card) && CARD_ELIGIBLE.includes(job) ? [] : [await cardBad(grant, seq, "a card request whose card id or job is not allowed on a card")];
}

/** An approval that passed the order check. Any card mark with no card request held is `card-bad` (S2: e.g. after a checker revert). */
export async function onCardApproval(s: CardsState, grant: string, seq: number, record: Record<string, unknown>, at: number): Promise<Finding[]> {
  const e = Object.hasOwn(s, grant) ? s[grant] : undefined;
  if (!e) return record.approval_kind !== undefined || record.manifest !== undefined ? [await cardBad(grant, seq, "a card approval with no card request the checker holds (no request context)")] : [];
  const v = await cardApproval(record as WriterRecord, { job: e.job, card: e.card, grant_hash: e.hash, expires_at: e.exp, requester: e.by }, at);
  if (v && "why" in v) return [await cardBad(grant, seq, v.why)];
  if (!v || challengeHash(record.assertion) !== v.hash) return [await cardBad(grant, seq, "Ben's passkey answer is not over this card's hash")];
  e.deadline = v.manifest.deadline;
  return [];
}

/** A result that passed the order check: for a card grant, its outcome; late after deadline + 1 h; `unknown` alerts once (D3). */
export async function onCardResult(s: CardsState, grant: string, seq: number, record: Record<string, unknown>, at: number): Promise<Finding[]> {
  const e = Object.hasOwn(s, grant) ? s[grant] : undefined;
  if (!e) return [];
  const out: Finding[] = [], shown = `card grant ${await fp(grant)} (record ${seq})`;
  if (!(typeof record.outcome === "string" && CARD_OUTCOMES.includes(record.outcome))) out.push(await cardBad(grant, seq, "a result whose outcome is not done, failed or unknown"));
  if (e.deadline !== undefined && (e.end === "incomplete" || at > e.deadline + CARD_RESULT_MS)) out.push({ id: `card-late:${grant}:${seq}`, text: `${shown}: its result came over an hour after the card's deadline` });
  if (record.outcome === "unknown") out.push({ id: `card-unknown:${grant}`, text: `${shown}: the result is unknown -- the job may have run; do not tap it again` });
  e.end = "result";
  return out;
}

/**
 * After the hour's read: a card approval with no result by deadline + 1 h is `card-incomplete`, raised only
 * once a complete read has passed that time (`through`, the run-op watermark), so a stalled read never alarms.
 * Entries are let go 3 days after their request is behind the watermark, or 30 days after first held.
 */
export async function settleCards(s: CardsState, now: number, through: number | undefined): Promise<Finding[]> {
  const out: Finding[] = [];
  for (const [g, e] of Object.entries(s)) {
    e.read ??= now;
    // Due: the card's deadline, or the grant's 24 h if sooner (no result can be stored after it), + 1 h.
    const due = e.deadline === undefined ? undefined : Math.min(e.deadline, e.at + GRANT_TTL_MS) + CARD_RESULT_MS;
    if (through !== undefined && due !== undefined && !e.end && due < through) {
      out.push({ id: `card-incomplete:${g}`, text: `card grant ${await fp(g)} (record ${e.seq}) has no result an hour after its card's deadline: it may not have run, or ran unrecorded` });
      e.end = "incomplete";
    }
    // An approved entry is never let go unsettled in silence (Codex build r1 #2): after 30 days with no
    // complete read past its due time it becomes its own standing incident, then goes.
    if (due !== undefined && !e.end && e.read < now - 30 * DAY_MS) {
      out.push({ id: `card-unsettled:${g}`, text: `card grant ${await fp(g)} (record ${e.seq}) could not be settled: no complete read of the records for 30 days after its approval was read` });
      e.end = "incomplete";
    }
    if ((e.end || due === undefined) && ((through ?? 0) > e.at + 3 * DAY_MS || e.read < now - 30 * DAY_MS)) delete s[g];
  }
  return out;
}
