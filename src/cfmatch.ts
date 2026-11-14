// Card beec640b build b, the consumer (epic cafd3acc, D4): every create or delete made with the front desk's
// master key must be named by an eligible signed tap result (`cf`). The records check publishes those taps as
// `effects` in state/records.json (src/records.ts); this file judges the hourly audit check's master events
// against them. Design: studio-os docs/specifications/trust-but-verify/REFINE-beec640b-build-b.md v3.3, sections
// 4.4-4.7 as overridden by 12 and 13. Working state is `m` inside state/cfaudit.json, saved in cfaudit's one
// conditional save (B-D5). Two append-only objects sit beside it: state/cfepochs.json (activations, 12.5) and
// state/cfindex/<YYYY-MM>.json (tap -> matched events) with
// state/cfindex/by-record.json (record number -> month), written before a tap is acknowledged done (13.3). Alert words never hold a key id or a written name.
import { GRANT_TTL_MS } from "./contract.ts";
import { CF_FROM } from "./card.ts";
import { judge, type Judged, type Who } from "./cfjudge.ts";
import { ref, SETTLE_MS } from "./cfaudit.ts";
import { STATE_KEY as RECORDS_KEY } from "./records.ts";

const MIN = 60_000, H = 60 * MIN;
export const RESULT_WAIT_MS = 15 * MIN, WARM_MS = GRANT_TTL_MS + H, MAX_PENDING = 500, STALE_MS = 6 * H;
export const HELPER_MS = 24 * H, HC_IDLE_MS = 48 * H, LATE_KEEP_MS = 72 * H, PROBE_MS = 6 * MIN;
// A replay reads 3 pages (600 events) a run; 24 runs is a day and 14,400 events, about 150 times the busiest real
// hour (93): a replay still unfinished then is stuck (one instant holding more than a run reads), so the light goes red.
export const REPLAY_RUNS = 24, RETAIN_MS = 517 * 86_400_000; // 17 months
export const EPOCHS_KEY = "state/cfepochs.json", INDEX_PREFIX = "state/cfindex/", BY_RECORD = "state/cfindex/by-record.json";
export const MASTER_GROUP = "master writes, not yet matched";
const HC_JOB = "cf.token.headcount.setup";
// Job table (base REFINE 5.2, vault @2f77f7e): [creates, deletes, name kind, permission groups]. Deletes: own helpers,
// the read jobs' two sweeps of SWEEP_DELETES 1, accept's one (acceptKeys runs only sweepHelpers), and for the headcount
// setup OLD_HEADCOUNT_DELETES 8 plus a failed candidate. 12.4: one create. Groups by Cloudflare name, as the vault asks.
const ALLOW: Record<string, [number, number, "p" | "h", string[]]> = { "cf.audit.read": [1, 3, "p", ["Account Settings Read"]], "cf.zone.read": [2, 4, "p", ["Zone Read"]], "cf.dns.list": [2, 4, "p", ["Zone Read", "DNS Read"]], [HC_JOB]: [1, 11, "h", ["Account API Tokens Read"]], "cf.token.accept": [0, 1, "p", []] };

interface Stamp { n: number; at: number }
interface Grant { job: string; req?: Stamp; appr?: Stamp; res?: Stamp; cf?: { made: string[]; deleted: string[] } | "unknown" | "none"; tainted?: string }
interface Effects { gen: number; since: number; covered_to: number; grants: Record<string, Grant>; retired: Record<string, number>; index: Record<string, string>; revoked: Record<string, string>; replay_from?: number }
/** One master event: action, key id, time, success, epoch; `s`/`x` name kind and expiry (creates); `g`/`j`/`r` its tap once matched; `o` lifetime decided; `i` in the index; `pg` permission group names (creates). */
export interface Ev { id: string; a: "create" | "delete"; k: string; t: number; ok: boolean; ep: number; s?: string; x?: number; g?: string; j?: string; r?: number; o?: 1; i?: 1; pg?: string[] }
export interface M { t: number; ids: string[]; ep: number; from?: number; since?: number; gen?: number; cov: number; pend: Ev[]; expl: Ev[]; late: Ev[]; hc: Record<string, number>; done: string[]; rev: string[]; rj: string[]; ix: string[]; ux?: boolean; sh?: boolean; rp?: { s: number; from: number; ids: string[]; to: number; runs: number } }

const isO = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const fin = (x: unknown): x is number => Number.isFinite(x), str = (x: unknown): x is string => typeof x === "string";
const strs = (l: unknown) => Array.isArray(l) && l.every(str);
const stamp = (s: unknown) => s === undefined || (isO(s) && fin(s.n) && fin(s.at));
const entry = (e: unknown) => isO(e) && str(e.job) && stamp(e.req) && stamp(e.appr) && stamp(e.res) && (e.tainted === undefined || str(e.tainted))
  && (e.cf === undefined || e.cf === "unknown" || e.cf === "none" || (isO(e.cf) && strs(e.cf.made) && strs(e.cf.deleted)));
/** The published effects, checked to every leaf the matcher reads (4.1), or why they cannot be used. */
export function readEffects(x: unknown): Effects | string {
  if (!isO(x)) return "missing";
  const ok = Number.isInteger(x.gen) && fin(x.since) && fin(x.covered_to) && isO(x.grants) && Object.values(x.grants).every(entry)
    && isO(x.retired) && Object.values(x.retired).every(fin) && isO(x.index) && Object.values(x.index).every(str) && isO(x.revoked) && Object.values(x.revoked).every(str) && (x.replay_from === undefined || Number.isInteger(x.replay_from));
  return ok ? (x as Effects) : "malformed";
}
const evOk = (e: unknown) => isO(e) && str(e.id) && (e.a === "create" || e.a === "delete") && str(e.k) && fin(e.t) && typeof e.ok === "boolean" && Number.isInteger(e.ep);
const validM = (m: unknown): m is M => isO(m) && fin(m.t) && strs(m.ids) && Number.isInteger(m.ep) && (m.ep === 0 || fin(m.from)) && fin(m.cov) && [m.pend, m.expl, m.late].every((l) => Array.isArray(l) && l.every(evOk))
  && isO(m.hc) && [m.done, m.rev, m.rj, m.ix].every(strs) && (m.rp === undefined || (isO(m.rp) && [m.rp.s, m.rp.from, m.rp.to, m.rp.runs].every(fin) && strs(m.rp.ids)));
const iso = (t: number) => new Date(t).toISOString();
const month = (t: number, back = 0) => { const d = new Date(t); return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() - back, 1)).toISOString().slice(0, 7); };
type Copy = Pick<R2Bucket, "get" | "put">;
/** Read-modify-write of an append-only object: create-if-absent or etag-conditional; undefined when it did not land. */
async function append<T>(copy: Copy, key: string, f: (cur: T | undefined) => T): Promise<T | undefined> {
  try {
    const o = await copy.get(key), next = f(o ? JSON.parse(await o.text()) : undefined);
    return (await copy.put(key, JSON.stringify(next), { onlyIf: o ? { etagMatches: o.etag } : new Headers({ "If-None-Match": "*" }) })) ? next : undefined;
  } catch { return undefined; }
}
const readJson = (copy: Copy, key: string) => copy.get(key).then(async (o) => (o ? JSON.parse(await o.text()) : undefined));

/** Why an event is not explained by the effects, and the one tap involved; no `why` means matched to `g` (4.4, 12.4). */
export function explain(ev: Ev, fx: Effects, expl: Ev[]): { g?: string; why?: string } {
  if (!ev.ok) return { why: "the change failed; failed changes are never matched" };
  const inWin = (e: Grant) => !!e.appr && !!e.res && ev.t >= e.appr.at && ev.t <= e.res.at;
  const list = (e: Grant) => (isO(e.cf) ? (ev.a === "create" ? e.cf.made : e.cf.deleted) : []);
  const named = Object.entries(fx.grants).filter(([, e]) => !e.tainted && list(e).includes(ev.k));
  if (named.length > 1) return { why: "two taps name this key" };
  if (!named.length) {
    const vague = Object.entries(fx.grants).filter(([, e]) => (e.tainted || !isO(e.cf)) && inWin(e));
    if (vague.length !== 1) return { why: "no approved tap names it" };
    return { why: vague[0][1].tainted ? "its tap's records were found bad" : "a front-desk tap could not say which keys it touched", g: vague[0][0] };
  }
  const [g, e] = named[0], al = Object.hasOwn(ALLOW, e.job) ? ALLOW[e.job] : undefined;
  if (!inWin(e)) return { why: "outside its tap's time", g };
  if (expl.some((x) => x.a === ev.a && x.k === ev.k && x.id !== ev.id)) return { why: "a second log entry for the same key change", g };
  if (!al || expl.filter((x) => x.g === g && x.a === ev.a).length >= (ev.a === "create" ? al[0] : al[1])) return { why: "more than its job allows", g };
  if (ev.a === "create" && (ev.s !== al[2] || (al[2] === "h" ? ev.x !== -1 : !(ev.x! >= 0 && ev.x! <= ev.t + PROBE_MS)))) return { why: "its shape does not fit the job", g };
  if (ev.a === "create" && !(ev.pg?.length && ev.pg.every((p) => al[3].includes(p)))) return { why: "its permissions do not fit the job, or could not be read", g };
  return { g };
}

type Add = (id: string, text: string) => void;
type Page = (q: string) => Promise<{ events: { id: string; t: number; e: Record<string, unknown> }[]; cursor?: string; bad?: string }>;
const word = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

/** The matcher for one cfaudit run. `s`: cfaudit's loaded state (m lives in it). */
export async function matcher(copy: Copy, who: Who, s: { bm: { t: number; ids: string[] }; m?: unknown; week: { counts: Record<string, number> } }, T: number, add: Add) {
  const week0 = s.week.counts;
  const raw = await readJson(copy, RECORDS_KEY).catch(() => null);
  const r = raw === null ? "unreadable" : readEffects(isO(raw) ? raw.effects : undefined);
  let fx = typeof r === "string" ? undefined : r, bad = typeof r === "string" ? r : undefined, on = false, reset = false;
  const ex = await readJson(copy, EPOCHS_KEY).catch(() => null);
  let epochs: { n: number; boundary: number }[] = Array.isArray(ex?.epochs) && ex.epochs.every((e: any) => fin(e?.boundary) && Number.isInteger(e?.n)) ? ex.epochs : [];
  if (ex !== undefined && !(Array.isArray(ex?.epochs) && ex.epochs.length === epochs.length)) bad = "the activation record could not be read", fx = undefined;
  const addEpoch = async (boundary: number) => {
    const next = await append<{ epochs: typeof epochs }>(copy, EPOCHS_KEY, (c) => (c?.epochs.at(-1)?.boundary === boundary ? c : { epochs: [...(c?.epochs ?? []), { n: (c?.epochs.length ?? 0) + 1, boundary }] }));
    if (next) epochs = next.epochs;
    return next ? epochs.at(-1)!.n : 0;
  };
  const epOf = (t: number) => epochs.filter((e) => e.boundary <= t).at(-1)?.n ?? 0;
  // Missing or corrupt matching state is a recovery from the first epoch, where unresolved work may start (13.1);
  // a checkpoint behind the bookmark, by time or by ids at its instant, is too (13.2).
  const saved = s.m; // as loaded, before a recovery replaces it
  const m: M = validM(s.m) ? s.m : { t: epochs[0]?.boundary ?? s.bm.t, ids: [], ep: epochs.at(-1)?.n ?? 0, from: epochs[0]?.boundary, cov: 0, pend: [], expl: [], late: [], hc: {}, done: [], rev: [], rj: [], ix: [] };
  s.m = m;
  if (recovering(m, s.bm)) m.rp = { s: m.t, from: m.t, ids: [...m.ids], to: s.bm.t, runs: 0 }, await addEpoch(s.bm.t);
  if (fx && m.since !== undefined && (fx.since !== m.since || fx.gen < m.gen!)) reset = true, add(`reset:${fx.since}`, `the front-desk tap records restarted at ${iso(fx.since)}: master writes before ${iso(fx.since + WARM_MS)} not yet matched are alerted as unmatchable`);
  if (fx && !reset && fx.covered_to < m.cov) bad = "their coverage went backwards", fx = undefined;
  // Before matching has seen effects or activated, none is the deployed starting state (4.5), not a fault.
  if (bad && (m.ep || m.since !== undefined)) add(`effects:${bad}`, `the front-desk tap records could not be used (${bad}): no master write is matched until they can`);
  if (fx?.replay_from !== undefined) add(`incomplete:records:${fx.replay_from}`, `matching incomplete: the tap records are held back from record ${fx.replay_from}`);
  const hold = !fx || fx.replay_from !== undefined;
  if (fx && !hold) (m.since = fx.since), (m.gen = fx.gen), (m.cov = fx.covered_to);
  const cand = m.from ?? (fx ? fx.since + WARM_MS : undefined);
  // The index starts complete from the first activation (13.3), so absence there is proof (Codex r2 #7) -- but only with
  // positive evidence that this is the first: no epoch, no saved matching state that ever activated, no month file from
  // the build's earliest possible month on. Otherwise it is complete only from now, and that is raised.
  const prior = epochs.length > 0 || (saved !== undefined && !(validM(saved) && !saved.ep && saved.from === undefined));
  let firstSeen: boolean | undefined; // read once a run
  const first = async () => { if (prior) return false; for (let t = T, i = 0; month(t, i) >= month(CF_FROM); i++) if ((await readJson(copy, `${INDEX_PREFIX}${month(t, i)}.json`)) !== undefined) return false; return true; };
  const firstStart = async () => (firstSeen ??= await first().catch(() => false));
  const wellFormed = (c: any) => isO(c) && isO(c.n) && fin(c.complete_from);
  if (!m.ep && cand !== undefined && T - SETTLE_MS >= cand) {
    const from = (await firstStart()) ? cand : T;
    if (from === T) add("unavailable:index", "matching incomplete: the index of matched taps could not be shown complete from the first activation");
    // An existing index keeps its own claim and the epoch it was made for: never made to look more complete (Codex r3 SR4).
    if ((await append(copy, BY_RECORD, (c: any) => (wellFormed(c) ? c : { complete_from: from, epoch_boundary: cand, n: {} }))) && (m.ep = await addEpoch(cand))) (m.from = cand), (on = true);
  }
  const known = (id: string) => [m.pend, m.expl, m.late].some((l) => l.some((x) => x.id === id));
  const counts: Record<string, number> = {};
  const bump = (k: string) => (counts[k] = (counts[k] ?? 0) + 1);

  /** A master create or delete read from the log: queued for judgment, or counted as before activation (4.5). */
  function take(e: Record<string, any>, id: string, t: number): string | undefined {
    const rs = e.resource?.response, pg: string[] | undefined = Array.isArray(rs?.policies) ? rs.policies.flatMap((p: any) => (Array.isArray(p?.permission_groups) ? p.permission_groups.map((g: any) => (str(g?.name) ? g.name : "?")) : ["?"])) : undefined;
    // R after deploy (Codex r2 #1): how many master creates carried readable permission groups. No test claims the live shape.
    if (e.action.type === "create" && cand !== undefined && !known(id)) { bump("master key creates seen"); if (pg?.length && !pg.includes("?")) bump("master key creates with readable permission groups"); else if (!m.sh) (m.sh = true), add("shape:create", "token-create shape not as expected; honest taps will alert until fixed"); }
    if (m.from === undefined || t < m.from) return cand === undefined ? MASTER_GROUP : `${MASTER_GROUP} (before ${iso(cand)})`;
    if (known(id)) return;
    const a = e.action.type, k = a === "create" ? e.resource?.response?.id : e.resource?.id;
    const ev: Ev = { id, a, k: str(k) ? k : "", t, ok: e.action.result === "success", ep: epOf(t) };
    if (a === "create") (ev.s = !str(rs?.name) ? "o" : rs.name.startsWith("front-desk probe ") ? "p" : rs.name.startsWith("front-desk headcount ") ? "h" : "o"), (ev.x = str(rs?.expires_on) ? Date.parse(rs.expires_on) : -1), (ev.pg = pg);
    m.pend.push(ev);
  }
  const isMaster = (j: Judged) => j.verdict.v === "counted" && j.verdict.group === MASTER_GROUP;
  /** A headcount key's own "List Tokens" read, by event time (12.3), kept only for keys a headcount tap made. */
  function saw(e: Record<string, any>, t: number) {
    const k = e.actor?.token?.id;
    if (e.action?.type !== "view" || e.action?.description !== "List Tokens" || !str(k)) return;
    if (fx && Object.values(fx.grants).some((g) => g.job === HC_JOB && isO(g.cf) && g.cf.made.includes(k))) m.hc[k] = Math.max(m.hc[k] ?? -Infinity, t);
  }
  const alert = (ev: Ev, why: string, g?: string) => {
    add(`change:${ev.id}`, `a key ${ev.a} by the front desk's master key that no approved tap names, at ${iso(ev.t)}, ref ${ref(ev.id)} (${why}${g ? `; tap ${g.slice(0, 8)}` : ""})`);
    bump("master writes unmatched");
  };
  const matched = (ev: Ev, g: string) => { m.expl.push({ ...ev, g, j: fx!.grants[g].job, r: fx!.grants[g].res!.at }); bump(tapLabel(g)); };
  // The weekly line stays under alert.ts's cut (12.6): five taps by name, the rest counted together.
  const tapLabel = (g: string) => { const k = `master writes matched to tap ${g.slice(0, 8)}`, named = [...new Set([...Object.keys(week0), ...Object.keys(counts)])].filter((x) => x.startsWith("master writes matched to tap ")); return named.includes(k) || named.length < 5 ? k : "master writes matched to other taps"; };
  const unexplain = (ev: Ev) => add(`unexplained-after:${ev.id}`, `a master-key ${ev.a} at ${iso(ev.t)}, ref ${ref(ev.id)}, matched to tap ${(ev.g ?? "").slice(0, 8)}, is no longer explained: that tap's records were found bad`);

  /** 13.2: re-reads the audit log from the matching checkpoint to where build a left the bookmark. A red reason, or undefined. */
  async function replay(page: Page): Promise<string | undefined> {
    const rp = m.rp;
    if (!rp) return;
    // `since` stays fixed for the cursor's whole life (this run); the position moves past every event read, master or
    // not, with the ids at its instant, like the main bookmark, so the next run starts where this one stopped.
    let cursor: string | undefined;
    const since = rp.from;
    for (let p = 0; p < 3; p++) {
      const pg = await page(`/logs/audit?since=${iso(since)}&before=${iso(rp.to + 1)}&direction=asc&limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
      // Any answer that is not a clean page keeps the range: matching stays incomplete, never "lost" by inference.
      if (pg.bad) return `replay: ${pg.bad}`;
      for (const { id, t, e } of pg.events) {
        if (t < rp.from || (t === rp.from && rp.ids.includes(id))) continue;
        if (isMaster(judge(e, who))) { if (m.pend.length >= MAX_PENDING) return `replay: ${MAX_PENDING} master writes are waiting; it holds its place`; take(e, id, t); }
        if (t > rp.from) (rp.from = t), (rp.ids = [id]);
        else rp.ids.push(id);
      }
      if (!(cursor = pg.cursor)) break;
    }
    // Contract: Cloudflare keeps audit logs 18 months, then deletes them (developers.cloudflare.com/fundamentals/account/
    // account-security/audit-logs/). Within 17 months a clean final page closes the range; a range starting earlier is
    // never treated as complete: kept, red, incomplete, one incident.
    if (!cursor && T - rp.s > RETAIN_MS) { add(`unavailable:retention:${rp.s}`, `matching incomplete: the replay from ${iso(rp.s)} reaches past Cloudflare's 18-month audit log retention; its writes cannot all be judged`); return "replay: past the audit log's retention"; }
    if (cursor) return ++rp.runs >= REPLAY_RUNS ? `the replay of what build a judged alone is unfinished after ${rp.runs} runs, at ${iso(rp.from)}` : undefined; // more next hour; incomplete meanwhile
    add(`gap:${rp.s}`, `master writes from ${iso(rp.s)} to ${iso(rp.to)} were not judged when they happened (build b was off): ${word(countIn(rp.s, rp.to), "master write")} in that range, judged now`);
    delete m.rp;
  }
  const countIn = (a: number, b: number) => [...m.pend, ...m.expl, ...m.late].filter((x) => x.t >= a && x.t <= b).length;

  /** After the read: revocation, retirement, late results, pending judgments, reverse and lifetime checks, done (4.3-4.7, 12.2-12.4, 13.3). */
  async function finish(bmThrough: number, week: Record<string, number>) {
    const through = m.rp ? Math.min(bmThrough, m.rp.from) : bmThrough; // absence is judged only where replay has read (#6)
    if (fx && !hold) {
      const out = new Set<string>();
      for (const ev of [...m.expl]) {
        const e = Object.hasOwn(fx.grants, ev.g!) ? fx.grants[ev.g!] : undefined;
        if (e?.tainted || (!e && !reset && !Object.hasOwn(fx.retired, ev.g!))) unexplain(ev), m.expl.splice(m.expl.indexOf(ev), 1);
        else if (!e && Object.hasOwn(fx.retired, ev.g!)) out.add(ev.g!);
      }
      // A retired tap's events leave working state once they are in the index (all are, unless matched after done).
      const gone = [...out].filter((g) => m.expl.some((x) => x.g === g && !x.i));
      if (!gone.length || (await index(gone))) m.expl = m.expl.filter((x) => !out.has(x.g!));
      m.ux = false;
      for (const n of Object.keys(fx.revoked)) if (!m.rj.includes(n)) {
        const hit = await lookup(n, fx.revoked[n]); // unknown: unresolved, matching incomplete, tried again next run
        if (hit === undefined) { m.ux = true; add("unavailable:index", "matching incomplete: the index of matched taps is missing, unreadable or not complete, so records found bad cannot be settled"); continue; }
        for (const ev of hit.evs) unexplain(ev); // a number the complete index never names was never a matched tap's: nothing to re-judge
        m.rj.push(n);
      }
      m.rj = m.rj.filter((n) => Object.hasOwn(fx!.revoked, n));
      for (const ev of [...m.late]) {
        const x = explain(ev, fx, m.expl);
        if (!x.why) add(`explained-after:${ev.id}`, `the master-key ${ev.a} at ${iso(ev.t)}, ref ${ref(ev.id)}, was explained after the alert by tap ${x.g!.slice(0, 8)}`), matched(ev, x.g!);
        if (!x.why || fx.covered_to > ev.t + GRANT_TTL_MS + LATE_KEEP_MS) m.late.splice(m.late.indexOf(ev), 1); // by records' progress (#11)
      }
    }
    if (fx && !hold && m.ep) for (const ev of [...m.pend]) {
      const x = ev.t < fx.since + WARM_MS ? { why: "the tap records for its time were restarted" } : explain(ev, fx, m.expl);
      if (!x.why) matched(ev, x.g!);
      else if (ev.t < fx.since + WARM_MS || fx.covered_to >= ev.t + RESULT_WAIT_MS) alert(ev, x.why, x.g), m.late.push(ev);
      else continue;
      m.pend.splice(m.pend.indexOf(ev), 1);
    }
    const old = m.pend.reduce((a, x) => Math.min(a, x.t), Infinity);
    if (T - old > STALE_MS) add(`incomplete:${old}`, `matching incomplete: ${word(m.pend.length, "master write")} waiting since ${iso(old)}`);
    if (fx && !hold && m.ep) {
      const c = checks(through), fresh = c.filter((g) => !m.ix.includes(g) || m.expl.some((x) => x.g === g && !x.i));
      m.done = (await index(fresh)) ? (m.ix.push(...fresh.filter((g) => !m.ix.includes(g))), c) : c.filter((g) => !fresh.includes(g));
      m.ix = m.ix.filter((g) => Object.hasOwn(fx!.grants, g));
    }
    for (const [k, n] of Object.entries(counts)) week[k] = (week[k] ?? 0) + n;
    if (on) add(`on:${m.ep}`, `Cloudflare matching on: master writes judged from ${iso(m.from!)}: ${Object.entries(counts).filter(([k]) => k.startsWith("master writes matched")).reduce((a, [, n]) => a + n, 0)} matched, ${counts["master writes unmatched"] ?? 0} unmatched, ${m.pend.length} pending; creates seen ${counts["master key creates seen"] ?? 0}, groups readable ${counts["master key creates with readable permission groups"] ?? 0}`);
  }
  /** Reverse check and outlived helpers; returns the taps whose matching is complete (4.7, 12.2, 12.3). */
  function checks(through: number): string[] {
    for (const [g, e] of Object.entries(fx!.grants)) {
      if (!isO(e.cf) || e.tainted || !e.appr || !e.res || e.appr.at < m.from! || m.rev.includes(g) || through <= e.res.at + SETTLE_MS) continue;
      const want = [...e.cf.made.map((k) => ["create", k]), ...e.cf.deleted.map((k) => ["delete", k])];
      const miss = want.filter(([a, k]) => !m.expl.some((x) => x.g === g && x.a === a && x.k === k)).length;
      if (miss) add(`reverse:${g}`, `tap ${g.slice(0, 8)} named ${word(miss, "key change")} that Cloudflare did not log as a successful master-key change in its time`);
      m.rev.push(g);
    }
    m.rev = m.rev.filter((g) => Object.hasOwn(fx!.grants, g));
    // 12.3: a headcount key is current only when it is the newest among keys read after their own setup result, and
    // read within 48 h; checked every run, never decided for good while the key lives. Unconfirmed stays pending.
    const read = (ev: Ev) => (m.hc[ev.k] ?? -Infinity) > ev.r!;
    const newest = m.expl.filter((x) => x.a === "create" && x.j === HC_JOB && read(x)).sort((a, b) => m.hc[b.k] - m.hc[a.k])[0]?.k;
    for (const ev of m.expl) {
      if (ev.a !== "create" || ev.o) continue;
      // Any matched delete ends a headcount key's watch; an ordinary helper must go within 24 h (Codex r2 N1).
      if (m.expl.some((x) => x.a === "delete" && x.k === ev.k && (ev.j === HC_JOB || x.t <= ev.t + HELPER_MS))) { ev.o = 1; continue; }
      if (through <= ev.t + HELPER_MS) continue;
      const hc = ev.j === HC_JOB;
      if (hc && read(ev) && ev.k === newest && through - m.hc[ev.k] < HC_IDLE_MS) continue;
      if (hc && !read(ev) && through <= ev.t + HC_IDLE_MS) continue;
      add(`outlived:${ev.id}`, `a key made by the front desk's master key at ${iso(ev.t)}, ref ${ref(ev.id)}, was not deleted within a day (tap ${(ev.g ?? "").slice(0, 8)})`);
      if (!hc) ev.o = 1; // a headcount key stays under watch until a matched delete
    }
    return Object.entries(fx!.grants).filter(([g, e]) => {
      const end = e.res?.at ?? (e.req?.at ?? 0) + GRANT_TTL_MS, start = e.appr?.at ?? end;
      return through > end + SETTLE_MS && (!isO(e.cf) || e.tainted || !e.appr || start < m.from! || m.rev.includes(g))
        && !m.expl.some((x) => x.g === g && x.a === "create" && !x.o) && !m.pend.some((x) => x.t >= start && x.t <= end);
    }).map(([g]) => g);
  }
  /** 12.2 with 13.3: indexes taps before they are acknowledged or retired: every record number records saw for the tap
   * (verdicts too) in by-record.json, and its matched events in this month's file. True once both landed. */
  async function index(gs: string[]) {
    const evs = m.expl.filter((x) => !x.i && gs.includes(x.g!)), mo = month(T), ns = Object.entries(fx!.index).filter(([, g]) => gs.includes(g)).map(([n]) => n);
    if (!gs.length) return true;
    const ok = (await append<Record<string, Ev[]>>(copy, `${INDEX_PREFIX}${mo}.json`, (c) => {
      const next = { ...c };
      for (const ev of evs) if (!(next[ev.g!] ?? []).some((x) => x.id === ev.id)) next[ev.g!] = [...(next[ev.g!] ?? []), { ...ev, i: 1 }];
      return next;
    })) && (await append<{ complete_from: number; epoch_boundary?: number; n: Record<string, { g: string; mo: string[] }> }>(copy, BY_RECORD, (c) => {
      const ok = isO(c) && isO(c.n) && fin(c.complete_from); // recreated or malformed: complete only from now
      const next = { complete_from: ok ? c!.complete_from : T, epoch_boundary: ok ? (c as any).epoch_boundary : epochs[0]?.boundary, n: ok ? { ...c!.n } : {} };
      for (const n of ns) { const g = fx!.index[n], had = next.n[n]?.mo ?? []; next.n[n] = { g, mo: had.includes(mo) ? had : [...had, mo] }; }
      return next;
    }));
    if (ok) for (const ev of evs) ev.i = 1;
    return Boolean(ok);
  }
  /** The tap a record number belongs to and its matched events, at any age. No tap only when nothing was ever matched, or the
   * index exists, is well-formed and is complete from the first epoch; anything else is unknown (undefined). */
  async function lookup(n: string, named: string): Promise<{ g?: string; evs: Ev[] } | undefined> {
    try {
      const ix = await readJson(copy, BY_RECORD);
      // "Never matched" needs positive evidence: a first start (no epochs, index, month file or activated state), or an
      // index made complete for the current first epoch (Codex r3 SR2, SR4).
      if (!epochs.length && ix === undefined && !named && (await firstStart())) return { evs: [] };
      if (!epochs.length || !isO(ix) || !fin(ix.complete_from) || ix.epoch_boundary !== epochs[0].boundary || ix.complete_from > epochs[0].boundary || !isO(ix.n)) return undefined;
      const p = ix.n[n];
      if (p === undefined) return named ? undefined : { evs: [] }; // records names a tap the complete index lacks: unknown
      if (!isO(p) || !str(p.g) || !strs(p.mo) || (named && p.g !== named)) return undefined;
      const evs: Ev[] = [];
      for (const mo of p.mo) { const f = await readJson(copy, `${INDEX_PREFIX}${mo}.json`); if (!isO(f)) return undefined; evs.push(...(Array.isArray(f[p.g]) ? f[p.g] : [])); }
      return { g: p.g, evs };
    } catch { return undefined; }
  }
  const status = () => (hold || m.rp || m.ux || T - m.pend.reduce((a, x) => Math.min(a, x.t), Infinity) > STALE_MS ? "incomplete" : m.ep ? "active" : "warming up");
  return { take, saw, replay, finish, status, isMaster, full: (t: number) => m.from !== undefined && t >= m.from && m.pend.length >= MAX_PENDING, sync: () => void ((m.t = s.bm.t), (m.ids = [...s.bm.ids])), state: (id: string) => m.expl.find((x) => x.id === id)?.g ?? (m.pend.some((x) => x.id === id) ? "" : undefined), m };
}
/** 13.1: the matching checkpoint behind the audit bookmark (build a moved it, or matching state was lost) and no replay running. */
const recovering = (m: M, bm: { t: number; ids: string[] }) => (m.t < bm.t || (m.t === bm.t && bm.ids.some((id) => !m.ids.includes(id)))) && !m.rp;
