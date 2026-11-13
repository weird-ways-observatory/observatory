// Card beec640b build b, the consumer (epic cafd3acc, D4): every create or delete made with the front desk's
// master key must be named by an eligible signed tap result (`cf`). The records check publishes those taps as
// `effects` in state/records.json (src/records.ts); this file judges the hourly audit check's master events
// against them. Design: studio-os docs/specifications/trust-but-verify/REFINE-beec640b-build-b.md v3.3, sections
// 4.4-4.7 as overridden by 12 and 13. Working state is `m` inside state/cfaudit.json, saved in cfaudit's one
// conditional save (B-D5). Two append-only objects sit beside it: state/cfepochs.json (activations, 12.5) and
// state/cfindex/<YYYY-MM>.json (retired associations, 13.3). Alert words never hold a key id or a written name.
import { GRANT_TTL_MS } from "./contract.ts";
import { judge, type Judged, type Who } from "./cfjudge.ts";
import { ref, SETTLE_MS } from "./cfaudit.ts";
import { STATE_KEY as RECORDS_KEY } from "./records.ts";

const MIN = 60_000, H = 60 * MIN;
export const RESULT_WAIT_MS = 15 * MIN, WARM_MS = GRANT_TTL_MS + H, MAX_PENDING = 500, STALE_MS = 6 * H;
export const HELPER_MS = 24 * H, HC_IDLE_MS = 48 * H, LATE_KEEP_MS = 72 * H, PROBE_MS = 6 * MIN, INDEX_MONTHS = 36;
export const EPOCHS_KEY = "state/cfepochs.json", INDEX_PREFIX = "state/cfindex/";
export const MASTER_GROUP = "master writes, not yet matched";
const HC_JOB = "cf.token.headcount.setup";
// Job table (base REFINE 5.2, vault @2f77f7e): [creates, deletes, name kind]. Deletes: own helpers, two sweeps of
// SWEEP_DELETES 1, and for the headcount setup OLD_HEADCOUNT_DELETES 8 plus a failed candidate. 12.4: one create.
const ALLOW: Record<string, [number, number, "p" | "h"]> = { "cf.audit.read": [1, 3, "p"], "cf.zone.read": [2, 4, "p"], "cf.dns.list": [2, 4, "p"], [HC_JOB]: [1, 11, "h"], "cf.token.accept": [0, 2, "p"] };

interface Stamp { n: number; at: number }
interface Grant { job: string; req?: Stamp; appr?: Stamp; res?: Stamp; cf?: { made: string[]; deleted: string[] } | "unknown" | "none"; tainted?: string }
interface Effects { gen: number; since: number; covered_to: number; grants: Record<string, Grant>; retired: Record<string, number>; revoked: Record<string, string>; replay_from?: number }
/** One master event: action, key id, time, success, epoch; `s`/`x` name kind and expiry (creates); `g`/`j`/`r` its tap once matched; `o` lifetime decided. */
export interface Ev { id: string; a: "create" | "delete"; k: string; t: number; ok: boolean; ep: number; s?: string; x?: number; g?: string; j?: string; r?: number; o?: 1 }
export interface M { t: number; ep: number; from?: number; since?: number; gen?: number; cov: number; pend: Ev[]; expl: Ev[]; late: Ev[]; hc: Record<string, number>; done: string[]; rev: string[]; rj: string[]; rp?: { s: number; from: number; to: number } }

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
    && isO(x.retired) && Object.values(x.retired).every(fin) && isO(x.revoked) && Object.values(x.revoked).every(str) && (x.replay_from === undefined || Number.isInteger(x.replay_from));
  return ok ? (x as Effects) : "malformed";
}
const evOk = (e: unknown) => isO(e) && str(e.id) && (e.a === "create" || e.a === "delete") && str(e.k) && fin(e.t) && typeof e.ok === "boolean" && Number.isInteger(e.ep);
const validM = (m: unknown): m is M => isO(m) && fin(m.t) && Number.isInteger(m.ep) && fin(m.cov) && [m.pend, m.expl, m.late].every((l) => Array.isArray(l) && l.every(evOk))
  && isO(m.hc) && [m.done, m.rev, m.rj].every(strs) && (m.rp === undefined || (isO(m.rp) && [m.rp.s, m.rp.from, m.rp.to].every(fin)));
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
  return { g };
}

type Add = (id: string, text: string) => void;
type Page = (q: string) => Promise<{ events: { id: string; t: number; e: Record<string, unknown> }[]; cursor?: string; bad?: string }>;
const word = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

/** The matcher for one cfaudit run. `s`: cfaudit's loaded state (m lives in it). */
export async function matcher(copy: Copy, who: Who, s: { bm: { t: number }; m?: unknown }, T: number, add: Add, open: (re: RegExp) => boolean) {
  const raw = await readJson(copy, RECORDS_KEY).catch(() => null);
  const r = raw === null ? "unreadable" : readEffects(isO(raw) ? raw.effects : undefined);
  let fx = typeof r === "string" ? undefined : r, bad = typeof r === "string" ? r : undefined, on = false, reset = false;
  let epochs: { n: number; boundary: number }[] = await readJson(copy, EPOCHS_KEY).then((x) => (Array.isArray(x?.epochs) ? x.epochs : []), () => []);
  const addEpoch = async (boundary: number) => {
    const next = await append<{ epochs: typeof epochs }>(copy, EPOCHS_KEY, (c) => (c?.epochs.at(-1)?.boundary === boundary ? c : { epochs: [...(c?.epochs ?? []), { n: (c?.epochs.length ?? 0) + 1, boundary }] }));
    if (next) epochs = next.epochs;
    return next ? epochs.at(-1)!.n : 0;
  };
  const epOf = (t: number) => epochs.filter((e) => e.boundary <= t).at(-1)?.n ?? 0;
  // Missing or corrupt matching state is a recovery from the last epoch (13.1); `m.t` behind the bookmark is too.
  const m: M = validM(s.m) ? s.m : { t: epochs.at(-1)?.boundary ?? s.bm.t, ep: epochs.at(-1)?.n ?? 0, from: epochs[0]?.boundary, cov: 0, pend: [], expl: [], late: [], hc: {}, done: [], rev: [], rj: [] };
  s.m = m;
  if (recovering(m, s.bm.t)) m.rp = { s: m.t, from: m.t, to: s.bm.t }, await addEpoch(s.bm.t);
  if (fx && m.since !== undefined && (fx.since !== m.since || fx.gen < m.gen!)) reset = true, add(`reset:${fx.since}`, `the front-desk tap records restarted at ${iso(fx.since)}: master writes before ${iso(fx.since + WARM_MS)} not yet matched are alerted as unmatchable`);
  if (fx && !reset && fx.covered_to < m.cov) bad = "their coverage went backwards", fx = undefined;
  // Before matching has seen effects or activated, none is the deployed starting state (4.5), not a fault.
  if (bad && (m.ep || m.since !== undefined)) add(`effects:${bad}`, `the front-desk tap records could not be used (${bad}): no master write is matched until they can`);
  if (fx?.replay_from !== undefined) add(`incomplete:records:${fx.replay_from}`, `matching incomplete: the tap records are held back from record ${fx.replay_from}`);
  const hold = !fx || fx.replay_from !== undefined;
  if (fx && !hold) (m.since = fx.since), (m.gen = fx.gen), (m.cov = fx.covered_to);
  const cand = m.from ?? (fx ? fx.since + WARM_MS : undefined);
  if (!m.ep && cand !== undefined && T - SETTLE_MS >= cand && (m.ep = await addEpoch(cand))) (m.from = cand), (on = true);
  const known = (id: string) => [m.pend, m.expl, m.late].some((l) => l.some((x) => x.id === id));
  const counts: Record<string, number> = {};
  const bump = (k: string) => (counts[k] = (counts[k] ?? 0) + 1);

  /** A master create or delete read from the log: queued for judgment, or counted as before activation (4.5). */
  function take(e: Record<string, any>, id: string, t: number): string | undefined {
    if (m.from === undefined || t < m.from) return cand === undefined ? MASTER_GROUP : `${MASTER_GROUP} (before ${iso(cand)})`;
    if (known(id)) return;
    const a = e.action.type, k = a === "create" ? e.resource?.response?.id : e.resource?.id, rs = e.resource?.response;
    const ev: Ev = { id, a, k: str(k) ? k : "", t, ok: e.action.result === "success", ep: epOf(t) };
    if (a === "create") (ev.s = !str(rs?.name) ? "o" : rs.name.startsWith("front-desk probe ") ? "p" : rs.name.startsWith("front-desk headcount ") ? "h" : "o"), (ev.x = str(rs?.expires_on) ? Date.parse(rs.expires_on) : -1);
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
  const matched = (ev: Ev, g: string) => { m.expl.push({ ...ev, g, j: fx!.grants[g].job, r: fx!.grants[g].res!.at }); bump(`master writes matched to tap ${g.slice(0, 8)}`); };
  const unexplain = (ev: Ev) => add(`unexplained-after:${ev.id}`, `a master-key ${ev.a} at ${iso(ev.t)}, ref ${ref(ev.id)}, matched to tap ${(ev.g ?? "").slice(0, 8)}, is no longer explained: that tap's records were found bad`);

  /** 13.2: re-reads the audit log from the matching checkpoint to where build a left the bookmark. A red reason, or undefined. */
  async function replay(page: Page): Promise<string | undefined> {
    const rp = m.rp;
    if (!rp) return;
    let cursor: string | undefined, lost = false;
    for (let p = 0; p < 3; p++) {
      const pg = await page(`/logs/audit?since=${iso(rp.from)}&before=${iso(rp.to + 1)}&direction=asc&limit=200${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
      if (pg.bad && /answered 4(?!01|03|29)\d\d/.test(pg.bad)) { lost = true; break; }
      if (pg.bad) return `replay: ${pg.bad}`;
      for (const { id, t, e } of pg.events) if (isMaster(judge(e, who))) take(e, id, t), (rp.from = t);
      if (!(cursor = pg.cursor)) break;
    }
    if (cursor) return; // more next hour; matching stays incomplete meanwhile
    if (lost) add(`unavailable:${rp.from}`, `matching incomplete: Cloudflare no longer returns the log from ${iso(rp.from)} to ${iso(rp.to)}; master writes in it cannot be judged`);
    add(`gap:${rp.s}`, `master writes from ${iso(rp.s)} to ${iso(rp.to)} were not judged when they happened (build b was off): ${word(countIn(rp.s, rp.to), "master write")} in that range, judged now${lost ? ", except what Cloudflare no longer returns" : ""}`);
    delete m.rp;
  }
  const countIn = (a: number, b: number) => [...m.pend, ...m.expl, ...m.late].filter((x) => x.t >= a && x.t <= b).length;

  /** After the read: revocation, retirement, late results, pending judgments, reverse and lifetime checks, done (4.3-4.7, 12.2-12.4, 13.3). */
  async function finish(through: number, week: Record<string, number>) {
    if (fx && !hold) {
      const out: Record<string, Record<string, Ev[]>> = {};
      for (const ev of [...m.expl]) {
        const e = Object.hasOwn(fx.grants, ev.g!) ? fx.grants[ev.g!] : undefined;
        if (e?.tainted || (!e && !reset && !Object.hasOwn(fx.retired, ev.g!))) unexplain(ev), m.expl.splice(m.expl.indexOf(ev), 1);
        else if (!e && Object.hasOwn(fx.retired, ev.g!)) ((out[month(fx.retired[ev.g!])] ??= {})[ev.g!] ??= []).push(ev);
      }
      for (const [mo, gs] of Object.entries(out)) if (await retire(mo, gs)) m.expl = m.expl.filter((x) => !Object.hasOwn(gs, x.g!));
      for (const [n, g] of Object.entries(fx.revoked)) if (!m.rj.includes(n)) {
        const evs = await lookup(g);
        if (evs === undefined) continue;
        if (!evs.length) add(`unavailable:record:${n}`, `matching incomplete: record ${n} was found bad after its tap retired, and no matched events are on file for it`);
        for (const ev of evs) unexplain(ev);
        m.rj.push(n);
      }
      m.rj = m.rj.filter((n) => Object.hasOwn(fx!.revoked, n));
      for (const ev of [...m.late]) {
        const x = explain(ev, fx, m.expl);
        if (!x.why) add(`explained-after:${ev.id}`, `the master-key ${ev.a} at ${iso(ev.t)}, ref ${ref(ev.id)}, was explained after the alert by tap ${x.g!.slice(0, 8)}`), matched(ev, x.g!);
        if (!x.why || T - ev.t > LATE_KEEP_MS) m.late.splice(m.late.indexOf(ev), 1);
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
    if (fx && !hold && m.ep) checks(through);
    for (const [k, n] of Object.entries(counts)) week[k] = (week[k] ?? 0) + n;
    if (on) add(`on:${m.ep}`, `Cloudflare matching on: master writes judged from ${iso(m.from!)}: ${Object.entries(counts).filter(([k]) => k.startsWith("master writes matched")).reduce((a, [, n]) => a + n, 0)} matched, ${counts["master writes unmatched"] ?? 0} unmatched, ${m.pend.length} pending`);
  }
  /** Reverse check, outlived helpers, and the done acknowledgement records retires by (4.7, 12.2, 12.3). */
  function checks(through: number) {
    for (const [g, e] of Object.entries(fx!.grants)) {
      if (!isO(e.cf) || e.tainted || !e.appr || !e.res || e.appr.at < m.from! || m.rev.includes(g) || through <= e.res.at + SETTLE_MS) continue;
      const want = [...e.cf.made.map((k) => ["create", k]), ...e.cf.deleted.map((k) => ["delete", k])];
      const miss = want.filter(([a, k]) => !m.expl.some((x) => x.g === g && x.a === a && x.k === k)).length;
      if (miss) add(`reverse:${g}`, `tap ${g.slice(0, 8)} named ${word(miss, "key change")} that Cloudflare did not log as a successful master-key change in its time`);
      m.rev.push(g);
    }
    m.rev = m.rev.filter((g) => Object.hasOwn(fx!.grants, g));
    const newest = Object.entries(m.hc).sort((a, b) => b[1] - a[1])[0]?.[0];
    for (const ev of m.expl) {
      if (ev.a !== "create" || ev.o) continue;
      if (m.expl.some((x) => x.a === "delete" && x.k === ev.k && x.t <= ev.t + HELPER_MS)) { ev.o = 1; continue; }
      if (through <= ev.t + HELPER_MS) continue;
      const seen = m.hc[ev.k], read = seen !== undefined && seen > ev.r!;
      if (ev.j === HC_JOB && read && ev.k === newest) { ev.o = 1; continue; }
      if (ev.j === HC_JOB && !read && through <= ev.t + HC_IDLE_MS) continue; // identity unconfirmed: still pending
      add(`outlived:${ev.id}`, `a key made by the front desk's master key at ${iso(ev.t)}, ref ${ref(ev.id)}, was not deleted within a day (tap ${(ev.g ?? "").slice(0, 8)})`);
      ev.o = 1;
    }
    m.done = Object.entries(fx!.grants).filter(([g, e]) => {
      const end = e.res?.at ?? (e.req?.at ?? 0) + GRANT_TTL_MS, start = e.appr?.at ?? end;
      return through > end + SETTLE_MS && (!isO(e.cf) || e.tainted || !e.appr || start < m.from! || m.rev.includes(g))
        && !m.expl.some((x) => x.g === g && x.a === "create" && !x.o) && !m.pend.some((x) => x.t >= start && x.t <= end);
    }).map(([g]) => g);
  }
  /** 13.3: appends retired taps' matched events to the month's append-only index; true once it landed. */
  const retire = (mo: string, gs: Record<string, Ev[]>) => append<Record<string, Ev[]>>(copy, `${INDEX_PREFIX}${mo}.json`, (c) => {
    const next = { ...c };
    for (const [g, evs] of Object.entries(gs)) next[g] = [...(next[g] ?? []), ...evs.filter((e) => !(next[g] ?? []).some((x) => x.id === e.id))];
    return next;
  }).then(Boolean);
  /** A retired tap's events from the monthly index, newest month first; undefined when a month could not be read. */
  async function lookup(g: string): Promise<Ev[] | undefined> {
    try {
      for (let i = 0; i < INDEX_MONTHS; i++) { const ix = await readJson(copy, `${INDEX_PREFIX}${month(T, i)}.json`); if (isO(ix) && Array.isArray(ix[g])) return ix[g]; }
      return [];
    } catch { return undefined; }
  }
  const status = () => (hold || m.rp || open(/^(unavailable|incomplete):/) ? "incomplete" : m.ep ? "active" : "warming up");
  return { take, saw, replay, finish, status, isMaster, full: (t: number) => m.from !== undefined && t >= m.from && m.pend.length >= MAX_PENDING, sync: () => void (m.t = s.bm.t), m };
}
/** 13.1: the matching checkpoint behind the audit bookmark (build a moved it, or matching state was lost) and no replay running. */
const recovering = (m: M, bm: number) => m.t < bm && !m.rp;
