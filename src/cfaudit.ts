// Card beec640b build a (epic cafd3acc, D4): the hourly outside-record check. Cloudflare logs every
// change to the studio's main account; this job reads that log (read-only key, Ben-made) and judges
// each write on its own fields (src/cfjudge.ts). A write the table does not count -- a leftover or
// stolen key, a Global API Key, a dashboard key or member change (even Ben's), any kind never seen,
// any `api` key echo -- becomes an incident, and Ben's phone gets one alert per run.
// Design: studio-os docs/specifications/trust-but-verify/REFINE-beec640b-outside-record.md v2.6;
// threats: THREATS-beec640b.md. Build b (matching master-key writes to signed results) is not here:
// master-key key writes are counted "not yet matched" until then.
// The light means "the checker ran and read everything it should", never "Cloudflare is fine".
// It only reads Cloudflare and writes only state/cfaudit.json (COPY bucket, unlocked state/).
import { alert, redact, type AlertEnv } from "./alert.ts";
import { judge, type Action, type Judged } from "./cfjudge.ts";

export const CFAUDIT_CRON = "45 * * * *";
export const STATE_KEY = "state/cfaudit.json";
export const VERSION = 1;
// Where a first run (or a rebuild) starts reading: set to the day this check was proposed. Reviewed constant.
export const START = Date.parse("2026-11-13T00:00:00.000Z");
const API = "https://api.cloudflare.com/client/v4";
export const SETTLE_MS = 20 * 60_000; // Cloudflare posts an event within this (one sample: 182 s); a starting setting
export const PAGE = 200; // events judged per run: the accepted capacity, 200 an hour (busiest real hour: 93)
export const SKIP_PAGES = 3; // extra pages that hold only events already judged at the bookmark's millisecond
export const WITNESS_PAGES = 3; // pages read looking for the check's own earlier read
export const WITNESS_GRACE_MS = 40 * 60_000; // own read not in the log after this long: an incident
export const PAIR_MS = 5_000; // an echo and its key event: same action, same address, within 5 s (seen: 3 s)
export const LAG_MS = 3 * 3_600_000; // behind by more than this: one incident
export const KEEP_MS = 30 * 86_400_000; // an incident leaves the list after 30 days; nobody marks one seen
export const MAX_INCIDENTS = 200; // the list, including one overflow line
export const MAX_RECENT = 500; // events waiting 5 s for a possible pair
export const REMIND_DAY = 1, REMIND_HOUR = 14; // Monday 14:00 UTC: the weekly line
const HEX32 = /^[0-9a-f]{32}$/;
const https = (x: string | undefined) => { try { return new URL(x ?? "").protocol === "https:"; } catch { return false; } };
export const BUDGET = 1024; // alert.ts cuts a message here: every line is budgeted against the whole message

export interface CfAuditEnv extends AlertEnv {
  COPY: Pick<R2Bucket, "get" | "put">;
  PING_URL_CFAUDIT?: string; // this job's own light
  CF_AUDIT_TOKEN?: string; // Audit Logs Read on the main account only; Ben makes it
  CF_MAIN_ACCOUNT_ID?: string;
  CF_MASTER_KEY_ID?: string; // the front-desk vault's master key: its key writes are counted, not alerted (build a)
  CF_BEN_USER_ID?: string; // Ben's Cloudflare user id: his dashboard writes of known kinds are counted weekly
}

export interface Incident { id: string; text: string; at: number; told: boolean }
interface Recent { id: string; k: "key" | "echo"; a: Action; ip: string; t: number; p?: string; pt?: number }
interface State {
  v: number;
  bm: { t: number; ids: string[] }; // the last judged event's time and every id judged at that exact millisecond
  witness?: { key: string; t: number }; // an earlier read of ours that Cloudflare answered
  recent: Recent[];
  incidents: Incident[];
  dropped: number; // incidents that found no room, ever
  week: { counts: Record<string, number>; lag: number };
  remindedOn?: string;
  redTold?: boolean;
  rebuiltAt?: number; // events before this were read while rebuilding lost state: listed, told as one summary
}

const iso = (t: number) => new Date(t).toISOString();
const ref = (id: string) => id.replace(/[^A-Za-z0-9]/g, "").slice(0, 8) || "none";
/** An echo with no key event to explain it: the riskier kind, so it gets its own line before paired ones (provisional, Ben to confirm). */
const lonely = (i: Incident) => i.id.startsWith("echo:") && i.text.includes("logged only as an echo");
const KIND: Record<string, [string, string]> = {
  echo: ["paired key echo", "paired key echoes"], lonely: ["unpaired key echo", "unpaired key echoes"], noecho: ["key event without an echo", "key events without an echo"],
  fresh: ["freshness line", "freshness lines"], rebuilt: ["rebuild line", "rebuild lines"], first: ["start line", "start lines"],
};
/** One line counting the incidents that did not fit in a push, by kind: they are on the list, told by this line. */
export function closing(xs: Incident[]) {
  const by = new Map<string, number>();
  for (const x of xs) { const k = lonely(x) ? "lonely" : x.id.split(":")[0]; by.set(k, (by.get(k) ?? 0) + 1); }
  const kinds = [...by].map(([k, n]) => { const [one, many] = KIND[k] ?? ["other line", "other lines"]; return `${n} ${n === 1 ? one : many}`; });
  return `and ${xs.length} more: ${kinds.join(", ")}; ask an agent to read the list`;
}
const hours = (ms: number) => Math.round(ms / 360_000) / 10;
/** The weekly line's week: the latest Monday 14:00 UTC at or before `t` (its date is the key). */
export function weekStart(t: number) {
  const d = new Date(t), m = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - ((d.getUTCDay() + 7 - REMIND_DAY) % 7), REMIND_HOUR);
  return m > t ? m - 7 * 86_400_000 : m;
}
// New state counts its own week as told: the first weekly line comes at the next Monday 14:00 UTC.
const fresh = (start: number, now: number): State => ({ v: VERSION, bm: { t: start, ids: [] }, recent: [], incidents: [], dropped: 0, week: { counts: {}, lag: 0 }, remindedOn: iso(weekStart(now)).slice(0, 10) });
async function hashIp(ip: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`cfaudit-ip:${ip}`));
  return [...new Uint8Array(d)].slice(0, 6).map((b) => b.toString(16).padStart(2, "0")).join("");
}

const isObj = (x: unknown): x is Record<string, any> => typeof x === "object" && x !== null && !Array.isArray(x);
const isStr = (x: unknown): x is string => typeof x === "string";
const ACTIONS = new Set(["create", "delete", "update"]);
/** Every field the reader uses, checked to its leaves: valid JSON with a wrong shape is corrupt (Codex r1 #4). */
export function validState(s: unknown): s is State {
  if (!isObj(s) || s.v !== VERSION) return false;
  const { bm, witness, recent, incidents, week } = s;
  return isObj(bm) && Number.isFinite(bm.t) && Array.isArray(bm.ids) && bm.ids.every(isStr)
    && (witness === undefined || (isObj(witness) && isStr(witness.key) && Number.isFinite(witness.t)))
    && Array.isArray(recent) && recent.every((r) => isObj(r) && isStr(r.id) && (r.k === "key" || r.k === "echo") && ACTIONS.has(r.a) && isStr(r.ip) && Number.isFinite(r.t) && ((r.p === undefined && r.pt === undefined) || (isStr(r.p) && Number.isFinite(r.pt))))
    && Array.isArray(incidents) && incidents.every((i) => isObj(i) && isStr(i.id) && isStr(i.text) && Number.isFinite(i.at) && typeof i.told === "boolean")
    && Number.isInteger(s.dropped) && s.dropped >= 0
    && isObj(week) && isObj(week.counts) && Object.values(week.counts).every((n) => Number.isInteger(n) && (n as number) >= 0) && Number.isFinite(week.lag)
    && (s.remindedOn === undefined || isStr(s.remindedOn)) && (s.redTold === undefined || typeof s.redTold === "boolean")
    && (s.rebuiltAt === undefined || Number.isFinite(s.rebuiltAt));
}

/** Loads state. `newer`: written by a later version of this code -- never read, never overwritten. `first`: none yet. */
export function parseState(text: string | undefined, start: number, now: number): { state: State; rebuilt: boolean; newer?: boolean; first?: boolean } {
  if (text === undefined) return { state: fresh(start, now), rebuilt: false, first: true };
  try {
    const s: unknown = JSON.parse(text);
    if (isObj(s) && typeof s.v === "number" && s.v > VERSION) return { state: fresh(start, now), rebuilt: false, newer: true };
    if (validState(s)) return { state: s, rebuilt: false };
  } catch { /* unreadable: rebuilt below */ }
  return { state: { ...fresh(start, now), rebuiltAt: now }, rebuilt: true };
}

/**
 * Every save is conditional on the etag the previous one returned (the first: the etag read, or absent).
 * This guards against conflicting state updates, not "one run at a time" (Codex targeted r3): a staggered
 * second run may also send, and delivery is at least once. R2's etag is the content's MD5, so a rival
 * write of byte-identical state passes the condition; it holds the same state, so nothing is lost.
 */
export class Saver {
  private bucket: Pick<R2Bucket, "put">;
  private etag: string | null;
  constructor(bucket: Pick<R2Bucket, "put">, etag: string | null) { this.bucket = bucket; this.etag = etag; }
  async save(s: State): Promise<boolean> {
    const onlyIf = this.etag ? { etagMatches: this.etag } : new Headers({ "If-None-Match": "*" });
    const r = await this.bucket.put(STATE_KEY, JSON.stringify(s), { onlyIf }).catch(() => null);
    if (!r) return false; // R2 answers null when the condition fails: another run holds the state
    this.etag = r.etag;
    return true;
  }
}

type Get = (path: string) => Promise<{ status: number; body?: any }>;
/** One page of the log. `bad` names why it cannot be read; then nothing on it is used. */
async function page(get: Get, q: string): Promise<{ events: { id: string; t: number; e: Record<string, unknown> }[]; cursor?: string; bad?: string }> {
  const r = await get(q);
  if (r.status !== 200) return { events: [], bad: r.status ? `the log answered ${r.status}` : "the log could not be reached" };
  const b = r.body;
  if (!b || b.success !== true || !Array.isArray(b.result)) return { events: [], bad: "the log answered something that is not a page" };
  const events = [];
  let last = -Infinity;
  for (const e of b.result) {
    const t = typeof e?.action?.time === "string" ? Date.parse(e.action.time) : NaN;
    if (typeof e?.id !== "string" || !e.id || !Number.isFinite(t)) return { events: [], bad: "an event on the page has no id or time" };
    if (t < last) return { events: [], bad: "the page is not in time order" };
    last = t;
    events.push({ id: e.id, t, e });
  }
  const cursor = typeof b.result_info?.cursor === "string" && b.result_info.cursor ? b.result_info.cursor : undefined;
  return { events, cursor };
}

const RANK = ["change", "echo", "rebuilt", "first", "fresh", "tie", "lag", "noecho", "more"];
const rank = (i: Incident) => { const r = RANK.indexOf(i.id.split(":")[0]); return r < 0 ? RANK.length : r; };

export async function runCfAudit(env: CfAuditEnv, fetchFn: (req: Request) => Promise<Response>, now: Date, start = START) {
  const T = now.getTime(), ping = https(env.PING_URL_CFAUDIT) ? env.PING_URL_CFAUDIT! : undefined;
  const report: Record<string, unknown> = { cfaudit: "did not finish", capacity: `${PAGE} an hour (provisional until the CPU check card passes)` };
  const finish = async (ok: boolean, reason: string) => {
    report.cfaudit = ok ? "ran" : "did not finish";
    report.reason = redact(reason, env).slice(0, 1500);
    console.log(JSON.stringify(report));
    if (ping) await fetchFn(new Request(ok ? ping : `${ping}/fail`, { method: "POST", body: JSON.stringify(report) })).catch(() => undefined);
    return report;
  };
  // Settings: missing or malformed means red, before anything is read or saved (no alert storm).
  const missing = [
    !env.CF_AUDIT_TOKEN?.trim() && "audit key not set",
    !HEX32.test(env.CF_MAIN_ACCOUNT_ID ?? "") && "account id not set or malformed",
    !HEX32.test(env.CF_MASTER_KEY_ID ?? "") && "master key id not set or malformed",
    !HEX32.test(env.CF_BEN_USER_ID ?? "") && "Ben's user id not set or malformed",
    !ping && "the light (PING_URL_CFAUDIT) not set or not an https address", // Codex r1 #6: with no light, nothing reaches Ben
  ].filter(Boolean);
  if (missing.length) return finish(false, missing.join("; "));
  const who = { master: env.CF_MASTER_KEY_ID!, ben: env.CF_BEN_USER_ID! };
  const base = `${API}/accounts/${env.CF_MAIN_ACCOUNT_ID}`;
  const get: Get = async (path) => {
    const r = await fetchFn(new Request(`${base}${path}`, { headers: { Authorization: `Bearer ${env.CF_AUDIT_TOKEN!.trim()}` } })).catch(() => undefined);
    if (!r) return { status: 0 };
    return { status: r.status, body: await r.json().catch(() => undefined) };
  };

  const saved = await env.COPY.get(STATE_KEY).catch(() => undefined);
  if (saved === undefined) return finish(false, "state could not be read");
  const loaded = parseState(saved ? await saved.text() : undefined, start, T);
  if (loaded.newer) return finish(false, "state was written by a newer version of this check: not read, not overwritten");
  const s = loaded.state, saver = new Saver(env.COPY, saved ? saved.etag : null);
  const stop = () => finish(false, "another run holds the state: stopped, nothing sent");
  const incidents = new Map(s.incidents.filter((i) => T - i.at < KEEP_MS).map((i) => [i.id, i]));
  const add = (id: string, text: string, told = false) => { if (!incidents.has(id)) incidents.set(id, { id, text, at: T, told }); };
  if (loaded.rebuilt) add(`rebuilt:${T}`, `the Cloudflare check's saved state was unreadable and was rebuilt from ${iso(start).slice(0, 10)}: changes found while it catches up are on the list, sent only as this line`);
  const reds: string[] = [];
  /**
   * Writes the incident map into the state, worst first, at most MAX_INCIDENTS with one counted overflow line.
   * Run before every save, so a save never holds a bookmark without the incidents read up to it. Idempotent:
   * what it cuts leaves the map and is counted once. Only lag and tie lines never leave early: they are
   * recomputed each run, so one would come back as new and be told again; they are at most two. Every other
   * line (an event's, freshness, rebuilt, first) can leave (Codex r1 #5). Told ones leave first, oldest first;
   * an untold one is never pushed out by a told one; still over, the newest untold ones are counted, not kept.
   */
  const settle = () => {
    const prevMore = incidents.get("more");
    incidents.delete("more");
    let list = [...incidents.values()].sort((a, b) => rank(a) - rank(b) || a.at - b.at);
    if (list.length > MAX_INCIDENTS - 1) {
      const removable = (i: Incident) => !/^(lag$|tie:)/.test(i.id);
      const told = list.filter((i) => i.told && removable(i)).sort((a, b) => a.at - b.at), untold = list.filter((i) => !i.told && removable(i));
      const excess = list.length - (MAX_INCIDENTS - 1), gone = new Set(told.slice(0, excess).map((i) => i.id));
      const cut = Math.max(0, excess - gone.size);
      for (const i of untold.sort((a, b) => b.at - a.at).slice(0, cut)) gone.add(i.id);
      for (const id of gone) incidents.delete(id);
      list = list.filter((i) => !gone.has(i.id));
      s.dropped += gone.size;
    }
    if (s.dropped) {
      const text = `${s.dropped} more Cloudflare incidents could not be kept: ask an agent to read the log`;
      const more = { id: "more", text, at: prevMore?.at ?? T, told: prevMore?.told === true && prevMore.text === text };
      incidents.set("more", more);
      list.push(more);
    }
    s.incidents = list;
  };

  // 1. This run's own read: tokens/verify, answered by Cloudflare and so logged as a view by our key.
  const v = await get("/tokens/verify");
  const keyId = v.status === 200 && v.body?.success === true && typeof v.body.result?.id === "string" ? (v.body.result.id as string) : undefined;
  if (!keyId) reds.push(v.status ? `the audit key was refused (${v.status})` : "Cloudflare could not be reached");

  // 2. Freshness: does the log show our earlier read? Not found after 40 minutes: an incident, and the
  //    witness moves on, so nothing waits forever on one read nor forgets one silently.
  let freshness = "starting", replace = true;
  if (keyId && s.witness) {
    const w = s.witness, q = `/logs/audit?since=${iso(w.t - 5_000)}&before=${iso(Math.min(w.t + 30 * 60_000, T))}&direction=asc&limit=${PAGE}`;
    let cursor: string | undefined, found = false, done = false, bad: string | undefined;
    for (let n = 0; n < WITNESS_PAGES && !found; n++) {
      const p = await page(get, q + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""));
      if (p.bad) { bad = p.bad; break; }
      found = p.events.some((x) => (x.e.actor as any)?.token?.id === w.key);
      cursor = p.cursor;
      if (!cursor) { done = true; break; }
    }
    if (bad) (freshness = "unknown"), (replace = false), reds.push(`own-read lookup: ${bad}`);
    else if (found) freshness = "ok";
    else if (!done) {
      freshness = "incomplete", replace = false;
      add(`fresh:incomplete:${w.t}`, `the check's own read at ${iso(w.t)} could not be looked for in full: over ${WITNESS_PAGES * PAGE} events in that half hour`);
      reds.push("own-read lookup incomplete");
    } else if (T - w.t > WITNESS_GRACE_MS) {
      freshness = "missing";
      add(`fresh:missing:${w.t}`, `the Cloudflare log did not show the check's own read at ${iso(w.t)}: the log may not be recording`);
      reds.push("own read missing from the log");
    } else (freshness = "waiting"), (replace = false);
  }
  if (keyId && replace) s.witness = { key: keyId, t: T };
  report.freshness = freshness;

  // 3. The backlog, oldest first, from the bookmark (inclusive) to now minus the settle time.
  const before = T - SETTLE_MS;
  let judged = 0, skipped = 0, skipPages = 0, ended = false, readOk = Boolean(keyId);
  const counts = s.week.counts;
  const hashed = new Map<string, string>(); // one digest per address per run (CPU: REFINE 5.6)
  const recent = s.recent;
  const q0 = `/logs/audit?since=${iso(s.bm.t)}&before=${iso(before)}&direction=asc&limit=${PAGE}`;
  let cursor: string | undefined;
  while (readOk) {
    if (before <= s.bm.t) { ended = true; break; }
    const p = await page(get, q0 + (cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""));
    if (p.bad) { reds.push(p.bad); readOk = false; break; }
    let judgedHere = 0;
    for (const { id, t, e } of p.events) {
      if (t < s.bm.t || (t === s.bm.t && s.bm.ids.includes(id))) { skipped++; continue; }
      judgedHere++;
      const j = judge(e, who);
      await record(j, id, t);
      if (t > s.bm.t) s.bm = { t, ids: [id] };
      else s.bm.ids.push(id);
    }
    judged += judgedHere;
    cursor = p.cursor;
    if (loaded.first && cursor && s.rebuiltAt === undefined) {
      // D1: a first backlog that will not fit in this run is listed, not replayed: one summary line now, and every
      // change read until the check catches up is on the list, told as that line (as a rebuild is, D2).
      for (const i of incidents.values()) i.told = true;
      s.rebuiltAt = T;
      add(`first:${T}`, `the Cloudflare check started: changes since ${iso(start).slice(0, 10)} found while it catches up are on the list, sent only as this line`);
    }
    settle(); // Codex r1 #1: the page's incidents are saved with its bookmark, never after it
    if (!(await saver.save(s))) return stop(); // per page: a run cut short loses at most this page
    if (!cursor) { ended = true; break; }
    if (judgedHere) break; // one judging page a run
    if (++skipPages > SKIP_PAGES) {
      add(`tie:${s.bm.t}`, `more events at one instant (${iso(s.bm.t)}) than the check can step through: it has stopped there`);
      reds.push("too many events at one instant");
      break;
    }
  }

  async function record(j: Judged, id: string, t: number) {
    const v = j.verdict;
    if (v.v === "read") return;
    const at = v.v === "counted" ? "" : iso(t); // built only for incident text
    if (v.v === "counted") counts[v.group] = (counts[v.group] ?? 0) + 1;
    else if (v.v === "unreadable") add(`change:${id}`, `Cloudflare logged an unreadable change at ${at}, ref ${ref(id)}`, s.rebuiltAt !== undefined && t < s.rebuiltAt);
    else if (v.v === "alert") add(`change:${id}`, `Cloudflare ${j.attempted ? "change attempted (it failed)" : "changed"} with no approved request on record: ${j.label} by ${j.how} at ${at}, ref ${ref(id)} (${v.why})`, s.rebuiltAt !== undefined && t < s.rebuiltAt);
    if (j.pair && j.pair.ip !== undefined) {
      const ip = hashed.get(j.pair.ip) ?? hashed.set(j.pair.ip, await hashIp(j.pair.ip)).get(j.pair.ip)!, want = j.pair.k === "key" ? "echo" : "key";
      const r: Recent = { id, k: j.pair.k, a: j.pair.a, ip, t };
      const mate = recent.filter((x) => x.k === want && !x.p && x.a === r.a && x.ip === ip && Math.abs(x.t - t) <= PAIR_MS).sort((x, y) => Math.abs(x.t - t) - Math.abs(y.t - t))[0];
      if (mate) (mate.p = id), (mate.pt = t), (r.p = mate.id), (r.pt = mate.t);
      recent.push(r);
    } else if (v.v === "echo") add(`echo:${id}`, `a key ${v.action} logged only as an echo at ${at}, ref ${ref(id)}: no matching key event`, s.rebuiltAt !== undefined && t < s.rebuiltAt);
  }

  // 4. Echo pairing settles once everything within 5 s of an event has been read. Every echo pushes
  //    (Ben, c79e2293 A); the pair only labels it. A key event with no echo is a diagnostic line.
  const through = ended ? before : s.bm.t;
  const keep: Recent[] = [];
  recent.sort((a, b) => a.t - b.t);
  const over = Math.max(0, recent.length - MAX_RECENT);
  recent.forEach((r, n) => {
    if (r.t + PAIR_MS >= through && n >= over) return void keep.push(r);
    const told = s.rebuiltAt !== undefined && r.t < s.rebuiltAt;
    if (r.k === "echo") add(`echo:${r.id}`, r.p ? `a key ${r.a} echo at ${iso(r.t)}, ref ${ref(r.id)}: probably the log's duplicate entry of the key ${r.a} at ${iso(r.pt!)} (ref ${ref(r.p)})` : `a key ${r.a} logged only as an echo at ${iso(r.t)}, ref ${ref(r.id)}: no matching key event`, told);
    else if (!r.p) add(`noecho:${r.id}`, `a key ${r.a} at ${iso(r.t)}, ref ${ref(r.id)}, has no echo in the log (diagnostic)`, told);
  });
  s.recent = keep;
  if (ended && s.rebuiltAt !== undefined) delete s.rebuiltAt;

  // 5. Lag against the accepted capacity; ties cleared once the bookmark moves past them.
  // A failed read says nothing about lag: no lag incident is made or cleared from it.
  const behind = !readOk ? -1 : ended ? 0 : Math.max(0, before - s.bm.t);
  report.behind_by_h = behind < 0 ? "unknown" : hours(behind);
  s.week.lag = Math.max(s.week.lag, behind);
  if (behind > LAG_MS) {
    const text = `the Cloudflare check is ${hours(behind)} hours behind: it reads ${PAGE} changes an hour`;
    const l = incidents.get("lag");
    incidents.set("lag", l ? { ...l, text } : { id: "lag", text, at: T, told: false });
  } else if (behind === 0) incidents.delete("lag");
  for (const id of [...incidents.keys()]) if (id.startsWith("tie:") && Number(id.slice(4)) < s.bm.t) incidents.delete(id);

  // 6. The list: worst first, at most MAX_INCIDENTS with one counted overflow line (settle, above).
  settle();
  const list = s.incidents;
  report.judged = judged;
  report.skipped = skipped;
  report.open = list.length;

  // 7. Tell Ben: untold incidents are saved first, then one alert, then saved again marked told.
  //    The whole message is budgeted against alert.ts's cut (Codex r1 #7). Every untold incident is in this run's
  //    push, by its line or counted in one closing line, so none waits for a later hour (Codex r1 #2). The weekly
  //    line goes only whole; if it does not fit, it waits for the next run, this week's counts kept.
  const ok = reds.length === 0;
  const remindKey = iso(weekStart(T)).slice(0, 10);
  const remind = s.remindedOn !== remindKey;
  const untold = list.filter((i) => !i.told);
  report.new = untold.length;
  if (!(await saver.save(s))) return stop();
  const light = ping!;
  const lines: string[] = [], sent: Incident[] = [];
  const fits = (more: string[]) => redact([...lines, ...more].join("\n"), env).length <= BUDGET;
  if (!ok && !s.redTold) lines.push(`The Cloudflare check could not finish: ${reds.join("; ")}`.slice(0, 300));
  const changes = untold.filter((i) => i.id.startsWith("change:"));
  if (changes.length) {
    lines.push(`${changes[0].text.slice(0, 400)}${changes.length > 1 ? ` (and ${changes.length - 1} more)` : ""}. Ask an agent to look up the ref.`);
    sent.push(...changes);
  }
  const rest = untold.filter((x) => !x.id.startsWith("change:")).sort((a, b) => Number(lonely(b)) - Number(lonely(a)));
  for (let n = 0; n < rest.length; n++) {
    const line = rest[n].text.slice(0, 300), after = rest.slice(n + 1);
    if (fits(after.length ? [line, closing(after)] : [line])) { lines.push(line); sent.push(rest[n]); continue; }
    lines.push(closing(rest.slice(n)));
    sent.push(...rest.slice(n));
    break;
  }
  let weekly = false;
  if (remind) {
    const c = Object.entries(counts).map(([k, n]) => `${n} ${k}`).join(", ") || "no counted writes";
    const line = `Cloudflare this week: ${c}; largest lag ${hours(s.week.lag)} h; ${list.length} open incident${list.length === 1 ? "" : "s"}.`;
    if (fits([line])) lines.push(line), (weekly = true);
  }
  if (lines.length) {
    const title = changes.length ? "Observatory: Cloudflare changed with no approved request on record" : !ok && !s.redTold ? "Observatory: the Cloudflare check could not finish" : sent.length ? "Observatory: Cloudflare check" : "Observatory: Cloudflare this week";
    // A complete run turns the light green first, so a fallback /fail is a state change that emails.
    const green = ok && (await fetchFn(new Request(light, { method: "POST", body: "run complete; an alert follows" })).then((r) => r.ok, () => false));
    const via = await alert({ ...env, PING_URL: light }, fetchFn, title, lines.join("\n"));
    if (via === "pushover" || (via === "healthchecks" && green)) {
      for (const i of sent) i.told = true;
      if (weekly) (s.remindedOn = remindKey), (s.week = { counts: {}, lag: 0 });
    }
    if (via === "pushover" && !ok) s.redTold = true;
    if (!(await saver.save(s))) return stop();
  }
  if (ok && s.redTold) {
    s.redTold = false;
    if (!(await saver.save(s))) return stop();
  }
  return finish(ok, ok ? `${judged} events judged; ${list.length} open incident${list.length === 1 ? "" : "s"}` : reds.join("; "));
}
