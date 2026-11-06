// Card f0d4e2fc (design DESIGN-watch-home 3e): every hour, check that what runs here is what is on
// main. A merge that never went live is caught within about 7 hours. This job has its own cron,
// its own state file and its own healthchecks check, so the nightly backup can never clear it.
import { alert, redact, type AlertEnv } from "./alert.ts";

export interface FreshEnv extends AlertEnv {
  COPY: Pick<R2Bucket, "get" | "put">;
  DEPLOYED_SHA?: string; // set by the deploy command: --var DEPLOYED_SHA:$WORKERS_CI_COMMIT_SHA
  PING_URL_FRESH?: string; // this job's own healthchecks check; Ben creates it after cutover
}

export const FRESH_CRON = "30 * * * *";
// Public repo, read without a credential, by its numeric id: the id survives the move to its own
// org, so nothing relies on GitHub's redirect from the old name (design DESIGN-watch-home 3c).
export const REPO_ID = 1440498313;
export const STATE_KEY = "state/freshness.json"; // state/ has no lock
const HOUR = 3_600_000;
export const NOT_LIVE_AFTER = 6 * HOUR;
export const UNREADABLE_AFTER = 3 * HOUR;
const SHA = /^[0-9a-f]{40}$/;

export interface State {
  mismatchSince?: string; // first hour main was seen ahead of DEPLOYED_SHA
  unreadableSince?: string; // first hour GitHub could not be read
  alerted?: Verdict; // the bad verdict Ben has already been told about
  upAt?: string; // the run whose up ping healthchecks confirmed (card 4070b32f)
}
// waiting = something is off but still inside its grace window.
export type Verdict = "healthy" | "waiting" | "not-live" | "unverified";
export type Main = { sha: string } | { error: string };

// Card c7be60fc: the API's anonymous quota (60 an hour per address) is shared with every Worker on the same
// outgoing address, so it ran out in about half the hours. main is read first with git's own protocol, the
// request `git ls-remote` makes; the API is asked only when that read fails. No credential either way
// (DESIGN-watch-home 3a). If the repo is renamed or moved, this URL changes in the same change: redirects
// are not followed, so a moved repo is an error here and the API by id still answers.
export const GIT_URL = "https://github.com/weird-ways-observatory/observatory.git/info/refs?service=git-upload-pack";
export const READ_DEADLINE = 10_000; // per source, body included: both stalled is still well inside a cron run
const ADVERT = "application/x-git-upload-pack-advertisement";
const MAX_BODY = 256 * 1024;
const HEADERS = { "User-Agent": "observatory-freshness" };
// Capabilities: names per the spec's cap-list, single spaces between; a value after "=" (symref=HEAD:refs/heads/main,
// agent=git/...) is printable ASCII without spaces. Nothing else -- no NUL, LF or markup -- may hide behind the NUL.
const CAPS = /^[a-z0-9_-]+(=[\x21-\x7e]+)?( [a-z0-9_-]+(=[\x21-\x7e]+)?)*$/;
type Fetch = (req: Request) => Promise<Response>;

/** The body, refused past `max` bytes. Reading stops at the request's deadline like the fetch itself. */
async function capped(res: Response, max: number): Promise<Uint8Array> {
  const out = new Uint8Array(max);
  let n = 0;
  const reader = res.body?.getReader();
  for (let r = await reader?.read(); r && !r.done; r = await reader!.read()) {
    if (n + r.value.length > max) {
      await reader!.cancel();
      throw new Error("reply too large");
    }
    out.set(r.value, n);
    n += r.value.length;
  }
  return out.subarray(0, n);
}

/** A git smart-HTTP body as pkt-lines (gitprotocol-http, frozen copy in studio-os docs/house-style/frozen):
 * each a 4-digit lowercase hex length that counts itself, 0000 = flush (null). Anything left over or short
 * is an error. */
export function pktLines(body: Uint8Array): (string | null)[] {
  const text = new TextDecoder("latin1").decode(body); // one char per byte, so lengths stay byte lengths
  const out: (string | null)[] = [];
  for (let i = 0; i < text.length; ) {
    const head = text.slice(i, i + 4);
    if (!/^[0-9a-f]{4}$/.test(head)) throw new Error("bad packet length");
    const len = parseInt(head, 16);
    if (len === 0) {
      out.push(null);
      i += 4;
      continue;
    }
    if (len < 4 || len > 65520 || i + len > text.length) throw new Error("bad packet length");
    out.push(text.slice(i + 4, i + len));
    i += len;
  }
  return out;
}

/** main's sha from a git ref advertisement. Only an exact `refs/heads/main` record counts, and only one. */
export function mainFromAdvert(body: Uint8Array): string {
  const p = pktLines(body);
  if (p[0] !== "# service=git-upload-pack\n" && p[0] !== "# service=git-upload-pack") throw new Error("no service line");
  if (p[1] !== null) throw new Error("no flush after the service line");
  if (p.length < 4 || p.at(-1) !== null) throw new Error("no final flush");
  let main: string | undefined;
  p.slice(2, -1).forEach((pkt, i) => {
    if (pkt === null) throw new Error("flush inside the ref list");
    let rec = pkt.endsWith("\n") ? pkt.slice(0, -1) : pkt;
    const nul = rec.indexOf("\0");
    // The spec requires the capability list behind a NUL on the first ref, and only there (Codex build r1).
    if (i === 0 && nul < 0) throw new Error("no capabilities on the first ref");
    if (nul >= 0) {
      if (i !== 0) throw new Error("capabilities after the first ref");
      if (!CAPS.test(rec.slice(nul + 1))) throw new Error("bad capability list");
      rec = rec.slice(0, nul);
    }
    // `<sha> refs/tags/v1^{}` (a peeled annotated tag) is a valid record that is never main (H1).
    const m = /^([0-9a-f]{40}) ([^ \0\n]+)$/.exec(rec);
    if (!m) throw new Error("bad ref record");
    if (m[2] !== "refs/heads/main") return;
    if (main) throw new Error("two main records");
    main = m[1];
  });
  if (!main) throw new Error("no refs/heads/main");
  return main;
}

/** main's head over git's protocol. A reply that is not exactly a git advertisement is an error. */
async function readGit(fetchFn: Fetch, deadline: number): Promise<Main> {
  const req = new Request(GIT_URL, { headers: HEADERS, redirect: "manual", signal: AbortSignal.timeout(deadline) });
  try {
    const res = await fetchFn(req);
    if (res.status !== 200) return { error: `git answered ${res.status}` };
    if (res.headers.get("content-type") !== ADVERT) return { error: "git reply is not a ref advertisement" };
    return { sha: mainFromAdvert(await capped(res, MAX_BODY)) };
  } catch (e) {
    const why = req.signal.aborted ? "timed out" : e instanceof Error && e.message ? e.message : "unreachable";
    return { error: `git ${why}` };
  }
}

/** main's head from the public GitHub API, by repo id. Any failure, a rate limit included, is an error. */
async function readApi(fetchFn: Fetch, deadline: number): Promise<Main> {
  const req = new Request(`https://api.github.com/repositories/${REPO_ID}/commits/main`, {
    headers: { ...HEADERS, Accept: "application/vnd.github.sha" },
    signal: AbortSignal.timeout(deadline),
  });
  try {
    const res = await fetchFn(req);
    if (!res.ok) {
      const limited = res.headers.get("x-ratelimit-remaining") === "0" ? ", rate limited" : "";
      return { error: `GitHub answered ${res.status}${limited}` };
    }
    const sha = (await res.text()).trim();
    return SHA.test(sha) ? { sha } : { error: "GitHub did not return a commit" };
  } catch {
    return { error: req.signal.aborted ? "GitHub timed out" : "GitHub unreachable" };
  }
}

/** main's head: git first; the API only when git failed, so the two are never weighed against each other
 * and the healthier answer is never preferred. Both failing is one error naming both reasons. */
export async function readMain(fetchFn: Fetch, deadline = READ_DEADLINE): Promise<Main> {
  const git = await readGit(fetchFn, deadline);
  if ("sha" in git) return git;
  const api = await readApi(fetchFn, deadline);
  return "sha" in api ? api : { error: `${git.error}; ${api.error}` };
}

/** Whole hours from `iso` to `now`, as "3h". */
const since = (iso: string, now: Date) => `${Math.floor((now.getTime() - Date.parse(iso)) / HOUR)}h`;

/** The verdict for this hour and the state to keep. Only a matching read is ever healthy. */
export function judge(prev: State, deployed: string | undefined, main: Main, now: Date): { verdict: Verdict; state: State; reason: string } {
  const state: State = { ...prev };
  if (!deployed || !SHA.test(deployed)) {
    return { verdict: "unverified", state, reason: "DEPLOYED_SHA is not set, so nothing records which commit went live" };
  }
  if ("error" in main) {
    state.unreadableSince ??= now.toISOString();
    const over = now.getTime() - Date.parse(state.unreadableSince) >= UNREADABLE_AFTER;
    return { verdict: over ? "unverified" : "waiting", state, reason: `${main.error} (unreadable for ${since(state.unreadableSince, now)})` };
  }
  delete state.unreadableSince;
  if (main.sha === deployed) {
    delete state.mismatchSince;
    return { verdict: "healthy", state, reason: `live is main (${deployed.slice(0, 7)})` };
  }
  state.mismatchSince ??= now.toISOString();
  const over = now.getTime() - Date.parse(state.mismatchSince) >= NOT_LIVE_AFTER;
  return { verdict: over ? "not-live" : "waiting", state, reason: `main is ${main.sha.slice(0, 7)}, live is ${deployed.slice(0, 7)}, for ${since(state.mismatchSince, now)}` };
}

/** True when the confirmed up ping is the previous hour's: only then is the light surely green, so a
 * /fail now is a change that emails. An older one may predate a /fail whose state save failed. */
const greenLastHour = (upAt: string | undefined, now: Date) =>
  upAt !== undefined && Math.floor(now.getTime() / HOUR) - Math.floor(Date.parse(upAt) / HOUR) === 1;

/** The verdicts that alert and send /fail. */
const isBad = (v: Verdict): v is "not-live" | "unverified" => v === "not-live" || v === "unverified";
const TITLES = { "not-live": "Observatory: a merge did not go live", unverified: "Observatory: cannot verify what is live" } as const;

/** One hour's run: read, judge, alert once per bad state, keep state, then ping this job's own check. */
export async function runFresh(env: FreshEnv, fetchFn: (req: Request) => Promise<Response>, now: Date) {
  let prev: State = {}, stateError = "";
  try {
    const saved = await env.COPY.get(STATE_KEY);
    if (saved) prev = JSON.parse(await saved.text());
  } catch {
    stateError = "freshness state could not be read";
  }
  const main = await readMain(fetchFn);
  let { verdict, state, reason } = judge(prev, env.DEPLOYED_SHA, main, now);
  if (stateError) [verdict, reason] = ["unverified", `${stateError}; ${reason}`];
  const ping = env.PING_URL_FRESH;

  // Until Ben creates this job's check, it only logs: no alert, and nothing that claims healthy.
  let via: string | undefined;
  if (ping && isBad(verdict) && state.alerted !== verdict) {
    // The fallback goes to this job's own check, never the backup check (PING_URL).
    via = await alert({ ...env, PING_URL: ping }, fetchFn, TITLES[verdict], reason);
    // healthchecks emails only on a change: its /fail tells Ben only if the light was confirmed up.
    // Not told, it is tried again next hour.
    if (via === "pushover" || (via === "healthchecks" && greenLastHour(prev.upAt, now))) state.alerted = verdict;
  }
  if (!isBad(verdict)) delete state.alerted;
  delete state.upAt; // set again below only once this hour's up ping is confirmed
  try {
    await env.COPY.put(STATE_KEY, JSON.stringify(state));
  } catch {
    if (!stateError) reason = `freshness state could not be saved; ${reason}`;
    verdict = "unverified";
  }

  const report = { fresh: verdict, reason: redact(reason, env), setup: ping ? "complete" : "PING_URL_FRESH not set: log only" };
  console.log(JSON.stringify(report));
  // "Up" means the hourly job ran and nothing is overdue; a bad verdict is /fail every hour.
  // An alert that fell back to healthchecks has already sent /fail.
  if (ping && via !== "healthchecks") {
    const ok = await fetchFn(new Request(isBad(verdict) ? `${ping}/fail` : ping, { method: "POST", body: JSON.stringify(report) })).then((r) => r.ok, () => false);
    // A failed save here leaves upAt unset or stale: the next fallback is then retried, never wrongly told.
    if (ok && !isBad(verdict)) await env.COPY.put(STATE_KEY, JSON.stringify({ ...state, upAt: now.toISOString() })).catch(() => undefined);
  }
  return report;
}
