import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FRESH_CRON, GIT_URL, mainFromAdvert, pktLines, readMain, runFresh, STATE_KEY, type FreshEnv } from "../src/fresh.ts";

const LIVE = "a".repeat(40), AHEAD = "b".repeat(40);
const HOUR = 3_600_000;
const T0 = Date.parse("2026-11-01T00:30:00Z");
const at = (h: number) => new Date(T0 + h * HOUR);

function bucket(fail?: "get" | "put") {
  const store = new Map<string, string>();
  return {
    store,
    async get(key: string) {
      if (fail === "get") throw new Error("R2 down");
      const v = store.get(key);
      return v === undefined ? null : ({ text: async () => v } as R2ObjectBody);
    },
    async put(key: string, value: string) {
      if (fail === "put") throw new Error("R2 down");
      store.set(key, value);
      return {} as R2Object;
    },
  };
}

// git's wire format (gitprotocol-http): each packet is its 4-hex length (counting itself) then the bytes.
const pkt = (s: string) => (s.length + 4).toString(16).padStart(4, "0") + s;
const ADVERT = { "content-type": "application/x-git-upload-pack-advertisement" };
const advert = (refs: string[]) => `${pkt("# service=git-upload-pack\n")}0000${refs.map(pkt).join("")}0000`;
const mainAdvert = (sha: string) => advert([`${sha} HEAD\0multi_ack symref=HEAD:refs/heads/main\n`, `${sha} refs/heads/main\n`]);
const gitReply = (body: string, headers: Record<string, string> = ADVERT, status = 200) =>
  new Response(new TextEncoder().encode(body), { status, headers });

// git (github.com) answers `main` and the API answers `api` (default: the same): a sha, or a status
// number (the API's carries a spent rate limit); Pushover answers `pushover`; healthchecks answers `hc`.
function wire(opts: { main?: string | number; api?: string | number; pushover?: number } = {}) {
  const calls: { host: string; path: string; body: string }[] = [];
  const state = { main: opts.main ?? LIVE, api: opts.api ?? opts.main ?? LIVE, pushover: opts.pushover ?? 200, hc: 200 };
  const fetch = async (req: Request) => {
    const url = new URL(req.url);
    calls.push({ host: url.hostname, path: url.pathname, body: await req.text() });
    if (url.hostname === "github.com") {
      if (typeof state.main === "number") return new Response("{}", { status: state.main });
      return gitReply(mainAdvert(state.main));
    }
    if (url.hostname === "api.github.com") {
      if (typeof state.api === "number") return new Response("{}", { status: state.api, headers: { "x-ratelimit-remaining": "0" } });
      return new Response(state.api);
    }
    if (url.hostname === "api.pushover.net") return new Response("{}", { status: state.pushover });
    return new Response("OK", { status: state.hc });
  };
  const hc = () => calls.filter((c) => c.host === "hc-fresh.example").map((c) => c.path);
  const pushes = () => calls.filter((c) => c.host === "api.pushover.net").length;
  return { calls, fetch, state, hc, pushes };
}

const env = (over: Partial<FreshEnv> = {}): FreshEnv => ({
  COPY: bucket(),
  DEPLOYED_SHA: LIVE,
  PING_URL: "https://hc-backup.example/night",
  PING_URL_FRESH: "https://hc-fresh.example/hour",
  PUSHOVER_TOKEN: "t".repeat(30),
  PUSHOVER_USER: "u".repeat(30),
  ...over,
});

// Card c7be60fc: git's protocol first, the API only when git failed.
const REAL = "4742af08b96c29390d4ee93f1468377e9ca3a856"; // main when the fixture was captured, 2026-11-06
const noApi = async (req: Request) => {
  if (new URL(req.url).hostname === "api.github.com") throw new Error("API down");
  return wireGit(req);
};
let wireGit: (req: Request) => Promise<Response> = async () => gitReply(mainAdvert(LIVE));
/** readMain where git gives `reply` and the API is down: the result must be a git error, never a sha. */
async function refused(reply: Response) {
  wireGit = async () => reply;
  return readMain(noApi);
}
/** A request that answers only when its own deadline aborts it; `safety` ends it anyway so a missing deadline
 * shows as a slow read, not a hung test. */
const stall = (req: Request, safety = 1000) =>
  new Promise<Response>((_, reject) => {
    const t = setTimeout(() => reject(new Error("no deadline")), safety);
    req.signal.addEventListener("abort", () => (clearTimeout(t), reject(req.signal.reason)));
  });

test("readMain reads main over git's protocol, with a User-Agent, no credential and no redirects; the API is not asked", async () => {
  const seen: Request[] = [];
  const main = await readMain(async (req) => (seen.push(req), gitReply(mainAdvert(AHEAD))));
  assert.deepEqual(main, { sha: AHEAD });
  assert.deepEqual(seen.map((r) => r.url), [GIT_URL]);
  assert.equal(GIT_URL, "https://github.com/weird-ways-observatory/observatory.git/info/refs?service=git-upload-pack");
  assert.equal(seen[0].redirect, "manual", "redirects must not be followed");
  assert.ok(seen[0].headers.get("User-Agent"));
  assert.equal(seen[0].headers.get("Authorization"), null);
});

test("the real reply GitHub gave on 2026-11-06 reads as that day's main", async () => {
  const body = readFileSync(join(import.meta.dirname, "fixtures", "git", "info-refs-2026-11-06.bin"));
  assert.equal(mainFromAdvert(new Uint8Array(body)), REAL);
  assert.deepEqual(await readMain(async () => new Response(body, { headers: ADVERT })), { sha: REAL });
});

test("H1: an annotated tag's peeled record is accepted and never taken for main", () => {
  const tag = "c".repeat(40), peeled = "d".repeat(40);
  const body = advert([`${LIVE} HEAD\0multi_ack\n`, `${LIVE} refs/heads/main\n`, `${tag} refs/tags/v1\n`, `${peeled} refs/tags/v1^{}\n`]);
  assert.equal(mainFromAdvert(new TextEncoder().encode(body)), LIVE);
});

test("git refusals: anything but one exact main record in a well-formed advertisement is an error, never a sha", async () => {
  const head = `${LIVE} HEAD\0multi_ack\n`, main = `${LIVE} refs/heads/main\n`;
  const svc = pkt("# service=git-upload-pack\n");
  const big = advert([head, main, ...Array.from({ length: 6000 }, (_, i) => `${"e".repeat(40)} refs/pull/${i}/head\n`)]);
  const cases: [string, Response][] = [
    ["a valid advertisement under the wrong content type", gitReply(advert([head, main]), { "content-type": "text/html" })],
    ["a valid advertisement under a status other than 200", gitReply(advert([head, main]), ADVERT, 203)],
    ["a redirect (repo moved)", new Response(null, { status: 301, headers: { location: "https://github.com/elsewhere" } })],
    ["a page with a sha elsewhere in a packet", gitReply(advert([head, `see ${LIVE} refs/heads/main\n`]))],
    ["only refs/heads/main-old", gitReply(advert([head, `${LIVE} refs/heads/main-old\n`]))],
    ["only refs/heads/mainline", gitReply(advert([head, `${LIVE} refs/heads/mainline\n`]))],
    ["only refs/heads/main^{}", gitReply(advert([head, `${LIVE} refs/heads/main^{}\n`]))],
    ["two main records", gitReply(advert([head, main, `${AHEAD} refs/heads/main\n`]))],
    ["capabilities on a later ref", gitReply(advert([`${LIVE} HEAD\n`, `${LIVE} refs/heads/main\0multi_ack\n`]))],
    ["a wrong service line", gitReply(`${pkt("# service=git-receive-pack\n")}0000${pkt(head)}${pkt(main)}0000`)],
    ["no flush after the service line", gitReply(`${svc}${pkt(head)}${pkt(main)}${pkt(`${LIVE} refs/tags/v1\n`)}0000`)],
    ["no final flush", gitReply(`${svc}0000${pkt(main)}${pkt(`${LIVE} refs/tags/v1\n`)}`)],
    ["a packet longer than git allows", gitReply(advert([head, main, `${LIVE} refs/tags/${"x".repeat(65469)}\n`]))], // 65525: 4 hex digits, over 65520
    ["a truncated packet", gitReply(advert([head, main]).slice(0, -10))],
    ["bytes left over after the final flush", gitReply(`${advert([head, main])}00`)],
    ["a bad length", gitReply(`zzzz${advert([head, main])}`)],
    ["a reply over 256 KB", gitReply(big)],
  ];
  for (const [name, reply] of cases) {
    const r = await refused(reply);
    assert.ok("error" in r && r.error.startsWith("git "), name);
  }
});

test("pktLines refuses a length of 1-3 (a packet shorter than its own length field)", () => {
  for (const len of ["0001", "0002", "0003"]) assert.throws(() => pktLines(new TextEncoder().encode(`${len}abcd`)), /bad packet length/, len);
});

test("git fails, the API answers: the API's sha is used", async () => {
  const w = wire({ main: 500, api: AHEAD });
  assert.deepEqual(await readMain(w.fetch), { sha: AHEAD });
  assert.deepEqual(w.calls.map((c) => c.host), ["github.com", "api.github.com"]);
});

test("the sources disagree: a valid git answer is used and the API is read only when git failed", async () => {
  const w = wire({ main: AHEAD, api: LIVE }); // the API would say healthy
  const r = await runFresh(env(), w.fetch, at(0));
  assert.equal(r.fresh, "waiting", "the API is read only when git failed");
  assert.ok(!w.calls.some((c) => c.host === "api.github.com"), "the API is read only when git failed");
});

test("both fail: one error naming both reasons", async () => {
  const w = wire({ main: 429, api: 403 });
  assert.deepEqual(await readMain(w.fetch), { error: "git answered 429; GitHub answered 403, rate limited" });
});

test("G3: git stalls and the API answers, inside the deadline", async () => {
  const t0 = Date.now();
  const main = await readMain(async (req) => (new URL(req.url).hostname === "github.com" ? stall(req) : new Response(AHEAD)), 50);
  assert.deepEqual(main, { sha: AHEAD });
  assert.ok(Date.now() - t0 < 500, "git read has no deadline");
});

test("G3: both stall: an error naming both within two deadlines, so the verdict is still written", async () => {
  const t0 = Date.now();
  const main = await readMain(stall, 50);
  assert.ok(Date.now() - t0 < 500, "a read has no deadline");
  assert.deepEqual(main, { error: "git timed out; GitHub timed out" });
});

test("G3: a git body that stalls after its headers is cut off by the same deadline", async () => {
  const keepAlive = setTimeout(() => undefined, 1000); // Node's deadline timer alone does not keep a test alive
  const t0 = Date.now();
  const main = await readMain(async (req) => {
    if (new URL(req.url).hostname === "api.github.com") return new Response(AHEAD);
    const body = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode("001e")); req.signal.addEventListener("abort", () => c.error(req.signal.reason)); } });
    return new Response(body, { headers: ADVERT });
  }, 50);
  clearTimeout(keepAlive);
  assert.ok(Date.now() - t0 < 500, "the git body has no deadline");
  assert.deepEqual(main, { sha: AHEAD });
});

test("Outcome 2: the API rate limited all day, git answering a newer main: waiting, then not-live at 6 hours", async () => {
  const e = env(), w = wire({ main: AHEAD, api: 403 });
  for (let h = 0; h < 6; h++) assert.equal((await runFresh(e, w.fetch, at(h))).fresh, "waiting");
  const r = await runFresh(e, w.fetch, at(6));
  assert.equal(r.fresh, "not-live");
  assert.equal(w.pushes(), 1);
});

test("live matches main: healthy, pings this job's own check up, nothing else", async () => {
  const w = wire();
  const r = await runFresh(env(), w.fetch, at(0));
  assert.equal(r.fresh, "healthy");
  assert.deepEqual(w.hc(), ["/hour"]);
  assert.equal(w.pushes(), 0);
  assert.ok(!w.calls.some((c) => c.host === "hc-backup.example"));
});

test("main ahead: waiting for 6 hours, then one alert, /fail every hour, cleared when it goes live", async () => {
  const copy = bucket(), e = env({ COPY: copy }), w = wire({ main: AHEAD });
  for (let h = 0; h < 6; h++) assert.equal((await runFresh(e, w.fetch, at(h))).fresh, "waiting");
  assert.equal(w.pushes(), 0);
  assert.ok(w.hc().every((p) => p === "/hour"));

  const r = await runFresh(e, w.fetch, at(6));
  assert.equal(r.fresh, "not-live");
  assert.match(r.reason, /main is bbbbbbb, live is aaaaaaa, for 6h/);
  assert.equal(w.pushes(), 1);
  await runFresh(e, w.fetch, at(7));
  assert.equal(w.pushes(), 1, "one alert per bad state, not one an hour");
  assert.deepEqual(w.hc().slice(-2), ["/hour/fail", "/hour/fail"]);

  w.state.main = LIVE;
  assert.equal((await runFresh(e, w.fetch, at(8))).fresh, "healthy");
  assert.equal(w.hc().at(-1), "/hour");
  assert.deepEqual(JSON.parse(copy.store.get(STATE_KEY)!), { upAt: at(8).toISOString() });
});

test("GitHub unreadable (rate limit): waiting under 3 hours, then unverified -- never healthy", async () => {
  const e = env(), w = wire({ main: 403 });
  for (let h = 0; h < 3; h++) assert.equal((await runFresh(e, w.fetch, at(h))).fresh, "waiting");
  const r = await runFresh(e, w.fetch, at(3));
  assert.equal(r.fresh, "unverified");
  assert.match(r.reason, /rate limited/);
  assert.equal(w.pushes(), 1);
  assert.equal(w.hc().at(-1), "/hour/fail");
});

test("an unreadable spell does not reset a mismatch already being timed", async () => {
  const e = env(), w = wire({ main: AHEAD });
  await runFresh(e, w.fetch, at(0));
  w.state.main = 429;
  await runFresh(e, w.fetch, at(2));
  w.state.main = AHEAD;
  assert.equal((await runFresh(e, w.fetch, at(6))).fresh, "not-live");
});

test("no DEPLOYED_SHA (or a malformed one): unverified and /fail, even when main reads fine", async () => {
  for (const DEPLOYED_SHA of [undefined, "", "main", "$WORKERS_CI_COMMIT_SHA"]) {
    const w = wire();
    const r = await runFresh(env({ DEPLOYED_SHA }), w.fetch, at(0));
    assert.equal(r.fresh, "unverified", String(DEPLOYED_SHA));
    assert.ok(!w.hc().includes("/hour"), "never pings up");
  }
});

test("the alert's fallback goes to this job's own check, never the backup check", async () => {
  const w = wire({ main: AHEAD, pushover: 400 });
  const e = env();
  for (let h = 0; h <= 6; h++) await runFresh(e, w.fetch, at(h));
  assert.equal(w.hc().at(-1), "/hour/fail");
  assert.equal(w.hc().filter((p) => p === "/hour/fail").length, 1, "the fallback /fail stands in for the hourly /fail");
  assert.ok(!w.calls.some((c) => c.host === "hc-backup.example"));
});

// Card 4070b32f: healthchecks emails only when the light changes, so its /fail tells Ben only when
// the light was confirmed up before. Anything else is not told and is tried again next hour.
test("Pushover down while the light is already red: the new bad verdict is retried until Pushover takes it", async () => {
  const e = env(), w = wire({ main: AHEAD });
  for (let h = 0; h <= 6; h++) await runFresh(e, w.fetch, at(h));
  assert.equal(w.pushes(), 1, "not-live told through Pushover");

  w.state.pushover = 500;
  e.DEPLOYED_SHA = ""; // straight to a different bad verdict, no green hour between
  for (let h = 7; h <= 9; h++) assert.equal((await runFresh(e, w.fetch, at(h))).fresh, "unverified");
  assert.equal(w.pushes(), 4, "unverified tried at hours 7, 8, 9: each /fail changed nothing");

  w.state.pushover = 200;
  await runFresh(e, w.fetch, at(10));
  await runFresh(e, w.fetch, at(11));
  assert.equal(w.pushes(), 5, "taken at hour 10, then no more");
});

test("Pushover down at the first bad hour after a confirmed up: the fallback /fail is a real change and counts as told", async () => {
  const e = env(), w = wire({ main: AHEAD, pushover: 500 });
  for (let h = 0; h <= 8; h++) await runFresh(e, w.fetch, at(h));
  assert.equal(w.pushes(), 1, "told once by the fallback at hour 6");
});

test("an up ping healthchecks did not confirm does not make the next fallback count", async () => {
  const e = env(), w = wire({ main: AHEAD, pushover: 500 });
  w.state.hc = 503;
  for (let h = 0; h < 6; h++) await runFresh(e, w.fetch, at(h));
  w.state.hc = 200;
  for (let h = 6; h <= 7; h++) await runFresh(e, w.fetch, at(h));
  assert.equal(w.pushes(), 2, "the light was never confirmed up, so hour 6 is tried again at hour 7");
});

test("a failed save after the fallback turned the light red leaves no stale green to trust (Codex r1 on 4070b32f)", async () => {
  const copy = bucket();
  let failPut = false;
  const flaky = { ...copy, put: async (k: string, v: string) => { if (failPut) throw new Error("R2 down"); return copy.put(k, v); } };
  const e = env({ COPY: flaky }), w = wire({ main: AHEAD, pushover: 500 });
  for (let h = 0; h < 6; h++) await runFresh(e, w.fetch, at(h)); // waiting: up pings confirmed
  failPut = true;
  await runFresh(e, w.fetch, at(6)); // the fallback /fail turns the light red; nothing is saved
  failPut = false;
  e.DEPLOYED_SHA = ""; // a different bad verdict, straight away
  for (let h = 7; h <= 8; h++) await runFresh(e, w.fetch, at(h));
  assert.equal(w.pushes(), 3, "unverified is tried at hours 7 and 8: the green seen at hour 5 is stale");
});

test("neither channel takes the alert: it is tried again next hour", async () => {
  const e = env(), w = wire({ main: AHEAD, pushover: 500 });
  for (let h = 0; h < 6; h++) await runFresh(e, w.fetch, at(h));
  w.state.hc = 503;
  for (let h = 6; h <= 7; h++) await runFresh(e, w.fetch, at(h));
  assert.equal(w.pushes(), 2);
});

test("PING_URL_FRESH not set yet: log only -- no alert, no ping, nothing claims healthy", async () => {
  const w = wire({ main: AHEAD });
  const e = env({ PING_URL_FRESH: undefined, DEPLOYED_SHA: undefined });
  const r = await runFresh(e, w.fetch, at(0));
  assert.equal(r.fresh, "unverified");
  assert.match(r.setup, /log only/);
  assert.deepEqual(w.calls.map((c) => c.host), ["github.com"]);
});

test("its own state cannot be read or saved: unverified and /fail", async () => {
  for (const fail of ["get", "put"] as const) {
    const w = wire();
    const r = await runFresh(env({ COPY: bucket(fail) }), w.fetch, at(0));
    assert.equal(r.fresh, "unverified", fail);
    assert.equal(w.hc().at(-1), "/hour/fail");
  }
});

test("the hourly cron runs only freshness: no backup work, and nothing reaches the backup check", async (t) => {
  const w = wire();
  t.mock.method(globalThis, "fetch", w.fetch);
  const jobs: Promise<unknown>[] = [];
  await worker.scheduled({ cron: FRESH_CRON } as ScheduledController, env() as never, { waitUntil: (p: Promise<unknown>) => jobs.push(p) } as never);
  await Promise.all(jobs);
  assert.deepEqual(w.calls.map((c) => c.host), ["github.com", "hc-fresh.example"]);
});

test("an unknown cron runs neither job", async (t) => {
  const w = wire();
  t.mock.method(globalThis, "fetch", w.fetch);
  const jobs: Promise<unknown>[] = [];
  await worker.scheduled({ cron: "* * * * *" } as ScheduledController, env() as never, { waitUntil: (p: Promise<unknown>) => jobs.push(p) } as never);
  await Promise.all(jobs);
  assert.equal(w.calls.length, 0);
});
