import { test } from "node:test";
import assert from "node:assert/strict";
import worker from "../src/index.ts";
import { FRESH_CRON, readMain, runFresh, STATE_KEY, type FreshEnv } from "../src/fresh.ts";

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

// GitHub answers `main` (a sha, or a status number); Pushover answers `pushover`; healthchecks answers `hc`.
function wire(opts: { main?: string | number; pushover?: number } = {}) {
  const calls: { host: string; path: string; body: string }[] = [];
  const state = { main: opts.main ?? LIVE, pushover: opts.pushover ?? 200, hc: 200 };
  const fetch = async (req: Request) => {
    const url = new URL(req.url);
    calls.push({ host: url.hostname, path: url.pathname, body: await req.text() });
    if (url.hostname === "api.github.com") {
      if (typeof state.main === "number") return new Response("{}", { status: state.main, headers: { "x-ratelimit-remaining": "0" } });
      return new Response(state.main);
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

test("readMain asks the public API for main's sha, with a User-Agent and no credential", async () => {
  let seen: Request | undefined;
  const main = await readMain(async (req) => ((seen = req), new Response(`${LIVE}\n`)));
  assert.deepEqual(main, { sha: LIVE });
  assert.equal(seen!.url, "https://api.github.com/repositories/1440498313/commits/main");
  assert.equal(seen!.headers.get("Accept"), "application/vnd.github.sha");
  assert.ok(seen!.headers.get("User-Agent"));
  assert.equal(seen!.headers.get("Authorization"), null);
});

test("readMain: a rate limit, an error page or a network failure is an error, never a sha", async () => {
  assert.deepEqual(await readMain(async () => new Response("", { status: 403, headers: { "x-ratelimit-remaining": "0" } })), { error: "GitHub answered 403, rate limited" });
  assert.deepEqual(await readMain(async () => new Response("<html>")), { error: "GitHub did not return a commit" });
  assert.deepEqual(await readMain(async () => { throw new Error("x"); }), { error: "GitHub unreachable" });
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
  assert.deepEqual(w.calls.map((c) => c.host), ["api.github.com"]);
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
  assert.deepEqual(w.calls.map((c) => c.host), ["api.github.com", "hc-fresh.example"]);
});

test("an unknown cron runs neither job", async (t) => {
  const w = wire();
  t.mock.method(globalThis, "fetch", w.fetch);
  const jobs: Promise<unknown>[] = [];
  await worker.scheduled({ cron: "* * * * *" } as ScheduledController, env() as never, { waitUntil: (p: Promise<unknown>) => jobs.push(p) } as never);
  await Promise.all(jobs);
  assert.equal(w.calls.length, 0);
});
