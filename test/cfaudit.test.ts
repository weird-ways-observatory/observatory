// Card beec640b build a: the Cloudflare outside-record check. One test (or more) per row of
// studio-os docs/specifications/trust-but-verify/THREATS-beec640b.md (E6), each driving runCfAudit
// itself; only Cloudflare, the bucket and the alert channels are faked (test/cfaudit-fakes.ts).
import { test } from "node:test";
import assert from "node:assert/strict";
import { runCfAudit, START, SETTLE_MS, PAGE, STATE_KEY, VERSION } from "../src/cfaudit.ts";
import { judge } from "../src/cfjudge.ts";
import { ACCOUNT, AUDIT, BEN, MASTER, OTHER, PING, bucket, cloudflare, env, ev, shapes, state } from "./cfaudit-fakes.ts";

const H = 3_600_000, M = 60_000;
const T0 = START + H; // events at T0.., runs at T0 + 1 h and later (past the settle time)

function setup(log: any[] = [], o: { keyId?: string; logReads?: boolean } = {}) {
  const b = bucket();
  let now = T0;
  const cf = cloudflare(log, { ...o, clock: () => now });
  const run = async (at: number, over: Record<string, unknown> = {}) => { now = at; return runCfAudit(env(b, over), cf.fetch, new Date(at)); };
  return { b, cf, run };
}
const lit = (cf: ReturnType<typeof cloudflare>) => cf.pings.filter((p) => p.url.startsWith(PING) && p.body.startsWith("{")).at(-1);
const red = (cf: ReturnType<typeof cloudflare>) => lit(cf)?.url.endsWith("/fail") === true; // no light at all is not red
const ids = (b: ReturnType<typeof bucket>) => state(b).incidents.map((i: any) => i.id);
const who = { master: MASTER, ben: BEN };

// ---------- A. What the check is for ----------

test("A1: a write by a key other than the master key alerts once, with one push", async () => {
  const { b, cf, run } = setup([ev("e1", T0, { token: OTHER, product: "dns_records" })]);
  await run(T0 + H);
  assert.deepEqual(ids(b), ["change:e1"], "M:A1 non-master write listed");
  assert.equal(cf.alerts.length, 1);
  assert.match(cf.alerts[0].message, /no approved request on record: dns_records\/missing create by api_token at .*ref e1 \(a write by a key other than the vault's master key\)/, "M:A1 why");
  await run(T0 + 2 * H);
  assert.equal(cf.alerts.length, 1, "told once, never again");
});

test("A2: a Global API Key write alerts", () => {
  assert.equal(judge(ev("x", T0, { ctx: "api_key", atype: "user", actor: BEN, product: "dns_records" }), who).verdict.v, "alert");
});

test("A3: Ben's dashboard key create alerts; someone else's dashboard DNS edit alerts; Ben's dashboard DNS edit is counted", () => {
  assert.deepEqual(judge(shapes.benDash("k", T0, "tokens"), who).verdict, { v: "alert", why: "a key or member change in the dashboard" }, "M:A3 dashboard key change alerts");
  assert.deepEqual(judge(ev("u", T0, { ctx: "dash", atype: "user", actor: BEN, product: null, rtype: "tokens", type: "delete" }), who).verdict.v, "alert", "user-level key");
  assert.deepEqual(judge(shapes.benDash("m", T0, "account", "members"), who).verdict.v, "alert", "members");
  assert.deepEqual(judge(ev("o", T0, { ctx: "dash", atype: "user", actor: OTHER, product: "dns_records" }), who).verdict, { v: "alert", why: "a dashboard change by someone other than Ben" }, "M:A3 non-Ben dashboard");
  assert.deepEqual(judge(shapes.benDash("d", T0), who).verdict, { v: "counted", group: "dashboard" });
  assert.deepEqual(judge(shapes.benDash("a", T0, "analytics", "query.top-n"), who).verdict, { v: "counted", group: "dashboard" });
  assert.equal(judge(shapes.benDash("n", T0, "zero_trust", "policies"), who).verdict.v, "alert", "an unlisted dashboard kind");
});

test("A4 (build a part): a master-key update alerts; master writes that are not keys alert; master key create/delete are counted", () => {
  assert.deepEqual(judge(ev("u", T0, { type: "update", token: MASTER, product: "tokens" }), who).verdict, { v: "alert", why: "the master key updated a key (no job does that)" });
  assert.equal(judge(ev("d", T0, { token: MASTER, product: "dns_records" }), who).verdict.v, "alert");
  assert.deepEqual(judge(shapes.masterCreate("c", T0), who).verdict, { v: "counted", group: "master writes, not yet matched" });
  assert.deepEqual(judge(shapes.masterDelete("x", T0), who).verdict, { v: "counted", group: "master writes, not yet matched" });
});

test("A6: unknown or missing sign-in kinds alert; a missing actor is an unreadable change", () => {
  for (const ctx of ["oauth", "cloudflare_admin", "something_new"]) assert.equal(judge(ev("x", T0, { ctx, atype: "user", actor: BEN, product: "dns_records" }), who).verdict.v, "alert", ctx);
  assert.equal(judge(ev("x", T0, { ctx: null, atype: "user", actor: BEN, product: "dns_records" }), who).verdict.v, "alert", "no context, not system");
  assert.equal(judge(ev("x", T0, { ctx: null, atype: "", product: "dns", rtype: "record" }), who).verdict.v, "alert", "missing actor type");
  const noActor = ev("x", T0); delete noActor.actor;
  assert.equal(judge(noActor, who).verdict.v, "unreadable");
  assert.equal(judge(ev("x", T0, { type: "purge" }), who).verdict.v, "alert", "a new action type");
});

test("A7: a system write of a kind that is never automatic alerts; known system kinds are counted", () => {
  assert.equal(judge(ev("x", T0, { ctx: null, atype: "system", product: "tokens" }), who).verdict.v, "alert", "M:A7 system tokens");
  assert.equal(judge(ev("x", T0, { ctx: null, atype: "system" }), who).verdict.v, "alert", "system DNS through the records API is not automatic");
  assert.equal(judge(ev("x", T0, { ctx: null, atype: "system", product: "access", rtype: "apps" }), who).verdict.v, "alert");
  for (const [p, t] of [["dns", "record"], ["certificates", "certificate_pack"], ["certificates", "zone_settings"], ["zone", "settings"]]) assert.deepEqual(judge(ev("x", T0, { ctx: null, atype: "system", product: p, rtype: t }), who).verdict, { v: "counted", group: "system" });
});

test("A8: api events other than Ben's sign-in and the three echoes alert", () => {
  assert.deepEqual(judge(ev("l", T0, { type: "update", ctx: "api", atype: "user", actor: BEN, product: "", rtype: "user", desc: "LOGIN" }), who).verdict, { v: "counted", group: "sign-in" });
  assert.equal(judge(ev("l", T0, { type: "update", ctx: "api", atype: "user", actor: OTHER, product: null, rtype: "user", desc: "LOGIN" }), who).verdict.v, "alert");
  assert.equal(judge(ev("l", T0, { type: "update", ctx: "api", atype: "user", actor: BEN, product: "account", rtype: "settings", desc: "SOMETHING_ELSE" }), who).verdict.v, "alert");
  assert.deepEqual(judge(shapes.echo("e", T0, "TOKEN_REVOKE"), who).verdict, { v: "echo", action: "delete" }, "a revoke echo pairs with a delete");
});

test("A9: events close in time never borrow each other's verdict", async () => {
  const { b, cf, run } = setup([shapes.masterCreate("m1", T0), ev("x1", T0 + 500, { token: OTHER, product: "dns_records" }), shapes.systemDns("s1", T0 + 900), ev("x2", T0 + 1200, { ctx: "api", atype: "user", actor: OTHER, product: "account", rtype: "settings", desc: "TOKEN_CREATE" })]);
  await run(T0 + H);
  assert.deepEqual(ids(b).sort(), ["change:x1", "change:x2", "noecho:m1"].sort());
  assert.equal(cf.alerts.length, 1);
});

test("A10: every echo pushes; a pair only labels it; a key event without its echo is a diagnostic line", async () => {
  const { b, cf, run } = setup([shapes.masterCreate("k1", T0, "192.0.2.1"), shapes.echo("e1", T0 + 1500, "TOKEN_CREATE", "192.0.2.1"), shapes.echo("e2", T0 + 10_000, "TOKEN_CREATE", "192.0.2.1"), shapes.masterCreate("k3", T0 + 20_000, "192.0.2.1")]);
  await run(T0 + H);
  const s = state(b), byId = Object.fromEntries(s.incidents.map((i: any) => [i.id, i.text]));
  assert.match(byId["echo:e1"], /probably the log's duplicate entry of the key create at .* \(ref k1\)/);
  assert.match(byId["echo:e2"], /logged only as an echo .* no matching key event/);
  assert.match(byId["noecho:k3"], /has no echo in the log \(diagnostic\)/);
  assert.equal(byId["noecho:k1"], undefined);
  assert.equal(cf.alerts.length, 1);
  assert.match(cf.alerts[0].message, /ref e1/);
  assert.match(cf.alerts[0].message, /ref e2/);
});

test("A10: a compensating gap -- a key event that lost its echo next to an unrelated echo-only change -- still pushes the echo", async () => {
  const { b, cf, run } = setup([shapes.masterCreate("k1", T0, "192.0.2.1"), shapes.echo("stray", T0 + 2000, "TOKEN_CREATE", "192.0.2.1")]);
  await run(T0 + H);
  assert.ok(ids(b).includes("echo:stray"), "the echo is on the list whatever it pairs with");
  assert.match(cf.alerts[0].message, /ref stray/);
});

test("A10: an echo and its key event split across runs still pair once, judged once each", async () => {
  // The key event is just before the first run's settle line; its echo just after.
  const run1 = T0 + 30 * M, edge = run1 - SETTLE_MS;
  const { b, run } = setup([shapes.masterDelete("k", edge - 1000, "192.0.2.7"), shapes.echo("e", edge + 1000, "TOKEN_REVOKE", "192.0.2.7")]);
  await run(run1);
  assert.equal(state(b).recent.length, 1, "the key event waits for its possible pair");
  await run(run1 + H);
  const s = state(b);
  assert.deepEqual(s.incidents.map((i: any) => i.id), ["echo:e"]);
  assert.match(s.incidents[0].text, /duplicate entry of the key delete/);
  assert.equal(s.recent.length, 0);
});

test("A10: the address is kept only as a hash", async () => {
  // Just inside the read and within 5 s of its end, so the event waits in state for a possible echo.
  const { b, run } = setup([shapes.masterDelete("k", T0 + H - SETTLE_MS - 2000, "198.51.100.77")]);
  await run(T0 + H);
  assert.equal(state(b).recent.length, 1, "M:A10 waiting in state");
  assert.doesNotMatch(b.store.get(STATE_KEY)!.body, /198\.51\.100\.77/, "M:A10 hashed");
});

// ---------- B. Reading the log honestly ----------

for (const [name, resp] of [["an HTTP error", () => new Response("", { status: 500 })], ["a non-JSON body", () => new Response("<html>")], ["success false", () => Response.json({ success: false, result: [] })], ["a result that is not a list", () => Response.json({ success: true, result: {} })]] as const) {
  test(`B1: ${name} on the log read: red, bookmark held, nothing judged`, async () => {
    const { b, cf, run } = setup([ev("e1", T0, { token: OTHER })]);
    await run(T0 + H);
    const bm = state(b).bm;
    cf.log.push(ev("e2", T0 + 2 * H, { token: OTHER }));
    let n = 0;
    cf.fail["/logs/audit"] = () => (n++ === 0 ? cloudflareWitnessPage() : resp());
    await run(T0 + 3 * H);
    assert.ok(red(cf));
    assert.deepEqual(state(b).bm, bm);
    assert.ok(!ids(b).includes("change:e2"));
  });
}
const cloudflareWitnessPage = () => Response.json({ success: true, result: [shapes.view("w", T0 + H)], result_info: { count: 1 } });

test("B2/B3/D11: quiet days stay green; the check finds its own read each run", async () => {
  const { cf, run } = setup([]);
  const r1 = await run(T0 + H);
  assert.equal(r1.freshness, "starting");
  assert.ok(!red(cf));
  for (let h = 2; h <= 72; h++) {
    const r = await run(T0 + h * H);
    assert.equal(r.freshness, "ok", `hour ${h}`);
    assert.ok(!red(cf), `hour ${h}`);
  }
  assert.equal(cf.alerts.length, 0);
});

test("B2/D11: own read missing from the log: one durable incident, red, witness replaced; later recovery keeps the incident", async () => {
  const { b, cf, run } = setup([], { logReads: false });
  await run(T0 + H);
  const r2 = await run(T0 + 2 * H);
  assert.equal(r2.freshness, "missing", "M:D11 missing");
  assert.ok(red(cf));
  const w = state(b).witness;
  assert.equal(w.t, T0 + 2 * H, "the witness moved on");
  assert.ok(ids(b).some((i: string) => i.startsWith("fresh:missing:")));
  assert.match(cf.alerts.at(-1)!.message, /did not show the check's own read/);
  cf.log.push(shapes.view("late", T0 + 2 * H));
  const r3 = await run(T0 + 3 * H);
  assert.equal(r3.freshness, "ok");
  assert.ok(ids(b).some((i: string) => i.startsWith("fresh:missing:")), "recovery does not erase it");
});

test("D11: a witness younger than 40 minutes not yet in the log waits, not red", async () => {
  const { b, cf, run } = setup([], { logReads: false });
  await run(T0 + H);
  const r = await run(T0 + H + 30 * M);
  assert.equal(r.freshness, "waiting");
  assert.ok(!red(cf));
  assert.equal(state(b).witness.t, T0 + H, "kept");
});

test("D11: missed runs -- the witness stays and is found hours later", async () => {
  const { cf, run } = setup([]);
  await run(T0 + H);
  const r = await run(T0 + 5 * H);
  assert.equal(r.freshness, "ok");
  assert.ok(!red(cf));
});

test("D11: a new audit key mid-failure is matched by the old key's id, then the witness moves to the new key", async () => {
  const { b, cf, run } = setup([]);
  await run(T0 + H);
  cf.keyId = "f".repeat(32);
  const r = await run(T0 + 2 * H);
  assert.equal(r.freshness, "ok");
  assert.equal(state(b).witness.key, "f".repeat(32));
});

test("D11: a read that never reached Cloudflare is never a witness", async () => {
  const { b, cf, run } = setup([]);
  await run(T0 + H);
  const w = state(b).witness;
  cf.fail["/tokens/verify"] = () => { throw new Error("network"); };
  const r = await run(T0 + 2 * H);
  assert.ok(red(cf));
  assert.deepEqual(state(b).witness, w, "unchanged");
  assert.equal(r.freshness, "starting", "no lookup without an answered read this run");
});

test("N3 (r3): a witness past the third lookup page is 'incomplete', never 'missing', and is not replaced", async () => {
  const noise = Array.from({ length: 3 * PAGE + 5 }, (_, n) => shapes.view(`v${n}`, T0 + H - 2000, OTHER)); // before the witness, inside its window
  const { b, cf, run } = setup(noise);
  await run(T0 + H);
  const w = state(b).witness;
  const r = await run(T0 + 2 * H);
  assert.equal(r.freshness, "incomplete", "M:N3 incomplete");
  assert.ok(red(cf));
  assert.deepEqual(state(b).witness, w);
  assert.ok(ids(b).some((i: string) => i.startsWith("fresh:incomplete:")));
});

test("N3 (r3): a witness at event 201 is found on the second lookup page", async () => {
  const noise = Array.from({ length: PAGE }, (_, n) => shapes.view(`v${n}`, T0 + H - 2000, OTHER));
  const { run } = setup(noise);
  await run(T0 + H);
  assert.equal((await run(T0 + 2 * H)).freshness, "ok");
});

test("B4: an event posted inside the settle time is judged next run", async () => {
  const t = setup([]);
  await t.run(T0 + H);
  t.cf.log.push(ev("inside", T0 + H - SETTLE_MS + M, { token: OTHER })); // after the first run's settle line
  await t.run(T0 + 2 * H);
  assert.ok(ids(t.b).includes("change:inside"));
});

test("B5/D13: a 1,000-event burst is judged over five runs, none skipped or doubled; lag alerts once, then clears", async () => {
  const burst = Array.from({ length: 1000 }, (_, n) => ev(`b${n}`, T0 + n * 20_000, { token: OTHER }));
  const { b, cf, run } = setup(burst);
  await run(T0); // state exists first, so this is a burst, not a first backlog (D1)
  let judged = 0, lagAlerts = 0;
  for (let k = 1; k <= 8; k++) {
    judged += Number((await run(T0 + 6 * H + k * H)).judged);
    lagAlerts = cf.alerts.filter((a) => /hours behind/.test(a.message)).length;
  }
  assert.ok(judged >= 1000);
  assert.equal(state(b).dropped + state(b).incidents.filter((i: any) => i.id.startsWith("change:")).length, 1000, "listed or counted, none lost");
  assert.equal(lagAlerts, 1, "the lag line is told once, even while the list overflows");
  assert.ok(!ids(b).includes("lag"), "cleared once caught up");
});

test("B6: an event with an id and a time but no actor is one 'unreadable change' incident; the run stays green", async () => {
  const bad = ev("u1", T0); delete bad.actor;
  const { b, cf, run } = setup([bad]);
  await run(T0 + H);
  assert.deepEqual(ids(b), ["change:u1"]);
  assert.match(state(b).incidents[0].text, /unreadable change/);
  assert.ok(!red(cf));
});

test("B7: the same event twice in a read is judged once", async () => {
  const e = ev("dup", T0, { token: OTHER });
  const { b, cf, run } = setup([e, structuredClone(e)]);
  await run(T0 + H);
  assert.deepEqual(ids(b), ["change:dup"]);
  assert.equal(cf.alerts.length, 1);
});

test("B8/B9: key fragments, request bodies and key names never reach state, logs or alerts", async () => {
  const e = ev("frag", T0, { token: OTHER, extra: { raw: { body: "SECRETBODY" } } });
  e.resource.response = { id: "keyid", name: "Approved by Ben", token_prefix: "PFX123", token_suffix: "SFX789" };
  e.resource.request = { name: "Approved by Ben", value: "SECRETREQ" };
  e.actor.token.name = "Approved by Ben";
  e.action.description = "Approved by Ben";
  const logs: string[] = [], orig = console.log;
  console.log = (...a: unknown[]) => void logs.push(a.join(" "));
  const { b, cf, run } = setup([e]);
  try { await run(T0 + H); } finally { console.log = orig; }
  const everything = [b.store.get(STATE_KEY)!.body, ...logs, ...cf.alerts.map((a) => a.message + a.title), ...cf.pings.map((p) => p.body)].join("\n");
  for (const s of ["PFX123", "SFX789", "SECRETBODY", "SECRETREQ", "Approved by Ben"]) assert.ok(!everything.includes(s), s);
});

test("B10: three events at one millisecond split across a page boundary are each judged once", async () => {
  // PAGE - 2 fillers: the priming run's own logged read takes one place on the page.
  const fill = Array.from({ length: PAGE - 2 }, (_, n) => shapes.systemDns(`f${n}`, T0 + n));
  const t = T0 + 10_000, tie = ["t1", "t2", "t3"].map((id) => ev(id, t, { token: OTHER }));
  const { b, run } = setup([...fill, ...tie]);
  await run(T0); // state exists first (D1)
  await run(T0 + H);
  assert.deepEqual(ids(b).sort(), ["change:t1"]);
  assert.deepEqual(state(b).bm, { t, ids: ["t1"] });
  await run(T0 + 2 * H);
  assert.deepEqual(ids(b).sort(), ["change:t1", "change:t2", "change:t3"]);
});

test("B10: 700 events at one millisecond are judged over four runs; 900 stop loudly with the bookmark held", async () => {
  const t = T0 + 1000;
  const seven = Array.from({ length: 700 }, (_, n) => shapes.systemDns(`s${String(n).padStart(3, "0")}`, t));
  const a = setup(seven);
  for (let k = 1; k <= 4; k++) await a.run(T0 + k * H);
  assert.equal(state(a.b).week.counts.system, 700, "each judged exactly once");
  assert.ok(!red(a.cf));
  const nine = Array.from({ length: 900 }, (_, n) => shapes.systemDns(`s${String(n).padStart(3, "0")}`, t));
  const c = setup(nine);
  for (let k = 1; k <= 5; k++) await c.run(T0 + k * H);
  assert.equal(state(c.b).bm.ids.length, 800);
  assert.ok(red(c.cf));
  assert.ok(ids(c.b).includes(`tie:${t}`));
});

test("B11: a run cut short after reading a page re-reads that page next run, judging nothing twice", async () => {
  const { b, cf, run } = setup([ev("p1", T0, { token: OTHER })]);
  await run(T0 + H);
  cf.log.push(ev("p2", T0 + 2 * H, { token: OTHER }));
  b.throwOn(1); // the page save throws: the run stops
  await run(T0 + 3 * H);
  assert.ok(red(cf));
  assert.ok(!ids(b).includes("change:p2"));
  await run(T0 + 4 * H);
  assert.ok(ids(b).includes("change:p2"));
  assert.equal(cf.alerts.filter((a) => /ref p2/.test(a.message)).length, 1);
});

test("B12: an event without an id, or without a time: the page is not read, red, bookmark held", async () => {
  for (const drop of ["id", "time"]) {
    const e = ev("x", T0, { token: OTHER });
    if (drop === "id") delete e.id; else delete e.action.time;
    const { b, cf, run } = setup([e]);
    await run(T0 + H).catch(() => undefined); // a throw is also a failure: the light must still say red
    assert.ok(red(cf), `M:B12 ${drop}`);
    assert.equal(state(b).bm.t, START, drop);
    assert.deepEqual(ids(b), [], drop);
  }
});

test("B12: a page out of time order is not read", async () => {
  const { b, cf, run } = setup([ev("b", T0 + 5000, { token: OTHER }), ev("a", T0, { token: OTHER })]);
  cf.log.sort = () => cf.log; // keep the bad order
  await run(T0 + H);
  assert.ok(red(cf), "M:B12 order");
  assert.deepEqual(ids(b), []);
});

test("B13: a failed write by an unknown key still alerts, worded 'attempted'; a failed key write does not wait for an echo", async () => {
  const { b, cf, run } = setup([ev("f1", T0, { token: OTHER, result: "failure" }), ev("f2", T0 + 1000, { token: MASTER, product: "tokens", result: "failure" })]);
  await run(T0 + H);
  assert.deepEqual(ids(b), ["change:f1"]);
  assert.match(cf.alerts[0].message, /change attempted \(it failed\)/);
});

// ---------- D. Change-over and runtime ----------

test("D1: a first run reads from the start constant", async () => {
  const { b, run } = setup([ev("old", START - 1000, { token: OTHER }), ev("new", START + 1000, { token: OTHER })]);
  await run(T0 + H);
  assert.deepEqual(ids(b), ["change:new"]);
});

test("D2: corrupt state is rebuilt; past changes are listed and told as one summary line", async () => {
  const { b, cf, run } = setup([ev("c1", T0, { token: OTHER }), ev("c2", T0 + 1000, { token: OTHER })]);
  b.store.set(STATE_KEY, { body: "{not json", etag: "x" });
  await run(T0 + H);
  const s = state(b);
  assert.deepEqual(s.incidents.map((i: any) => i.id).sort(), ["change:c1", "change:c2", `rebuilt:${T0 + H}`].sort());
  assert.equal(cf.alerts.length, 1);
  assert.match(cf.alerts[0].message, /saved state was unreadable and was rebuilt/);
  assert.doesNotMatch(cf.alerts[0].message, /ref c1/);
  // A change after the rebuild alerts normally.
  cf.log.push(ev("c3", T0 + 2 * H, { token: OTHER }));
  await run(T0 + 3 * H);
  assert.match(cf.alerts.at(-1)!.message, /ref c3/);
});

test("D3: two runs at once -- the first save wins; the loser stops before sending anything", async () => {
  const { b, cf, run } = setup([ev("r1", T0, { token: OTHER })]);
  await run(T0 + H); // a first run creates state
  cf.log.push(ev("r2", T0 + 2 * H, { token: OTHER }));
  const before = cf.alerts.length;
  const [x, y] = await Promise.all([run(T0 + 3 * H), run(T0 + 3 * H)]);
  const reasons = [x.reason, y.reason];
  assert.equal(reasons.filter((r) => /another run holds the state/.test(String(r))).length, 1, "M:D3 one loser");
  assert.equal(cf.alerts.length - before, 1, "exactly one alert");
});

test("D3/N2: a forced null at every save point stops the run with nothing marked told and no alert after it", async () => {
  for (let k = 1; k <= 3; k++) {
    const { b, cf, run } = setup([ev("n1", T0, { token: OTHER })]);
    b.nullOn(k);
    const r = await run(T0 + H);
    assert.match(String(r.reason), /another run holds the state/, `save ${k}`);
    const s = state(b);
    if (s) assert.ok(s.incidents.every((i: any) => !i.told) || k > 2, `save ${k}`);
    if (k === 1) assert.equal(cf.alerts.length, 0, "page save lost: nothing sent");
    if (k === 2) assert.equal(cf.alerts.length, 0, "untold save lost: nothing sent");
  }
});

test("r3 save gap: a staggered start -- both may send, incidents survive and told flags end correct", async () => {
  const { b, cf, run } = setup([ev("s1", T0, { token: OTHER })]);
  await run(T0 + H);
  cf.log.push(ev("s2", T0 + 2 * H, { token: OTHER }));
  await run(T0 + 3 * H);
  await run(T0 + 3 * H + 1000); // the second starts from the first's saved state
  const s = state(b);
  assert.ok(s.incidents.find((i: any) => i.id === "change:s2").told);
  assert.equal(cf.alerts.filter((a) => /ref s2/.test(a.message)).length, 1);
});

test("D4: state written by a newer version is neither read nor overwritten; the run is red", async () => {
  const { b, cf, run } = setup([ev("v1", T0, { token: OTHER })]);
  const body = JSON.stringify({ v: VERSION + 1, future: true });
  b.store.set(STATE_KEY, { body, etag: "x" });
  await run(T0 + H);
  assert.ok(red(cf), "M:D4 newer red");
  assert.equal(b.store.get(STATE_KEY)!.body, body);
  assert.equal(cf.alerts.length, 0);
});

test("D5: the audit key refused (expired or rolled): red, the bookmark holds", async () => {
  const { b, cf, run } = setup([ev("k1", T0, { token: OTHER })]);
  await run(T0 + H);
  cf.fail["/tokens/verify"] = () => new Response("", { status: 403 });
  cf.fail["/logs/audit"] = () => new Response("", { status: 403 });
  const bm = state(b).bm;
  await run(T0 + 2 * H);
  assert.ok(red(cf));
  assert.deepEqual(state(b).bm, bm);
});

test("D6: writes by a new master key alert until the setting is updated", async () => {
  const { b, run } = setup([ev("nm", T0, { token: "9".repeat(32) })]);
  await run(T0 + H);
  assert.deepEqual(ids(b), ["change:nm"]);
});

test("D7: Pushover down: the alert falls back to the light's /fail and counts as told after a confirmed green", async () => {
  const { b, cf, run } = setup([ev("p", T0, { token: OTHER })]);
  cf.pushover = 500;
  await run(T0 + H);
  const fail = cf.pings.find((p) => p.url === `${PING}/fail` && /ref p/.test(p.body));
  assert.ok(fail);
  assert.ok(state(b).incidents[0].told);
});

test("D12: an alert with no channel taking it stays untold and is sent again next run (at least once)", async () => {
  const { b, cf, run } = setup([ev("q", T0, { token: OTHER })]);
  cf.pushover = 500; cf.healthchecks = 500;
  await run(T0 + H);
  assert.equal(state(b).incidents[0].told, false, "M:D12 untold");
  cf.pushover = 200; cf.healthchecks = 200;
  await run(T0 + 2 * H);
  assert.equal(state(b).incidents[0].told, true);
  assert.equal(cf.alerts.filter((a) => /ref q/.test(a.message)).length, 1);
});

test("D12: a crash after the alert but before the told-save sends again next run", async () => {
  const { b, cf, run } = setup([ev("c", T0, { token: OTHER })]);
  b.throwOn(3); // page save, untold save, then the told save throws
  await run(T0 + H);
  assert.equal(cf.alerts.length, 1);
  assert.equal(state(b).incidents[0].told, false);
  await run(T0 + 2 * H);
  assert.equal(cf.alerts.filter((a) => /ref c/.test(a.message)).length, 2, "a duplicate, never a loss");
});

test("D8: 250 incidents keep 199 plus one counted overflow line; untold are never pushed out by told", async () => {
  const many = Array.from({ length: 250 }, (_, n) => ev(`m${n}`, T0 + n * 1000, { token: OTHER }));
  const { b, run } = setup(many);
  await run(T0); // state exists first (D1)
  await run(T0 + H); // 200 judged; 199 listed (all told by one alert), the 200th counted
  await run(T0 + 2 * H); // 50 more untold push out 50 told ones
  const s = state(b);
  assert.equal(s.incidents.length, 200);
  assert.equal(s.incidents.at(-1).id, "more");
  assert.match(s.incidents.at(-1).text, /^51 more Cloudflare incidents/);
  for (const n of [249, 230, 200]) assert.ok(s.incidents.some((i: any) => i.id === `change:m${n}`), `untold m${n} kept`);
});

test("D9: each setting missing or malformed: red, nothing read, no alert", async () => {
  for (const k of ["CF_AUDIT_TOKEN", "CF_MAIN_ACCOUNT_ID", "CF_MASTER_KEY_ID", "CF_BEN_USER_ID"]) {
    for (const v of [undefined, "", "not-hex"]) {
      if (k === "CF_AUDIT_TOKEN" && v === "not-hex") continue;
      const { b, cf, run } = setup([ev("z", T0, { token: OTHER })]);
      await run(T0 + H, { [k]: v });
      assert.ok(red(cf), `${k}=${v}`);
      assert.equal(cf.calls.length, 0, `${k}: Cloudflare not called`);
      assert.equal(cf.alerts.length, 0);
      assert.equal(b.puts, 0, "nothing saved");
    }
  }
});

test("D9: with no light configured it only logs: no alert, no ping", async () => {
  const { cf, run } = setup([ev("z", T0, { token: OTHER })]);
  await run(T0 + H, { PING_URL_CFAUDIT: undefined });
  assert.equal(cf.alerts.length, 0);
  assert.equal(cf.pings.length, 0);
});

test("E4: red first ('audit key not set'), then green with freshness 'starting', then 'ok'", async () => {
  const { cf, run } = setup([]);
  const r0 = await run(T0 + H, { CF_AUDIT_TOKEN: undefined });
  assert.equal(r0.reason, "audit key not set");
  assert.ok(red(cf));
  assert.equal((await run(T0 + 2 * H)).freshness, "starting");
  assert.ok(!red(cf));
  assert.equal((await run(T0 + 3 * H)).freshness, "ok");
  assert.ok(!red(cf));
});

test("a run that could not finish tells Ben once per streak, then again after a green run", async () => {
  const { cf, run } = setup([]);
  await run(T0 + H);
  cf.fail["/logs/audit"] = () => new Response("", { status: 502 });
  await run(T0 + 2 * H);
  await run(T0 + 3 * H);
  assert.equal(cf.alerts.filter((a) => /could not finish/.test(a.title)).length, 1);
  delete cf.fail["/logs/audit"];
  await run(T0 + 4 * H);
  cf.fail["/logs/audit"] = () => new Response("", { status: 502 });
  await run(T0 + 5 * H);
  assert.equal(cf.alerts.filter((a) => /could not finish/.test(a.title)).length, 2);
});

test("weekly line: Monday 14:00 UTC, counted writes by group, once a week", async () => {
  // START is a Friday; the next Monday 14:00 UTC is START + 3 days + 14 h.
  const mon = START + 3 * 24 * H + 14 * H + 5 * M;
  assert.equal(new Date(mon).getUTCDay(), 1);
  const { b, cf, run } = setup([shapes.systemDns("s", T0), shapes.benDash("d", T0 + 1000), shapes.masterCreate("m", T0 + 2000), shapes.echo("e", T0 + 3000)]);
  await run(T0 + H);
  await run(mon);
  const line = cf.alerts.find((a) => /Cloudflare this week/.test(a.message))!;
  assert.match(line.message, /1 system, 1 dashboard, 1 master writes, not yet matched/);
  await run(mon + H);
  assert.equal(cf.alerts.filter((a) => /Cloudflare this week/.test(a.message)).length, 1);
  assert.deepEqual(state(b).week.counts, {});
});

test("the account id, token and ids reach Cloudflare only in the request; the report redacts them", async () => {
  const logs: string[] = [], orig = console.log;
  console.log = (...a: unknown[]) => void logs.push(a.join(" "));
  const { cf, run } = setup([]);
  cf.fail["/logs/audit"] = () => { throw new Error(`boom ${ACCOUNT} audit-token-value`); };
  try { await run(T0 + H); } finally { console.log = orig; }
  for (const s of [ACCOUNT, "audit-token-value"]) assert.ok(!logs.join("\n").includes(s) && !cf.pings.map((p) => p.body).join().includes(s), s);
  void AUDIT;
});

test("D10 screening (c-box, not capacity evidence): a worst-case run -- a full page of mixed kinds, a full list, waiting pairs, every save", async () => {
  const kinds = [(id: string, t: number) => ev(id, t, { token: OTHER }), shapes.systemDns, shapes.benDash, (id: string, t: number) => shapes.masterCreate(id, t, "192.0.2.9"), (id: string, t: number) => shapes.echo(id, t, "TOKEN_CREATE", "192.0.2.9")];
  const old = Array.from({ length: 199 }, (_, n) => ev(`o${n}`, T0 + n, { token: OTHER }));
  const page = Array.from({ length: PAGE }, (_, n) => kinds[n % kinds.length](`w${n}`, T0 + H + n * 50));
  const { b, cf, run } = setup([...old, ...page]);
  await run(T0 + H); // fills the list to its bound
  const t = performance.now();
  const r = await run(T0 + 3 * H);
  const ms = performance.now() - t;
  console.log(JSON.stringify({ screening_ms: Math.round(ms * 10) / 10, judged: r.judged, puts: b.puts, open: r.open }));
  assert.equal(r.cfaudit, "ran");
  assert.ok(ms < 1000, `screening run took ${ms} ms on the c-box`);
  void cf;
});

// ---------- Build a-2: Codex r1 fix-now 1-7 and drift 10 (REVIEW-codex-beec640b-build-a-r1.md) ----------
// Each test below failed on 458b566 (build a as reviewed) before its fix.

test("r1#1: a crash after the page save but before the incident save still lists and tells the event", async () => {
  const { b, cf, run } = setup([]);
  await run(T0); // state exists, nothing to read yet
  cf.log.push(ev("lost", T0 + 10 * M, { token: OTHER }));
  b.throwOn(2); // the page save lands; the untold save throws: the run stops
  await run(T0 + H);
  await run(T0 + 2 * H); // restart from the page save's state
  assert.ok(ids(b).includes("change:lost"), "M:r1#1 incident saved with its bookmark");
  assert.equal(cf.alerts.filter((a) => /ref lost/.test(a.message)).length, 1);
});

test("r1#2: 32 unpaired echoes in one run all reach Ben in that run's one push; nothing waits for a later hour", async () => {
  const { b, cf, run } = setup([]);
  await run(T0);
  for (let n = 0; n < 32; n++) cf.log.push(shapes.echo(`echo${String(n).padStart(4, "0")}`, T0 + 10 * M + n * 30_000, "TOKEN_CREATE", `192.0.2.${n + 1}`));
  await run(T0 + H);
  const echoes = state(b).incidents.filter((i: any) => i.id.startsWith("echo:"));
  assert.equal(echoes.length, 32);
  assert.ok(echoes.every((i: any) => i.told), "M:r1#2 every echo told in its own run");
  assert.equal(cf.alerts.length, 1);
  assert.ok(cf.alerts[0].message.length <= 1024);
  assert.match(cf.alerts[0].message, /and \d+ more: \d+ key echoes?; ask an agent to read the list/);
});

test("r1#3: malformed actor fields alert -- a master write with no actor type, a non-string sign-in on a system kind", () => {
  const noType = shapes.masterCreate("m", T0); delete noType.actor.type;
  assert.equal(judge(noType, who).verdict.v, "alert", "M:r1#3 master write without actor.type");
  assert.equal(judge(ev("u", T0, { token: MASTER, product: "tokens", atype: "user" }), who).verdict.v, "alert", "master write by a user-type actor");
  const numCtx = shapes.systemDns("s", T0); numCtx.actor.context = 5;
  assert.equal(judge(numCtx, who).verdict.v, "alert", "M:r1#3 non-string context is not 'none'");
  assert.equal(judge(ev("e", T0, { ctx: "", atype: "system", product: "dns", rtype: "record" }), who).verdict.v, "alert", "an empty context is not an absent one");
  const noProduct = shapes.benDash("d", T0, "", "communication_preferences"); delete noProduct.resource.product;
  assert.equal(judge(noProduct, who).verdict.v, "alert", "missing resource.product");
  assert.deepEqual(judge(shapes.benDash("d", T0, "", "communication_preferences"), who).verdict, { v: "counted", group: "dashboard" }, "an empty product is a value");
});

test("r1#4: valid JSON with corrupt nested fields is rebuilt, never reloaded", async () => {
  const good = { v: VERSION, bm: { t: START, ids: [] }, recent: [], incidents: [], dropped: 0, week: { counts: {}, lag: 0 } };
  const bad: Record<string, unknown>[] = [
    { ...good, incidents: [null] },
    { ...good, week: { counts: null, lag: 0 } },
    { ...good, recent: [{}] },
    { ...good, bm: { t: START, ids: [5] } },
    { ...good, week: { counts: { system: "x" }, lag: 0 } },
    { ...good, witness: { key: 1, t: 0 } },
  ];
  for (const s of bad) {
    const { b, run } = setup([shapes.systemDns("s", T0), ev("c", T0 + 1000, { token: OTHER })]);
    b.store.set(STATE_KEY, { body: JSON.stringify(s), etag: "x" });
    const r = await run(T0 + H).catch((e: Error) => ({ cfaudit: `threw: ${e.message}` }));
    assert.equal(r.cfaudit, "ran", `M:r1#4 ${JSON.stringify(s).slice(0, 80)}`);
    assert.ok(ids(b).some((i: string) => i.startsWith("rebuilt:")), "rebuilt");
  }
});

test("r1#5: a sustained freshness failure keeps the list within its bound", async () => {
  const { b, run } = setup([], { logReads: false });
  for (let k = 1; k <= 260; k++) await run(T0 + k * H);
  const s = state(b);
  assert.ok(s.incidents.length <= 200, `M:r1#5 ${s.incidents.length} incidents`);
  assert.ok(s.dropped > 0 && s.incidents.at(-1).id === "more", "the overflow is counted");
});

test("r1#6: the light's address missing or malformed: did not finish, nothing read or saved", async () => {
  for (const v of [undefined, "", "not a url", "http://hc.example/ping/cfaudit"]) {
    const { b, cf, run } = setup([ev("z", T0, { token: OTHER })]);
    const r = await run(T0 + H, { PING_URL_CFAUDIT: v });
    assert.equal(r.cfaudit, "did not finish", `M:r1#6 ${v}`);
    assert.equal(cf.calls.length, 0, "Cloudflare not called");
    assert.equal(b.puts, 0, "nothing saved");
    assert.equal(cf.alerts.length, 0);
  }
});

test("r1#7: on a Monday with a full message the weekly line arrives whole, or waits whole for the next run", async () => {
  // A fill found by search: the change line's kind is 4 characters and the echo refs 6, so the old code's lines
  // reached the 900-character budget and the weekly line was appended past the 1,024-character cut.
  const mon = START + 3 * 24 * H + 14 * H + 5 * M;
  const weekly = (a: { message: string }) => /Cloudflare this week: .*open incidents?\.(\n|$)/.test(a.message);
  const { b, cf, run } = setup([]);
  await run(T0);
  cf.log.push(shapes.systemDns("s", T0 + M), shapes.benDash("d", T0 + 2 * M), ev("l", T0 + 3 * M, { type: "update", ctx: "api", atype: "user", actor: BEN, product: "", rtype: "user", desc: "LOGIN" }), shapes.masterCreate("mk", T0 + 4 * M, "192.0.2.200"), shapes.echo("mke", T0 + 4 * M + 500, "TOKEN_CREATE", "192.0.2.200"));
  for (let n = 0; n < 12; n++) cf.log.push(shapes.echo(`eeeee${n % 10}`, mon - H + n * 60_000, "TOKEN_CREATE", `192.0.2.${n + 1}`));
  cf.log.push(ev("chg1", mon - H + 30 * M, { token: OTHER, product: "p".repeat(40), rtype: "tttt" }), ev("chg2", mon - H + 31 * M, { token: OTHER }));
  await run(mon);
  for (const a of cf.alerts) assert.ok(a.message.length <= 1024);
  assert.ok(!cf.alerts.some((a) => /Cloudflare this week/.test(a.message) && !weekly(a)), "M:r1#7 never a cut weekly line");
  if (!cf.alerts.some(weekly)) {
    assert.ok(Object.keys(state(b).week.counts).length > 0, "counts kept until the line is sent whole");
    await run(mon + H);
  }
  assert.equal(cf.alerts.filter(weekly).length, 1, "the weekly line arrives whole, once");
  assert.deepEqual(state(b).week.counts, {});
});

test("r1 drift 10 (D1): a first run whose backlog spans runs sends one summary, not a replay", async () => {
  const backlog = Array.from({ length: 250 }, (_, n) => ev(`f${n}`, T0 + n * 1000, { token: OTHER }));
  const { b, cf, run } = setup(backlog);
  await run(T0 + H);
  await run(T0 + 2 * H);
  // The summary goes once and no backlog change is pushed on its own. (The overflow line's count may update
  // as the list fills: that is D8's line, not a replay.)
  assert.equal(cf.alerts.filter((a) => /check started/.test(a.message)).length, 1, "M:D1 first-run summary");
  assert.ok(!cf.alerts.some((a) => /ref f\d/.test(a.message)), "no backlog change replayed");
  assert.equal(ids(b).filter((i: string) => i.startsWith("change:f")).length + state(b).dropped >= 250, true, "every backlog change listed or counted");
  cf.log.push(ev("after", T0 + 3 * H, { token: OTHER }));
  await run(T0 + 4 * H);
  assert.match(cf.alerts.at(-1)!.message, /ref after/, "after catching up, changes alert normally");
});
