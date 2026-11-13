// Fakes for the Cloudflare outside-record check (card beec640b), faked only at the edges: Cloudflare's
// API, the COPY bucket and the alert channels. The check's own reader, judging and state code run as
// in production. Every id is synthetic: no live account, key, user, address or zone appears here.
export const ACCOUNT = "c".repeat(32), MASTER = "a".repeat(32), BEN = "b".repeat(32), OTHER = "d".repeat(32), AUDIT = "e".repeat(32);
export const PING = "https://hc.example/ping/cfaudit";
export const env = (bucket: unknown, over: Record<string, unknown> = {}) => ({
  COPY: bucket, PING_URL: "https://hc.example/ping/main", PING_URL_CFAUDIT: PING, PUSHOVER_TOKEN: "t".repeat(30), PUSHOVER_USER: "u".repeat(30),
  CF_AUDIT_TOKEN: "audit-token-value", CF_MAIN_ACCOUNT_ID: ACCOUNT, CF_MASTER_KEY_ID: MASTER, CF_BEN_USER_ID: BEN, ...over,
}) as any;

/** The COPY bucket: get and conditional put, R2's way (null when the condition fails; a fresh etag per write). */
export function bucket() {
  const store = new Map<string, { body: string; etag: string }>();
  let n = 0, nullAt = new Set<number>(), throwAt = new Set<number>(), puts = 0;
  return {
    store,
    /** The k-th put from now (1-based) answers null, as a lost condition would; `throwAt` makes it throw. */
    nullOn(...k: number[]) { nullAt = new Set(k.map((x) => puts + x)); },
    throwOn(...k: number[]) { throwAt = new Set(k.map((x) => puts + x)); },
    get puts() { return puts; },
    async get(k: string) { const v = store.get(k); return v ? { etag: v.etag, text: async () => v.body } : null; },
    async put(k: string, body: string, o?: { onlyIf?: { etagMatches?: string } | Headers }) {
      puts++;
      if (throwAt.has(puts)) throw new Error("R2 down");
      if (nullAt.has(puts)) return null;
      const cur = store.get(k), c = o?.onlyIf;
      if (c instanceof Headers) { if (c.get("If-None-Match") === "*" && cur) return null; }
      else if (c?.etagMatches !== undefined && cur?.etag !== c.etagMatches) return null;
      const etag = `etag${++n}`;
      store.set(k, { body, etag });
      return { etag };
    },
  };
}

type Ev = Record<string, any>;
/** One audit-log event. `t` is ms since the epoch. */
export function ev(id: string, t: number, o: { type?: string; ctx?: string | null; atype?: string; actor?: string; token?: string; product?: string | null; rtype?: string | null; desc?: string; result?: string; ip?: string; extra?: Ev } = {}): Ev {
  const actor: Ev = { type: o.atype ?? "account", ip_address: o.ip ?? "192.0.2.10" };
  if (o.ctx !== null) actor.context = o.ctx ?? "api_token";
  if (o.actor) actor.id = o.actor;
  if (o.token) actor.token = { id: o.token, name: "front-desk probe x" };
  const resource: Ev = {};
  if (o.product !== null) resource.product = o.product ?? "dns_records";
  if (o.rtype) resource.type = o.rtype;
  return { id, action: { time: new Date(t).toISOString(), type: o.type ?? "create", result: o.result ?? "success", description: o.desc ?? "" }, actor, resource, ...o.extra };
}
// Shapes taken from the real log's kinds (counts only were read; values here are synthetic).
export const shapes = {
  masterCreate: (id: string, t: number, ip?: string) => ev(id, t, { token: MASTER, product: "tokens", ip }),
  masterDelete: (id: string, t: number, ip?: string) => ev(id, t, { type: "delete", token: MASTER, product: "tokens", ip }),
  echo: (id: string, t: number, desc = "TOKEN_CREATE", ip?: string) => ev(id, t, { type: desc === "TOKEN_CREATE" ? "create" : "update", ctx: "api", atype: "user", actor: BEN, product: "account", rtype: "settings", desc, ip }),
  systemDns: (id: string, t: number) => ev(id, t, { ctx: null, atype: "system", product: "dns", rtype: "record" }),
  benDash: (id: string, t: number, product = "dns_records", rtype?: string) => ev(id, t, { ctx: "dash", atype: "user", actor: BEN, product, rtype }),
  view: (id: string, t: number, token = AUDIT) => ev(id, t, { type: "view", token, product: "logs", rtype: "audit" }),
};

/**
 * Cloudflare's API as the check uses it, following the paging the live probe showed (2026-11-12):
 * `since` inclusive, `before` exclusive, ascending, `limit`, a cursor in result_info while more remain.
 * tokens/verify answers with the audit key's id and, when `logReads`, logs that read at the request time.
 */
export function cloudflare(log: Ev[], o: { keyId?: string; logReads?: boolean; clock?: () => number } = {}) {
  const calls: string[] = [], alerts: { title: string; message: string }[] = [], pings: { url: string; body: string }[] = [];
  const fail: Record<string, () => Response> = {};
  let seq = 0;
  const api = {
    log, calls, alerts, pings, fail,
    keyId: o.keyId ?? AUDIT,
    pushover: 200,
    healthchecks: 200,
    fetch: async (req: Request): Promise<Response> => {
      const u = new URL(req.url);
      if (u.hostname === "api.pushover.net") {
        const f = new URLSearchParams(await req.text());
        if (api.pushover === 200) alerts.push({ title: f.get("title")!, message: f.get("message")! });
        return new Response("", { status: api.pushover });
      }
      if (u.hostname === "hc.example") { pings.push({ url: req.url, body: await req.text() }); return new Response("", { status: api.healthchecks }); }
      if (req.headers.get("Authorization") !== "Bearer audit-token-value") return new Response("", { status: 403 });
      const path = u.pathname.replace(`/client/v4/accounts/${ACCOUNT}`, "");
      calls.push(path);
      for (const [k, f] of Object.entries(fail)) if (path.startsWith(k)) return f();
      if (path === "/tokens/verify") {
        if (o.logReads !== false) log.push(shapes.view(`own${++seq}`, (o.clock ?? Date.now)(), api.keyId)), log.sort((a, b) => Date.parse(a.action.time) - Date.parse(b.action.time));
        return Response.json({ success: true, result: { id: api.keyId, status: "active" } });
      }
      if (path === "/logs/audit") {
        const since = Date.parse(u.searchParams.get("since")!), before = Date.parse(u.searchParams.get("before")!), limit = Number(u.searchParams.get("limit"));
        // An event with no readable time is returned as is: the check must refuse the page, not the fake.
        const all = log.filter((e) => { const t = Date.parse(e.action?.time); return Number.isNaN(t) || (t >= since && t < before); });
        const from = Number(u.searchParams.get("cursor") ?? 0), slice = all.slice(from, from + limit);
        const more = from + limit < all.length;
        return Response.json({ success: true, errors: [], result: slice, result_info: more ? { count: slice.length, cursor: String(from + limit) } : { count: slice.length } });
      }
      return new Response("", { status: 404 });
    },
  };
  return api;
}

/** The state the check saved, parsed. */
export const state = (b: ReturnType<typeof bucket>) => JSON.parse(b.store.get("state/cfaudit.json")?.body ?? "null");
