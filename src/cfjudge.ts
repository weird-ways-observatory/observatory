// Card beec640b build a (outside-record check): how ONE event in the main Cloudflare account's audit
// log is judged, from its own fields only. Nothing here looks at a nearby event: an event never
// inherits a verdict (REFINE-beec640b 5.1, Codex R1). The table below was taken from the 210 real
// writes of 2026-09-01..11-12 (re-read 2026-11-12, counts only); anything not on it alerts, because an
// unknown-risk default is never removed by a claim that it does not apply (technical-decision threat-fit).
// Event text is writer-influenced (key names, descriptions): only fixed words and short, character-
// checked Cloudflare field values ever leave this file; key fragments and request bodies are never read.

export interface Who { master: string; ben: string } // the vault's master key id; Ben's user id

/** Words from the event, safe to show: Cloudflare's own short field values, else a fixed word. */
export const word = (x: unknown): string => (typeof x !== "string" ? "missing" : x === "" ? "none" : /^[A-Za-z0-9_.-]{1,40}$/.test(x) ? x : "unknown");
const str = (x: unknown) => (typeof x === "string" ? x : "");
const obj = (x: unknown): Record<string, unknown> | undefined => (x && typeof x === "object" && !Array.isArray(x) ? (x as Record<string, unknown>) : undefined);

export type Verdict =
  | { v: "read" } // a view: not judged (reads are a stated blind spot)
  | { v: "counted"; group: "system" | "dashboard" | "sign-in" | "master writes, not yet matched" } // counted in the weekly line
  | { v: "alert"; why: string } // one incident by event id
  | { v: "echo"; action: Action } // an `api` TOKEN_* echo: always pushes (Ben, c79e2293 A); pairing only labels it
  | { v: "unreadable"; why: string }; // has an id and a time but not the fields to judge it

export type Action = "create" | "delete" | "update";
export interface Judged { verdict: Verdict; label: string; how: string; attempted: boolean; pair?: { k: "key" | "echo"; a: Action; ip: string } }

// (product|type) pairs a system actor writes on its own: DNS, certificates, zone settings.
const SYSTEM = new Set(["dns|record", "certificates|certificate_pack", "certificates|zone_settings", "zone|settings"]);
// Ben's known dashboard writes of kinds that are not keys or members: counted weekly, never pushed.
const DASH = new Set(["r2|buckets.lifecycle", "r2|buckets.lock", "access|apps", "workers|subdomain", "dns_records|", "|communication_preferences"]);
// The three echoes Cloudflare logs under Ben's id for an account-key change, mapped to the key event's action
// (a revoke is logged as an update; its key event is a delete -- VERIFIED 2026-11-12, 19 of 19).
const ECHO: Record<string, Action> = { TOKEN_CREATE: "create", TOKEN_REVOKE: "delete", TOKEN_UPDATE: "update" };
const WRITES = new Set(["create", "delete", "update"]);

export function judge(e: Record<string, unknown>, who: Who): Judged {
  const action = obj(e.action), actor = obj(e.actor), res = obj(e.resource);
  const type = action && typeof action.type === "string" ? action.type : undefined;
  const product = str(res?.product), rtype = str(res?.type);
  // Alert words (live alert 2026-11-13): a field Cloudflare left out is not shown, and key changes read plainly.
  const label = `${res?.product === "tokens" ? "API key" : word(res?.product)}${res?.type === undefined ? "" : `/${word(res.type)}`} ${word(type)}`;
  // A sign-in field Cloudflare left out (system writes: VERIFIED 2026-11-12, 60 of 60) differs from one that is
  // present but not text: the second is malformed and never reads as "none" (Codex r1 #3).
  const rawCtx = actor?.context, ctx = typeof rawCtx === "string" ? rawCtx : undefined, atype = str(actor?.type);
  const how = ctx !== undefined ? word(ctx) : rawCtx !== undefined ? "unknown" : atype ? word(atype) : "missing";
  const attempted = action?.result !== "success";
  const out = (verdict: Verdict, pair?: Judged["pair"]): Judged => ({ verdict, label, how, attempted, pair });
  if (!action || !type || !actor || !res) return out({ v: "unreadable", why: "missing action, actor or resource" });
  if (type === "view") return out({ v: "read" });
  if (!WRITES.has(type)) return out({ v: "alert", why: "a kind of change the check has not seen" });
  const key = `${product}|${rtype}`;
  const accountKey = product === "tokens" && rtype === "";
  const anyKey = accountKey || (product === "" && rtype === "tokens");
  const member = /member|role/i.test(product) || /member|role/i.test(rtype);
  // Only a successful account-key write is expected to have an echo; only those pair.
  const ip = str(actor.ip_address);
  const keyPair = accountKey && !attempted ? { k: "key" as const, a: type as Action, ip } : undefined;
  const isBen = atype === "user" && typeof actor.id === "string" && actor.id === who.ben;
  if (typeof res.product !== "string") return out({ v: "alert", why: "a change with no product named" }, keyPair);

  if (atype === "system" && rawCtx === undefined) return out(SYSTEM.has(key) ? { v: "counted", group: "system" } : { v: "alert", why: "a system change of a kind that is never automatic" });
  if (ctx === "dash") {
    if (!isBen) return out({ v: "alert", why: "a dashboard change by someone other than Ben" }, keyPair);
    if (anyKey || member) return out({ v: "alert", why: "a key or member change in the dashboard" }, keyPair);
    return out(product === "analytics" && rtype.startsWith("query.") || DASH.has(key) ? { v: "counted", group: "dashboard" } : { v: "alert", why: "a dashboard change of a kind the check has not seen" });
  }
  if (ctx === "api") {
    if (!isBen) return out({ v: "alert", why: "an api change by someone other than Ben" });
    if (key === "|user" && action.description === "LOGIN") return out({ v: "counted", group: "sign-in" });
    const echo = key === "account|settings" && typeof action.description === "string" && Object.hasOwn(ECHO, action.description) ? ECHO[action.description] : undefined;
    if (echo) return out({ v: "echo", action: echo }, attempted ? undefined : { k: "echo", a: echo, ip });
    return out({ v: "alert", why: "an api change of a kind the check has not seen" });
  }
  if (ctx === "api_token") {
    const token = obj(actor.token);
    if (token?.id !== who.master) return out({ v: "alert", why: "a write by a key other than the vault's master key" }, keyPair);
    // The master key is an account key: its writes carry actor.type "account" (VERIFIED 2026-11-12, 35 of 35).
    if (atype !== "account") return out({ v: "alert", why: "a master-key write with an unknown actor type" }, keyPair);
    if (accountKey && (type === "create" || type === "delete")) return out({ v: "counted", group: "master writes, not yet matched" }, keyPair);
    return out({ v: "alert", why: accountKey ? "the master key updated a key (no job does that)" : "the master key wrote something other than a key" }, keyPair);
  }
  // api_key (a Global API Key), oauth, cloudflare_admin, a missing or unknown sign-in.
  return out({ v: "alert", why: ctx === "api_key" ? "a write by a Global API Key" : "a write signed in a way the check has not seen" }, keyPair);
}
