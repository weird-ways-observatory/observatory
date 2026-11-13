// One-tap card approvals (card 586da182; studio-os docs/specifications/studio-architecture/spike-08313e62/
// REFINE-586da182.md v2.2). A card is 1-5 ordinary grants run in order, approved by one Face ID tap over the
// card hash. One place for the card format, used by both sides: the recorder (src/recorder/ledger.ts) refuses
// a card approval that breaks it before storing anything, and the hourly checker (src/runcheck.ts) re-reads
// stored card records against the same rules. Every refusal is a fixed reason, never the writer's text.
//
// Name overlap: here `card` is a request's card id (a grant-id-shaped string), set on each entry's `request`
// record. Inside run ops (ops.ts) `card` is a Brain task id, a different thing on a different record type.
import { GRANT, sha256, unb64, type WriterRecord } from "./contract.ts";
import { canonical } from "./recorder/passkey.ts";

/**
 * Jobs a card may hold, the Observatory's own list (APPROACH §13): changed only by a PR Ben merges in an org
 * no agent can reach. Empty refuses every card (an off switch beside the vault's). gh.repo.create joined in
 * card build 4 (77ec1e64): the vault makes an empty private repo on Ben's card tap.
 */
export const CARD_ELIGIBLE: readonly string[] = Object.freeze(["test.echo", "cf.zone.read", "cf.dns.list", "cf.audit.read", "gh.repo.create"]);
export const CARD_SHARE = 100; // of the tap pool's 400 daily slots: at most 25 card entries a UTC day
export const CARD_MAX = 5; // entries on one card
export const CARD_RUN_MS = 15 * 60_000; // a card's deadline is at most its grants' expiry + this
export const CARD_RESULT_MS = 3_600_000; // the checker expects each entry's result by deadline + this
export const CARD_OUTCOMES: readonly string[] = Object.freeze(["done", "failed", "unknown"]);

/** The repo-maker job (card 77ec1e64). Its `done` result names the repo GitHub made by id, so the nightly check and M1 can match it. */
export const REPO_JOB = "gh.repo.create";
const REPO_ID = /^[1-9][0-9]{0,19}$/;
/**
 * Why a result's `repo_id` is refused, or undefined (REFINE-77ec1e64 X1, Y1): a `done` gh.repo.create result must
 * carry GitHub's repository id as a string of digits; no other result may carry one. Used by the recorder and the checker.
 */
export function repoIdRefusal(r: Record<string, unknown>): string | undefined {
  const has = Object.hasOwn(r, "repo_id");
  if (r.job === REPO_JOB && r.outcome === "done") return has && typeof r.repo_id === "string" && REPO_ID.test(r.repo_id) ? undefined : "a done gh.repo.create result must carry GitHub's repo_id (digits)";
  return has ? "only a done gh.repo.create result may carry a repo_id" : undefined;
}

/**
 * Jobs that open the Cloudflare master (card 139071ea; studio-os REFINE-139071ea-cf-keys-in-results.md v2.1 R6), the
 * Observatory's own list: only their results carry `cf`, the keys the tap made and deleted, so the hourly audit
 * check (cfaudit.ts) can match master-key events to Ben's taps. Card or ordinary tap alike.
 */
export const CF_JOBS: readonly string[] = Object.freeze(["cf.zone.read", "cf.dns.list", "cf.audit.read", "cf.token.headcount.setup", "cf.token.accept"]);
export const CF_LIST_MAX = 16; // ids per list; the desk's producer never exceeds 12 (R10), and never cuts a list short
/**
 * The rule binds grants whose request was recorded at or after this time (R6). Chosen after the front desk that writes
 * `cf` went live: front-desk main 2f77f7e, merged 2026-11-13 18:31:48 UTC, Workers Builds succeeded; a live card result
 * carrying `cf` was recorded at 18:35:27.985Z (studio-os LIVE-PROOF-139071ea.md). Earlier grants are legacy: `cf` is
 * optional, so their frozen bodies resend as they are, and they end by themselves 24 h on (GRANT_TTL_MS). After a
 * rollback, turning the rule back on takes a fresh time chosen the same way, never this one again (R7).
 */
export const CF_FROM = Date.parse("2026-11-13T19:00:00.000Z");
const KEY_ID = /^[0-9a-f]{32}$/;
const idList = (v: unknown) => Array.isArray(v) && v.length <= CF_LIST_MAX && v.every((x) => typeof x === "string" && KEY_ID.test(x));

/**
 * Why a record's `cf` is refused, or undefined (R6). `opened`: when the grant's request was recorded, as the recorder
 * stored it (the recorder's `Grant.opened`, the checker's request `recorded_at`), never a time the writer supplies.
 * Only a Cloudflare-master result may carry `cf`; from CF_FROM on it must, as `"unknown"` or exactly
 * `{made, deleted}`, each a list of 0-16 key ids. A legacy result may leave it out, but one it carries is checked too.
 */
export function cfRefusal(r: Record<string, unknown>, opened: number, from = CF_FROM): string | undefined {
  const has = Object.hasOwn(r, "cf");
  if (r.stage !== "result") return has ? "only a result may carry cf" : undefined;
  if (!CF_JOBS.includes(r.job as string)) return has ? "only a Cloudflare-master job's result may carry cf" : undefined;
  if (!has) return opened >= from ? "a Cloudflare-master result must carry cf" : undefined;
  const cf = r.cf;
  if (cf === "unknown") return undefined;
  const ok = !!cf && typeof cf === "object" && !Array.isArray(cf) && Object.keys(cf).sort().join() === "deleted,made" && idList((cf as Record<string, unknown>).made) && idList((cf as Record<string, unknown>).deleted);
  return ok ? undefined : `cf must be "unknown" or {made, deleted}, each at most ${CF_LIST_MAX} key ids`;
}

/** What Ben's tap covers, exactly these six keys. `deadline`: epoch ms, the latest any entry may start. */
export interface Manifest { kind: "card/v1"; card: string; requester: string; entries: string[]; deadline: number; jobs_version: number }
/** What a grant carries for the card rules: its job, the request's card id, its checked grant hash and expiry. */
export interface CardGrant { job: string; card?: string; grant_hash?: string; expires_at?: number; requester?: string }

const SHA = /^[0-9a-f]{64}$/;
const KEYS = ["card", "deadline", "entries", "jobs_version", "kind", "requester"];
const int = (v: unknown): v is number => Number.isSafeInteger(v) && !Object.is(v, -0) && (v as number) > 0;

/** True if `v` is a valid card id. */
export const isCardId = (v: unknown): v is string => typeof v === "string" && GRANT.test(v);

/** The manifest, or why it is refused: exact keys and types, 1-5 distinct grant hashes. */
export function parseManifest(v: unknown): Manifest | string {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "no manifest";
  const m = v as Record<string, unknown>;
  if (Object.keys(m).sort().join() !== KEYS.join()) return "the manifest has the wrong fields";
  if (m.kind !== "card/v1" || !isCardId(m.card) || typeof m.requester !== "string" || !m.requester || m.requester.length > 200) return "the manifest's kind, card id or requester is not valid";
  const e = m.entries;
  if (!Array.isArray(e) || e.length < 1 || e.length > CARD_MAX || !e.every((h) => typeof h === "string" && SHA.test(h)) || new Set(e).size !== e.length) return "the manifest's entries are not 1 to 5 distinct grant hashes";
  if (!int(m.deadline) || !int(m.jobs_version)) return "the manifest's deadline or jobs version is not valid";
  return m as unknown as Manifest;
}

/** The card hash Ben's phone signs: SHA-256 of the canonical manifest. A grant hash covers other keys, so the two never meet. */
export const cardHashOf = (m: Manifest) => sha256(canonical(m));

/** The card hash a passkey answer's challenge carries (16 random bytes + 32), or undefined if unreadable. */
export function challengeHash(assertion: unknown): string | undefined {
  try {
    const c = (assertion as { client_data_json: string }).client_data_json;
    const url = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));
    const ch = url(JSON.parse(new TextDecoder().decode(url(c))).challenge);
    return ch.length === 48 ? [...ch.slice(16)].map((b) => b.toString(16).padStart(2, "0")).join("") : undefined;
  } catch {
    return undefined;
  }
}

export type CardVerdict = { status: 409 | 410; why: string } | { hash: string; manifest: Manifest };

/**
 * Checks (a)-(e) of an approval against its grant, in order: kinds agree with the request's card mark, the
 * manifest's shape and card id, an eligible job, this grant's checked hash among the entries, and the
 * deadline (bounded by expiry + 15 min, and `now` no later than it). `now` is the time that becomes the
 * record's signed `recorded_at`. Undefined: an ordinary approval for an ordinary request, checked as before.
 * Otherwise a refusal, or the card hash for the passkey check (f).
 */
export async function cardApproval(r: WriterRecord, g: CardGrant, now: number): Promise<CardVerdict | undefined> {
  const marked = r.approval_kind !== undefined || r.manifest !== undefined;
  if (g.card === undefined) return marked ? { status: 409, why: "a card approval for a request that is not on a card" } : undefined;
  if (r.approval_kind !== "card/v1") return { status: 409, why: "a request on a card needs a card/v1 approval" };
  const m = parseManifest(r.manifest);
  if (typeof m === "string") return { status: 409, why: m };
  if (m.card !== g.card) return { status: 409, why: "the manifest names another card" };
  // Each grant hash covers its own requester; the card's must be the same one (commit security review).
  // `jobs_version` is the vault's job-template version: covered by Ben's signature, not the recorder's to judge.
  if (m.requester !== g.requester) return { status: 409, why: "the manifest names another requester" };
  if (!CARD_ELIGIBLE.includes(g.job)) return { status: 409, why: "this job is not allowed on a card" };
  if (!g.grant_hash || !m.entries.includes(g.grant_hash)) return { status: 409, why: "this grant is not on the card Ben approved" };
  if (!Number.isSafeInteger(g.expires_at) || m.deadline > g.expires_at! + CARD_RUN_MS) return { status: 409, why: "the card's deadline is past its grants' expiry" };
  if (now > m.deadline) return { status: 410, why: "the card's deadline has passed" };
  return { hash: await cardHashOf(m), manifest: m };
}
