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
 * no agent can reach. Empty refuses every card (an off switch beside the vault's). gh.repo.create joins in
 * card build 4, with the job itself.
 */
export const CARD_ELIGIBLE: readonly string[] = Object.freeze(["test.echo", "cf.zone.read", "cf.dns.list", "cf.audit.read"]);
export const CARD_SHARE = 100; // of the tap pool's 400 daily slots: at most 25 card entries a UTC day
export const CARD_MAX = 5; // entries on one card
export const CARD_RUN_MS = 15 * 60_000; // a card's deadline is at most its grants' expiry + this
export const CARD_RESULT_MS = 3_600_000; // the checker expects each entry's result by deadline + this
export const CARD_OUTCOMES: readonly string[] = Object.freeze(["done", "failed", "unknown"]);

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
