// The recorder's own check of Ben's Face ID (card 7190ab0a). Before an `approval` record is stored,
// the passkey answer inside it must be signed by the passkey pinned here, for this exact grant, on the
// front desk's site, with Face ID. The front desk checks the same answer first; this check means a
// tampered front desk cannot record an approval Ben never gave. Every value in the pin is public.
import { sha256, unb64, type WriterRecord } from "../contract.ts";

/** Ben's passkey, pinned by a Ben-merged PR. The site name and origin are SHA-256 hex: no hostname here. */
export interface PasskeyPin { id: string; key: string; rp_hash: string; origin_hash: string }
// Undefined refuses every approval (fail closed). Values come from the front desk's /passkeys page.
export const PASSKEY_PIN: PasskeyPin | undefined = undefined;

/** Why an approval is refused, or undefined when its passkey answer checks out. Reasons are fixed words. */
export type ApprovalCheck = (r: WriterRecord, grantHash: string | undefined) => Promise<string | undefined>;

const SHA = /^[0-9a-f]{64}$/;
const hex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const unb64url = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4));

// Sorted keys, as the front desk's canonical() (front-desk src/desk.ts), so both sides hash the same bytes.
function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v && typeof v === "object") return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`).join(",")}}`;
  return JSON.stringify(v);
}

/**
 * The grant hash worked out here from the request record's own fields, as the front desk's grantHash()
 * does. It covers the grant id, so it belongs to one grant only: a request cannot borrow another
 * grant's hash to reuse Ben's answer for that grant (commit security review, 2026-11-01).
 */
export async function grantHashOf(r: WriterRecord): Promise<string> {
  return sha256(canonical({ id: r.grant, job: r.job, params: r.params, requester: r.requester, expires_at: r.expires_at }));
}

/** The checker for one pin; the recorder uses PASSKEY_PIN, tests pass their own. */
export function approvalCheck(pin: PasskeyPin | undefined): ApprovalCheck {
  return async (r, grantHash) => {
    if (!pin) return "no passkey is pinned: Ben must pin one";
    if (!grantHash || !SHA.test(grantHash)) return "the request's grant hash is missing or wrong";
    const a = r.assertion as Record<string, unknown> | undefined;
    const fields = ["passkey_id", "authenticator_data", "client_data_json", "signature"];
    if (!a || typeof a !== "object" || !fields.every((f) => typeof a[f] === "string")) return "no passkey answer";
    if (a.passkey_id !== pin.id) return "not the pinned passkey";
    try {
      const clientBytes = unb64url(a.client_data_json as string);
      const client = JSON.parse(new TextDecoder().decode(clientBytes));
      if (client.type !== "webauthn.get") return "not a passkey sign-in";
      if (typeof client.origin !== "string" || (await sha256(client.origin)) !== pin.origin_hash) return "not the front desk's site";
      const challenge = unb64url(client.challenge);
      if (challenge.length !== 48 || hex(challenge.slice(16)) !== grantHash) return "the answer is for another grant";
      const auth = unb64url(a.authenticator_data as string);
      if (auth.length < 37 || hex(auth.slice(0, 32)) !== pin.rp_hash) return "not the front desk's site";
      if ((auth[32] & 0x05) !== 0x05) return "Face ID was not used";
      const signed = new Uint8Array([...auth, ...new Uint8Array(await crypto.subtle.digest("SHA-256", clientBytes))]);
      const key = await crypto.subtle.importKey("jwk", coseToJwk(unb64url(pin.key)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRaw(unb64url(a.signature as string)), signed);
      return ok ? undefined : "the passkey signature does not verify";
    } catch {
      return "the passkey answer could not be read";
    }
  };
}

/**
 * A COSE ES256 public key (a small CBOR map) as a JWK. Only what a passkey key holds is read:
 * small integer keys, integers, and byte strings; anything else throws.
 */
export function coseToJwk(bytes: Uint8Array): JsonWebKey {
  let i = 0;
  const item = (): number | Uint8Array => {
    const b = bytes[i++], major = b >> 5, info = b & 0x1f;
    const n = info < 24 ? info : info === 24 ? bytes[i++] : NaN;
    if (Number.isNaN(n) || i > bytes.length) throw new Error("cbor");
    if (major === 0) return n;
    if (major === 1) return -1 - n;
    if (major === 2) { const v = bytes.slice(i, i + n); i += n; if (v.length !== n) throw new Error("cbor"); return v; }
    throw new Error("cbor");
  };
  if (bytes[i] >> 5 !== 5) throw new Error("cbor");
  const count = bytes[i++] & 0x1f, m = new Map<number, number | Uint8Array>();
  if (count > 23) throw new Error("cbor");
  for (let k = 0; k < count; k++) { const key = item(); if (typeof key !== "number") throw new Error("cbor"); m.set(key, item()); }
  const x = m.get(-2), y = m.get(-3);
  // kty 2 (EC2), alg -7 (ES256), crv 1 (P-256), 32-byte coordinates.
  if (m.get(1) !== 2 || m.get(3) !== -7 || m.get(-1) !== 1 || !(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) throw new Error("not ES256");
  const b64u = (v: Uint8Array) => btoa(String.fromCharCode(...v)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return { kty: "EC", crv: "P-256", x: b64u(x), y: b64u(y), ext: true };
}

/** WebAuthn's DER ECDSA signature as the raw 64-byte r||s WebCrypto takes (probed 2026-11-02). */
export function derToRaw(der: Uint8Array): Uint8Array {
  if (der[0] !== 0x30 || der[1] !== der.length - 2) throw new Error("der");
  const out = new Uint8Array(64);
  let i = 2;
  for (const at of [0, 32]) {
    if (der[i] !== 0x02) throw new Error("der");
    const len = der[i + 1];
    let v = der.slice(i + 2, i + 2 + len);
    if (v.length !== len) throw new Error("der");
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error("der");
    out.set(v, at + 32 - v.length);
    i += 2 + len;
  }
  if (i !== der.length) throw new Error("der");
  return out;
}
