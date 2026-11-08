// A software passkey for tests (moved from passkey.test.ts for card 586da182): a P-256 key, its COSE public
// key, and WebAuthn-shaped answers with DER signatures over any 32-byte hash (a grant hash or a card hash).
import { sha256 } from "../src/contract.ts";
import type { PasskeyPin } from "../src/recorder/passkey.ts";

export const ORIGIN = "https://desk.example", RP = "desk.example";
export const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
export const digest = async (b: Uint8Array | string) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof b === "string" ? new TextEncoder().encode(b) : b));

/** A software passkey: a P-256 key, its COSE public key, and WebAuthn-shaped answers with DER signatures. */
export async function softKey(id = "cred-ben-1") {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  const x = Buffer.from(jwk.x!, "base64url"), y = Buffer.from(jwk.y!, "base64url");
  // {1: 2, 3: -7, -1: 1, -2: x, -3: y}
  const cose = new Uint8Array([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, ...x, 0x22, 0x58, 0x20, ...y]);
  return {
    id, cose,
    async answer(grantHash: string, o: { origin?: string; rp?: string; flags?: number; type?: string; id?: string; challenge?: Uint8Array; client?: object } = {}) {
      const challenge = o.challenge ?? new Uint8Array([...crypto.getRandomValues(new Uint8Array(16)), ...Buffer.from(grantHash, "hex")]);
      const clientData = new TextEncoder().encode(JSON.stringify({ type: o.type ?? "webauthn.get", challenge: b64u(challenge), origin: o.origin ?? ORIGIN, crossOrigin: false, ...o.client }));
      const auth = new Uint8Array([...(await digest(o.rp ?? RP)), o.flags ?? 0x1d, 0, 0, 0, 0]);
      const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new Uint8Array([...auth, ...(await digest(clientData))])));
      return { passkey_id: o.id ?? id, authenticator_data: b64u(auth), client_data_json: b64u(clientData), signature: b64u(rawToDer(raw)) };
    },
  };
}
export function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (v: Uint8Array) => { let i = 0; while (i < 31 && v[i] === 0) i++; v = v.slice(i); return v[0] & 0x80 ? [0x02, v.length + 1, 0, ...v] : [0x02, v.length, ...v]; };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}
export async function pinFor(k: { id: string; cose: Uint8Array }): Promise<PasskeyPin> {
  return { id: k.id, key: b64u(k.cose), rp_hash: Buffer.from(await digest(RP)).toString("hex"), origin_hash: await sha256(ORIGIN) };
}

