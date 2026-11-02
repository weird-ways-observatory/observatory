import { test } from "node:test";
import assert from "node:assert/strict";
import { sha256 } from "../src/contract.ts";
import { keyFor } from "../src/contract.ts";
import { Ledger, type Storage } from "../src/recorder/ledger.ts";
import { approvalCheck, coseToJwk, derToRaw, grantHashOf, PASSKEY_PIN, type PasskeyPin } from "../src/recorder/passkey.ts";

// Card 7190ab0a: the recorder stores an approval only if Ben's pinned passkey signed it for that grant.
const NOW = () => new Date("2026-11-02T12:00:00Z");
const ORIGIN = "https://desk.example", RP = "desk.example";
const b64u = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const digest = async (b: Uint8Array | string) => new Uint8Array(await crypto.subtle.digest("SHA-256", typeof b === "string" ? new TextEncoder().encode(b) : b));

function storage() {
  const m = new Map<string, unknown>();
  return {
    m,
    async get<T>(k: string) { return structuredClone(m.get(k)) as T | undefined; },
    async put(e: Record<string, unknown>) { for (const [k, v] of Object.entries(e)) m.set(k, structuredClone(v)); },
    async delete(k: string) { return m.delete(k); },
  } satisfies Storage & { m: Map<string, unknown> };
}
function bucket() {
  const store = new Map<string, string>();
  return {
    store,
    async get(k: string) { const v = store.get(k); return v ? ({ arrayBuffer: async () => new TextEncoder().encode(v).buffer } as unknown as R2ObjectBody) : null; },
    async list(o: { prefix?: string }) { return { objects: [...store.keys()].filter((k) => k.startsWith(o.prefix ?? "")).map((key) => ({ key })) } as unknown as R2Objects; },
    async put(k: string, body: string) { store.set(k, body); return {} as R2Object; },
  };
}

/** A software passkey: a P-256 key, its COSE public key, and WebAuthn-shaped answers with DER signatures. */
async function softKey(id = "cred-ben-1") {
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
function rawToDer(raw: Uint8Array): Uint8Array {
  const int = (v: Uint8Array) => { let i = 0; while (i < 31 && v[i] === 0) i++; v = v.slice(i); return v[0] & 0x80 ? [0x02, v.length + 1, 0, ...v] : [0x02, v.length, ...v]; };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return new Uint8Array([0x30, body.length, ...body]);
}
async function pinFor(k: { id: string; cose: Uint8Array }): Promise<PasskeyPin> {
  return { id: k.id, key: b64u(k.cose), rp_hash: Buffer.from(await digest(RP)).toString("hex"), origin_hash: await sha256(ORIGIN) };
}

const JOB = "test.echo";
/** A recorded request for `grant` shaped like the desk's, its grant hash (or `claim` instead), and its sha. */
async function requested(l: Ledger, grant: string, claim?: string | null) {
  const fields = { v: 1 as const, grant, stage: "request" as const, job: JOB, params: { word: "hi" }, requester: "c-box agent", reason: "test", created_at: 1, expires_at: 1793000000000 };
  const grantHash = (await grantHashOf(fields))!;
  const body = JSON.stringify({ ...fields, ...(claim === null ? {} : { grant_hash: claim ?? grantHash }) });
  assert.equal((await l.accept(body, NOW)).status, 201);
  return { grantHash, request: await sha256(body) };
}
const approval = (grant: string, request: string, assertion: unknown) => JSON.stringify({ v: 1, grant, stage: "approval", job: JOB, request, grant_hash: "x", approved_at: 1, assertion });

async function setup() {
  const key = await softKey(), st = storage(), b = bucket();
  const l = new Ledger(st, b, undefined, approvalCheck(await pinFor(key)));
  return { key, st, b, l };
}
/** The outcome, and proof nothing was stored for a refusal: no new number, no approval object. */
async function refusedWith(s: Awaited<ReturnType<typeof setup>>, body: string, why: string) {
  const before = s.b.store.size;
  const o = await s.l.accept(body, NOW);
  assert.deepEqual([o.status, "why" in o ? o.why : ""], [409, why]);
  assert.equal(s.b.store.size, before);
}

test("genuine: Ben's pinned passkey signed this grant with Face ID -> stored, then the result may follow", async () => {
  const s = await setup();
  const { grantHash, request } = await requested(s.l, "grant-aaaa1");
  const o = await s.l.accept(approval("grant-aaaa1", request, await s.key.answer(grantHash)), NOW);
  assert.equal(o.status, 201);
  assert.equal((await s.l.accept(JSON.stringify({ v: 1, grant: "grant-aaaa1", stage: "result", job: JOB, request }), NOW)).status, 201);
});

test("no pin: the shipped recorder refuses every approval until Ben pins a key (fail closed)", async () => {
  const key = await softKey(), st = storage(), b = bucket();
  const l = new Ledger(st, b); // the default check, from PASSKEY_PIN
  const { grantHash, request } = await requested(l, "grant-bbbb1");
  const o = await l.accept(approval("grant-bbbb1", request, await key.answer(grantHash)), NOW);
  if (PASSKEY_PIN) assert.deepEqual([o.status, "why" in o && o.why], [409, "not the pinned passkey"]);
  else assert.deepEqual([o.status, "why" in o && o.why], [409, "no passkey is pinned: Ben must pin one"]);
});

test("the pinned values are well formed when set: a readable ES256 key and SHA-256 hex hashes", () => {
  if (!PASSKEY_PIN) return;
  assert.equal(coseToJwk(Buffer.from(PASSKEY_PIN.key, "base64url")).crv, "P-256");
  assert.match(PASSKEY_PIN.rp_hash, /^[0-9a-f]{64}$/);
  assert.match(PASSKEY_PIN.origin_hash, /^[0-9a-f]{64}$/);
  assert.ok(PASSKEY_PIN.id.length > 0);
});

test("forged: signed by another key, or the signature altered -> refused, nothing stored", async () => {
  const s = await setup(), other = await softKey(s.key.id);
  const { grantHash, request } = await requested(s.l, "grant-cccc1");
  await refusedWith(s, approval("grant-cccc1", request, await other.answer(grantHash)), "the passkey signature does not verify");
  const a = await s.key.answer(grantHash);
  const auth = Buffer.from(a.authenticator_data, "base64url"); auth[36] ^= 1; // the counter byte, after signing
  await refusedWith(s, approval("grant-cccc1", request, { ...a, authenticator_data: b64u(auth) }), "the passkey signature does not verify");
});

test("replay: Ben's real answer for grant A presented for grant B -> refused", async () => {
  const s = await setup();
  const A = await requested(s.l, "grant-dddd1"), B = await requested(s.l, "grant-dddd2");
  await refusedWith(s, approval("grant-dddd2", B.request, await s.key.answer(A.grantHash)), "the answer is for another grant");
  await refusedWith(s, approval("grant-dddd2", B.request, await s.key.answer(B.grantHash, { challenge: Buffer.from(B.grantHash, "hex") })), "the answer is for another grant"); // 32 bytes, no random part
});

test("wrong site, no Face ID, not a sign-in, another passkey -> each refused with its reason", async () => {
  const s = await setup();
  const { grantHash, request } = await requested(s.l, "grant-eeee1");
  const cases: [object, string][] = [
    [{ origin: "https://evil.example" }, "not the front desk's site"],
    [{ rp: "evil.example" }, "not the front desk's site"],
    [{ flags: 0x01 }, "Face ID was not used"], // user present, not verified
    [{ flags: 0x04 }, "Face ID was not used"], // verified, not present
    [{ type: "webauthn.create" }, "not a passkey sign-in"],
    [{ id: "cred-other" }, "not the pinned passkey"],
    [{ client: { crossOrigin: true } }, "not the front desk's site"], // asked from inside another site's frame
    [{ client: { topOrigin: "https://evil.example" } }, "not the front desk's site"],
    [{ flags: 0x15 }, "the passkey answer could not be read"], // backed up but not backup-eligible
    [{ flags: 0x45 }, "the passkey answer could not be read"], // attested credential data in a sign-in
  ];
  for (const [o, why] of cases) await refusedWith(s, approval("grant-eeee1", request, await s.key.answer(grantHash, o)), why);
});

test("a request without the desk's grant hash, or with one that is not its own: its approval is refused", async () => {
  const s = await setup();
  const { grantHash, request } = await requested(s.l, "grant-ffff1", null);
  await refusedWith(s, approval("grant-ffff1", request, await s.key.answer(grantHash)), "the request's grant hash is missing or wrong");
  // A tampered desk records grant B claiming grant A's hash, then replays Ben's real answer for A.
  const A = await requested(s.l, "grant-ffff2");
  const B = await requested(s.l, "grant-ffff3", A.grantHash);
  await refusedWith(s, approval("grant-ffff3", B.request, await s.key.answer(A.grantHash)), "the request's grant hash is missing or wrong");
});

test("grant hash: only the desk's shapes get one -- odd numbers, non-text params or a missing requester get none", async () => {
  const base = { v: 1 as const, grant: "grant-odd-0001", stage: "request" as const, job: "test.echo", params: { word: "hi" }, requester: "c-box agent", expires_at: 1793000000000 };
  assert.match((await grantHashOf(base))!, /^[0-9a-f]{64}$/);
  for (const odd of [{ expires_at: JSON.parse("1e400") }, { expires_at: null }, { expires_at: -0 }, { expires_at: 1.5 }, { params: { n: 1 } }, { params: ["hi"] }, { params: undefined }, { requester: undefined }]) {
    assert.equal(await grantHashOf({ ...base, ...odd }), undefined, JSON.stringify(odd));
  }
});

test("grant hash: the same bytes as the front desk's grantHash() (vector computed by front-desk src/desk.ts)", async () => {
  const r = { v: 1 as const, grant: "grant-vec-0001", stage: "request" as const, job: "test.echo", params: { word: "hi", b: "x\ny" }, requester: "c-box agent", expires_at: 1793000000000 };
  assert.equal(await grantHashOf(r), "905a973764998436ffcc519cf746e1ad383f3fcfb32963a6f0225928013b393e");
});

test("malformed answers: missing, wrong types, bad base64, bad JSON, junk DER -> fixed reasons, nothing echoed", async () => {
  const s = await setup();
  const { grantHash, request } = await requested(s.l, "grant-gggg1");
  const good = await s.key.answer(grantHash);
  await refusedWith(s, approval("grant-gggg1", request, undefined), "no passkey answer");
  await refusedWith(s, approval("grant-gggg1", request, { ...good, signature: 7 }), "no passkey answer");
  await refusedWith(s, approval("grant-gggg1", request, { ...good, client_data_json: "!!!MARKER" }), "the passkey answer could not be read");
  await refusedWith(s, approval("grant-gggg1", request, { ...good, client_data_json: b64u(new TextEncoder().encode("{MARKER")) }), "the passkey answer could not be read");
  await refusedWith(s, approval("grant-gggg1", request, { ...good, signature: b64u(new Uint8Array([0x30, 3, 2, 1, 1])) }), "the passkey answer could not be read");
  await refusedWith(s, approval("grant-gggg1", request, { ...good, signature: good.signature + "AA" }), "the passkey answer could not be read"); // trailing bytes
});

test("a pinned key that is not ES256 P-256 is refused, never trusted", async () => {
  const k = await softKey();
  const badAlg = Uint8Array.from(k.cose); badAlg[4] = 0x27; // alg -8 (EdDSA), still well-formed CBOR
  const badKty = Uint8Array.from(k.cose); badKty[2] = 0x03; // kty 3 (RSA)
  assert.throws(() => coseToJwk(badAlg), /not ES256/);
  assert.throws(() => coseToJwk(badKty), /not ES256/);
  assert.throws(() => coseToJwk(k.cose.slice(0, 20)));
  assert.throws(() => coseToJwk(new Uint8Array([...k.cose, 0x00])), /cbor/); // trailing bytes
  const dup = Uint8Array.from(k.cose); dup[0] = 0xa6; // six entries: alg 0x26 (-7) given twice
  assert.throws(() => coseToJwk(new Uint8Array([...dup, 0x03, 0x26])), /cbor/);
  assert.equal(coseToJwk(k.cose).kty, "EC");
});

test("DER to raw: leading-zero integers are trimmed and short ones padded to 32 bytes", () => {
  const r = new Uint8Array(32).fill(0x80), sv = new Uint8Array(32); sv[31] = 5;
  const raw = derToRaw(rawToDer(new Uint8Array([...r, ...sv])));
  assert.deepEqual([...raw.slice(0, 32)], [...r]);
  assert.deepEqual([...raw.slice(32)], [...sv]);
  assert.throws(() => derToRaw(new Uint8Array([0x30, 2, 0x02, 0])));
  const good = rawToDer(new Uint8Array([...r, ...sv]));
  const padded = new Uint8Array([0x30, good[1] + 1, ...good.slice(2), 0x00]); // a stray byte inside the sequence
  assert.throws(() => derToRaw(padded), /der/);
  const seq = (...ints: number[][]) => { const body = ints.flatMap((v) => [0x02, v.length, ...v]); return new Uint8Array([0x30, body.length, ...body]); };
  const one = [5];
  assert.throws(() => derToRaw(seq([0x85], one)), /der/); // negative
  assert.throws(() => derToRaw(seq([], one)), /der/); // empty
  assert.throws(() => derToRaw(seq([0x00, 0x05], one)), /der/); // needless leading zero
  assert.throws(() => derToRaw(seq([1, ...new Array(32).fill(7)], one)), /der/); // 33 bytes, no sign byte
  assert.deepEqual([...derToRaw(seq([0x00, 0x85], one)).slice(0, 32)].slice(-1), [0x85]); // a needed zero is fine
});

test("cutover: an approval queued unchecked before the pin is checked again before storing, and withdrawn without a gap", async () => {
  const key = await softKey(), st = storage(), b = bucket();
  let failPuts = 0;
  const flaky = { ...b, async put(k: string, body: string) { if (failPuts-- > 0) throw new Error("R2 down"); return b.put(k, body); } };
  // Before the deploy: a ledger with no passkey check queues an unsigned approval (the bucket is down).
  const old = new Ledger(st, flaky, undefined, async () => undefined);
  const { grantHash, request } = await requested(old, "grant-cut-001");
  failPuts = 1;
  const unsigned = approval("grant-cut-001", request, undefined);
  assert.equal((await old.accept(unsigned, NOW)).status, 503);
  // After the deploy, the retry of the same bytes: refused, never stored, its number given back.
  const now = new Ledger(st, b, undefined, approvalCheck(await pinFor(key)));
  const o = await now.accept(unsigned, NOW);
  assert.deepEqual([o.status, "why" in o && o.why], [409, "no passkey answer"]);
  assert.equal(st.m.get("pending"), undefined);
  assert.ok(![...b.store.keys()].some((k) => k.endsWith(".approval.json")));
  // Ben's real approval then takes number 2: no gap.
  const ok = await now.accept(approval("grant-cut-001", request, await key.answer(grantHash)), NOW);
  assert.equal(ok.status, 201);
  assert.equal("receipt" in ok && ok.receipt.key, keyFor(2, "grant-cut-001", "approval"));
});

test("cutover: a pending approval that passes the check is stored as before", async () => {
  const key = await softKey(), st = storage(), b = bucket();
  let failPuts = 0;
  const flaky = { ...b, async put(k: string, body: string) { if (failPuts-- > 0) throw new Error("R2 down"); return b.put(k, body); } };
  const l = new Ledger(st, flaky, undefined, approvalCheck(await pinFor(key)));
  const { grantHash, request } = await requested(l, "grant-cut-002");
  failPuts = 1;
  const body = approval("grant-cut-002", request, await key.answer(grantHash));
  assert.equal((await l.accept(body, NOW)).status, 503);
  assert.equal((await l.accept(body, NOW)).status, 200);
  assert.ok(b.store.has(keyFor(2, "grant-cut-002", "approval")));
});

test("cutover: a crash while withdrawing gives the number back only once", async () => {
  const key = await softKey(), st = storage(), b = bucket();
  let failPuts = 0, failDelete = false;
  const flaky = { ...b, async put(k: string, body: string) { if (failPuts-- > 0) throw new Error("R2 down"); return b.put(k, body); } };
  const old = new Ledger(st, flaky, undefined, async () => undefined);
  const { grantHash, request } = await requested(old, "grant-cut-003");
  failPuts = 1;
  const unsigned = approval("grant-cut-003", request, undefined);
  assert.equal((await old.accept(unsigned, NOW)).status, 503);
  // The withdrawal's first write lands, then the instance dies before the pending record is cleared.
  const crashing = { ...st, async delete(k: string) { if (failDelete) { failDelete = false; throw new Error("crash"); } return st.delete(k); } };
  failDelete = true;
  const pinned = approvalCheck(await pinFor(key));
  assert.equal((await new Ledger(crashing, b, undefined, pinned).accept(unsigned, NOW)).status, 503); // caught: retry later
  assert.ok(st.m.has("pending"));
  const meta = st.m.get("meta") as { seq: number };
  assert.equal(meta.seq, 1);
  // The next instance finishes the withdrawal without giving a second number back.
  const l = new Ledger(st, b, undefined, pinned);
  assert.equal((await l.accept(unsigned, NOW)).status, 409);
  assert.equal((st.m.get("meta") as { seq: number }).seq, 1);
  const ok = await l.accept(approval("grant-cut-003", request, await key.answer(grantHash)), NOW);
  assert.equal("receipt" in ok && ok.receipt.key, keyFor(2, "grant-cut-003", "approval"));
});
