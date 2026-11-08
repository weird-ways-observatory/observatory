# Records contract v1 (phase 2a, card feea07eb, route A)

The front desk records each grant here **before** it acts. It sends each record to the recorder
Worker (`src/recorder/`), which checks it, stores it add-only and answers with a receipt. The
Observatory re-reads every stored record each hour (`src/records.ts`). Both sides use one
definition of the format: `src/contract.ts`.

## How to send a record

    POST https://observatory-recorder.<account subdomain>.workers.dev/v1/records
    headers: CF-Access-Client-Id, CF-Access-Client-Secret   (the front desk's service token)
    body:    the record (JSON, at most 8192 bytes)

Cloudflare Access stands in front of the address and lets through only the front desk's service
token and Ben. The recorder checks Access's signed token again itself. `GET /v1/status` (front desk
or Ben) shows today's count, whether a write is pending, and the recorder's public key. Nothing else answers.

## The record

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | `1` |
| `grant` | yes | the front desk's grant id, 8-64 of `A-Z a-z 0-9 _ -` |
| `stage` | yes | `request`, `verdict`, `approval` or `result` |
| `job` | yes | the job name, e.g. `cf.token.canary` (`a-z 0-9 . -`, up to 40); every stage of a grant names the same job |
| `request` | every stage but `request` | the SHA-256 (hex) of the request record's exact bytes, as in its receipt |
| anything else | no | e.g. `params`, `requester`, `outcome` |

The body is the exact bytes sent, UTF-8 with no byte-order mark (a leading mark is kept and then fails as not JSON).

No secret values, ever, and no field at any depth whose name contains `secret`, `password`,
`token`, `private` or `credential`, nested no deeper than 8 levels. The recorder refuses these;
it cannot detect a secret under an innocent name, so the front desk redacts (phase 3).

## What the recorder refuses, before storing anything

| Answer | Why |
|---|---|
| 401 / 403 | no valid edge-login token, or not the front desk (Ben may read status, not write) |
| 503 | its edge-login settings are missing; Access's keys unreadable; a write pending that the bucket has not taken yet (retry) |
| 413 | over 8192 bytes, counted as the body arrives |
| 400 | outside the record format above (a fixed reason, never the writer's own text) |
| 409 | approval or verdict with no recorded request; result with no recorded approval; wrong request hash or job; this stage already recorded with other content; an approval whose passkey answer fails the check below; a card request, approval or result that breaks "Card approvals" below |
| 410 | the grant's request is over 24 hours old; a card approval taken after its card's deadline |
| 429 | today's 400 tap slots (UTC day) are taken, or the lifetime storage budget (6 GiB of stored envelopes) is full. A request takes 4 slots and reserves room in the budget for its grant's other three stages, so admitted grants can always finish; a reservation lasts 24 hours from the request's recorded time (inclusive) and is then released. Run ops will have their own 400-slot pool and stop at 5 GiB (card 509a5d85). A new day starts with the slots still reserved by grants opened the day before, never at zero, so no UTC day stores more than 400 records; a write held over midnight by an outage, however briefly, is charged to the day it is finally stored and carries that day's time. A full budget refuses every request until Ben decides. |

**Approvals are checked against Ben's passkey (card 7190ab0a).** An `approval` is stored only if
its `assertion` (`passkey_id`, `authenticator_data`, `client_data_json`, `signature`, base64url) was
signed by the passkey pinned in `src/recorder/passkey.ts` (`PASSKEY_PIN`, changed only by a PR Ben
merges): a `webauthn.get` answer from the front desk's site (origin and site name compared as SHA-256
hashes), with Face ID (user present and verified flags), whose challenge is 16 random bytes followed
by the `grant_hash` the grant's request record carried. A request without `grant_hash` can never be
approved. With no pin, every approval is refused. Approvals stored before the pin were not checked.

The same bytes sent again for a recorded stage get the same receipt (200), so a lost answer is
safe to retry. A new record gets 201 and its receipt:

    { "receipt": { "v": 1, "seq": 42, "key": "records/v1/000000000042.<grant>.<stage>.json",
                   "grant": "...", "stage": "...", "sha256": "<hex of the body>",
                   "recorded_at": "2026-11-01T12:30:00.000Z", "sig": "<base64>" } }

`sig` (card 586da182) is the recorder's Ed25519 signature, with the same key as the envelopes (the
`public_key` in `/v1/status`), over the JSON of `{"kind":"receipt/v1", v, seq, key, grant, stage,
sha256, recorded_at}` in that order (`receiptSealed` in `src/contract.ts`). The fixed label first means
a receipt signature never verifies as an envelope signature, or the reverse. It is added when answering
(an identical retry gets the same signature) and never stored.

A receipt is given only after the record is in the bucket. **No receipt, no run** (phase 3).

## What is stored

Bucket `observatory-records` in the Observatory's Cloudflare account, written only by the
recorder. A lock rule on `records/` (at least 400 days) makes it add-only: Cloudflare refuses any
overwrite or delete of a locked object.

    records/v1/<12-digit sequence number>.<grant>.<stage>.json
    records/v1/<12-digit sequence number>.<grant>.<stage>.<16 random hex>.json   (only when the plain name was taken)

The recorder picks every name: numbers start at 1 with no gaps, so sorting by name is the order
it accepted them. Each object holds an envelope, with the writer's bytes untouched:

    { "v": 2, "seq": 42, "grant": "...", "stage": "...", "recorded_at": "<recorder's time>",
      "sha256": "<hex of body>", "body": "<the writer's record, as sent>", "sig": "<base64>" }

`sig` is the recorder's Ed25519 signature over the JSON of the other fields in that order
(`sealed` in `src/contract.ts`). The key is made inside the recorder's Durable Object on first use
(a record or a status read); its private half stays in that object's storage and is never returned
or logged. Records stored before signing began are version 1, with no `sig`.

## Pinning the recorder's key (Ben's step)

The checker trusts one public key, written into `PIN` in `src/records.ts` by a PR Ben merges:
`{ key: "<public_key from GET /v1/status>", from: <the first record number that must be signed> }`.
Until then the checker reads as it did before signing, except that a shared number is only a
finding. When a pin first takes effect, every number from `from` that was already read is checked
once for exactly one signed copy (an `unsigned` finding otherwise), without being counted again; the
run stays unverified until that check has caught up. A lost or replaced key makes every later record foreign, loudly, until Ben merges the
new key.

## What the Observatory checks every hour

Every record stored since its last run, asking for the next expected number by name each time,
so names elsewhere in the bucket cost nothing and cannot hide records still to come (at most 500
an hour; more is itself a finding). From `PIN.from` on, the record at a number is the one copy whose
signature the pinned key verifies and whose envelope names that same number, grant and stage; every
other object there is a foreign finding, and reading goes on with no step for Ben. The recorder
does not stop either: it writes beside anything else under its next number, and if its exact name
is already taken by other bytes, it stores the record at that same number as
`<number>.<grant>.<stage>.<16 random hex>.json`, a name no one can plant ahead (card 6f681cc1). With no signed
copy at a number yet, the bookmark waits there and reads it again next hour. Two signed copies at
one number mean the key may be stolen: a `forged` finding, ranked first, and the read stops there,
unverified. More than 20 objects at one number, or one that cannot be read, also leaves the run
unverified with the bookmark in place. Before the pin, two objects with one number are a finding
and none of them counts. A missing number with a
higher one present is a standing gap finding. For each record: the name, the size, the envelope against the name and R2's upload time (within
10 minutes), the hash, the record against this contract, and the order of each grant's stages
(no duplicates, request first, approval before result, same request and job). Also: any gap in
the numbers, anything outside `records/v1/`, a UTC day over 400 records, and the lock on
`records/` (once `LOCK_READ_TOKEN` exists). Once a day (04:30 UTC) it lists every name up to
the bookmark and reads each number holding more than one object, which catches an object slipped in
under an older number and names it as the hourly read would (a record number gone is `missing`). Findings
never repeat writer-chosen text: grant ids and unexpected names are shown as fingerprints (the first 16 hex of their SHA-256), and grant findings name the record number.
A lock it cannot read, including before `LOCK_READ_TOKEN` exists, is a finding. Each finding is an
incident on a standing list (card af0e4a2f), its id tied to the exact object (for a foreign object:
number, name fingerprint and content fingerprint). It alerts once, worst first, and counts as told
only once a channel took the alert; the rest are tried the next hour. A locked record's incident
stays listed; the lock, gap, unreadable-number, stray-outside-v1, day-cap and backlog incidents
leave when a run that read everything no longer finds them. Nothing marks an incident seen. The light (`PING_URL_RECORDS`)
says only that the run read what it should. Until Ben sets `PING_URL_RECORDS`, it only logs.

## Run operations (card 1a272a5c; build A: checked, not yet accepted)

A run is one Face ID tap that covers up to 50 read ops for up to 24 hours. Today the recorder still
refuses `op` and `op_result` (400 "no valid stage"); build B makes it accept them. The hourly checker
already reads them, so nothing changes in the checker when B arrives. Format and rules: `src/ops.ts`;
the checker's chain: `src/runcheck.ts`.

- **Run open** is an ordinary grant with job `cf.run.open` and params exactly `{descriptor}`: canonical
  JSON (sorted keys, no spaces) of `{run, cards, jobs, account, zones, template, deadline, budget}`.
  Deadline is within 24 hours of the request's recorded time; budget is 1 to 50. Ben's passkey answer
  covers exactly those bytes, through the grant hash.
- **`op`** `{v, grant: <op id>, stage: "op", job, run_grant, run_request, run, card, template, params}`,
  stored as `records/v1/<number>.<op id>.op.json`. Params are exactly the job's (`zone` as a zone name,
  or `since`/`until`). It is *covered by Ben's passkey-approved run* only if its run-open request is at or
  after `OPS_FROM` (unset in A, so nothing is covered yet), has an approval that passed the order check,
  and the op is inside the descriptor, before the deadline and within the budget.
- **`op_result`** `{v, grant: <same op id>, stage: "op_result", job, run, op: <sha256 of the op body>,
  outcome, why | answer_sha256}`: outcome `done` carries the answer's hash; `refused`, `failed` and
  `not_returned` carry one fixed `why` code. Never an answer body.
- **Hourly findings:** `op-uncovered`, `op-unlinked` (no such run or op, or a result naming other bytes),
  `op-late`, and `op-incomplete` (no valid result 24 hours after the op, raised only once a complete read
  has passed that time). A record stored over 10 minutes after its recorded time never covers or resolves.
- **Pools:** taps and ops have 400 slots a UTC day each; the checker alerts at 80% and 90% of each,
  counting outstanding reservations, and on storage at 80% / 90% and under 60 / 30 days of runway.

## Card approvals (card 586da182)

A **card** is 1 to 5 ordinary grants Ben approves with one Face ID tap, run in order by the vault.
Rules live in `src/card.ts`, used by the recorder and the checker alike.

- **Card request:** an ordinary request that also carries `card`, the card's id (8-64 of
  `A-Z a-z 0-9 _ -`; not the Brain task id named `card` inside run ops). Its job must be on
  `CARD_ELIGIBLE` (today `test.echo`, `cf.zone.read`, `cf.dns.list`, `cf.audit.read`, and since card
  77ec1e64 `gh.repo.create`, the vault making an empty private repo; changed only by a
  Ben-merged PR; empty refuses every card). It takes 4 tap slots as usual **and** 4 of a 100-slot card
  share a UTC day (at most 25 card entries a day; 300 tap slots always stay for single taps), and is
  refused at 5 GiB stored + reserved counting its own reservation (single taps keep the full 6 GiB).
  Status words: `card_refused` (409/410 on any card rule), `card_share_full`, `card_cutoff` (429).
- **Manifest:** exactly `{kind: "card/v1", card, requester, entries: [grant hashes in run order, 1-5,
  distinct], deadline, jobs_version}`; `deadline` (epoch ms) is the latest an entry may start, at most
  the grants' `expires_at` + 15 minutes. **Card hash** = SHA-256 of its canonical JSON (sorted keys).
- **Card approval:** an `approval` carrying `approval_kind: "card/v1"`, the manifest and Ben's
  `assertion`; every entry's approval carries the same manifest and answer. Stored only if, in order:
  the kinds agree with the request (a card approval only for a card request, and the reverse); the
  manifest's shape, card id and requester match the request; the job is eligible; this grant's hash
  (kept only if it matched the request's own fields) is in `entries`; the deadline is within bounds and
  the recorder's time -- the record's signed `recorded_at` -- is no later than it (410); and Ben's pinned
  passkey signed a challenge of 16 random bytes + the card hash. The same check runs again just before
  a pending approval is stored, with that moment's time. The recorder does not enforce run order between
  entries: the vault does. A write that stalls after the check may be receipted after the deadline; the
  vault refuses to start an entry past it.
- **Card result:** `outcome` must be `done`, `failed` (known not done) or `unknown` (started, no answer:
  it may have run; never retried).
- **Repo id (card 77ec1e64):** a `done` result of `gh.repo.create` must carry `repo_id`, GitHub's
  repository id as a string of digits (no leading zero, at most 20); no other result may carry
  `repo_id` (409; `card_refused` on a card grant). It is the durable evidence the nightly check and the
  "repos made by cards" measure match a new repo by. Rule: `repoIdRefusal()` in `src/card.ts`.
- **Hourly checker:** re-runs these checks on stored card approvals, timed by their signed
  `recorded_at`, and checks the challenge carries the card hash (`card-bad`); a card approval with no
  result recorded by deadline + 1 hour, raised only once a complete read has passed that time
  (`card-incomplete`); a result after that time (`card-late`); an `unknown` result, alerted once and then
  listed like any locked-record incident (`card-unknown`). A done `gh.repo.create` result without a valid
  `repo_id`, or a `repo_id` on any other result, is `card-bad`. A card approval whose request the checker does
  not hold (for example after a checker revert) is `card-bad` (no request context). A card grant still
  unresolved 30 days after the checker first held it (reads stalled) is `card-unsettled` before its state
  is let go; until then its order context is kept too, so its card checks still run when reading recovers.
- **No revert after the first card request.** A reverted recorder refuses card approvals; when this
  version returns, it sees that other code wrote (`meta.card` keeps the record number and pending write
  it last left) and treats the card share as full for the rest of that UTC day. A reverted checker drops
  its card state; card approvals it read meanwhile are never re-checked. Stop cards with an empty
  `CARD_ELIGIBLE` or the vault's off switch, not a revert.

## Choices for Ben to keep or change

400 tap records a day (100 grants), 8192 bytes a record, a 6 GiB lifetime storage budget, 24 hours
to finish a grant, and a 400-day lock are builder defaults (Codex r1 drift item), sized for the front desk's expected few
approvals a day. Changing any of them is one constant in `src/contract.ts` or `src/records.ts`. Before anything deletes old records after the lock, the daily count (records stored = last number) must change with it.
