# Observatory

The studio's independent check on its agents. It will record every request agents make through the Front Desk before it runs, read what the providers say changed, and alert Ben on anything that does not match. Only code Ben approved ever runs here.

Today it does three jobs: a second, locked copy of the studio's nightly backups (phase 2c), an hourly check that what runs here is what is on `main` (card f0d4e2fc), and an hourly check of the front desk's add-only records (phase 2a, card feea07eb). A second Worker, the recorder, takes those records in (below).

## Nightly backup copy (phase 2c, card 202ac367)

At 03:15 UTC, 9:15 pm Chicago time in winter (`triggers` in `wrangler.jsonc`), `src/copy.ts` runs:

1. Lists that night's backup objects in the main backup bucket, with a read-only key scoped to that one bucket. The objects are encrypted before upload, so the Observatory cannot read them.
2. Copies each one into this account's own bucket. R2 refuses a copy whose bytes do not hash to the source's MD5, and the Worker checks the result again. A source object without a plain MD5 fails the night rather than go unchecked.
3. Tries to delete a permanently locked canary object. If it is ever gone, the lock is not working and the night fails.
4. Reads this account's own lock rules for the copy bucket (`src/lock.ts`, design 3f), because a refused delete proves a lock exists but not how long it holds. The night fails if no enabled rule covers all of `daily/` for 30 days, or any enabled rule there holds less, or the rules cannot be read or understood. Until its read-only key (`LOCK_READ_TOKEN`, `LOCK_ACCOUNT_ID`) is set at cutover, the night logs `lockLength: "not set up"` and claims nothing about it.
5. Pings the dead-man check "up" only if every step passed; otherwise it reports a failure, so Ben gets an email. A missed night also emails him.

The copy bucket's lock rules keep each night for 30 days (D2, Ben 2026-10-31; the canary forever); a lifecycle rule then removes it. Lock rules win over lifecycle rules, and the Worker's own code cannot delete a locked object. One log line per night records counts, bytes, total stored bytes, the canary result and the lock-length verdict.

## The recorder and the hourly records check (phase 2a, card feea07eb, route A)

The front desk records each grant's request, verdict, approval and result **before** it acts; the format is in `RECORDS.md`. It sends each record to the **recorder**, a separate Worker (`src/recorder/`, deployed from `wrangler.recorder.jsonc`) that reaches only the `observatory-records` bucket and its own Durable Object, never the backups. The recorder refuses, before storing anything, a record outside the contract, a stage out of order for its grant, a later stage that does not name its request's exact bytes, or a request when the day's 400 tap slots are taken or the 6 GiB lifetime storage budget is full (each request reserves its grant's other three stages for 24 hours, and those reservations carry into the next day). Run ops will get their own 400-slot daily pool and stop at 5 GiB, so they can never take the room Ben's taps need (card 509a5d85; ops are still refused until card 8ff5110b). `GET /v1/status` shows both pools, their reservations, bytes stored and pending, refusals by reason, identical retries and expired reservations. It takes records one at a time, names each with a gap-free sequence number and its own time, saves it as pending, writes it to the bucket, and only then answers with a receipt. A lock rule on `records/` makes the bucket add-only.

At :30 past every hour, as a job separate from the freshness check, `src/records.ts` re-reads every record stored since its last run, asking for each next record number by name, against the same contract (`src/contract.ts`), and reports anything the recorder should have refused or that something else wrote: a gap in the numbers, a duplicate or out-of-order stage, a broken envelope or body, an object outside the record format, more than a day's cap, and a lock on `records/` shorter than 400 days. Once a day (04:30 UTC) it lists every record name up to the bookmark and reads any number holding more than one object, naming each extra object the same way the hourly read does. Findings never repeat writer-chosen text (grant ids and stray names appear as fingerprints), and a lock it cannot read, including before `LOCK_READ_TOKEN` exists, is a finding. Since card af0e4a2f, this job's own check (`PING_URL_RECORDS`) is a light that means only "the checker ran and read what it should": green after every such run, red when a run could not finish (including a daily count that could not read an object or finish listing), and healthchecks' own alarm when a run is missed; it never means the records are fine. Every finding is an incident on a standing list with an id tied to the exact object; each record number a run could not read is one too. At most one alert a run, through Pushover; if Pushover fails it goes to the same check's `/fail`, which emails only when the check changes state, so a run that read everything pings green first and green again after, and on a run that could not finish only Pushover counts as delivered. An incident stays listed while it is still found and alerts again only if it comes back. An incident about a locked record (a planted object, a broken record) stays listed for good; one the hourly run recomputes (the lock, a gap, an unreadable number, a stray outside `records/v1/`) leaves when a full run no longer finds it. Nobody can mark one seen. The list holds 200; past that one counted line stands for the rest and alerts whenever another joins them. It remembers up to 5,000 of those; past that it says it can no longer tell new ones apart, once. A crowded record number the day's read window skips keeps its open problem until a later window reads it. Every Monday at 14:00 UTC one line says how many are open and the worst. State lives at `state/records.json` in the copy bucket. The recorder signs every envelope (Ed25519, with a key made inside its Durable Object); once Ben pins its public key (`PIN` in `src/records.ts`), a record is the one copy at its number the recorder signed, anything else there is a foreign finding, and the bookmark never passes a number without exactly one signed copy. The checker needs no step from Ben for a shared number; the recorder does not stop either, and writes beside anything planted under its next number (under a random-tagged name if its exact name was taken). Until `PING_URL_RECORDS` is set it only logs. It reads; it never writes to the records bucket.

## One-tap card approvals (card 586da182)

Soon Ben approves a **card** (1 to 5 named jobs run in order) with one Face ID tap over the card's fingerprint (the card hash). The recorder stores a card approval (`approval_kind: "card/v1"`) only if Ben's pinned passkey signed that card hash, this grant is on the card, its job is on the Observatory's own list (`CARD_ELIGIBLE` in `src/card.ts`: `test.echo`, three read-only Cloudflare reads, and `gh.repo.create`, which makes an empty private repo and whose done result must name the repo's GitHub id), and the recorder takes it no later than the card's deadline. Card requests use at most 100 of the 400 daily tap slots and stop at 5 GiB of the 6 GiB, so single taps keep their room. Every receipt now carries the recorder's signature (`receipt/v1`), so the vault can check for itself that an approval was stored before it runs anything. The hourly checker reads card approvals again, alerts when an entry's result is `unknown` (it may have run), and when a card approval has no result an hour after its deadline. Format and rules: `RECORDS.md`, "Card approvals".

**Never revert either Worker below this version once the first card request is stored.** A reverted recorder refuses card approvals (fails closed), and on return blocks cards for the rest of that UTC day; a reverted checker goes silent on cards and loses what it held (card approvals it read in that time are never re-checked). To stop cards, empty `CARD_ELIGIBLE` here (one Ben-merged PR) or use the vault's own off switch; fix forward otherwise.

## Hourly freshness check (card f0d4e2fc)

At :30 past every hour, `src/fresh.ts` (and only it: `src/index.ts` routes each cron by name) reads `main`'s head commit from GitHub's public API by the repo's numeric id (it survives the move to a new org), without a credential, and compares it with `DEPLOYED_SHA`, which the deploy command records for each deploy.

- `main` ahead of what is live for 6 hours: one alert ("a merge did not go live").
- GitHub unreadable for 3 hours (including its 60-an-hour limit on reads without a key), or no `DEPLOYED_SHA`, or its own state unreadable: one alert ("cannot verify what is live"). Never "healthy".
- Its own healthchecks check (`PING_URL_FRESH`) hears "up" every hour while nothing is overdue and `/fail` every hour while something is. An alert that cannot reach the phone falls back to that check, never the backup check, so a good backup night never clears a freshness failure.
- State (when a mismatch was first seen, which alert was sent) lives at `state/freshness.json` in the copy bucket; `state/` has no lock.
- Until `PING_URL_FRESH` and the `DEPLOYED_SHA` deploy command are set up at cutover, it logs one line an hour and sends nothing.

Limit: it runs inside the thing it checks. That counts only after cutover, when nothing but Workers Builds can deploy.

## When a records incident fires

Steps marked FROM MEMORY name Cloudflare dashboard places not checked against the live dashboard.

1. Read the alert: it names a record number and a fingerprint, never anything the writer chose. A planted object stays on the list for 400 days (the lock keeps it); that is expected and needs no clearing.
2. Who can write the records bucket: the recorder Worker (through its binding, no token), any Cloudflare API token on the Observatory account with R2 write (none is held by an agent: the temporary setup keys were revoked and proven refused on 2026-11-11, studio-os CUTOVER-REFUSAL-PROOF-2026-11-11.md), and the account's owner login. Nothing else.
3. Which one wrote it: compare the object's upload time (R2, the records bucket, the object list; FROM MEMORY) with when each R2-write token existed and was last used (the account's API tokens page; FROM MEMORY). Cloudflare's audit log records token changes, not single object writes (FROM MEMORY).
4. Cut it off: roll or delete every R2-write token on the Observatory account (the recorder needs none). If the owner login is in doubt, change its password and check its 2FA.
5. `forged` (two copies carry the recorder's signature) means the recorder's key may be stolen: ask an agent for a new-key card. `missing` (a record gone below the bookmark) means the lock did not hold: check the lock rule first.

## Hourly Cloudflare check (card beec640b, build a)

At :45 past every hour, `src/cfaudit.ts` reads the main Cloudflare account's audit log with a read-only key Ben made (Audit Logs Read on that account only) and judges every write on its own fields (`src/cfjudge.ts`). It tells Ben, once, about any write it does not count:

- a write by any key other than the front desk vault's master key, or by a Global API Key;
- a key or member change made in the dashboard, including Ben's own;
- any kind of change, or way of signing in, it has never seen;
- every `api` key echo Cloudflare logs (paired with its key event only to label it), and a key event with no echo (a diagnostic line).

Counted, never pushed: system DNS and certificate work, Ben's dashboard writes of known kinds (analytics, R2 rules, Access apps, DNS records), his sign-ins, and the master key's key creates and deletes. Those last are "not yet matched": build b matches each one to the signed front desk result that names it.

- **The light** (`PING_URL_CFAUDIT`) means "the checker ran and read everything it should". It goes red when a setting is missing or malformed (the light's own address included: with none, the check does not run), the key is refused, a page cannot be read, the check's own earlier read is missing from the log after 40 minutes, or too many events share one instant.
- **Freshness:** each run calls `tokens/verify`; Cloudflare logs that read. The next run must find it in the log, so a log that stops recording turns the light red instead of looking quiet.
- **Reading:** oldest first from a bookmark (the last judged event's time and every id judged at that millisecond), up to 20 minutes before now, one judging page of 200 events a run. A backlog over 3 hours is one incident. 200 an hour is a proposed setting until Cloudflare's own CPU figure for a worst-case run is read.
- **State** (`state/cfaudit.json` in the copy bucket) is saved after every page, together with that page's incidents, and before any alert, each save conditional on the one before, so two runs at once never overwrite each other. Delivery is at least once: a crash after sending can send again. State that is unreadable or the wrong shape is rebuilt, with one summary line.
- **One push a run:** every new incident is in it, by its own line or counted in one closing line ("and N more: ...; ask an agent to read the list"), so nothing waits for a later hour. The list keeps at most 200 lines, the last one counting what could not be kept.
- **First run:** if the backlog since the start date does not fit in one run, Ben gets one "the Cloudflare check started" line instead of a replay; the backlog's changes are on the list.
- **Weekly line:** the first run after Monday 14:00 UTC sends the week's counted writes, only whole; if the push is full it waits for the next run.
- **Never kept or sent:** key fragments, request bodies, key names, descriptions and source addresses (the address is kept only as a short hash, to pair echoes).

## When a Cloudflare incident fires

Steps marked FROM MEMORY name Cloudflare dashboard places not checked against the live dashboard.

1. Read the alert: it names the kind of change, how it was signed in, the time, and a ref (the first 8 characters of Cloudflare's event id). It never repeats anything the writer chose.
2. Ask an agent to look up the ref in the audit log (agents hold a read-only key). Or, in the main account: Manage account, Audit log (FROM MEMORY), and search around the time.
3. A change Ben made himself in the dashboard (a key he created, a member he added) is expected to alert: nothing to do but recognise it.
4. A change by a key nobody recognises: delete or roll that key on the main account's API tokens page (FROM MEMORY), then ask an agent for a root-cause card.
5. "did not show the check's own read": the log may have stopped recording, or posts late; the light is red until a later read is found. The incident stays listed for 30 days.

## How it is protected

- **Who can change it:** `main` takes only pull requests with Ben's approval of the latest push (ruleset `protect-main`, the same as front-desk's): no bypass, no force push, no deletion.
- **Its own home (moved 2026-10-31, card 3e2f8870):** this repo lives in its own GitHub org, `weird-ways-observatory`, owned by `benculbert` and `weird-ways`, which refuses all personal access tokens, so no agent credential can reach it (proof 5.7.4: agent writes refused). Agents propose changes from a fork, `weird-ways-studio/observatory-proposals`, and send Ben a compare link (see `CLAUDE.md`). The cutover closed on 2026-11-11 (card f6f4f832): the construction keys were revoked and each was refused by its provider (studio-os CUTOVER-REFUSAL-PROOF-2026-11-11.md).
- **What deploys:** Cloudflare **Workers Builds** in the Observatory's own Cloudflare account builds `main` and deploys it; its trigger includes only `main`, because a branch build would run code nobody reviewed with the build's deploy rights. A merge starts the build by itself (proven 2026-11-01, PR #10; root-cause card c19f4946).
- **Who holds keys:** no agent holds any Observatory credential. The two temporary phase 2c setup keys (R2 and Workers scripts; reading and starting builds) were revoked on 2026-11-11 and proven refused (HTTP 401) the same day. Agents change the code only by opening pull requests.
- **Address (studio app-exposure doors), backup Worker:** none. `wrangler.jsonc` turns off workers.dev and preview URLs and has no routes, so the Worker is unreachable from any network, which is stricter than the tailnet-only door. `test/config.test.ts` fails if the address, bindings or schedules change.
- **Address, recorder Worker: door 2** (edge login in front of the whole Worker). Its one address is its workers.dev URL, behind Cloudflare Access, which admits only the front desk's service token and Ben. Why not door 1: the front desk runs on Cloudflare, not on the tailnet, so it cannot reach a tailnet-only address. Ben chose this route on 2026-11-01 (Brain task 56d8dd39, after a cross-model review). The Worker also checks Access's signed token itself (`src/recorder/access.ts`: signature, issuer, audience, expiry, identity) and refuses everything while its settings are missing, so a wrong Access setting alone never opens it. Answers carry `X-Robots-Tag: noindex`. `test/recorder-config.test.ts` fails if its address or bindings change.
- **Entry points:** `src/index.ts` (`main` in `wrangler.jsonc`); Cloudflare calls its default export's `scheduled` on each cron and `fetch` only if an address were ever added. The recorder: `src/recorder/index.ts` (`main` in `wrangler.recorder.jsonc`); Cloudflare calls `fetch` for each request (`src/recorder/http.ts` routes it) and runs the `Recorder` Durable Object class, named in the config's `durable_objects` binding, as one instance named "v1".

## Known limits

- Independence rests on the 2026-11-11 refusal proof (studio-os CUTOVER-REFUSAL-PROOF-2026-11-11.md): the main account's temporary global key, the GitHub temporary admin token, and both Observatory temporary keys were each refused by their provider after Ben revoked them. One read-only healthchecks key stays as a named exception. Anything that proof did not test is not claimed.
- The copy faithfully copies whatever the source holds. If tonight's source were overwritten with garbage, earlier nights stay locked here for 30 days; spotting the tampering is a later phase.
- Cloudflare's own GitHub app (Workers and Pages) holds administration write on the repos it is installed on. Cloudflare controls it; no studio agent can drive it.

- The recorder is live since 2026-11-01 (card feea07eb): Access in front with the front desk's service token, the records bucket under its lock, and its own Workers Builds connection. Refusals were proven live then (a stranger, a forged token and a wrong secret refused); the service token's admission is proven by the front desk's first real record (phase 3, card 97a2e83d).
- The recorder and the front desk agree on order, not on truth: a tampered front-desk deploy could skip recording. Phase 3 makes the front desk refuse to run without a receipt; Ben's review of `main` remains the control.
- The service token's identity is read from the token's `common_name` claim (FROM MEMORY of Access's service-token tokens; the sitting's live proof confirms it).

## Develop

`npm test`, `npm run typecheck`. Install packages only inside the studio sandbox.
