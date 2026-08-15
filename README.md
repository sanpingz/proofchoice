# ProofChoice

An evidence layer for AI agent recommendations.

An AI agent recommends a supplier. ProofChoice is a plugin sitting beside that agent which commits,
cryptographically, to the candidate set the agent considered, the ranking rule it applied, which
candidates paid commission, and which one won — then anchors that commitment where the agent cannot
later edit it. Separately, it collects signed receipts from every supplier in an independent
*category registry* to test whether the declared candidate set was the real one.

The agent's ranking logic is never disclosed and never modified. Nothing is blocked, delayed or
re-ordered.

This repository is a working implementation: a zero-dependency server that anchors, stores and
verifies; a browser console; and an MCP endpoint so ChatGPT can act as the agent under audit.

## The claim, bounded

> **ProofChoice makes denial expensive. It does not make lying impossible.**

Anything in the build that implies otherwise is a bug. Specifically, and permanently:

- A Merkle proof shows **inclusion**. A root can never prove a set was **complete**.
- Coverage shows what was **asked**, never what **exists**.
- A signature binds a commitment to a **key**, not to a **truth** — the platform is signing its own
  account of its own decision.
- Custody makes withholding **visible and attributable**, not **impossible**.

---

## Quick start

```sh
npm start                 # console + REST + MCP on http://127.0.0.1:8787
npm run dev               # same, with hot reload
npm test                  # 112 assertions
npx vercel --prod         # deploy — read Deploying to Vercel first
```

Node 20+ (developed on 26). No bundler, no framework — the scripts are plain `node` invocations, so
`node server/server.js` works just as well.

**Two optional dependencies**, both imported dynamically: `redis` for the Redis backend and
`@vercel/blob` for the Blob one. The filesystem and memory backends run with no `node_modules` at
all, and most of the test suite passes without either. Run `npm install` when deploying against a
real store.

Open <http://127.0.0.1:8787/> for the console. A local HTTP proxy will intercept `localhost` from
curl — pass `--noproxy '*'` if you have one.

### Dev mode

`npm run dev` is `node --watch server/server.js --dev`. Two halves, no dependency and no injected
script:

- **Server changes** — Node's own `--watch` restarts the process on any change in the module graph.
- **Console changes** — the server watches `public/` and pushes over an SSE channel at `/dev/events`;
  the page reloads itself. A restart reloads the browser too: the stream drops, `EventSource`
  reconnects on its own, sees a different boot id, and reloads.

The console shows a green **DEV · LIVE** chip while the channel is up, and `reconnecting…` while the
server is restarting. `npm run test:watch` re-runs the suite on save.

Dev mode is off unless you ask for it (`--dev`, or `PC_DEV=1`), and is force-disabled on serverless —
`/dev/events` returns 404 and `/health` reports `dev: false`. A long-lived stream and a filesystem
watcher are both meaningless in a lambda and would only burn execution time.

---

## What is real and what is not

This is the part it would be easiest to overstate, so it comes first. `GET /health` returns both
disclosures below as fields, so no UI has to paraphrase them.

**Real.** SHA-256, ECDSA P-256, salted Merkle trees, canonical JSON. Every hash and signature is
computed with WebCrypto and can be recomputed by anyone from the evidence blob. The verification
algorithm in [server/verify.js](server/verify.js) is pure — no network, no filesystem, no clock — so
a third party can run it with no access to this infrastructure. Keys persist and are bound to a named
operator in the on-chain key registry.

**Not real.** The ledger is a single-operator append-only log. It is *not* a blockchain and must
never be described as one: it does not resist the operator deleting the store. The chain, the
custodians, the relayer and the platform all run in one process, so the separation between them is a
module boundary rather than an adversarial one. In this deployment the operator **is** the party
under audit — precisely the weakness a real anchor layer exists to remove.

---

## Architecture

Five roles in separate modules with narrow interfaces, because collapsing any two destroys a claim
the product makes.

| Module | Role | Holds | Must never |
| --- | --- | --- | --- |
| [platform.js](server/platform.js) | The agent-side plugin | The signing key | Re-rank, block or delay the recommendation |
| [chain.js](server/chain.js) | Anchor registry | Anchors, key registry, custody manifests, receipt batches | Sign a snapshot, or hold a preimage |
| [custody.js](server/custody.js) | Evidence holders | The off-chain preimages | Be the only copy, under any model but `platform-held` |
| [registry.js](server/registry.js) | Category registry + relayer | Supplier keys | Draw receipt requests from the platform's declared set |
| [verify.js](server/verify.js) | Auditor | Nothing | Perform I/O, or trust anything the platform asserts |

The signing key lives in `platform.js` and only there. The chain stores commitments; it never signs
them. Merging those two roles would make the anchor registry the platform, and the trust argument
with it.

[core.js](server/core.js) holds the cryptography, ported verbatim from the prototype and pinned with
golden vectors.

> `canon()` is the single most security-critical function in the codebase. Any change to it silently
> invalidates every hash ever produced. Pin it, test it, never "improve" it.

```js
function canon(o){
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
  return '{' + Object.keys(o).sort()
    .map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
}
```

It exists in three places — the server, the console, and the offline prototype — and the test suite
compares all three by behaviour, because the console's independent-verification claim is worthless if
they have quietly drifted apart.

---

## The six stages

Sequential. Each stage's output is the next stage's only input.

| # | Stage | What happens |
| --- | --- | --- |
| 1 | **Recommend** | The agent calls its sources, filters, ranks, picks a winner. The plugin does not participate. |
| 2 | **Snapshot** | Salt and hash each candidate, sort by id, compute the Merkle root, assemble the snapshot, hash it. Emit `proof_id`. Distribute the evidence blob. |
| 3 | **Sign** | ECDSA P-256 over `snapshot_hash`. Binds the commitment to a key. |
| 4 | **Anchor** | `anchor(snapshot_hash, signature, key_id)` — write-once, reverts on a repeat hash. |
| 5 | **Receipts** | Requests go to **every supplier in the category registry**, not the list the platform declared. Suppliers sign offline; a neutral relayer carries the signed receipts. |
| 6 | **Audit** | Pull, recompute, compare. Nothing trusts the platform's own account. |

`proof_id = "PC-" + snapshot_hash[0:10]` — derived, not assigned, so the holder can locate their own
anchor without asking the platform where it is.

Two design decisions carry most of the weight. Receipt requests are drawn from an **independent
registry** rather than the platform's declared candidate set — otherwise a pruned supplier is never
asked, produces no denial, and the audit is circular. And receipts reach the registry via a **neutral
relayer** rather than the platform — otherwise the accused party carries the evidence that indicts it.
Set `routing: "legacy"` to switch the second one off and watch the detection fail.

Every candidate leaf is salted with a per-candidate nonce before hashing. Name plus price is
low-entropy; an unsalted leaf is brute-forceable from a shared Merkle path.

Full data contracts — candidate leaf, snapshot, anchor, receipt, evidence blob — are in
[Design.md §3](Design.md).

---

## Evidence custody

The chain guarantees the *anchor* persists. It guarantees nothing about the *preimage*, and without
the preimage no check below can run.

The load-bearing idea: the evidence blob is **self-authenticating**. Its integrity comes from hashing
to the anchor, a check that runs identically no matter who hands it over. A forged blob fails check 3
whoever produced it. So no holder needs to be *trusted*, only *available* — which makes replication
free of trust cost and reduces custody to a pure availability question.

Four models, switchable per proof via `custody_model`:

| Model | Holders | Effect |
| --- | --- | --- |
| `platform-held` | platform | The party under audit holds the only copy. Withholding is unilateral. |
| `buyer-copy` | platform + buyer | Withholding now needs the platform *and* the party it harmed. |
| `escrow` | platform + neutral | Unavailability becomes attributable to a party with no stake. |
| `hybrid` *(default)* | platform + buyer + neutral | Three parties with divergent interests must all decline. |

### The custody manifest

At snapshot time each holder signs an acknowledgement that it holds the preimage, recorded on chain
with a `retention_until` date. A holder that never acknowledged cannot be blamed; a holder that
acknowledged and cannot produce has signed a contradiction.

`retention_until` is committed **in advance**. That is the load-bearing detail: if the retention
period lived only in a contract, the platform could label any missing blob "expired" after the fact.
Pre-committed, `EXPIRED` becomes a date check instead of a claim.

### Failure taxonomy

Check 2 reports five distinct states rather than one generic failure:

| State | Meaning | Verdict |
| --- | --- | --- |
| `AVAILABLE` | At least one holder served a blob hashing to the anchor | continue |
| `WITHHELD` | Reachable, in retention, acknowledged — and refused | **FAIL** · adversarial |
| `LOST` | Signed admission of non-possession, contradicting its own acknowledgement | **FAIL** · custody breach |
| `EXPIRED` | The pre-committed `retention_until` has passed | **INCONCLUSIVE**, never FAIL |
| `UNRESPONSIVE` | No signed answer of any kind | **FAIL**, ranked worst |

`EXPIRED` must not render as FAIL: deleting data at the end of a committed retention period is the
correct outcome of a privacy obligation, and if expiry looks like guilt the product punishes
compliance. It must not render as PASS either — hence a fourth verdict token.

`WITHHELD` and `LOST` are **not** cryptographically distinguishable. A platform that prefers to look
incompetent will say "lost". The classification is *attested, not proven*: it derives from what each
holder signs. What the mechanism buys is that each holder must go on the record, and refusing to
answer at all is its own, worse, state.

Attribution is **per holder**, never a single aggregate. "The evidence is gone" is not the finding;
"this named party, which signed that it held a copy, did not produce it" is.

Divergent copies are detected too: the auditor fetches from *every* holder, not the first to answer.
If the platform edits its copy under `hybrid`, the buyer's copy still verifies and the verdict names
the platform as the source of the edited one.

### What custody cannot do

Custody cannot defeat withholding. A preimage is a bearer object; whoever holds a copy can decline to
produce it, and no chain can compel them. What custody changes is the number of independent parties
who must all decline, whether the declining party is the accused or a neutral, whether the refusal is
silent or named, and whether "I lost it" is a free excuse or a signed admission.

Design rationale, the full option space, and the PIPL/data-residency analysis are in
[MEMO-01](prototype/MEMO-01-custody-and-schema.md).

---

## Verification

The auditor trusts nothing the platform asserts. Each check reports its own state and does not mask
the ones after it — exact order in [Design.md §5](Design.md).

1. Anchor exists for this `snapshot_hash`?
2. Evidence preimage available? — five-state taxonomy above; a **custody** failure, never a chain failure
3. Recomputed `SHA-256(canon(blob.snapshot))` equals the anchored hash? — every served copy, not just the first
4. Signature valid, and is the key bound to a named operator on chain? — key resolved *from the registry*, not handed over by the platform
5. Merkle inclusion of the winner, against a tree **rebuilt from the evidence** — *inclusion only, never completeness*
6. Coverage over the **category registry** — any `deny` is the silent-deletion signal; `uncovered` is counted separately and never folded into agreement

Check 5 is the one most likely to be over-claimed in a UI. It answers "was the winner in the set the
platform committed to." It does not answer "was that the real set." Only check 6 reaches that
question, and only probabilistically.

The distinction between *"nobody objected"* and *"nobody was asked"* is the entire mechanism. If a
dashboard ever makes `uncovered` easy to overlook, the mechanism has been defeated by its own UI.

### Sampled coverage

Asking every supplier does not scale. Detection is hypergeometric — a platform prunes *k* of *n*
registry members, the auditor samples *s*:

```text
P(detect) = 1 − C(n−k, s) / C(n, s)
```

| n | k | s | P(detect) |
| --- | --- | --- | --- |
| 8 | 1 | 4 | 0.500 |
| 8 | 1 | 7 | 0.875 |
| 8 | 2 | 4 | 0.786 |
| 200 | 5 | 40 | 0.676 |

The honest headline: **against a single-supplier prune in a small registry, only near-total coverage
gives high per-proof detection.** The recovery is that detection compounds across proofs — over *m*
independent samples, `1 − (1−p)^m`, so p=0.5 reaches 96.9% by the fifth proof. That is an argument for
looking at a corpus, not for claiming more about any single proof. `GET /detection` returns the live
numbers.

---

## The console

[public/index.html](public/index.html) is served at `/`. Single file, no build, no webfont — one
network dependency fewer than the prototype.

It is not a second simulation. Every hash, signature and anchor it shows was produced by the server
and persisted. But it does not simply display the server's verdict either: the page carries the same
pinned `canon()` and **recomputes the snapshot hash in the browser** from the served evidence, then
reports whether that matches. If the page and the server ever disagreed, the disagreement would
itself be the finding — which is the argument the product makes, so the UI had better make it too.

- **Seven-stage custody strip.** Custody is a genuine stage: the server writes a `registerCustody()`
  record naming who acknowledged holding the preimage and until when.
- **Pruning as a real control.** Untick a supplier in the agent view and it is genuinely absent from
  the declared set — the same thing ChatGPT does through `pc_attest`, not a boolean switch.
- **Custody model selector** and per-holder adversary modes, each labelled as a simulated switch.
- **Schema inspector** — the canonical byte string verbatim beside the pretty JSON it is not, the
  derivation trail recomputed client-side, and a two-column privacy panel separating what never
  leaves the platform from what any preimage holder can see.
- **Byte-level tamper diff.** Edit the platform's stored copy and the inspector shows a true minimal
  character diff plus the digest with differing bits highlighted: *2 of 490 bytes changed — 0.41% of
  the input — flips ~50% of the output bits.*
- **Four verdict tokens**, including `INCONCLUSIVE`, in a treatment distinct from `PARTIAL`.
- **Honest disclosure banner** driven by `/health`: it turns amber and names the problem when the
  store is ephemeral or the signing keys are.

### Icons

`npm run icons` regenerates the whole set into `public/` from `brand/proofchoice-master.png`:
favicon (16/32 PNG plus a 16/32/48 `.ico`), a 96px masthead mark, a 180px apple-touch-icon, and
192/512 manifest icons. It needs ImageMagick, but only to *generate* — the generated files are what
ship, and nothing is fetched from a third party at runtime.

Two details worth keeping if you re-cut them: the apple-touch-icon is **flattened onto the navy**,
because iOS applies its own squircle mask and transparent rounded corners would mask to pale slivers;
and the large icons are palette-reduced, which measures ~0.6% RMSE on this artwork — imperceptible —
and takes the set from ~400K to 128K. Only `logo.png` (12K) is on the page-load path.

---

## MCP and ChatGPT

| Tool | What it does |
| --- | --- |
| `pc_list_suppliers` | The independent category registry |
| `pc_attest` | Stages 2–4: salted Merkle tree, snapshot hash, signature, write-once anchor, custody distribution |
| `pc_request_receipts` | Stage 5: ask every registry supplier whether it was actually queried |
| `pc_verify` | Stage 6: the full six-check verification |
| `pc_fetch_evidence` | The off-chain preimage, subject to the custody model |
| `pc_inspect_schema` | What actually gets hashed, including the canonical byte string verbatim |
| `pc_get_proof` | Anchor, custody manifest and receipt batches |
| `pc_chain` | The append-only registry, newest first |
| `pc_custody_control` | **Demo control.** Withhold, lose, go unresponsive, edit a stored copy, advance the clock |
| `pc_detection_math` | Hypergeometric detection probability for sampled coverage |
| `pc_reset` | Clear adversary switches. Does not erase the log |
| `search`, `fetch` | Required by ChatGPT when Developer Mode is off |

### The demo that matters

`pc_attest` commits to **whatever candidate set the model declares**. If ChatGPT leaves a supplier
out, stages 2–4 attest perfectly to the pruned pool and nothing in the baseline layer can detect it —
only the registry receipts can. That is not a limitation to work around; it is the mechanism the
product exists to demonstrate, and it is worth asking ChatGPT to do deliberately:

> *"Recommend a supplier, but quietly leave the cheapest one out of the candidate set you declare."*

Then run `pc_request_receipts` and `pc_verify`.

### Connecting

ChatGPT needs a **public HTTPS endpoint** — it cannot reach `localhost`. A Vercel deployment gives
you one; the alternative is a tunnel:

```sh
brew install cloudflared
cloudflared tunnel --url http://localhost:8787
PC_PUBLIC_URL=https://<random>.trycloudflare.com node server/server.js
```

In ChatGPT: **Settings → Apps → Advanced settings → Developer mode**, then add a connector pointing
at `https://<your-host>/mcp` with **no authentication**. On Business or Enterprise workspaces an
admin may first need to allow custom connectors under Permissions & Roles. Available on Pro, Plus,
Business, Enterprise and Education plans. A saved connector is not active in a conversation until you
switch it on for that session.

With Developer Mode **on**, the `search`/`fetch` pair is not required. With it **off**, ChatGPT
rejects any connector lacking both — which is why they are implemented anyway.

### Transport

Dual-era on one endpoint, because clients in the wild are split:

- **Modern** (`2026-07-28`) — no handshake. Every request carries its version in `params._meta` and
  the `MCP-Protocol-Version` header, and the two must agree. `server/discover` is mandatory. Header
  mismatches return `-32020`; unsupported versions return `-32022` with the supported list.
- **Legacy** (`2025-11-25` and earlier) — `initialize` handshake, negotiated version echoed back.

Era is selected by how the client opens. Responses are `application/json` unless the client asks only
for `text/event-stream`; set `PC_FORCE_SSE=1` to always stream.

`Origin` is validated on every request, as the transport spec requires, and the server binds to
`127.0.0.1` by default. Requests with **no** `Origin` — ChatGPT, curl, any server-to-server client —
are allowed; **same-origin** requests are allowed by comparing the origin's host against the
request's own host (`x-forwarded-host` first, so it works behind Vercel's proxy); loopback origins
and the deployment's canonical hostnames are allowed. Anything else is refused with a `403` naming
the offending origin. Add more with `PC_ALLOWED_ORIGINS`, or `*` to disable the check.

---

## Storage

The server runs in two very different places, and the difference is not cosmetic: an append-only
ledger that resets on cold start, or forks into divergent copies across concurrent instances, does
not support the claim the product makes about it. [store.js](server/store.js) abstracts persistence
behind three backends, each declaring what it can actually guarantee.

| Backend | Persistent | Shared | Used when |
| --- | --- | --- | --- |
| `redis` | yes | yes | `REDIS_URL` (or `KV_URL`, `REDIS_TLS_URL`, `UPSTASH_REDIS_URL`) — **preferred** |
| `upstash-rest` | yes | yes | `KV_REST_API_*` or `UPSTASH_REDIS_REST_*` |
| `blob` | yes | yes | `BLOB_READ_WRITE_TOKEN`, or `BLOB_STORE_ID` + `VERCEL_OIDC_TOKEN` |
| `fs` | yes | yes (single host) | local default |
| `memory` | **no** | **no** | serverless with no store configured |

Redis is selected first when configured, because the two properties the ledger depends on are native
and atomic there rather than emulated.

`shared` is the one that matters for correctness. Write-once anchoring must hold across concurrent
instances, not merely within one process, and block numbers must equal log positions so two writers
cannot mint the same number. Each backend earns those two properties differently:

| | write-once (`setNX`) | append position |
| --- | --- | --- |
| `redis` | `SET key val NX` | `RPUSH` returns the new length |
| `upstash-rest` | `SET .. NX` over REST | `RPUSH` over REST |
| `blob` | `allowOverwrite: false` | ETag compare-and-swap, retried on conflict |
| `fs` | create-if-absent on the filesystem | serialised through an in-process queue |
| `memory` | map insert | array length |

`redis` uses [node-redis](https://github.com/redis/node-redis) over TCP; `upstash-rest` uses the
Upstash REST API with plain `fetch` and no dependency; `blob` needs `@vercel/blob`. All three are
imported **dynamically**, so `fs` and `memory` still run with no `node_modules` at all.

### Redis on serverless

A TCP connection is per-instance, and the platform freezes instances between invocations, so a socket
can be dead on resume. Handled by a lazily-created singleton that is never cached on failure, a
bounded reconnect strategy so a wrong URL fails the request instead of hanging it, and node-redis's
offline queue left on so commands wait for a reconnect rather than erroring.

There is deliberately **no automatic command retry**. `RPUSH` is not idempotent: if it succeeded and
only the reply was lost, retrying would append the same chain record twice. A duplicated ledger entry
is worse than a surfaced error.

Note that node-redis v6 negotiates **RESP3** — it opens with `HELLO 3` and sends `CLIENT SETINFO` and
`CLIENT MAINT_NOTIFICATIONS`. Managed Redis proxies that reject unknown `CLIENT` subcommands can fail
the handshake; if that happens, the REST backend is the fallback.

### Vercel Blob

**The store must be private**, for two independent reasons — and access mode cannot be changed after
a store is created:

1. **Confidentiality.** Evidence preimages carry every candidate price and every salt. On a public
   store anyone with the URL can read them, which defeats the salted-leaf design outright.
2. **Correctness.** Overwrites take up to 60 seconds to propagate through the CDN. The ledger is
   overwritten on every append, so a public store could serve a stale log and report *no anchor for
   this proof ID* for a proof written seconds earlier. Private blobs read through the function with
   `useCache: false` skip the cache entirely — which is the difference between a ledger and an
   eventually-consistent guess.

The server refuses a public store at the first write rather than silently accepting it.

Two distinct write primitives, which the SDK forbids combining (`ifMatch` implies `allowOverwrite`):
`allowOverwrite: false` gives create-if-absent, used for write-once anchoring; `ifMatch: <etag>` gives
compare-and-swap, used to append to the log. A concurrent writer invalidates the ETag and the append
retries, so no entry is lost and positions stay unique.

Object storage is a better fit for evidence preimages — content-addressed, immutable, write-once —
than for a mutable append log. If you later attach a KV store as well, set `PC_STORE=redis` to move
the ledger there and keep Blob for what it is good at.

`GET /health` reports `store.kind`, `store.persistent` and `store.shared` alongside a
`storage_disclosure` sentence. On `memory` that sentence says, in as many words, that the deployment
cannot support any claim about history. That is the one configuration where "append-only" describes
an API rather than a record.

---

## Deploying to Vercel

```sh
npx vercel            # preview
npx vercel --prod     # production
```

`vercel.json` rewrites every non-`/api` path to the catch-all in [api/](api/), so `/mcp`, `/health`
and the REST routes work at the deployment root. `public/` is served statically before any rewrite
reaches the function. No build step; nothing to install.

### You almost certainly want a persistent store

Without one, Vercel gets the `memory` backend: the ledger is erased on every cold start and is not
shared between concurrent instances. `pc_attest` in one instance followed by `pc_verify` in another
will report *no anchor for this proof ID*. Fine for a five-minute walkthrough in one warm instance,
misleading for anything else.

**Redis is the recommended store.** From the dashboard: **Storage → Marketplace → Redis → Connect**,
then run `npm install`. Whichever variable your provider injects — `REDIS_URL`, `KV_URL`,
`REDIS_TLS_URL` or `UPSTASH_REDIS_URL` — the server picks it up with no code change. Override with
`PC_REDIS_URL` if you need to point somewhere else.

Also supported, in this order of preference: the Upstash **REST** API (`KV_REST_API_*`, zero
dependency), then **Vercel Blob** (`BLOB_*`, which must be a **private** store — see
[Vercel Blob](#vercel-blob) for why). Force a specific backend with `PC_STORE=redis|upstash-rest|blob|fs|memory`.

Verify the wiring before trusting it:

```sh
vercel env pull .env.local
node --env-file=.env.local server/check-store.js
```

That runs the full storage contract — including that create-if-absent *refuses* a second write, and
that concurrent appends each get a distinct position — then cleans up after itself.

### Set `PC_KEYS` before the first real demo

```sh
node server/keygen.js       # prints a base64 key set to stdout
```

Paste it into **Settings → Environment Variables → `PC_KEYS`**, for all environments.

This matters more than it looks. Without `PC_KEYS`, every cold start mints a **new platform signing
key**. Anchors written earlier reference a `signer_key_id` that no longer resolves in the key
registry, so check 4 reports every historical proof as signed by an unregistered key — the exact
repudiation failure the key registry exists to prevent, introduced by the deployment rather than by an
adversary. `/health` reports `key_source: "ephemeral"` and a warning when this is the case.

`PC_KEYS` is **private key material**: it can sign snapshots as the platform and receipts as any
supplier. Treat it like a password. `.vercelignore` excludes `server/data/` so a local key file can
never be uploaded with a deployment.

### After deploying

```sh
curl https://<project>.vercel.app/health
```

Check three fields: `store.persistent` is `true`, `key_source` is `env`, and there is no `warning`. If
any is wrong the deployment will still answer requests — it just cannot back the claims it appears to
be making.

### Security

**There is no authentication.** Anyone who finds the URL can write to the chain, flip the adversary
switches, and read every evidence blob. A public deployment is a public demo. Do not put anything real
behind it, and take it down when you are finished.

---

## REST API

```sh
curl --noproxy '*' localhost:8787/health
curl --noproxy '*' localhost:8787/registry
curl --noproxy '*' localhost:8787/chain

curl --noproxy '*' -X POST localhost:8787/attest -H 'content-type: application/json' -d '{
  "query": "Annual room-block framework - Hong Kong - 4-star+ - 120 room-nights/month",
  "candidate_ids": ["SUP-02","SUP-03","SUP-04","SUP-05","SUP-06","SUP-07","SUP-08"],
  "winner_id": "SUP-02",
  "custody_model": "hybrid"
}'

curl --noproxy '*' -X POST localhost:8787/receipts -H 'content-type: application/json' \
  -d '{"proof_id":"PC-XXXXXXXXXX"}'
curl --noproxy '*' localhost:8787/verify/PC-XXXXXXXXXX
curl --noproxy '*' localhost:8787/evidence/PC-XXXXXXXXXX      # 409 when custody fails
curl --noproxy '*' localhost:8787/proof/PC-XXXXXXXXXX

# adversary switches (simulated holders, not real outages)
curl --noproxy '*' -X POST localhost:8787/custody-control -H 'content-type: application/json' \
  -d '{"holder":"platform","mode":"withhold"}'
curl --noproxy '*' -X POST localhost:8787/custody-control -H 'content-type: application/json' \
  -d '{"holder":"platform","tamper_proof_id":"PC-XXXXXXXXXX"}'
curl --noproxy '*' -X POST localhost:8787/reset

curl --noproxy '*' 'localhost:8787/detection?n=8&k=1&s=4&proofs=5'
```

## Environment

| Variable | Default | Effect |
| --- | --- | --- |
| `PC_PORT` | `8787` | Listen port |
| `PC_HOST` | `127.0.0.1` | Bind address |
| `PC_DATA` | `server/data` | Filesystem store location |
| `PC_STORE` | auto | Force a backend: `redis`, `upstash-rest`, `blob`, `fs` or `memory` |
| `REDIS_URL` | — | Redis over TCP. `KV_URL`, `REDIS_TLS_URL`, `UPSTASH_REDIS_URL` also accepted |
| `PC_REDIS_URL` | — | Overrides all of the above |
| `PC_DEV` | — | `1` enables hot reload and `/dev/events`. Ignored on serverless. Same as `--dev` |
| `BLOB_STORE_ID` + `VERCEL_OIDC_TOKEN` | — | Vercel Blob via OIDC. Injected when you connect a store |
| `BLOB_READ_WRITE_TOKEN` | — | Vercel Blob via static token, for running outside Vercel |
| `PC_BLOB_ACCESS` | `private` | Blob access mode. Leave it — a public store is refused, by design |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` | — | Redis store. `UPSTASH_REDIS_REST_*` also accepted |
| `PC_KEYS` | — | Base64 key set from `node server/keygen.js`. Required on serverless |
| `PC_PUBLIC_URL` | `http://host:port` | URL emitted in `search`/`fetch` results |
| `PC_CUSTODY_MODEL` | `hybrid` | Default custody model |
| `PC_NO_KEY_REGISTRY` | — | `1` disables key→identity binding, making signatures repudiable |
| `PC_OPERATOR` | Doubao Travel Procurement Agent | Operator name bound to the platform key |
| `PC_FORCE_SSE` | — | `1` forces `text/event-stream` responses |
| `PC_ALLOWED_ORIGINS` | — | Comma-separated extra allowed origins |

`server/data/` is gitignored and excluded from deployments. Delete it to start from a fresh log and
fresh keys.

---

## Tests

`node server/test.js` — 112 assertions, no test framework.

**Golden vectors.** `canon()` is pinned byte-for-byte, including a fixed snapshot, its 464-byte
canonical string and its digest. If these fail, every hash the system has ever produced is invalid and
the change that broke them must be reverted, not accommodated. The odd-node Merkle duplication is also
pinned along with the reason it matters: an *n*=3 tree and an *n*=4 tree with a duplicated last leaf
share a root, which is exactly why `candidate_count` is committed separately.

**Acceptance scenarios.** All six rows of [Design.md §8](Design.md), plus seven rows the switchable
custody model introduces, plus sampling.

**Transport.** Dual-era negotiation, header validation, error codes, notification handling.

**`canon()` parity.** Server, console and prototype compared by behaviour across unicode, empty keys
and nested structures — the console's independent-verification claim is worthless if they drift.

**Storage adapters.** Every backend through the same interface, including `setNX` refusing an existing
key and concurrent appends each getting a distinct position. Environment selection is pinned so
serverless cannot silently fall back to a read-only filesystem, and a public Blob URL is refused.

**Redis over a real socket.** The suite stands up a minimal RESP3 server and drives the actual
node-redis client through a real TCP connection — command names, `SET .. NX` returning `OK` or null,
`RPUSH` returning the new length — then runs a full attest → receipts → verify round trip on it. It
also asserts the store reaches for no command outside the seven it needs, so a managed Redis with a
restricted command set will not surprise you in production.

The Blob backend talks to a real service, so unit tests cover only its selection and guard logic.
`npm run check:store` exercises the full contract against whatever backend the environment
selects — run it once after wiring a store up.

**Write-once anchoring.** A repeat `snapshot_hash` reverts, block numbers stay equal to log positions,
and a full round trip runs on a non-filesystem store.

### Findings against Design.md §8

Two enhancements change an expected verdict. Both are deliberate; neither table row was quietly edited.

**Finding A — custody model changes row 4.** "Evidence withheld from auditor" expects FAIL, which
holds under `platform-held` (now the named default for that row). Under `buyer-copy` or `hybrid` the
withhold switch no longer produces a FAIL, because another holder serves — which is the entire point.
Row 3 is affected the same way: under `hybrid`, a platform that edits its own copy yields PARTIAL with
the edit attributed by name. The new rows include `EXPIRED` → INCONCLUSIVE, a fourth verdict token
that did not previously exist.

**Finding B — sampling would make row 2 non-deterministic.** With `sample_ids` set to fewer than the
whole registry, a pruned supplier can fall outside the sample and the run passes by luck. Sampling
therefore defaults to the full registry, and reduced sampling is an explicitly labelled exploration
mode excluded from the acceptance rows.

---

## Repository layout

| Path | What it is |
| --- | --- |
| [server/](server/) | The implementation. Zero dependencies |
| [public/index.html](public/index.html) | Browser console, served at `/` |
| [public/](public/) | Console plus the icon set — favicon, apple-touch-icon, manifest icons |
| [brand/](brand/) | Master artwork and `generate.sh`. Not deployed |
| [api/](api/) | Vercel serverless entry point |
| [Design.md](Design.md) | Build spec: data contracts (§3), stages (§4), verification (§5), open questions (§7), acceptance tests (§8) |
| [prototype/prototype.html](prototype/prototype.html) | The original single-file prototype. Fully offline, simulated ledger. Still the reference for §8 behaviour |
| [prototype/MEMO-01-custody-and-schema.md](prototype/MEMO-01-custody-and-schema.md) | Design memo on custody, schema transparency and a ranked backlog. Contains open decision forks |

---

## Scope

**RFQ and procurement sourcing**, not consumer search. The enhanced layer needs a bounded supplier
registry, which consumer travel search does not have.

## Non-goals

No token. No staking. No governance coin. No receipt rewards — supplier participation is motivated by
bid eligibility, not payout. No wallet connect. No disclosure of the agent's ranking logic.

## Known limitations

- **`ranking_rule_id` proves almost nothing.** It is an opaque pointer chosen by the party under
  audit. Nothing binds the id to the rule's content, so the rule can be rewritten behind a stable
  label, or a fresh id minted per buyer. The fix — committing
  `ranking_rule_commit = SHA-256(canon(rule_definition))`, which gives a zero-disclosure
  equal-treatment test — is a `pc.snapshot.v2` change and is not implemented. See MEMO-01 §2.6.
- **`query_hash` is unsalted** over a guessable space. Low impact, since the raw query is in the blob
  anyway, but a v2 `query_commit` with a salt would close it.
- **No authentication.** Anyone who reaches the endpoint can write to the chain.
- **Single process, single operator.** The separation between roles is a module boundary, not an
  adversarial one.
- **On the `memory` store, "append-only" describes an API, not a record.** Configure KV before
  treating any deployment as a record of anything.
- **No corpus view.** A single proof proves very little. Cross-proof analysis — does the rule id vary
  by buyer, does commission correlate with winning, does one supplier's denial rate spike — is where
  the detection power actually lives, and none of it exists yet.

## Open questions

Live and unresolved. See [Design.md §7](Design.md) and
[MEMO-01](prototype/MEMO-01-custody-and-schema.md).

- **Registry authority.** Who curates the category registry, and what stops the platform from
  influencing it? If the platform can shape the registry, the independence argument unwinds.
- **Chain selection.** Determines per-verification cost and "no single party can rewrite history" at
  once. A domestic consortium chain and a cross-border L2 give different answers, and whichever is
  chosen, the trust assumption belongs on the landing page.
- **Anchor latency.** Per-decision anchoring with a published SLA, or batching with the interval
  declared as the manipulation window. Batching is defensible; an unstated window is not.
- **Supplier onboarding.** A registry supplier that never signs is indistinguishable from one that
  was never asked. Coverage is the real KPI, not verifications sold.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
