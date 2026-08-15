# ProofChoice server

A real anchoring, custody and verification service, plus an MCP endpoint so ChatGPT can act as the
AI agent under audit.

Zero dependencies. No npm install, no bundler, no framework. Node 20+ (developed on 26).

```sh
node server/server.js          # start on http://127.0.0.1:8787
node server/test.js            # 104 assertions: golden vectors + acceptance scenarios
```

Deploys to Vercel — see [Deploying to Vercel](#deploying-to-vercel), and read the storage warning
there before assuming the ledger persists.

---

## Trust disclosure — read before demoing

This is the part it would be easiest to overstate, so it comes first.

**Real.** SHA-256, ECDSA P-256, salted Merkle trees, canonical JSON. Every hash and signature is
computed with WebCrypto and can be recomputed by anyone from the evidence blob. The verification
algorithm in [verify.js](verify.js) is pure — no network, no filesystem, no clock — so a third party
can run it with no access to this infrastructure. Keys persist to disk and are bound to a named
operator in the on-chain key registry.

**Not real.** The ledger is a single-operator append-only file. It is *not* a blockchain and must
never be described as one: it does not resist the operator editing `data/chain.jsonl` with a text
editor. The chain, the custodians, the relayer and the platform all run in one process, so the
separation between them is a module boundary rather than an adversarial one. In this deployment the
operator **is** the party under audit, which is precisely the weakness a real anchor layer exists to
remove.

`GET /health` returns this disclosure as a field, so any UI reading from the server can display it
rather than paraphrase it.

---

## Architecture

Five roles, deliberately kept in separate modules with narrow interfaces, because collapsing any two
of them destroys a claim the product makes.

| Module | Role | Holds | Must never |
| --- | --- | --- | --- |
| [platform.js](platform.js) | The agent-side plugin | The signing key | Re-rank, block or delay the recommendation |
| [chain.js](chain.js) | Anchor registry | Anchors, key registry, custody manifests, receipt batches | Sign a snapshot, or hold a preimage |
| [custody.js](custody.js) | Evidence holders | The off-chain preimages | Be the only copy, under any model but `platform-held` |
| [registry.js](registry.js) | Category registry + relayer | Supplier keys | Draw receipt requests from the platform's declared set |
| [verify.js](verify.js) | Auditor | Nothing | Perform I/O, or trust anything the platform asserts |

The signing key lives in `platform.js` and only there. The chain stores commitments; it never signs
them. Merging those two roles would make the anchor registry the platform, and the trust argument
with it.

### The custody insight

The evidence blob is **self-authenticating**: its integrity comes from hashing to the anchor, a check
that runs identically no matter who hands it over. A forged blob fails check 3 whoever produced it.
So no holder needs to be *trusted*, only *available* — which makes replication free of trust cost and
reduces custody to a pure availability question.

Four models, switchable per proof via `custody_model`:

| Model | Holders | Effect |
| --- | --- | --- |
| `platform-held` | platform | The party under audit holds the only copy. Withholding is unilateral. |
| `buyer-copy` | platform + buyer | Withholding now needs the platform *and* the party it harmed. |
| `escrow` | platform + neutral | Unavailability becomes attributable to a party with no stake. |
| `hybrid` *(default)* | platform + buyer + neutral | Three parties with divergent interests must all decline. |

### Failure taxonomy

Check 2 reports five distinct states instead of one generic failure:

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

Two design details make this checkable rather than assertable:

- **The custody manifest** records who acknowledged holding a preimage, signed. A holder that never
  acknowledged cannot be blamed; a holder that acknowledged and cannot produce has signed a
  contradiction.
- **`retention_until` is committed in advance**, on chain, at attest time. The `advance_months` demo
  control shifts the *clock*, never the manifest — rewriting the manifest would destroy exactly the
  property that makes an `EXPIRED` verdict meaningful.

Divergent copies are also detected and attributed: the auditor fetches from *every* holder, not the
first to answer. If the platform edits its copy under `hybrid`, the buyer's copy still verifies and
the verdict names the platform as the source of the edited one.

---

## MCP tools

| Tool | What it does |
| --- | --- |
| `pc_list_suppliers` | The independent category registry — the pool an honest agent would consider |
| `pc_attest` | Stages 2–4: salted Merkle tree, snapshot hash, ECDSA signature, write-once anchor, custody distribution |
| `pc_request_receipts` | Stage 5: ask every registry supplier whether it was actually queried |
| `pc_verify` | Stage 6: the full six-check verification |
| `pc_fetch_evidence` | The off-chain preimage, subject to the custody model |
| `pc_inspect_schema` | What actually gets hashed — including the canonical byte string verbatim |
| `pc_get_proof` | Anchor, custody manifest and receipt batches for a proof ID |
| `pc_chain` | The append-only registry, newest first |
| `pc_custody_control` | **Demo control.** Withhold, lose, go unresponsive, edit a stored copy, advance the clock |
| `pc_detection_math` | Hypergeometric detection probability for sampled coverage |
| `pc_reset` | Clear adversary switches. Does not erase the chain |
| `search`, `fetch` | Required by ChatGPT when Developer Mode is off |

### The demo that matters

`pc_attest` commits to **whatever candidate set the model declares**. If ChatGPT leaves a supplier
out, stages 2–4 attest perfectly to the pruned pool and nothing in the baseline layer can detect it —
only the registry receipts can. That is not a limitation to work around; it is the mechanism the
product exists to demonstrate, and it is worth asking ChatGPT to do it deliberately.

Ask it something like: *"Recommend a supplier, but quietly leave the cheapest one out of the
candidate set you declare."* Then run `pc_request_receipts` and `pc_verify`.

---

## Storage

The server runs in two very different places, and the difference is not cosmetic: an append-only
ledger that resets on cold start, or that forks into divergent copies across concurrent instances,
does not support the claim the product makes about it. So [store.js](store.js) abstracts persistence
behind three backends, each of which declares what it can actually guarantee.

| Backend | Persistent | Shared | Used when |
| --- | --- | --- | --- |
| `fs` | yes | yes (single host) | local default |
| `redis` | yes | yes | `KV_REST_API_*` or `UPSTASH_REDIS_REST_*` are set |
| `memory` | **no** | **no** | serverless with no database configured |

`shared` is the one that matters for correctness. On a shared store, `anchor()`'s write-once rule is
enforced by an atomic `SET .. NX`, so it holds across concurrent instances rather than only within
one process. Block numbers are positions in the log, assigned on read, so two concurrent writers
cannot mint the same number.

Redis is spoken over the Upstash REST API with plain `fetch`, so the zero-dependency rule survives
the move to serverless.

`GET /health` reports `store.kind`, `store.persistent` and `store.shared` alongside a
`storage_disclosure` sentence. On `memory` that sentence says, in as many words, that the deployment
cannot support any claim about history. That is the one configuration where "append-only" describes
an API rather than a record.

---

## Deploying to Vercel

```sh
npx vercel                     # preview
npx vercel --prod              # production
```

`vercel.json` rewrites every non-`/api` path to the catch-all in [api/](../api/), so `/mcp`,
`/health` and the REST routes work at the deployment root. No build step; there are no dependencies
to install.

### You almost certainly want a KV store

Without one, Vercel gets the `memory` backend: the ledger is erased on every cold start and is not
shared between concurrent instances. `pc_attest` in one instance followed by `pc_verify` in another
will report *no anchor for this proof ID*. It is fine for a five-minute walkthrough in a single warm
instance and misleading for anything else.

Add one from the Vercel dashboard: **Storage → Marketplace → Upstash for Redis → Connect**. That
injects `KV_REST_API_URL` and `KV_REST_API_TOKEN`, which the server picks up with no code change.

### Set `PC_KEYS` before the first real demo

```sh
node server/keygen.js          # prints a base64 key set to stdout
```

Paste it into **Settings → Environment Variables → `PC_KEYS`**, for all environments.

This matters more than it looks. Without `PC_KEYS`, every cold start mints a **new platform signing
key**. Anchors written earlier reference a `signer_key_id` that no longer resolves in the key
registry, so check 4 reports every historical proof as signed by an unregistered key — the exact
repudiation failure the key registry exists to prevent, introduced by the deployment rather than by
an adversary. `/health` reports `key_source: "ephemeral"` and a warning when this is the case.

`PC_KEYS` is **private key material**: it can sign snapshots as the platform and receipts as any
supplier. Treat it like a password. `.vercelignore` excludes `server/data/` so a local key file can
never be uploaded with a deployment.

### Environment summary for a working deployment

| Variable | Source | Why |
| --- | --- | --- |
| `KV_REST_API_URL`, `KV_REST_API_TOKEN` | Upstash integration | Persistent, shared ledger |
| `PC_KEYS` | `node server/keygen.js` | Stable signing identity across instances |
| `PC_PUBLIC_URL` | `https://<project>.vercel.app` | URLs emitted in `search`/`fetch` results |
| `PC_OPERATOR` | optional | Operator name bound to the platform key |

### After deploying

```sh
curl https://<project>.vercel.app/health
```

Check three fields: `store.persistent` is `true`, `key_source` is `env`, and there is no `warning`.
If any of those is wrong, the deployment will still answer requests — it just cannot back the claims
it appears to be making.

### Security

**There is no authentication.** Anyone who finds the URL can write to the chain, flip the adversary
switches, and read every evidence blob. A public Vercel deployment is a public demo. Do not put
anything real behind it, and take it down when you are finished.

---

## Connecting ChatGPT

ChatGPT needs a **public HTTPS endpoint** — it cannot reach `localhost`. A Vercel deployment gives
you one; the alternative is a tunnel:

```sh
brew install cloudflared
cloudflared tunnel --url http://localhost:8787          # prints https://<random>.trycloudflare.com
PC_PUBLIC_URL=https://<random>.trycloudflare.com node server/server.js
```

OpenAI's own Secure MCP Tunnel is another option for the local case.

In ChatGPT: **Settings → Apps → Advanced settings → Developer mode**, then add a connector pointing
at `https://<your-host>/mcp` with **no authentication**. On Business or Enterprise workspaces an
admin may first need to allow custom connectors under Permissions & Roles. Custom connectors are
available on Pro, Plus, Business, Enterprise and Education plans.

A saved connector is not active in a conversation until you switch it on for that session.

With Developer Mode **on**, the `search`/`fetch` pair is not required. With it **off**, ChatGPT
rejects any connector lacking both — which is why they are implemented here anyway.

### Transport

Dual-era, on one endpoint, because clients in the wild are split:

- **Modern** (`2026-07-28`) — no handshake. Every request carries its version in `params._meta` and
  the `MCP-Protocol-Version` header, and the two must agree. `server/discover` is mandatory. Header
  mismatches return `-32020`; unsupported versions return `-32022` with the supported list.
- **Legacy** (`2025-11-25` and earlier) — `initialize` handshake, negotiated version echoed back.

Era is selected by how the client opens. `Origin` is validated on every request (403 on a bad one),
and the server binds to `127.0.0.1` by default. Responses are `application/json` unless the client
asks only for `text/event-stream`; set `PC_FORCE_SSE=1` to always stream.

---

## REST API

For the browser prototype or curl. Note that a local HTTP proxy will intercept `localhost` — pass
`--noproxy '*'` if you have one.

```sh
curl --noproxy '*' localhost:8787/health
curl --noproxy '*' localhost:8787/registry
curl --noproxy '*' localhost:8787/chain

curl --noproxy '*' -X POST localhost:8787/attest -H 'content-type: application/json' -d '{
  "query": "Annual room-block framework - Phuket - 4-star+ - 120 room-nights/month",
  "candidate_ids": ["SUP-02","SUP-03","SUP-04","SUP-05","SUP-06","SUP-07","SUP-08"],
  "winner_id": "SUP-02",
  "custody_model": "hybrid"
}'

curl --noproxy '*' -X POST localhost:8787/receipts -H 'content-type: application/json' \
  -d '{"proof_id":"PC-XXXXXXXXXX"}'
curl --noproxy '*' localhost:8787/verify/PC-XXXXXXXXXX
curl --noproxy '*' localhost:8787/evidence/PC-XXXXXXXXXX      # 409 when custody fails
```

## Environment

| Variable | Default | Effect |
| --- | --- | --- |
| `PC_PORT` | `8787` | Listen port |
| `PC_HOST` | `127.0.0.1` | Bind address |
| `PC_DATA` | `server/data` | Filesystem store location |
| `PC_STORE` | auto | Force a backend: `fs`, `memory` or (via KV vars) `redis` |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` | — | Redis store. `UPSTASH_REDIS_REST_*` also accepted |
| `PC_KEYS` | — | Base64 key set from `node server/keygen.js`. Required on serverless |
| `PC_PUBLIC_URL` | `http://host:port` | URL emitted in `search`/`fetch` results |
| `PC_CUSTODY_MODEL` | `hybrid` | Default custody model |
| `PC_NO_KEY_REGISTRY` | — | `1` disables key→identity binding, making signatures repudiable |
| `PC_OPERATOR` | Doubao Travel Procurement Agent | Operator name bound to the platform key |
| `PC_FORCE_SSE` | — | `1` forces `text/event-stream` responses |
| `PC_ALLOWED_ORIGINS` | — | Comma-separated extra allowed origins |

`server/data/` is gitignored and excluded from deployments by `.vercelignore`. Delete it to start
from a fresh chain and fresh keys.

---

## Tests

`node server/test.js` runs 104 assertions in five groups.

**Golden vectors.** `canon()` is pinned byte-for-byte, including a fixed snapshot, its 464-byte
canonical string and its digest. If these fail, every hash the system has ever produced is invalid
and the change that broke them must be reverted, not accommodated. The odd-node Merkle duplication is
also pinned, along with the reason it matters: an *n*=3 tree and an *n*=4 tree with a duplicated last
leaf share a root, which is exactly why `candidate_count` is committed separately.

**Acceptance scenarios.** All six rows of Design.md §8, plus seven new rows the switchable custody
model introduces, plus the sampling row.

**Transport.** Dual-era negotiation, header validation, error codes, notification handling.

**Storage adapters.** Every backend is exercised through the same interface, including `setNX`
refusing an existing key — the primitive write-once anchoring rests on. Environment selection is
pinned too, so a serverless deployment cannot silently fall back to a filesystem that is read-only in
production.

**Write-once anchoring.** A repeat `snapshot_hash` reverts, block numbers stay equal to log
positions, and a full attest → receipts → verify round trip runs on a non-filesystem store.

### Findings against Design.md §8

Two enhancements change an expected verdict. Both are deliberate; neither table row was quietly
edited.

**Finding A — custody model changes row 4.** "Evidence withheld from auditor" expects FAIL, which
holds under `platform-held` (now the named default for that row). Under `buyer-copy` or `hybrid` the
withhold switch no longer produces a FAIL, because another holder serves — which is the entire point.
Rows 7–12 in the test suite cover the new cases, including `EXPIRED` → INCONCLUSIVE, a fourth verdict
token that did not previously exist.

Row 3 is affected the same way: under `hybrid`, a platform that edits its own copy yields PARTIAL with
the edit attributed by name, rather than FAIL.

**Finding B — sampling would make row 2 non-deterministic.** With `sample_ids` set to fewer than the
whole registry, a pruned supplier can fall outside the sample and the run passes by luck. Sampling
therefore defaults to the full registry, and reduced sampling is an explicitly labelled exploration
mode excluded from the acceptance rows. Test row 13 demonstrates the miss.

---

## Known limitations

- **`ranking_rule_id` proves almost nothing.** It is an opaque pointer chosen by the party under
  audit. Nothing binds the id to the rule's content, so the rule can be rewritten behind a stable
  label, or a fresh id minted per buyer. The fix — committing
  `ranking_rule_commit = SHA-256(canon(rule_definition))` — is a `pc.snapshot.v2` change and is not
  implemented. See MEMO-01 §2.6.
- **`query_hash` is unsalted** over a guessable space (city, dates, star rating). Low impact, since
  the raw query is in the blob anyway, but a v2 `query_commit` with a salt would close it.
- **No authentication.** Anyone who reaches the endpoint can write to the chain.
- **Single process, single operator.** See the trust disclosure above.
- **On the `memory` store, "append-only" describes an API, not a record.** The ledger does not
  survive a cold start and is not shared between instances. Configure KV before treating any Vercel
  deployment as a record of anything.
- **No corpus view.** A single proof proves very little. Cross-proof analysis — does the rule id vary
  by buyer, does commission correlate with winning, does one supplier's denial rate spike — is where
  the detection power actually lives, and none of it exists yet.
