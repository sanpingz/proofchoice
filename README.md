# ProofChoice

An evidence layer for AI agent recommendations.

An AI agent recommends a supplier. ProofChoice is a plugin sitting beside that agent which commits,
cryptographically, to the candidate set the agent considered, the ranking rule it applied, which
candidates paid commission, and which one won — then anchors that commitment where the agent cannot
later edit it. Separately, it collects signed receipts from every supplier in an independent
*category registry* to test whether the declared candidate set was the real one.

The agent's ranking logic is never disclosed and never modified. Nothing is blocked, delayed or
re-ordered.

## The claim, bounded

> **ProofChoice makes denial expensive. It does not make lying impossible.**

Anything in the build that implies otherwise is a bug. Specifically, and permanently:

- A Merkle proof shows **inclusion**. A root can never prove a set was **complete**.
- Coverage shows what was **asked**, never what **exists**.
- A signature binds a commitment to a **key**, not to a **truth** — the platform is signing its own
  account of its own decision.
- Custody makes withholding **visible and attributable**, not **impossible**.

## Quick start

```sh
open prototype.html
```

No build step, no server, no npm, no bundler. It runs from a USB stick in a lecture room. Any
browser with WebCrypto (all current ones). The only network request is a Google Fonts link, and the
page degrades to system fonts without it.

Pick a role in the left rail, work through the six stages, then flip an adversary switch and re-run
to see which layer notices.

## What is real and what is simulated

This distinction is the whole point of the artifact, so it is labelled in the UI too.

| Layer | Status |
| --- | --- |
| **Real** | SHA-256 and ECDSA P-256 via WebCrypto. Canonical JSON serialisation. Salted Merkle tree — root, inclusion path, verification. Key IDs derived from real public keys. Every hash and signature you see was computed in your browser and can be recomputed. |
| **Simulated** | The ledger (an in-memory append-only array, marked `Chain: simulated`). The relayer transport. The off-chain evidence store, which is currently an in-memory object — see [Open questions](#open-questions). |

Nothing simulated is presented as real. If you add something simulated, label it the way the anchor
registry is labelled today.

## The six stages

Sequential. Each stage's output is the next stage's only input.

| # | Stage | What happens |
| --- | --- | --- |
| 1 | **Recommend** | The agent calls its sources, filters, ranks, picks a winner. The plugin does not participate. |
| 2 | **Snapshot** | Salt and hash each candidate, sort by id, compute the Merkle root, assemble the snapshot object, hash it. Emit `proof_id`. Write the evidence blob. |
| 3 | **Sign** | ECDSA P-256 over `snapshot_hash`. Binds the commitment to a key. |
| 4 | **Anchor** | `anchor(snapshot_hash, signature, key_id)` — write-once, reverts on a repeat hash. |
| 5 | **Receipts** | Requests go to **every supplier in the category registry**, not to the list the platform declared. Suppliers sign offline; a neutral relayer carries the signed receipts. |
| 6 | **Audit** | Pull, recompute, compare. Nothing trusts the platform's own account. |

`proof_id = "PC-" + snapshot_hash[0:10]` — derived, not assigned, so the holder can locate their own
anchor without asking the platform where it is.

Two design decisions carry most of the weight. Receipt requests are drawn from an **independent
registry** rather than the platform's declared candidate set — otherwise a pruned supplier is never
asked, produces no denial, and the audit is circular. And receipts reach the registry via a
**neutral relayer** rather than the platform — otherwise the accused party carries the evidence that
indicts it. The prototype lets you switch the second one off and watch the detection fail.

## Adversary switches

Out-of-band controls in the left rail. Turn one on, re-run, and watch which layer notices.

| Switch | Baseline layer | Enhanced layer | Verdict |
| --- | --- | --- | --- |
| *(none)* — honest run | all checks pass | 8 affirm, 0 deny | **PASS** |
| Drop the cheapest candidate | **passes — cannot see it** | 1 deny | **FAIL** · silent deletion detected |
| Edit evidence after anchoring | recompute mismatch | n/a | **FAIL** · attributable to the signing key |
| Withhold the evidence blob | anchor intact, unverifiable | n/a | **FAIL** · data availability, not chain failure |
| Pruning + legacy receipt routing | passes | denial signed, then dropped in transit | **FAIL to detect** |
| Disable the key registry | signature verifies | n/a | **PARTIAL** · verifiable but repudiable |

The fifth row is the important one: it is a scenario the system *fails*, and it is the fastest way to
explain to a non-technical stakeholder why the neutral relayer exists.

These six are the acceptance suite. An enhancement that changes an expected verdict is a finding to
be reported, not a table to be quietly updated.

## Repository layout

| File | What it is |
| --- | --- |
| [prototype.html](prototype.html) | The working single-file prototype. Real crypto, simulated ledger and transport. This is also the reference implementation — its behaviour under the six scenarios above *is* the specification. |
| [server/](server/) | A real anchoring, custody and verification service, plus an MCP endpoint so ChatGPT can drive it. Zero dependencies. See [server/README.md](server/README.md). |
| [Design.md](Design.md) | Build spec. Data contracts (§3), the six stages (§4), the verification algorithm (§5), the build plan (§6), open questions (§7), acceptance tests (§8). |
| [MEMO-01-custody-and-schema.md](MEMO-01-custody-and-schema.md) | Design memo on evidence custody, schema transparency, and a ranked backlog. Contains open decision forks. |

## Server and MCP

The prototype simulates the ledger and the evidence store in memory. `server/` makes both real —
persistent keys, an append-only ledger on disk, four switchable custody models, and a five-state
failure taxonomy — and exposes the whole mechanism over MCP so ChatGPT can act as the AI agent under
audit.

```sh
node server/server.js     # http://127.0.0.1:8787 — REST + MCP
node server/test.js       # 104 assertions: golden vectors + acceptance scenarios
npx vercel --prod         # deploy — see the storage note below first
```

ChatGPT decides the winner itself and calls `pc_attest` with the candidate set it chooses to declare.
If it omits a supplier, the baseline layer attests perfectly to the pruned pool and cannot see the
omission — only the registry receipts can. That is the mechanism demonstrated with a real agent
rather than a scripted switch.

ChatGPT needs a public HTTPS endpoint — a Vercel deployment or a tunnel. Setup, tool reference and
the trust disclosure are in [server/README.md](server/README.md).

**Deploying:** attach a KV store and set `PC_KEYS` before treating a deployment as a record of
anything. Serverless has no persistent filesystem, so without a database the ledger is erased on
every cold start and is not shared between concurrent instances, and without `PC_KEYS` every cold
start mints a new platform signing key — which would make every historical proof report as signed by
an unregistered key. Both conditions are reported by `GET /health` rather than left to be discovered.

The same honesty rule applies one level down: the cryptography is real, but the ledger is a
single-operator append-only log, not a blockchain, and every component runs in one process. The
server states this in `GET /health` so no UI has to paraphrase it.

## Data contracts

Hash inputs are **canonical JSON**: recursively key-sorted, no whitespace, `JSON.stringify` for
scalars.

```js
function canon(o){
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
  return '{' + Object.keys(o).sort()
    .map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
}
```

> `canon()` is the single most security-critical function in the codebase. Any change to it silently
> invalidates every hash ever produced. Pin it, test it with golden vectors, never "improve" it.

Five contracts are defined in [Design.md §3](Design.md): the candidate leaf, the snapshot
(`pc.snapshot.v1` — the object that gets hashed), the anchor (`pc.anchor.v1` — the on-chain payload,
fixed size, no candidate data), the receipt (`pc.receipt.v1`), and the off-chain evidence blob.

Every candidate leaf is salted with a per-candidate nonce before hashing. Name plus price is
low-entropy; an unsalted leaf is brute-forceable from a shared Merkle path.

## Verification

The auditor trusts nothing the platform asserts. Each check reports its own state and does not mask
the ones after it — see [Design.md §5](Design.md) for the exact order.

1. Anchor exists for this `snapshot_hash`?
2. Evidence blob retrievable? — *unavailable is a **custody** failure, never a chain failure*
3. `SHA-256(canon(blob.snapshot))` equals the anchored hash?
4. Signature valid, and is the key bound to a named operator on chain?
5. Merkle inclusion of the winner — *inclusion only, never completeness*
6. Coverage over the **category registry** — any `deny` is the silent-deletion signal; `uncovered` is
   counted separately and never folded into agreement

Check 5 is the one most likely to be over-claimed in a UI. It answers "was the winner in the set the
platform committed to." It does not answer "was that the real set." Only check 6 reaches that
question, and only probabilistically.

The distinction between *"nobody objected"* and *"nobody was asked"* is the entire mechanism. If a
dashboard ever makes `uncovered` easy to overlook, the mechanism has been defeated by its own UI.

## Scope

**RFQ and procurement sourcing**, not consumer search. The enhanced layer needs a bounded supplier
registry, which consumer travel search does not have.

## Open questions

Live and unresolved. See [Design.md §7](Design.md) and [MEMO-01](MEMO-01-custody-and-schema.md).

- **Evidence custody.** The chain guarantees the *anchor* persists; it guarantees nothing about the
  *preimage*, and without the preimage no check above can run. Today the party holding the only copy
  is the party under audit. This is the largest hole in the design. MEMO-01 Part 1 works the option
  space and recommends a hybrid model.
- **Registry authority.** Who curates the category registry, and what stops the platform from
  influencing it? If the platform can shape the registry, the independence argument unwinds.
- **Chain selection.** Determines two claims at once — per-verification cost and "no single party can
  rewrite history." A domestic consortium chain and a cross-border L2 give different answers, and
  whichever is chosen, the trust assumption belongs on the landing page.
- **Anchor latency.** Per-decision anchoring with a published SLA, or batching with the interval
  declared as the manipulation window. Batching is defensible; an unstated window is not.
- **Supplier onboarding.** A registry supplier that never signs is indistinguishable from one that was
  never asked. Coverage is the real KPI, not verifications sold.

## Non-goals

No token. No staking. No governance coin. No receipt rewards — supplier participation is motivated by
bid eligibility, not payout. No wallet connect. No disclosure of the agent's ranking logic.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
