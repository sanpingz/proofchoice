# ProofChoice — Prototype & Build Spec

**Purpose of this document.** It is the input to a Claude Code session that builds the real
application. It carries the design decisions, the canonical data contracts, the verification
algorithm, and the acceptance tests. It is written to be handed over whole — a fresh session
should not need the slide deck.

**Companion artifact.** `proofchoice-prototype.html` — a single self-contained file that runs the
whole mechanism end to end with real cryptography. Open it in any browser; no build step, no
server, no dependencies beyond a webfont.

---

## 1. What the product is, in one paragraph

An AI agent recommends a supplier. ProofChoice is a plugin sitting beside that agent which
commits, cryptographically, to the candidate set the agent considered, the ranking rule it
applied, which candidates paid commission, and which one won — then anchors that commitment
where the agent cannot later edit it. Separately, it collects signed receipts from every
supplier in the *category registry* to test whether the declared candidate set was the real
one. The agent's ranking logic is never disclosed and never modified.

The claim is bounded, deliberately: **ProofChoice makes denial expensive. It does not make
lying impossible.** Anything in the build that implies otherwise is a bug.

---

## 2. Design decisions carried into the build

These resolve gaps in the source deck. Each is implemented in the prototype and each is
load-bearing — dropping one collapses a claim the product makes.

| # | Decision | What it fixes |
|---|---|---|
| 1 | Receipt requests are drawn from an **independent category registry**, not from the candidate set the platform declares | Otherwise a pruned supplier is never asked, produces no denial, and the audit is circular |
| 2 | Signed receipts reach the registry via a **neutral relayer**, never via the platform under audit | Otherwise the accused party carries the evidence that indicts it, and denials degrade into "no response" |
| 3 | The off-chain evidence blob has a named **custodian and retention SLA** (see §7, unresolved) | The chain guarantees the anchor persists; it does not guarantee the preimage exists. Without a custody answer, an honest-looking anchor can be permanently unverifiable |
| 4 | Every candidate leaf is **salted** with a per-candidate nonce before hashing | Name + price is low-entropy; an unsalted leaf is brute-forceable from a shared Merkle path |
| 5 | `signer_key_id` is bound to an operator identity in an **on-chain key registry** with rotation history | Without it the platform claims key compromise and repudiates every past signature. "Non-repudiable" is otherwise unearned |
| 6 | `proof_id = "PC-" + snapshot_hash[0:10]` — **derived, not assigned** | The holder can locate their own anchor without asking the platform where it is |
| 7 | The snapshot schema is **one canonical object**, defined once (§3) | The deck states it three different ways; three schemas means no schema |
| 8 | The contract read method is named `getAnchor()`, not `verify()` | It returns a stored commitment. Verification is recomputation, and happens off-chain in the auditor |
| 9 | Coverage records `affirm / deny / uncovered` as three distinct states | "Nobody objected" and "nobody was asked" must never collapse into one number |
| 10 | Scope is **RFQ / procurement sourcing**, not consumer search | The enhanced layer needs a bounded supplier registry, which consumer travel search does not have. Say so on the landing page rather than implying coverage the product cannot deliver |

---

## 3. Canonical data contracts

Hash inputs are **canonical JSON**: recursively key-sorted, no whitespace, `JSON.stringify`
for scalars. Any deviation changes every hash. This function is the single most
security-critical thing in the codebase — pin it, test it, never "improve" it.

```js
function canon(o){
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
  return '{' + Object.keys(o).sort()
    .map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
}
```

### 3.1 Candidate leaf

```jsonc
{
  "id": "SUP-01",
  "name": "Kowloon Bay Lodge",
  "unit_price_cny": 1180,
  "commission_disclosed": false,   // binary only — never the rate, never the amount
  "salt": "<uuid v4, per candidate, per snapshot>"
}
```
`leaf = SHA-256(canon(candidate))`. Leaves are ordered by `id` ascending before the tree is
built, so the root is reproducible from an unordered set.

### 3.2 Snapshot — the object that gets hashed

```jsonc
{
  "schema_version": "pc.snapshot.v1",
  "query_hash": "<SHA-256 of the buyer's request string>",
  "candidate_merkle_root": "<64 hex>",
  "candidate_count": 8,
  "ranking_rule_id": "rr.value-weighted.v2",
  "commercial_disclosure": {
    "paid_placement": false,
    "disclosed_supplier_ids": ["SUP-02", "SUP-05"]
  },
  "winner_id": "SUP-01",
  "nonce": "<uuid v4>",
  "signer_key_id": "<16 hex>"
}
```
`snapshot_hash = SHA-256(canon(snapshot))`
`proof_id = "PC-" + snapshot_hash[0:10].toUpperCase()`

`ranking_rule_id` is a version pointer, not the rule itself. The rule stays private; what is
committed is *which* rule was in force, so that swapping rules per-buyer becomes detectable
across a corpus of proofs.

### 3.3 Anchor — the on-chain payload

```jsonc
{
  "snapshot_hash":      "<64 hex>",
  "platform_signature": "<ECDSA P-256 over snapshot_hash>",
  "signer_key_id":      "<16 hex>",
  "block_timestamp":    "<chain-assigned>",
  "schema_version":     "pc.anchor.v1"
}
```
Fixed size. No candidate data, no prices, no commission rates ever leave the platform.

### 3.4 Receipt

```jsonc
{
  "receipt_version": "pc.receipt.v1",
  "anchor_block":    412,
  "snapshot_hash":   "<64 hex>",
  "supplier_id":     "SUP-01",
  "status":          "affirm" | "deny",
  "query_type":      "room-block-rfq",
  "window":          "2026-08"
}
```
Signed by the supplier's own P-256 key over `canon(receipt)`. `deny` means *"I am in this
category registry and I was never queried in this window."*

### 3.5 Evidence blob — off-chain, the preimage

```jsonc
{
  "proof_id": "PC-…",
  "query": "<raw request string>",
  "snapshot": { /* §3.2 verbatim */ },
  "candidates": [ /* §3.1 leaves, with salts */ ]
}
```
Without this, none of the checks in §5 can run. See §7, unresolved.

---

## 4. The six stages

Sequential. Each stage's output is the next stage's only input.

**Stage 1 — the agent recommends.** Calls its data sources, filters, ranks, picks a winner.
The plugin does not participate. Nothing is blocked, delayed or re-ordered.

**Stage 2 — the plugin builds the snapshot.** Salts and hashes each candidate, sorts by id,
computes the Merkle root, assembles §3.2, hashes it. Emits `proof_id`. Writes the evidence
blob to the custodian.

**Stage 3 — the platform signs.** ECDSA P-256 over `snapshot_hash`. Synchronous with stage 2.
This binds the commitment to a key; it does not make the commitment true.

**Stage 4 — anchor.** `anchor(snapshot_hash, signature, key_id)` — write-once, reverts on a
repeat hash. Submitted asynchronously.

> **Unresolved timing question.** The deck says anchoring is asynchronous in one place and
> "locked immediately before the recommendation" in another. Asynchronous anchoring means the
> only trustworthy timestamp lands *after* the decision, leaving a window in which the outcome
> is known but the commitment is not yet fixed. Resolve explicitly:
> - *If* per-decision anchoring is affordable → anchor within N seconds, publish N as an SLA, alert on breach.
> - *If* cost forces batching → publish the batch interval, and treat the interval as the declared manipulation window rather than hiding it. Batching is defensible; an unstated window is not.

**Stage 5 — registry receipts.** Requests go to **every supplier in the category registry**.
Suppliers sign offline. Signed receipts reach the relayer, which batch-anchors them via
`appendReceipts()` and records `coverage_rate`.

**Stage 6 — audit.** §5.

---

## 5. Verification algorithm

The auditor trusts nothing the platform asserts. Implement exactly this order; each check
reports its own state and does not mask the ones after it.

```
1. getAnchor(snapshot_hash) → exists?
      no  → FAIL "no anchor for this proof ID"
2. fetch evidence blob for proof_id
      unavailable → FAIL "data availability" — the anchor is intact and the evidence is gone.
                    Do NOT report this as a chain failure. It is a custody failure.
3. recompute SHA-256(canon(blob.snapshot)) == anchor.snapshot_hash ?
      no  → FAIL "evidence edited after anchoring" (and it is attributable)
4. ECDSA verify(anchor.platform_signature, anchor.snapshot_hash, pubkey(anchor.signer_key_id))
      invalid            → FAIL
      valid, unregistered key → WARN "signature verifies but is repudiable —
                                no on-chain binding to a named operator"
5. Merkle inclusion proof for winner_id against snapshot.candidate_merkle_root
      → proves inclusion ONLY. A root can never prove the set was complete.
        Label it that way in the UI.
6. coverage over the CATEGORY REGISTRY, not the candidate set:
      any deny   → FAIL "silent deletion detected" — a registry supplier signed that it
                   was never queried, while the platform declared its pool complete
      uncovered  → WARN, counted separately, never folded into agreement
      all affirm → PASS
```

Check 5 is the one most likely to be over-claimed in the UI. It answers "was the winner in the
set the platform committed to." It does not answer "was that the real set." Only check 6
reaches that question, and only probabilistically.

---

## 6. Build plan

### Phase 0 — verifiable core, no UI *(this is the highest-value phase; do not skip ahead)*

A single package with no framework dependency:

```
packages/core/
  canon.ts          canonical JSON — pin with golden-vector tests
  merkle.ts         salted leaves, root, path, verify
  snapshot.ts       build + hash, schema validation
  sign.ts           P-256 sign / verify, key_id derivation
  verify.ts         the §5 algorithm, pure, no I/O
```

Every function pure and independently testable. `verify.ts` must run with no network, given
only `(anchor, blob, receipts, registry)` — that property is what makes third-party audit
possible at all, so enforce it with a lint rule.

### Phase 1 — SDK + local harness

- `@proofchoice/sdk` — `attest(candidates, winner, rule_id) → {proof_id, snapshot_hash}`
- Adapters: Express/Fastify middleware, an OpenAI tool definition, a LangChain tool
- Local anchor: an append-only SQLite table exposing the same interface as the contract
- **Gate:** integration must not increase agent p99 latency. Snapshot builds off the response
  path; anchoring is queued.

### Phase 2 — contract + registry

```solidity
anchor(bytes32 snapshotHash, bytes signature, bytes16 keyId)   // write-once, reverts on repeat
appendReceipts(bytes32 snapshotHash, bytes32 receiptsRoot, uint32 coverageBps)
registerKey(bytes16 keyId, string operator)                     // rotation history preserved
getAnchor(bytes32 snapshotHash) view returns (Anchor)
```
No token. No staking. No governance coin. No receipt rewards — supplier participation is
motivated by bid eligibility, not payout, which is the version consistent with the rest of the
model.

> **Chain selection is unresolved and it determines two claims at once.** The ¥0.05
> per-verification cost and the "no single party can rewrite history" property both depend on
> it. An L2 with a centralised sequencer weakens the second while delivering the first.
> - *If* the buyer is a Chinese enterprise → consortium chain or BSN is the realistic
>   compliance answer, and the honest framing becomes "no *single* party rewrites" rather than
>   "no party."
> - *If* the buyer is cross-border → an L2 with published fraud-proof assumptions, stated
>   plainly rather than glossed.
> Whichever is chosen, write the trust assumption into the landing page. The product's entire
> value is not overstating things.

### Phase 3 — the four consoles

Buyer / Agent / Supplier / Auditor, plus the anchor registry explorer. The prototype's layout
and copy transfer directly. Keep the **chain-of-custody strip** — it is the one element that
makes the two-layer mechanism legible in a demo, and it is the element to build the UI around.

### Phase 4 — relayer + coverage

Multiple independent relayers, a supplier signing page requiring no wallet, and a coverage
dashboard where `uncovered` is as visually prominent as `affirm`. If the dashboard makes
uncovered easy to overlook, the mechanism has been defeated by its own UI.

---

## 7. Unresolved — decide before Phase 2

1. **Evidence custody.** Buyer-side copy delivered with the `proof_id`? Encrypted escrow with a
   third party? Retention SLA and what happens at expiry? Currently unanswered, and check 2 of
   §5 fails without an answer. This is the largest hole in the design.
2. **Registry authority.** Who curates the category registry, and what stops the platform from
   influencing it? If the platform can shape the registry, decision 1 in §2 unwinds.
3. **Chain selection** — see Phase 2.
4. **Anchor latency SLA** — see Stage 4.
5. **Supplier onboarding cost.** A registry supplier that never signs is indistinguishable from
   one that was never asked. Coverage is the real product KPI, not verifications sold — which
   means the pricing model currently monetises the layer that proves the least.

---

## 8. Acceptance tests

Each row is a scenario the prototype already runs. Reproduce all six in CI.

| Scenario | Baseline layer | Enhanced layer | Expected verdict |
|---|---|---|---|
| Honest run | all checks pass | 8 affirm, 0 deny | **PASS** |
| Cheapest candidate pruned before snapshot | **passes — cannot see it** | 1 deny | **FAIL** · silent deletion detected |
| Evidence edited after anchoring | recompute mismatch | n/a | **FAIL** · attributable to the signing key |
| Evidence withheld from auditor | anchor intact, unverifiable | n/a | **FAIL** · data availability, not chain failure |
| Pruning + legacy receipt routing | passes | denial signed then dropped in transit | **FAIL to detect** — this is the test that proves decision 2 in §2 is load-bearing |
| Key registry disabled | signature verifies | n/a | **PARTIAL** · verifiable but repudiable |

The fifth row is the important one. It is a test that the system *fails* under a design choice
the deck currently leaves open, and it is the fastest way to explain to a non-technical
stakeholder why the relayer exists.

---

## 9. Handover prompt for Claude Code

> Read `PROOFCHOICE_BUILD_SPEC.md` and `proofchoice-prototype.html`. Build Phase 0 only:
> the `packages/core` modules in §6, in TypeScript, with vitest. Port the canonical-JSON,
> Merkle and verification logic from the prototype's `<script>` block — the prototype is the
> reference implementation and its behaviour under §8 is the specification. Write golden-vector
> tests for `canon()` first. Do not build UI. Do not touch the contract. Stop and report when
> all six §8 scenarios pass against the core with fixtures.
