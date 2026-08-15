# Memo 01 — Evidence custody · Schema transparency · Ranked backlog

Input: `Design.md` §3, §5, §7.1, §8 and `prototype.html`. No code written. Decision forks are
marked **F1–F4** and collected at the end; everything else is a recommendation I'm prepared to
implement on approval.

---

## 0. The reframing that makes Part 1 tractable

The evidence blob is **self-authenticating**. Its integrity comes from `SHA-256(canon(snapshot))`
matching the anchor — a check that runs identically no matter who handed the blob over. A buyer
cannot forge it. An auditor cannot forge it. The platform cannot forge it either; that is check 3
in §5 and it already works.

So custody is **not an integrity problem. It is an availability problem, and only an availability
problem.** The preimage needs no *trusted* custodian, only an *available* one. That single
observation collapses most of the option space:

- Nobody holding a copy has to be trusted, so copies can be handed to anyone, including parties
  with an interest in the outcome.
- Replication is therefore pure upside with no trust cost. The only cost is bytes, and the blob is
  ~1–2 KB for an eight-candidate pool.
- The entire design question reduces to: *how many independent parties must simultaneously decline
  to produce a copy, and can we tell which one declined?*

Everything below follows from that.

---

# Part 1 — Off-chain evidence storage

## 1.1 Custody models

| Model | Who can withhold | Who can lose it | Who pays | Auditor's recourse when gone |
|---|---|---|---|---|
| **Platform-held with SLA** (prototype today) | The platform — i.e. the party under audit, unilaterally | The platform; loss is indistinguishable from withholding | Platform; marginal cost ≈ 0, it already holds the data | None. `FAIL · data availability`. The anchor survives, the evidence does not. |
| **Buyer copy at recommendation time** | The buyer — but the buyer is the injured party | The buyer; enterprises lose things, but now ≥2 copies must fail together | ≈ 0. The blob rides the response as an extra field | Ask the other holder. Withholding now needs the platform *and* its own customer. |
| **Encrypted escrow, named third party** | The escrow agent — contractually bound, no stake in the outcome | The escrow agent, under an SLA that is their entire business | Per-proof fee, real contract, real onboarding friction | Failure is attributable to a **neutral**. That is evidentially different from the accused failing, and it is the only thing platform-held can never provide. |
| **IPFS (content-addressed)** | Whoever pins. If the platform is the sole pinner, this is platform-held with extra steps and a false sense of durability | Everyone, silently, when pins lapse | Pinning service — at which point it *is* escrow wearing a CID | Nothing, unless a paid pinner exists; then see escrow |
| **Arweave (permanent, public)** | Nobody — that's the pitch | Nobody | One-time endowment | Nothing needed. **But see §1.6 — this option is eliminated on jurisdiction, not on merit.** |
| **Auditor-held** | The auditor | The auditor | Auditor | Only works if the auditor exists *at issue time*. Most proofs are never audited; you cannot push to a party not yet retained. Valid as a **retention** model (auditor takes and keeps a copy when an audit opens, so the platform cannot withdraw mid-dispute), not as an **issuance** model. |
| **Hybrid** | Requires all holders to decline together | Requires all holders to fail together | Sum of the above, dominated by escrow | Names which holder failed, and why. **Recommended.** |

### Recommendation — hybrid, in this implementation order

1. **Buyer copy pushed at recommendation time.** Costs essentially nothing and produces the single
   largest structural change available: unilateral withholding by the platform stops working. The
   platform must now persuade or coerce the party it harmed.
2. **A custody manifest committed alongside the anchor** (see §1.2 below). This is what makes the
   failure taxonomy in §1.5 *checkable* rather than asserted.
3. **A neutral custodian** for regulated or high-value deals. Natural candidate: the relayer that
   already exists for receipts (§2 decision 2) — it is already specified as neutral, already
   handles per-proof traffic, and reusing it avoids introducing a fourth party.
4. **Liveness probes**, reported at corpus level (§1.4).

Marginal value falls steeply after step 1 and cost rises steeply after step 2. If only one thing
ships, ship step 1.

## 1.2 The custody manifest — the one new mechanism I'm proposing

Without this, "the blob is gone" is a bare assertion by whoever is standing there. With it, it is
a contradiction of a signed statement.

At snapshot time each intended holder signs a short acknowledgement over the snapshot hash — in
effect *"I hold a preimage of this hash and will serve it until `retention_until`."* The manifest
records `{holder_id, role, ack_signature}` plus the retention date, and is recorded next to the
anchor.

What this buys, precisely:

- A holder that **never acknowledged** cannot be blamed for not having it. Absence of a copy stops
  being an accusation by default.
- A holder that **acknowledged and cannot produce** has signed a contradiction. "Lost" becomes a
  costly admission rather than a free excuse.
- **`retention_until` is pre-committed.** This is the load-bearing detail. If the retention period
  lives only in a contract, the platform can label any missing blob "expired" after the fact.
  Committed in advance, `EXPIRED` becomes a date check instead of a claim.

Cost: one record type, one signature per holder, one field. It also introduces a genuine seventh
stage in the chain of custody — see **F4**.

## 1.3 Encryption and key custody

**Does the blob need encrypting at all?** Only where it leaves a party that already has the data:

- *Platform-held* — at rest under existing platform controls. No new scheme.
- *Buyer copy* — the buyer's own data about the buyer's own procurement. TLS in transit, buyer's
  controls at rest. No new scheme.
- *Neutral custodian* — **yes.** Here you are handing competitor price data to a third party, and
  this is where envelope encryption earns its complexity.

If used:

- Per-proof data key (AES-256-GCM), random, never reused.
- The DEK is **wrapped to multiple recipients**: the buyer's public key, the platform's KEK, and
  optionally a regulator or arbiter key. Multi-recipient wrapping is the right primitive because it
  means no single KEK holder gates access, and adding a regulator later is a re-wrap, not a
  re-encrypt of the payload.
- **ProofChoice must not hold a KEK.** If we do, we become the withholding adversary and the whole
  trust argument inverts. Say this in the UI, not just here.

**Buyer loses their key — is the evidence gone?**

Under multi-recipient wrapping, no: the other wraps still open. Buyer key loss degrades to "must
ask another holder" — an availability event, not data loss.

Under single-recipient-to-buyer encryption, yes, permanently — and that design must be **rejected**,
not because permanence is unacceptable in principle but because it hands the platform a free and
unfalsifiable excuse: *"the buyer lost their key."* Any design that manufactures excuses for the
audited party is worse than no design.

Note also that the *ciphertext present, no key produced* case is not the same failure as
*ciphertext absent*, and the verdict must say which — see §1.5.

**A distinction the current copy blurs.** The salts live in the blob, and salts are what make the
leaves non-brute-forceable (§2 decision 4). So blob confidentiality is doing real work: if the blob
leaks, the full candidate set including every price is readable. The claim "no prices leave the
platform" is true of the **anchor** and false of the **blob**. The prototype's Stage 4 copy is
accurate; a reader can nonetheless carry the claim across to the blob. The schema inspector's
"not committed" panel (§2.4) is where I'd fix this, with two explicit columns.

## 1.4 Availability guarantees

**Retention.** Propose 24 months default, buyer-configurable to 36. The ceiling is set by the
three-year general limitation period for contract claims (民法典 art. 188) — evidence that outlives
the claim it could support is retained without a purpose, which is itself a PIPL problem. The floor
is set by the buyer's own audit cycle. Whatever is chosen must be **in the manifest, in advance**.

**Replication.** Three holders, per §1.1. That is the guarantee. I would not publish durability
figures for infrastructure we do not operate.

**Proof of retrievability — over-engineered at this stage, and here is the specific reason.** PDP/PoR
schemes exist to prove possession *without transferring the data*, because transferring the data is
expensive. At 1–2 KB per blob, the transfer is cheaper than the challenge protocol. The correct
version is brute force: periodically re-fetch a sampled blob, recompute the hash, log the result.
That is PoR with the clever part removed, and at this size it is strictly better.

Where it becomes evidence rather than decoration is at corpus level: *"custodian X served 99.7% of
sampled probes last quarter, custodian Y served 71%."* A per-proof probe proves almost nothing; a
published availability record is a reputation an escrow agent will defend. This connects directly to
the corpus view (§3.1) and I would build them together or not at all.

## 1.5 Failure semantics — the taxonomy

The prototype collapses everything into one `FAIL · data availability`. Proposed five states for
check 2:

| State | Trigger | Verdict contribution | Rendering |
|---|---|---|---|
| `AVAILABLE` | ≥1 holder served a blob that hashes to the anchor | proceed to checks 3–6 | green; names which holder served, and which did not need to |
| `WITHHELD` | Holder is reachable, within retention, acknowledged in the manifest, and refuses | **FAIL · adversarial** | red; names each refusing holder individually |
| `LOST` | Within retention, holder signs an admission of non-possession — or ciphertext is present and no key can be produced | **FAIL · custody breach** | red-amber; copy says explicitly *"this is a broken promise, not necessarily a lie"* |
| `EXPIRED` | `now > retention_until` from the pre-committed manifest, consistently across holders | **INCONCLUSIVE · expired** — *not* FAIL | amber, distinct token; checks 1 and 4 still run and still report |
| `UNRESPONSIVE` | No signed answer of any kind | **FAIL · adversarial**, ranked worst | red; the only state where the holder declined even to go on record |

Three arguments for this shape:

1. **`EXPIRED` must not render as FAIL.** Deleting data at the end of a committed retention period
   is the *correct* outcome of a privacy obligation. If expiry looks like guilt, the product
   penalises PIPL compliance, and buyers will respond by retaining forever — which is worse for
   everyone including them. It must not render as PASS either. That requires a fourth top-level
   verdict token, `INCONCLUSIVE`, alongside pass / partial / fail.
2. **`WITHHELD` and `LOST` are not cryptographically distinguishable.** A platform that prefers to
   look incompetent rather than dishonest will always say "lost". We cannot prove otherwise, and the
   memo should not pretend we can. What we *can* do is require each holder to produce a **signed**
   answer. Then "lost" is an admission on the record with legal weight, and saying nothing becomes a
   distinct and worse state. The classification is **attested, not proven** — and the UI should say
   so in those words.
3. **Attribution is per-holder, not global.** Under hybrid custody the verdict should read *"3
   holders acknowledged; platform refused, custodian served, buyer copy not requested"* — not a
   single aggregate. The per-holder line is the thing the buyer's counsel will screenshot.

## 1.6 Jurisdiction — where options die outright

Assuming a Chinese enterprise buyer, these are eliminations, not caveats:

- **Arweave — eliminated.** Permanent, public, no deletion path, no controllable residency. PIPL
  art. 47 requires deletion when the retention period expires or the purpose is achieved; Arweave
  makes deletion impossible by construction. Art. 38 cross-border transfer obligations attach at
  upload. Encryption does not cure either: the transfer happens regardless, and "encrypted today"
  is "decrypted in 2040". Crypto-shredding has not been blessed by Chinese regulators as deletion,
  and the product's compliance story must not rest on an untested reading of a statute.
- **Public IPFS with foreign pinning — eliminated**, same reasoning minus permanence. Domestic
  pinning with a contractual deletion obligation is possible, but then a named custodian exists and
  it is model 3 with a CID.
- **Foreign-hosted escrow — gated, effectively eliminated for a pilot.** Cross-border transfer needs
  one of the art. 38 routes (CAC security assessment / filed SCCs / certification). Months, not
  weeks. If the buyer is a state-owned enterprise or the data touches 重要数据 under the DSL, the
  assessment route is mandatory.

What survives, and one of them is unexpectedly strong:

- **Platform-held, domestic.** Compliant, useless against the adversary.
- **Buyer copy.** No transfer occurs at all — the data stays with the party that generated the
  request. This is simultaneously the *most* compliant option and the *highest-value* one. That
  coincidence is worth stating to a compliance stakeholder, because it is rare.
- **Domestic neutral custodian, ideally a notary (公证处) offering 电子数据存证.** This is the
  strongest option on admissibility rather than on cryptography: Chinese Internet Courts already
  recognise blockchain-anchored 存证, and the buyer's counsel already knows what the term means. An
  IPFS CID does not have case law behind it; a 存证 record does.

**One design change that pays for itself immediately: define the evidence blob as PI-free by
schema.** Supplier *contact* data has no business in it — a supplier ID plus legal entity name is
sufficient, and organisational data is largely outside PIPL's scope. If the blob contains no
natural-person data, most of PIPL falls away and what remains is DSL and commercial-secret handling,
which is a much easier problem. This should be *enforced* in the schema inspector's "not committed"
panel rather than left as a convention.

This also interacts with the unresolved chain question in §6 Phase 2: if BSN or a consortium chain
is chosen, the natural custodian is a consortium member, and the honest framing extends cleanly —
"no *single* party rewrites" becomes "no *single* party can withhold."

## 1.7 The closing answer, stated plainly

**Custody cannot defeat withholding. The preimage is a bearer object; whoever holds a copy can
decline to produce it, and no chain can compel them.**

What custody changes is four things, all of them about cost and visibility rather than possibility:

1. The number of independent parties that must *all* decline: 1 → 3.
2. Whether the declining party is the accused or a neutral with no stake.
3. Whether the refusal is silent or **named** in the verdict.
4. Whether "I lost it" is a free excuse or a **signed admission** that contradicts an earlier
   signed acknowledgement.

Honest quantification, and I will not offer more than this: I cannot put a probability on collusion,
so I will not put a number in the UI. What I can state structurally is that buyer-copy-at-issue
alone removes unilateral withholding — the platform must now bring along the party it harmed. That
is a step change, and it costs approximately nothing. Every model after it is a smaller marginal
gain at a larger cost.

This is the same shape as the rest of the product: **denial becomes expensive; lying does not become
impossible.**

---

# Part 2 — Schema inspector

## 2.1 Field by field — `pc.snapshot.v1`

"Leaks" means: to whoever holds the preimage. Nothing in this table leaks to an anchor-only observer,
because the anchor carries only the hash.

| Field | Type | Source | What committing it proves | What it leaks | What breaks if dropped |
|---|---|---|---|---|---|
| `schema_version` | string enum | Plugin build constant | Which parse and canonicalisation rules apply to everything else | Nothing | A v2 verifier could parse a v1 object under v2 rules and return a **wrong answer confidently**. This field is what makes the migration rule in §2.5 possible at all. |
| `query_hash` | 64 hex | `SHA-256(raw request)`; raw string lives in the blob | This snapshot belongs to *this* request | Nothing directly. The blob holder sees the raw query — volumes, dates, spec, all commercially sensitive | Proofs become fungible across requests. Asked for the proof of a Hong Kong RFQ, the platform produces a clean snapshot from an unrelated one. Serious. |
| `candidate_merkle_root` | 64 hex | Salted leaves, sorted by `id` | The *content* of every candidate as claimed, and enables per-candidate inclusion proofs without revealing the set | Nothing | Total collapse of the baseline layer. The candidate array in the blob becomes uncommitted; prices could be rewritten freely and check 3 would still pass. |
| `candidate_count` | integer | `len(sorted)` | How many leaves the tree should contain | Pool size — commercially mild | Load-bearing, and for a non-obvious reason: this tree duplicates the last node on odd levels (`lvl[i+1] ?? lvl[i]`), so **cardinality is not recoverable from the root**. Two different leaf sets can share a root if the last leaf is duplicated — the classic Merkle malleability shape. Committing the count is precisely the mitigation. |
| `ranking_rule_id` | string | Constant | Which *label* was in force | The label | See §2.6 — as it stands, close to nothing. |
| `commercial_disclosure.paid_placement` | bool | `winner.comm > 0` | Whether the recommended supplier pays the platform — the single most decision-relevant conflict fact | That one bit | The conflict-of-interest claim disappears entirely. You would be committing to an outcome with no disclosure that money moved. |
| `commercial_disclosure.disclosed_supplier_ids` | string[] | Candidates with `comm > 0` | Which candidates had a commercial relationship, without rate or amount | **Which of your competitors pay the platform.** Real leak, commercially spicy, and it should be named rather than glossed | The corpus test dies. Without it you cannot ask whether winners come from the paying set more often than chance — which is where the detection power actually lives. |
| `winner_id` | string | Agent output | What the platform told the buyer, bound before any dispute existed | Nothing the buyer doesn't already know | The platform can retroactively claim it recommended something else. Base case. |
| `nonce` | uuid v4 | Random, per snapshot | Nothing on its own | Nothing | Two things break. (a) Two identical RFQs with identical outcomes collide, and the second `anchor()` reverts on a legitimate write. (b) **Every other field is public or low-entropy**, so without the nonce an anchor-only observer can enumerate plausible snapshots and recover the winner, the count and the rule by brute force. The nonce is the snapshot's salt, and the inspector should label it in exactly those words — it is decision 4 applied one level up. |
| `signer_key_id` | 16 hex | `SHA-256(raw pubkey)[0:16]` | Which key must have signed, and via the on-chain registry, which operator | Which operator instance produced this — intended | Key rotation becomes untraceable and repudiation gets easier. Note it appears in *both* the snapshot and the anchor, so a mismatch between the two is itself detectable — and the auditor should check that. |

### Fields I'd argue are missing (all v2, none of them v1 changes)

- **`ranking_rule_commit`** — §2.6. Highest value of anything in this memo.
- **`registry_version_id`** — a pointer to the category-registry version in force. This converts
  "was any supplier never asked" from a purely sampling question into a set-difference question for
  the *declared* scope: if registry v12 has 8 members and `candidate_count` is 7, the platform has
  committed on the record to considering fewer than the registry, and that is visible with **zero
  receipts**. To be precise about what it does not do: it does not prove the platform actually
  queried anyone. It commits the platform to a denominator. That is still a real upgrade, because
  denominators are currently uncommitted.
- **Custody manifest hash / `retention_until`** — §1.2.

### Findings against v1 as written

1. **`query_hash` is unsalted and the query space is guessable.** Dates, city, star rating, volume —
   an anchor-only observer with a candidate query list can confirm a match. The impact is limited
   (the raw query is in the blob anyway, so this only matters to someone holding anchors and nothing
   else) but the fix is free in v2: `query_commit = SHA-256(canon({query, salt}))`. Do not change v1.
2. **`paid_placement` is doing two jobs.** The name suggests something about the result set; the
   derivation is `winner.comm > 0`, a statement about the winner alone. In v2 I'd rename it
   `winner_pays_commission`. In v1 this is fixed for free by the inspector's *source* column, which
   is exactly the sort of thing the inspector exists to surface.
3. **The auditor verifies with the ambient platform key, not by registry lookup.**
   [prototype.html:504](prototype.html#L504) calls `verifyMsg(PLATFORM.kp.publicKey, …)` rather than
   resolving `onchain.signer_key_id` through `KEYREG`. This makes check 4 quietly stronger in the
   demo than in reality, and it means the `signer_key_id` mismatch case is untestable. Small fix,
   should be done regardless of everything else here.

## 2.2 The derivation trail

A vertical spine, one row per arrow, each row collapsed to `input → output` and expandable to the
exact bytes. Every step **recomputed live** from the existing functions rather than displaying
cached strings — the crypto is real and cheap, so the inspector should itself be a verifier rather
than a diagram of one.

```
candidate object
  └─ canon()                → canonical byte string        [shown verbatim, byte count]
     └─ SHA-256             → leaf                          [64 hex]
        └─ pairwise hash    → Merkle root                   [tree drawn, 8 leaves]
           └─ into snapshot → snapshot object               [pretty JSON]
              └─ canon()    → CANONICAL BYTE STRING         [verbatim, one wrapped line]
                 └─ SHA-256 → snapshot_hash                 [64 hex]
                    ├─ slice(0,10).toUpperCase() → proof_id
                    └─ ECDSA P-256 sign          → signature
                       └─ assemble               → anchor payload
```

Four details that carry the weight:

- **The canonical byte string, verbatim, on one wrapped line, with a byte-length badge** — displayed
  immediately beside the pretty JSON under an explicit label that the pretty form is *not* what is
  hashed. Everyone assumes it is. That contrast is the single most useful thing in the view.
- **Key reordering made visible.** Render the pretty object in insertion order and the canonical
  string in sorted order, so `canon()`'s sort is something you can see happen rather than something
  asserted in a comment.
- **The tree drawn with real leaves.** Under the *prune* switch the pool drops to 7 and the odd-node
  duplication becomes visible — which is both a good teaching moment and the concrete illustration
  of why `candidate_count` is committed.
- **Copy button per step.** Clipboard only, no network.

## 2.3 Byte-level tamper diff

With *tamper* on, the served blob is edited (`winner_id` SUP-01→SUP-02, `candidate_count` 8→7).
Show, computed live:

- The two canonical strings aligned, changed spans highlighted, with a readout: *"12 of 487 bytes
  differ — 2.5% of the input."*
- The two digests with differing **bits** highlighted, and the live Hamming distance: *"127 of 256
  bits differ — 49.6% of the output."*
- One sentence underneath: *"Changing 2.5% of the input changed 49.6% of the output. There is no
  partial match, and no way to steer a digest toward the anchored one."*

Hamming distance over two hex digests is a few lines. This is the most persuasive artefact available
in the whole product and it is currently invisible.

## 2.4 What is deliberately NOT committed

Two columns, because one column is where the current prose gets blurry.

**Never leaves the platform — not in the snapshot, not in the anchor, not in the blob:**

- Commission **rates** and **amounts** — only the per-candidate binary and the disclosed-ID list.
  The audit question is whether money moved, not how much.
- Ranking **weights** and the rule's content — trade secret. See §2.6 for what replaces it.
- Buyer identity — nothing in the snapshot identifies the buyer. PIPL minimisation, and it stops an
  anchor-only observer building a purchase profile.
- Supplier **contact** data — natural-person data, and per §1.6 the blob should be PI-free by schema.
- The agent's internal scores and reasoning — deliberately out of scope. The product commits to
  inputs and outcome, never to reasoning.

**In the anchor: only the hash. But visible to anyone holding the preimage:**

- Every candidate name and unit price.
- Every salt — and therefore the ability to reconstruct and confirm every leaf.
- The full pool, including who was *not* recommended.
- The raw query string.

That second column is the honest counterpart and it is currently only implied. The privacy argument
is about the anchor and the chain; it is *not* an argument about the blob, and the custody model in
Part 1 is what governs the blob.

## 2.5 Schema versioning — the migration rule, proposed now

1. **Verify-as-written.** A proof is verified under the version named *inside* the proof. A verifier
   implements every version it claims to support and **refuses rather than guesses** on an unknown
   version. Because `schema_version` is inside the hashed object, it cannot be retro-labelled.
2. **`canon()` is frozen across all versions, permanently.** Versioning changes which fields exist,
   never how bytes are produced. If canonicalisation must ever change, it takes a new function name
   and a new **anchor** schema version — not a snapshot version. This keeps the one thing that must
   never move from ever moving.
3. **Additive-only within a major.** `v1 → v1.1` may add optional fields. Since `canon()` sorts keys
   and hashes what is present, adding a field changes the hash of *new* proofs only; existing proofs
   remain byte-identical. A v1.1 verifier reads v1 proofs unchanged. Removing or retyping a field
   forces v2.
4. **No silent re-hashing.** A v1 proof is never re-canonicalised under v2 rules. Migration means
   *the verifier learns v2*, never *the archive is upgraded*.
5. **Deprecation is announced with a date.** Proofs outlive software; dropping v1 support is a
   published event, not a release note.
6. **Golden vectors per version, shipped everywhere** — in the repo, in the portable bundle, and
   displayed in the inspector. A fixed snapshot object, its canonical string, its digest. That is how
   a third party confirms an independent implementation agrees, and having it visible in the
   inspector means it can be checked in the room, offline.

## 2.6 `ranking_rule_id` — yes, it is a real hole

Your diagnosis is right, and the hole is open in **both** directions:

- **Same rule, many ids.** Mint `rr.value-weighted.v2-buyerA`, `-buyerB`, … and stay technically
  honest while defeating the corpus test by construction — id variation is only suspicious when ids
  are drawn from a small shared vocabulary.
- **Same id, many rules.** Nothing binds the id to any content, so the rule can be rewritten weekly
  behind a stable label. This direction is worse and is the one the field's description in §3.2
  implicitly assumes away.

As it stands the field proves that the platform used a label.

**What closes it, ascending cost:**

1. **`ranking_rule_commit = SHA-256(canon(rule_definition))`, alongside the id.** The rule stays
   private; the commitment binds it. A platform that changes the rule must change the commit;
   identical commits across buyers becomes a *checkable* claim of identical treatment, and a
   different commit for buyer B is visible even when the id is unchanged. One field, no disclosure,
   and it is the highest-value change in this memo.
   - Honest limits, both of which belong in the UI: the commit binds the *serialised rule object*,
     not the rule's *behaviour* — a rule object containing a random seed or an opaque model
     reference can change behaviour under a stable commit. And it lets you verify **sameness**, never
     **content**. But sameness-across-buyers is exactly the discrimination test, and getting it with
     zero disclosure is an unusually clean win.
2. **A published rule registry.** The platform publishes `rule_commit → human description` on chain
   when a rule is introduced, description fixed at publication. Reveals no weights; prevents silently
   redefining what "value-weighted" means. Cheap.
3. **Rule disclosure under dispute.** Escrow the rule definition preimage with the same custodian as
   the evidence blob, released on a dispute trigger. Same machinery as Part 1, one level up — no new
   concept required.
4. Full disclosure — off the table per §1, not proposed.

Note that the corpus view (§3.1) is the *consumer* of `ranking_rule_commit`. The field is inert
without a corpus, and the corpus's strongest test is unavailable without the field. They should be
scheduled together.

---

# Part 3 — Ranked backlog

Ordered by demo impact per unit of work.

### 3.1 Corpus view — highest, and it is not close

A single proof proves very little. Generate ~50 proofs with real crypto (WebCrypto is fast enough
that this is a second or two), across several buyers and months, with switchable platform behaviours:
rule-commit varies by buyer · commission correlates with winning · one supplier's denial rate spikes.
Three panels: a `rule_commit × buyer` matrix, win-rate for commission-disclosed vs not with the live
binomial, per-supplier denial rate over time.

The copy discipline that makes it credible rather than a dashboard: **correlation is a signal to
investigate, not proof of manipulation** — and show the *n* actually required to reach significance
rather than a manufactured p-value. With eight suppliers and a mild bias, that n is large, and saying
so is more persuasive than hiding it.

### 3.2 Byte-level tamper diff and the avalanche readout

Formally part of the schema inspector (§2.3), but the single highest-impact element inside it. Called
out separately so it does not get scheduled as a detail.

### 3.3 Portable proof bundle + offline verifier

Export one proof as a `.json` bundle: anchor, blob, receipts, key-registry excerpt, golden vectors,
schema version. The verifier, given the single-file constraint, is elegant: **the same HTML file is
the verifier.** Drag a bundle onto the page and it runs §5 against the bundle with no state from the
demo and no network. One file that is both the demonstration and the audit tool.

Label required: the bundle cannot prove the anchor is on a real chain without chain access. The
offline verifier checks the hash, the signature, the Merkle inclusion and the receipt signatures, and
reports the anchor as **asserted, not checked**. The chain is simulated here anyway, so the label is
honest in both worlds.

### 3.4 Sampled coverage with the live number

It is a clean hypergeometric. Platform prunes *k* of *n* registry members; auditor samples *s*
uniformly without replacement; detection is at least one pruned member landing in the sample:

```
P(detect) = 1 − C(n−k, s) / C(n, s)
```

Live figures worth putting on screen:

| n | k | s | P(detect) |
|---|---|---|---|
| 8 | 1 | 4 | 0.500 |
| 8 | 1 | 6 | 0.750 |
| 8 | 1 | 7 | 0.875 |
| 8 | 2 | 4 | 0.786 |
| 200 | 5 | 40 | 0.676 |

The honest and slightly uncomfortable headline: **against a single-supplier prune in a small
registry, only near-total coverage gives high per-proof detection.** Say it. The recovery is that
detection compounds across proofs — over *m* independent samples, `1 − (1−p)^m`, so p=0.5 reaches
96.9% by the fifth proof. That is the real argument, and it points straight back at the corpus view.

One discipline to carry over from decision 9: unresponsive suppliers reduce *effective* coverage, so
the denominator is the responding sample, and `uncovered` is excluded from it rather than counted as
agreement.

### 3.5 Custody selector + failure taxonomy

Task 2.2 as commissioned. See the §8 finding below — it changes an expected verdict, deliberately.

### 3.6 Key rotation timeline

Low effort, sharp payoff. A horizontal timeline of `registerKey` events with validity intervals, the
audited proof plotted on it. The repudiation argument becomes concrete: *"this signature falls inside
the window in which key X was bound to operator Y, registered at block N, before this proof existed."*
Include the back-dating case — a key registered *after* the anchor — because the timeline is the only
rendering in which that is immediately obvious.

### 3.7 Regulator view

Mostly a *composition* of corpus + coverage + custody, so it gets much cheaper once 3.1 and 3.4
exist. Defer until then, then assemble. The genuinely interesting part is rendering the **tiering** —
what a regulator sees that a buyer does not — which is where the selective-disclosure discussion in
§1 becomes visible rather than theoretical.

### 3.8 Cost / latency panel

Lower impact than it looks; a slider that changes a number. It earns its place only because of one
move: the anchor interval, batch size and per-proof cost drive a **declared manipulation window**,
and that window should be displayed *in the Anchor segment of the custody strip* instead of a
timestamp. That puts the §4 unresolved timing question onto the organising element, where it reads as
a consequence of a cost choice rather than a footnote. Build it that way or not at all.

### 3.9 Small fixes worth doing regardless

- **Registry key lookup in check 4** (finding 3 in §2.1). Removes a place where the demo is quietly
  nicer than reality.
- **A permanent "what this does not prove" panel** on the auditor verdict. Inclusion ≠ completeness ·
  coverage = what was asked, not what exists · a signature binds a key, not a truth · custody makes
  withholding visible, not impossible. This is the product's thesis and it is currently distributed
  across four separate notes.
- **Font fallback.** `--sans` and `--mono` both terminate in real system faces and are fine.
  `--disp: "Space Grotesk", "IBM Plex Sans", sans-serif` falls back to a second webfont that also
  will not load, then to generic sans — acceptable, but display type flattens noticeably. With
  `display=swap` there is no blocking FOIT, so the failure mode is cosmetic rather than functional.
  I would keep the link as progressive enhancement and **verify the page with the network blocked**,
  checking for layout shift in the strip and the tables. If you would rather remove the last network
  dependency entirely, dropping the link and using a system stack costs one small design compromise
  and removes the failure mode — your call, tell me which.

---

# Findings against §8 acceptance tests

Two enhancements change an expected verdict. Per your instruction, flagging rather than updating.

**Finding A — the custody selector changes row 4 by design.**
§8 row 4 ("Evidence withheld from auditor") expects `FAIL · data availability`. That holds under
`platform-held`. Under `buyer-copy` or `hybrid`, the *withhold* switch **no longer produces a FAIL**,
because another holder serves the blob — which is the entire point of the demo. Proposed resolution:
name `platform-held` as the table's default so the existing row stays literally true, and add rows
for the other models rather than editing row 4:

| Scenario | Custody model | Expected verdict |
|---|---|---|
| Evidence withheld from auditor | platform-held | **FAIL** · withheld *(unchanged)* |
| Evidence withheld from auditor | buyer copy | **PASS**, with the platform's refusal recorded and attributed |
| Evidence withheld from auditor | hybrid | **PASS**, refusal attributed per holder |
| Retention period elapsed | any | **INCONCLUSIVE · expired** — new row, new verdict token |

The fourth row is new and introduces the fourth verdict token. It needs your sign-off because
`INCONCLUSIVE` is a change to the verdict vocabulary, not just to a scenario.

**Finding B — sampled coverage would make row 2 non-deterministic.**
§8 row 2 ("cheapest candidate pruned") expects a deterministic FAIL, which holds only because all 8
registry suppliers are asked. With sampling at s < n, a run can pass by luck and the acceptance test
stops being a test. Proposed resolution: **sampling defaults to s = n**, and reduced sampling is an
explicitly-labelled exploration mode that is excluded from the acceptance suite. No row changes.

The other four rows are unaffected by everything in this memo.

---

# Decision forks

**F1 — Jurisdiction, and therefore which custody models the selector even offers.**
- *If* the pilot buyer is Chinese-domestic → consortium/BSN chain, domestic custodian, and I would
  offer 存证 notarisation as the escrow option because admissibility is a stronger selling point than
  cryptography with this audience. Arweave and public IPFS are removed from the selector entirely,
  with a one-line note saying why — the elimination is itself a good demo beat.
- *If* cross-border → L2 with published fraud-proof assumptions, and the escrow option carries a
  visible art. 38 transfer-route caveat. Arweave becomes technically available but I would still not
  recommend it, for the deletion reason.

**F2 — Demo audience.**
- *If* it includes a regulator or procurement-compliance persona → corpus (3.1) and regulator view
  (3.7) outrank the portable bundle.
- *If* investor or technical → portable bundle (3.3) outranks the regulator view, because "here is
  the artifact, verify it yourself, offline" is the strongest single moment available.

**F3 — Is `ranking_rule_commit` in scope this cycle?**
- *If yes* → it becomes `pc.snapshot.v2`, and I ship v1 and v2 side by side with a version selector.
  That is a bonus, not a cost: it demonstrates migration rules 1 and 3 concretely instead of
  describing them. Proof IDs change between versions, which is correct and worth showing.
- *If no* → v1 stays frozen, and the inspector documents the hole as a known, dated limitation with
  the proposed fix visible. Also defensible; the hole is more persuasive when named than when quietly
  patched.

**F4 — Where does the custody manifest live, and does the strip grow?**
- *If on-chain* → a new `registerCustody()` record, and the chain-of-custody strip gains a genuine
  seventh stage: `Query · Snapshot · Signature · Anchor · Custody · Receipts · Verdict`. I think this
  is correct — stage 2 in §4 already says "writes the evidence blob to the custodian" without the
  strip ever showing it, so the stage exists in the spec and is missing from the UI. The strip already
  scrolls at 900px minimum, so seven segments fit.
- *If off-chain* → a signed attestation shown only in the auditor view; strip unchanged. Lower risk
  against your "don't decorate the strip" constraint, weaker mechanism, because an off-chain manifest
  can itself be withheld — which is the problem it exists to solve.

---

# What I'd implement on approval, in your stated order

1. **Schema inspector** — §2.1–2.5, including the byte diff and avalanche readout. Needs no decision
   from you except F3, and F3 can be answered after seeing v1 rendered.
2. **Custody selector + failure taxonomy** — §1.1, §1.5, gated on F1 and F4. Includes the per-holder
   attribution line in the verdict and the `INCONCLUSIVE` token.
3. **Corpus view** — §3.1, which is what I ranked first in Part 3, scheduled together with
   `ranking_rule_commit` if F3 is yes.

Everything simulated will be labelled the way `Chain: simulated` is labelled today: the custodian
responses, the corpus proofs' provenance, and the availability record.
