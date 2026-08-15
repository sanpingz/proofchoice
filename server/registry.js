/* ============================================================
   ProofChoice — category registry, supplier receipts, relayer
   ------------------------------------------------------------
   Design decision 1 (Design.md §2): receipt requests are drawn from
   an INDEPENDENT CATEGORY REGISTRY, never from the candidate set
   the platform declares. Otherwise a pruned supplier is never
   asked, produces no denial, and the audit is circular.

   Design decision 2: signed receipts reach the registry via a
   NEUTRAL RELAYER, never via the platform under audit. Otherwise
   the accused party carries the evidence that indicts it, and
   denials degrade into "no response".

   Set routing to 'legacy' to run receipts through the platform and
   watch the detection fail. That failure is a feature of the demo:
   it is the fastest way to explain why the relayer exists.
   ============================================================ */

import { canon, signMsg, sha256, merkleRoot } from './core.js';

/** The independent registry. Prices and commissions here are the
 *  ground truth a platform could prune from — the auditor never
 *  sees this table, only the signed receipts it produces. */
/* SUP-01 is deliberately the cheapest supplier, the highest-scoring
 * one, AND the one paying no commission. That is what makes pruning
 * it the sharpest possible test: the platform drops the candidate
 * that is best for the buyer and worst for its own revenue, and the
 * baseline layer still attests perfectly to what remains.
 *
 * Changing these names or prices is safe. Changing the ORDERING —
 * SUP-01 cheapest, scores descending by id, commissions on 02/05/06/
 * 07/08 — is not: the acceptance scenarios in Design.md §8 depend on
 * it. */
export const REGISTRY = [
  { id: 'SUP-01', name: 'Kowloon Bay Lodge',   price: 1180, score: 88, comm: 0  },
  { id: 'SUP-02', name: 'Harbourview Central', price: 1540, score: 86, comm: 8  },
  { id: 'SUP-03', name: 'Lantern Court',       price: 1320, score: 84, comm: 0  },
  { id: 'SUP-04', name: 'Sheung Wan Boutique', price: 1240, score: 81, comm: 0  },
  { id: 'SUP-05', name: 'Peak & Stone',        price: 1410, score: 79, comm: 5  },
  { id: 'SUP-06', name: 'Nathan Grand',        price: 1690, score: 76, comm: 10 },
  { id: 'SUP-07', name: 'Star Ferry Suites',   price: 1870, score: 74, comm: 12 },
  { id: 'SUP-08', name: 'Aurora Causeway',     price: 1790, score: 71, comm: 12 },
];

export const bySupplierId = id => REGISTRY.find(s => s.id === id) ?? null;

export class Relayer {
  constructor(supplierKeys) {
    this.keys = supplierKeys;           // supplier_id -> key pair
  }

  /** Ask EVERY registry supplier whether it was queried in this
   *  window. An honest supplier answers truthfully about its own
   *  experience; it has no view of the ranking and cannot sign on
   *  another supplier's behalf. */
  async collect({ snapshot_hash, anchor_block, declaredIds, routing = 'relayer',
                  window = '2026-08', query_type = 'room-block-rfq', sample = null }) {
    const asked = sample ?? REGISTRY.map(s => s.id);
    const receipts = [];

    for (const sup of REGISTRY) {
      if (!asked.includes(sup.id)) {
        receipts.push({ supplier_id: sup.id, name: sup.name, status: 'uncovered',
                        asked: false, delivered: false, suppressed: false });
        continue;
      }
      const status = declaredIds.includes(sup.id) ? 'affirm' : 'deny';
      const body = canon({
        receipt_version: 'pc.receipt.v1',
        anchor_block, snapshot_hash, supplier_id: sup.id,
        status, query_type, window,
      });
      const sig = await signMsg(this.keys[sup.id], body);

      /* Legacy routing: the platform batches receipts on the
       * suppliers' behalf, and drops what indicts it. The receipt is
       * still validly signed — it simply never arrives. */
      const suppressed = routing === 'legacy' && status === 'deny';

      receipts.push({
        supplier_id: sup.id, name: sup.name, status, body, signature: sig,
        key_id: this.keys[sup.id].key_id,
        asked: true, delivered: !suppressed, suppressed, routing,
      });
    }
    return receipts;
  }

  /** Coverage is recorded, never rounded up. "Nobody objected" and
   *  "nobody was asked" must never collapse into one number. */
  static coverage(receipts) {
    const delivered = receipts.filter(r => r.delivered);
    return {
      total: REGISTRY.length,
      asked: receipts.filter(r => r.asked).length,
      affirm: delivered.filter(r => r.status === 'affirm').length,
      deny: delivered.filter(r => r.status === 'deny').length,
      uncovered: REGISTRY.length - delivered.length,
      coverage_rate: +(delivered.length / REGISTRY.length).toFixed(3),
    };
  }

  static async receiptsRoot(receipts) {
    const delivered = receipts.filter(r => r.delivered);
    if (!delivered.length) return '0'.repeat(64);
    const leaves = [];
    for (const r of delivered.slice().sort((a, b) => a.supplier_id.localeCompare(b.supplier_id))) {
      leaves.push(await sha256(r.body + r.signature));
    }
    return merkleRoot(leaves);
  }
}

/* ============================================================
   Sampled coverage — MEMO-01 §3.4
   ------------------------------------------------------------
   Detection is hypergeometric. A platform prunes k of n registry
   members; the auditor samples s uniformly without replacement;
   detection is at least one pruned member landing in the sample.

       P(detect) = 1 − C(n−k, s) / C(n, s)

   The honest headline this produces: against a single-supplier
   prune in a small registry, only near-total coverage gives high
   PER-PROOF detection. The recovery is that detection compounds
   across proofs — which is the argument for a corpus, not for a
   bigger claim about any single proof.
   ============================================================ */

export function detectionProbability(n, k, s) {
  if (k <= 0 || s <= 0) return 0;
  if (s > n) s = n;
  if (k > n) k = n;
  if (n - k < s) return 1;
  /* ratio = C(n-k, s) / C(n, s) = Π (n-k-i)/(n-i) for i in [0, s) */
  let ratio = 1;
  for (let i = 0; i < s; i++) ratio *= (n - k - i) / (n - i);
  return 1 - ratio;
}

/** Detection compounded over m independently sampled proofs. */
export const detectionOverProofs = (p, m) => 1 - Math.pow(1 - p, m);

/** Smallest sample size reaching the target per-proof detection. */
export function sampleForTarget(n, k, target = 0.95) {
  for (let s = 1; s <= n; s++) if (detectionProbability(n, k, s) >= target) return s;
  return n;
}
