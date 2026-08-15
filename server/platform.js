/* ============================================================
   ProofChoice — the platform-side plugin (Design.md stages 2–4)
   ------------------------------------------------------------
   The plugin OBSERVES. It never re-ranks, blocks, delays or
   re-orders the agent's recommendation. It commits to what the
   agent already decided, and signs that commitment.

   Read that literally, because it is the honest boundary of the
   product: whatever candidate set the agent declares is the set
   that gets committed. If the agent prunes a supplier before
   calling attest(), stages 2–4 will attest perfectly to the pruned
   pool and NOTHING in the baseline layer can detect it. Only the
   registry receipts in registry.js reach that question.

   The signing key lives here and only here. The chain never signs
   snapshots; it stores commitments. Collapsing those two roles
   would make the anchor registry the platform, and the whole trust
   argument with it.
   ============================================================ */

import { canon, sha256, uuid, leavesFor, merkleRoot, signMsg, proofIdFor } from './core.js';

const DEFAULT_RULE_ID = 'rr.value-weighted.v2';

export class Platform {
  constructor({ chain, custody, key, operator = 'Doubao Travel Procurement Agent' }) {
    this.chain = chain;
    this.custody = custody;
    this.key = key;
    this.operator = operator;
  }

  /** Stage 2–4: build the snapshot, sign it, anchor it, distribute
   *  the preimage to the holders named by the custody model. */
  async attest({
    query,
    candidates,
    winner_id,
    ranking_rule_id = DEFAULT_RULE_ID,
    custody_model = 'hybrid',
    retention_months = 24,
  }) {
    if (!Array.isArray(candidates) || !candidates.length) throw new Error('candidates must be a non-empty array');
    if (!candidates.some(c => c.id === winner_id)) {
      throw new Error(`winner_id ${winner_id} is not among the declared candidates — the plugin commits to what the agent decided, but it cannot commit to a winner outside the set`);
    }

    /* Stage 2 — salt every candidate, sort by id, build the tree. */
    const salted = candidates.map(c => ({
      id: c.id,
      name: c.name,
      unit_price_cny: c.unit_price_cny ?? c.price,
      commission_disclosed: c.commission_disclosed ?? (c.comm > 0),
      comm: c.comm ?? 0,
      salt: c.salt ?? uuid(),
    }));
    const { sorted, leaves } = await leavesFor(salted);
    const root = await merkleRoot(leaves);
    const winner = salted.find(c => c.id === winner_id);

    const snapshot = {
      schema_version: 'pc.snapshot.v1',
      query_hash: await sha256(query),
      candidate_merkle_root: root,
      candidate_count: sorted.length,
      ranking_rule_id,
      commercial_disclosure: {
        paid_placement: winner.commission_disclosed,
        disclosed_supplier_ids: sorted.filter(c => c.commission_disclosed).map(c => c.id),
      },
      winner_id,
      nonce: uuid(),
      signer_key_id: this.key.key_id,
    };

    const canonical = canon(snapshot);
    const snapshot_hash = await sha256(canonical);
    const proof_id = proofIdFor(snapshot_hash);

    /* The off-chain preimage. Without this, no check in Design.md §5
     * can run — which is why custody is the largest open question in
     * the design and not an implementation detail. */
    const blob = {
      proof_id,
      query,
      snapshot,
      candidates: sorted.map(c => ({
        id: c.id, name: c.name, unit_price_cny: c.unit_price_cny,
        commission_disclosed: c.commission_disclosed, salt: c.salt,
      })),
      snapshot_hash,
    };

    /* Stage 3 — sign. Binds the commitment to a key. It does not make
     * the commitment true: the platform is signing its own account of
     * its own decision. */
    const platform_signature = await signMsg(this.key, snapshot_hash);

    /* Stage 4 — anchor. Write-once; reverts on a repeat hash. */
    const anchor = await this.chain.anchor({
      snapshot_hash, platform_signature, signer_key_id: this.key.key_id,
    });

    /* Custody — distribute the preimage and record who acknowledged
     * holding it, and until when. retention_until is committed in
     * ADVANCE so that "expired" is a date check rather than a claim
     * made after the fact. See MEMO-01 §1.2. */
    const manifest = await this.custody.distribute(blob, { model: custody_model, retention_months });
    await this.chain.registerCustody({
      snapshot_hash,
      holders: manifest.holders,
      retention_until: manifest.retention_until,
    });

    return {
      proof_id, snapshot_hash, snapshot, canonical,
      canonical_bytes: Buffer.byteLength(canonical, 'utf8'),
      leaves, merkle_root: root,
      anchor, manifest, blob,
      platform_signature,
    };
  }
}
