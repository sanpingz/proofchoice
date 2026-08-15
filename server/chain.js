/* ============================================================
   ProofChoice — anchor registry (the "chain")
   ------------------------------------------------------------
   HONEST LABELLING. This is a real append-only log run by a
   SINGLE OPERATOR. It is not a blockchain and must never be
   presented as one.

   What it genuinely provides:
     · append-only writes — no update and no delete code path
       exists on this class
     · anchor() is write-once and reverts on a repeat hash. On a
       shared store the guard is an atomic SET NX, so it holds
       across concurrent instances rather than only within one
       process
     · every record is content-addressed and independently
       recomputable by the auditor

   What it does NOT provide, and what a consortium chain or an L2
   would provide:
     · resistance to the operator deleting the underlying store
     · an independently attested timestamp
     · any guarantee at all if the operator is the party under
       audit — which, in this deployment, it is

   Block numbers are POSITIONS IN THE LOG, assigned on read rather
   than written into each record. That way two concurrent writers
   cannot mint the same block number, and the numbering stays
   consistent with the log itself.
   ============================================================ */

export class Chain {
  constructor(store) {
    this.store = store;
    this.blocks = [];
    this.byHash = new Map();   // snapshot_hash -> anchor block
    this.keys = new Map();     // key_id -> keyreg block
    this._queue = Promise.resolve();
  }

  async load() {
    const lines = await this.store.list('chain');
    this.blocks = []; this.byHash.clear(); this.keys.clear();
    lines.forEach((line, i) => {
      try { this._index({ ...JSON.parse(line), block: i + 1 }); } catch { /* skip malformed */ }
    });
    return this;
  }

  /** Re-read the log when the store can be written by other
   *  instances. A no-op for single-process backends. */
  async refresh() {
    if (this.store.refreshBetweenRequests) await this.load();
    return this;
  }

  _index(b) {
    this.blocks.push(b);
    if (b.type === 'anchor') this.byHash.set(b.snapshot_hash, b);
    if (b.type === 'keyreg') this.keys.set(b.key_id, b);
  }

  /** Serialised so concurrent callers within one process cannot
   *  interleave a read-modify-write. Cross-instance safety comes
   *  from the store's setNX, not from this. */
  _serialise(fn) {
    const next = this._queue.then(fn, fn);
    this._queue = next.catch(() => {});
    return next;
  }

  async append(rec) {
    return this._serialise(async () => {
      const body = { ...rec, block_timestamp: new Date().toISOString() };
      const n = await this.store.append('chain', JSON.stringify(body));
      const block = { ...body, block: n };
      this._index(block);
      return block;
    });
  }

  /** anchor() — write-once. Reverts on a repeat snapshot_hash,
   *  which is what stops a platform re-anchoring a corrected
   *  commitment over an inconvenient one. */
  async anchor({ snapshot_hash, platform_signature, signer_key_id }) {
    const claimed = await this.store.setNX('anchor:' + snapshot_hash, snapshot_hash);
    if (!claimed) {
      const e = new Error('anchor() reverted: snapshot_hash already anchored');
      e.code = 'ALREADY_ANCHORED';
      throw e;
    }
    return this.append({
      type: 'anchor',
      snapshot_hash, platform_signature, signer_key_id,
      schema_version: 'pc.anchor.v1',
    });
  }

  /** Returns a stored commitment. It does NOT verify anything —
   *  verification is recomputation and happens off-chain, in the
   *  auditor. The method is deliberately not called verify(). */
  getAnchor(snapshot_hash) { return this.byHash.get(snapshot_hash) ?? null; }

  async registerKey({ key_id, pub_raw, operator, curve = 'P-256' }) {
    return this.append({ type: 'keyreg', key_id, pub_raw, operator, curve });
  }

  getKey(key_id) { return this.keys.get(key_id) ?? null; }

  /** Rotation history, oldest first — the timeline that makes a
   *  "the key was compromised" repudiation claim checkable. */
  keyHistory() { return this.blocks.filter(b => b.type === 'keyreg'); }

  async appendReceipts({ snapshot_hash, receipts_root, coverage_bps, receipt_count }) {
    return this.append({ type: 'receipts', snapshot_hash, receipts_root, coverage_bps, receipt_count });
  }

  /** Custody manifest — MEMO-01 §1.2. Records WHO acknowledged
   *  holding a preimage and until when, so a later "it's gone"
   *  contradicts a signed statement instead of being a bare claim.
   *  retention_until is committed in ADVANCE; that is the whole
   *  point, and it is what makes an EXPIRED verdict checkable
   *  rather than assertable after the fact. */
  async registerCustody({ snapshot_hash, holders, retention_until }) {
    return this.append({ type: 'custody', snapshot_hash, holders, retention_until });
  }

  getCustody(snapshot_hash) {
    return this.blocks.find(b => b.type === 'custody' && b.snapshot_hash === snapshot_hash) ?? null;
  }

  receiptsFor(snapshot_hash) {
    return this.blocks.filter(b => b.type === 'receipts' && b.snapshot_hash === snapshot_hash);
  }

  anchorByProofId(proof_id) {
    const want = String(proof_id || '').toUpperCase();
    for (const b of this.blocks) {
      if (b.type === 'anchor' && 'PC-' + b.snapshot_hash.slice(0, 10).toUpperCase() === want) return b;
    }
    return null;
  }

  tail(limit = 50) { return this.blocks.slice(-limit).reverse(); }
}
