/* ============================================================
   ProofChoice — evidence custody
   ------------------------------------------------------------
   Implements MEMO-01 Part 1: custody models, the custody manifest,
   and the five-state failure taxonomy.

   The load-bearing idea: the evidence blob is SELF-AUTHENTICATING.
   Its integrity comes from hashing to the anchor, a check that runs
   identically no matter who hands it over. Nobody holding a copy
   has to be trusted — a forged blob fails check 3 whoever produced
   it. So custody is an AVAILABILITY problem and only an
   availability problem, and replication costs nothing in trust.

   What this does NOT do, and must never be shown as doing:
   custody cannot defeat withholding. A preimage is a bearer
   object; whoever holds a copy can decline to produce it and no
   chain can compel them. What custody changes is how many
   independent parties must ALL decline, whether the declining
   party is the accused or a neutral, and whether the refusal is
   silent or named.
   ============================================================ */

import { canon, signMsg } from './core.js';

/** Every holder is a distinct party with its own signing key, so a
 *  refusal or an admission of loss carries a signature attributable
 *  to a name rather than being an anonymous HTTP error. */
export const HOLDERS = {
  platform: { id: 'platform', label: 'Platform (party under audit)', neutral: false },
  buyer:    { id: 'buyer',    label: 'Requester copy, delivered at recommendation time', neutral: false },
  neutral:  { id: 'neutral',  label: 'Neutral custodian / relayer', neutral: true },
};

export const MODELS = {
  'platform-held': {
    holders: ['platform'],
    label: 'Platform-held with SLA',
    note: 'The party under audit holds the only copy. Withholding is a unilateral act.',
  },
  'buyer-copy': {
    holders: ['platform', 'buyer'],
    label: 'Requester receives a copy at recommendation time',
    note: 'Withholding now requires the platform AND the requester it harmed. Costs almost nothing to run.',
  },
  'escrow': {
    holders: ['platform', 'neutral'],
    label: 'Encrypted escrow with a named third party',
    note: 'Unavailability becomes attributable to a party with no stake in the outcome.',
  },
  'hybrid': {
    holders: ['platform', 'buyer', 'neutral'],
    label: 'Hybrid — platform + requester + neutral custodian',
    note: 'Three parties with divergent interests must all decline. Each refusal is named.',
  },
};

/** Five states. The distinction between them is the point: the
 *  prototype collapsed all failures into one FAIL, which made a
 *  policy-compliant deletion look identical to an adversarial
 *  refusal. */
export const STATES = {
  AVAILABLE:    { fatal: false, verdict: 'ok' },
  EXPIRED:      { fatal: false, verdict: 'expired' },      // policy — INCONCLUSIVE, never FAIL
  LOST:         { fatal: true,  verdict: 'bad' },          // custody breach, signed admission
  WITHHELD:     { fatal: true,  verdict: 'bad' },          // adversarial, signed refusal
  UNRESPONSIVE: { fatal: true,  verdict: 'bad' },          // declined even to go on record
};

/* Ranked worst-first for aggregation when nothing was served. */
const SEVERITY = ['UNRESPONSIVE', 'WITHHELD', 'LOST', 'EXPIRED'];

const DEFAULT_RETENTION_MONTHS = 24;

export class Custody {
  constructor(store, keys) {
    this.store = store;
    this.keys = keys;            // holder id -> key pair
    this.mode = {};              // holder id -> 'serve' | 'withhold' | 'lost' | 'unresponsive'
    for (const h of Object.keys(HOLDERS)) this.mode[h] = 'serve';
    /* Demo control only. Shifts the clock used to compare against
     * retention_until. We do NOT edit the manifest to simulate
     * expiry — the manifest is pre-committed and rewriting it would
     * destroy the property that makes EXPIRED checkable. */
    this.clockOffsetMs = 0;
  }

  now() { return new Date(Date.now() + this.clockOffsetMs); }

  /** Each holder gets its own keyspace, so "who still has a copy"
   *  is a per-holder fact rather than a single shared flag. */
  _key(holder, hash) { return `blob:${holder}:${hash}`; }

  static retentionUntil(months = DEFAULT_RETENTION_MONTHS, from = new Date()) {
    const d = new Date(from);
    d.setMonth(d.getMonth() + months);
    return d.toISOString();
  }

  /** Distribute a blob to the holders named by the custody model,
   *  and collect a signed acknowledgement from each. The ack is what
   *  later turns "I never had it" into a contradiction. */
  async distribute(blob, { model = 'hybrid', retention_months = DEFAULT_RETENTION_MONTHS } = {}) {
    const spec = MODELS[model];
    if (!spec) throw new Error(`unknown custody model: ${model}`);
    const hash = blob.snapshot.__hash ?? blob.snapshot_hash;
    const retention_until = Custody.retentionUntil(retention_months);
    const holders = [];

    for (const h of spec.holders) {
      await this.store.set(this._key(h, hash), JSON.stringify(blob));
      const ack_body = canon({
        statement: 'holds-preimage',
        snapshot_hash: hash,
        holder: h,
        retention_until,
      });
      holders.push({
        holder: h,
        label: HOLDERS[h].label,
        neutral: HOLDERS[h].neutral,
        ack_signature: await signMsg(this.keys[h], ack_body),
        ack_key_id: this.keys[h].key_id,
      });
    }
    return { model, holders, retention_until };
  }

  /** Attempt retrieval from EVERY acknowledged holder — not just the
   *  first that answers. Collecting all copies is what lets the
   *  auditor detect divergence: if two holders serve different
   *  preimages for the same anchor, at most one can be authentic and
   *  the anchor decides which. That turns a tampered platform copy
   *  into an attributable finding rather than a bare hash mismatch.
   *
   *  Attribution is per-holder, never a single global verdict. */
  async fetch(hash, manifest) {
    const acked = manifest?.holders ?? [];
    const retention_until = manifest?.retention_until ?? null;
    const expired = retention_until ? this.now() > new Date(retention_until) : false;

    const detail = [];
    const served = [];

    for (const h of acked) {
      const id = h.holder;
      const mode = this.mode[id] ?? 'serve';
      const present = await this.store.has(this._key(id, hash));

      if (expired) {
        detail.push({ holder: id, label: h.label, state: 'EXPIRED',
          note: `Retention period ended ${retention_until}. Deletion at expiry is the correct outcome of a privacy obligation.` });
        continue;
      }
      if (mode === 'unresponsive') {
        detail.push({ holder: id, label: h.label, state: 'UNRESPONSIVE',
          note: 'No signed answer of any kind. This is the only state that avoids going on the record.' });
        continue;
      }
      if (mode === 'withhold') {
        detail.push({ holder: id, label: h.label, state: 'WITHHELD',
          statement: await this._statement(id, hash, 'refuses-to-serve'),
          note: 'Holder is reachable, within retention, acknowledged the manifest, and refuses.' });
        continue;
      }
      if (mode === 'lost' || !present) {
        detail.push({ holder: id, label: h.label, state: 'LOST',
          statement: await this._statement(id, hash, 'no-longer-holds'),
          note: 'Signed admission of non-possession, contradicting this holder’s own acknowledgement. A broken promise, not necessarily a lie.' });
        continue;
      }

      const raw = await this.store.get(this._key(id, hash));
      served.push({ holder: id, label: h.label, blob: JSON.parse(raw) });
      detail.push({ holder: id, label: h.label, state: 'AVAILABLE' });
    }

    let state;
    if (served.length) state = 'AVAILABLE';
    else if (!acked.length) state = 'UNRESPONSIVE';
    else if (detail.every(d => d.state === 'EXPIRED')) state = 'EXPIRED';
    else state = SEVERITY.find(s => detail.some(d => d.state === s)) ?? 'LOST';

    return {
      state, served,
      blob: served[0]?.blob ?? null,
      servedBy: served[0]?.holder ?? null,
      holders: detail, retention_until, model: manifest?.model ?? null,
    };
  }

  /** Adversary control: edit the stored evidence at ONE holder after
   *  anchoring. This is a real write to real stored bytes, which is
   *  what makes the recompute check meaningful — the prototype
   *  mutated an in-memory copy at audit time instead. */
  async tamper(hash, holder, mutate) {
    const raw = await this.store.get(this._key(holder, hash));
    if (!raw) throw new Error(`${holder} holds no copy of ${hash}`);
    const blob = JSON.parse(raw);
    mutate(blob);
    await this.store.set(this._key(holder, hash), JSON.stringify(blob));
    return blob;
  }

  async _statement(holder, hash, statement) {
    const body = canon({ statement, snapshot_hash: hash, holder, at: this.now().toISOString() });
    return { body, signature: await signMsg(this.keys[holder], body), key_id: this.keys[holder].key_id };
  }

  /** Demo controls. Every one of these is a switch on a simulated
   *  holder, not a real outage — label it that way in any UI. */
  setMode(holder, mode) {
    if (!HOLDERS[holder]) throw new Error(`unknown holder: ${holder}`);
    if (!['serve', 'withhold', 'lost', 'unresponsive'].includes(mode)) throw new Error(`unknown mode: ${mode}`);
    this.mode[holder] = mode;
    return this.mode;
  }

  setClockOffsetMonths(months) {
    this.clockOffsetMs = months * 30.44 * 24 * 3600 * 1000;
    return this.clockOffsetMs;
  }

  reset() {
    for (const h of Object.keys(HOLDERS)) this.mode[h] = 'serve';
    this.clockOffsetMs = 0;
  }
}
