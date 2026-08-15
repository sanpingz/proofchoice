/* ============================================================
   ProofChoice — the verification algorithm (Design.md §5)
   ------------------------------------------------------------
   PURE. No network, no filesystem, no clock, no imports beyond the
   cryptographic core. Given (anchor, custody result, receipts, key
   record) it returns a verdict and nothing else.

   That property is what makes third-party audit possible at all:
   an auditor must be able to run this with no access to our
   infrastructure. Do not add I/O to this file. Design.md §6 asks
   for a lint rule enforcing exactly that.

   The auditor trusts nothing the platform asserts. Each check
   reports its own state and does not mask the ones after it.
   ============================================================ */

import { canon, sha256, leavesFor, merkleRoot, merklePath, merkleCheck, verifyMsg, importPublic } from './core.js';

/* Verdict precedence: fail > inconclusive > partial > pass. */
function verdictFor(checks, custodyState) {
  const bad = checks.filter(c => c.state === 'bad').length;
  const soft = checks.filter(c => c.state === 'warn' || c.state === 'idle').length;
  if (bad) return 'fail';
  if (custodyState === 'EXPIRED') return 'inconclusive';
  if (soft) return 'partial';
  return 'pass';
}

export async function verify({
  anchor,            // chain anchor record, or null
  custody,           // result of Custody.fetch()
  receipts = [],     // signed receipts as delivered
  coverage = null,   // Relayer.coverage(receipts)
  keyRecord = null,  // on-chain keyreg record for anchor.signer_key_id, or null
  assertedPubkey = null, // raw-hex pubkey handed over by the platform, unbound
  supplierKeys = {}, // supplier_id -> raw-hex pubkey, for receipt verification
} = {}) {
  const checks = [];
  const push = (title, state, detail, extra = {}) => checks.push({ title, state, detail, ...extra });

  /* ---- 1. anchor exists ---------------------------------- */
  push('Anchor found for this proof ID', anchor ? 'ok' : 'bad',
    anchor
      ? `Block ${anchor.block} · anchored ${anchor.block_timestamp}`
      : 'No anchor matches this proof ID. Nothing was ever committed, or it was committed elsewhere.');

  if (!anchor) {
    return { checks, verdict: 'fail', custody_state: custody?.state ?? 'UNRESPONSIVE',
      summary: 'There is no anchor for this proof ID. Every check after this one is unreachable.' };
  }

  /* ---- 2. evidence availability --------------------------
     The chain cannot help here. An anchor proves a commitment was
     made; it says nothing about whether the preimage still exists. */
  const cs = custody?.state ?? 'UNRESPONSIVE';
  const holderLine = (custody?.holders ?? [])
    .map(h => `${h.holder}: ${h.state}`).join(' · ');

  const CUSTODY_COPY = {
    AVAILABLE: s => `Preimage retrieved from ${s}. Query, candidate list, salts and snapshot fields all present.`,
    WITHHELD: () => 'Reachable, within retention, acknowledged the manifest — and refused. This is a custody failure, not a chain failure, and it is adversarial.',
    LOST: () => 'A holder signed an admission of non-possession, contradicting its own earlier acknowledgement. A broken promise, not necessarily a lie.',
    EXPIRED: () => 'The pre-committed retention period has ended. Deletion at expiry is the correct outcome of a privacy obligation, so this is not a failure — but it is not a verification either.',
    UNRESPONSIVE: () => 'No holder produced a signed answer of any kind. This is the only state a holder can choose without going on the record.',
  };
  push('Evidence preimage available',
    cs === 'AVAILABLE' ? 'ok' : cs === 'EXPIRED' ? 'idle' : 'bad',
    CUSTODY_COPY[cs](custody?.servedBy), { custody_state: cs, holders: custody?.holders ?? [], holder_line: holderLine });

  /* ---- 3. recompute the hash -----------------------------
     Every served copy is recomputed, not just the first. Divergent
     copies are attributable: at most one can be authentic, and the
     anchor decides which. */
  const evaluated = [];
  for (const s of custody?.served ?? []) {
    const h = await sha256(canon(s.blob.snapshot));
    evaluated.push({ holder: s.holder, hash: h, match: h === anchor.snapshot_hash, blob: s.blob });
  }
  const authentic = evaluated.find(e => e.match) ?? null;
  const divergent = evaluated.filter(e => !e.match);

  if (!evaluated.length) {
    push('Recomputed hash matches the anchor', 'idle', 'Skipped — no preimage to recompute from.');
  } else if (authentic && divergent.length) {
    push('Recomputed hash matches the anchor', 'warn',
      `A copy served by ${authentic.holder} recomputes to the anchored hash. ${divergent.length} other cop${divergent.length === 1 ? 'y' : 'ies'} did not: ` +
      divergent.map(d => `${d.holder} served evidence hashing to ${d.hash.slice(0, 24)}…`).join('; ') +
      `. The proof still verifies, and the edit is attributable to the holder that served it.`,
      { divergent: divergent.map(d => ({ holder: d.holder, hash: d.hash })) });
  } else if (authentic) {
    push('Recomputed hash matches the anchor', 'ok', anchor.snapshot_hash);
  } else {
    push('Recomputed hash matches the anchor', 'bad',
      `Recomputed ${evaluated[0].hash.slice(0, 24)}… against anchored ${anchor.snapshot_hash.slice(0, 24)}…. ` +
      `The stored evidence was edited after anchoring, and the edit is attributable to the signing key that committed to the original.`,
      { recomputed: evaluated[0].hash });
  }

  const blob = authentic?.blob ?? null;
  const snapshot = blob?.snapshot ?? null;

  /* ---- 4. signature, and is the key bound to an identity? ----
     Resolve the public key from the ON-CHAIN REGISTRY by
     signer_key_id. Verifying with a key the platform hands you
     proves internal consistency and nothing more. */
  let sigOK = false, keyUsed = null;
  const pubHex = keyRecord?.pub_raw ?? assertedPubkey ?? null;
  if (pubHex) {
    try {
      keyUsed = await importPublic(pubHex);
      sigOK = await verifyMsg(keyUsed, anchor.snapshot_hash, anchor.platform_signature);
    } catch { sigOK = false; }
  }
  /* The key id is committed INSIDE the snapshot as well as sitting in
   * the anchor, so a mismatch between the two is itself detectable. */
  const keyIdConsistent = !snapshot || snapshot.signer_key_id === anchor.signer_key_id;

  push('Platform signature valid, key bound to a named operator',
    !sigOK ? 'bad' : !keyIdConsistent ? 'bad' : keyRecord ? 'ok' : 'warn',
    !pubHex ? 'No public key could be resolved for this signer_key_id. The signature cannot be checked at all.'
      : !sigOK ? 'Signature does not verify against the resolved public key.'
      : !keyIdConsistent ? `signer_key_id inside the snapshot (${snapshot.signer_key_id}) does not match the anchor (${anchor.signer_key_id}). The commitment and the anchor disagree about who signed.`
      : keyRecord ? `ECDSA P-256 verified · key ${anchor.signer_key_id} registered on chain at block ${keyRecord.block} to "${keyRecord.operator}".`
      : `ECDSA P-256 verified, but against a key the platform supplied. No on-chain registry binds ${anchor.signer_key_id} to a named operator, so the platform can later claim the key was compromised and repudiate everything signed with it.`);

  /* ---- 5. Merkle inclusion of the winner -------------------
     Rebuild the leaves from the served candidates rather than
     trusting a tree the platform hands over. Proves INCLUSION only:
     a root can never prove the set was complete. */
  if (!snapshot) {
    push('Winner proven inside the committed candidate set', 'idle',
      'Skipped — no authentic preimage to rebuild the tree from.');
  } else {
    const { sorted, leaves } = await leavesFor(blob.candidates ?? []);
    const root = await merkleRoot(leaves);
    const rootOK = root === snapshot.candidate_merkle_root;
    const countOK = leaves.length === snapshot.candidate_count;
    const idx = sorted.findIndex(c => c.id === snapshot.winner_id);

    if (!rootOK || !countOK || idx < 0) {
      push('Winner proven inside the committed candidate set', 'bad',
        !rootOK ? `Rebuilt Merkle root ${root.slice(0, 24)}… does not match the committed root ${snapshot.candidate_merkle_root.slice(0, 24)}….`
          : !countOK ? `candidate_count commits to ${snapshot.candidate_count} but the evidence carries ${leaves.length} candidates. Because this tree duplicates the last node on odd levels, cardinality is not recoverable from the root — which is exactly why the count is committed separately.`
          : `Declared winner ${snapshot.winner_id} does not appear in the served candidate set.`);
    } else {
      const path = await merklePath(leaves, idx);
      const incl = await merkleCheck(leaves[idx], path, snapshot.candidate_merkle_root);
      push('Winner proven inside the committed candidate set', incl ? 'ok' : 'bad',
        incl
          ? `Merkle inclusion proof verified against a tree rebuilt from the evidence, ${path.length} sibling${path.length === 1 ? '' : 's'}. Proves inclusion ONLY — a root can never prove the set was complete. Only check 6 reaches that question, and only probabilistically.`
          : 'Inclusion proof failed.',
        { path_length: path.length });
    }
  }

  /* ---- 6. registry coverage -------------------------------
     Over the CATEGORY REGISTRY, not the candidate set. This is the
     only check that reaches "was the declared set the real one",
     and it reaches it probabilistically. */
  const verifiedReceipts = [];
  for (const r of receipts.filter(x => x.delivered)) {
    const pub = supplierKeys[r.supplier_id];
    let ok = false;
    if (pub) { try { ok = await verifyMsg(await importPublic(pub), r.body, r.signature); } catch { ok = false; } }
    verifiedReceipts.push({ ...r, signature_valid: ok });
  }
  const forged = verifiedReceipts.filter(r => !r.signature_valid);
  const c = coverage ?? { total: 0, affirm: 0, deny: 0, uncovered: 0 };

  push('Registry coverage — was any supplier never asked?',
    forged.length ? 'bad' : c.deny > 0 ? 'bad' : c.uncovered > 0 ? 'warn' : c.affirm ? 'ok' : 'idle',
    forged.length
      ? `${forged.length} receipt signature${forged.length === 1 ? '' : 's'} did not verify against the registered supplier key. Discard them; they prove nothing.`
      : c.deny > 0
        ? `${c.deny} supplier${c.deny === 1 ? '' : 's'} in the category registry signed a denial: never queried, while the platform declared its pool complete. This is the silent-deletion signal.`
      : c.uncovered > 0
        ? `${c.uncovered} of ${c.total} registry suppliers returned no receipt. Recorded as uncovered — never counted as agreement. "Nobody objected" and "nobody was asked" are different facts.`
      : c.affirm
        ? `All ${c.total} registry suppliers returned signed receipts affirming they were queried.`
        : 'No receipts requested yet.',
    { coverage: c });

  /* ---- verdict ------------------------------------------- */
  const verdict = verdictFor(checks, cs);
  const summary = summarise(verdict, { cs, authentic, divergent, coverage: c, keyRecord, forged });

  return {
    checks, verdict, custody_state: cs,
    summary,
    recomputed: authentic?.hash ?? evaluated[0]?.hash ?? null,
    served_by: authentic?.holder ?? null,
    divergent_holders: divergent.map(d => d.holder),
  };
}

function summarise(verdict, { cs, authentic, divergent, coverage, keyRecord, forged }) {
  if (verdict === 'inconclusive') {
    return 'The retention period committed in advance has ended and the evidence was deleted on schedule. The anchor and the signature still verify, so nothing here suggests wrongdoing — but the commitment can no longer be opened, and that is not the same as a pass.';
  }
  if (verdict === 'fail') {
    if (cs === 'WITHHELD') return 'The anchor is intact and the evidence is being withheld. The chain proved a commitment was made; it cannot prove what was committed to. Custody makes this refusal visible and attributable — it cannot make it impossible.';
    if (cs === 'UNRESPONSIVE') return 'No holder went on the record at all. That is worse than a refusal, because a refusal is at least a signed statement someone has to defend.';
    if (cs === 'LOST') return 'A holder that signed an acknowledgement can no longer produce the preimage. Treat this as a custody breach; it is not, by itself, evidence of a lie.';
    if (forged?.length) return 'One or more receipts failed signature verification. They carry no weight and the coverage figure must be recomputed without them.';
    if (coverage?.deny > 0) return 'Baseline attestation is internally valid. The registry receipts contradict it: a supplier that was never asked proves the declared pool was not the real one.';
    if (!authentic) return 'The stored evidence no longer hashes to the anchored commitment. The edit is detected, and it is attributable to the key that signed the original.';
    return 'One or more checks failed.';
  }
  if (verdict === 'partial') {
    if (divergent?.length) return `The proof verifies against a copy served by an independent holder. A different copy — served by ${divergent.map(d => d.holder).join(', ')} — does not hash to the anchor, so that copy was edited after anchoring. The commitment holds and the edit is attributable.`;
    if (!keyRecord) return 'Verifiable, but repudiable: the signature checks out against a key with no on-chain binding to a named operator.';
    return 'Verifiable, with gaps that must be read as gaps rather than as agreement.';
  }
  return 'Every check recomputes independently. Nothing here required trusting the platform’s own account. Note the bounds: inclusion is not completeness, and coverage is what was asked, not what exists.';
}
