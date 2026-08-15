/* ============================================================
   ProofChoice — MCP server (dual-era)
   ------------------------------------------------------------
   Speaks BOTH protocol eras on one endpoint, because clients in
   the wild are split:

     · modern  (2026-07-28) — no handshake. Every request carries
       its version in params._meta and in the MCP-Protocol-Version
       header, which must agree. server/discover is mandatory.
     · legacy  (2025-11-25 and earlier) — initialize handshake,
       optional Mcp-Session-Id.

   Era is selected by how the client opens: an `initialize` request
   selects legacy; a request carrying modern per-request _meta is
   served statelessly per the modern revision.

   Error codes used here are the protocol-defined ones:
     -32022 UnsupportedProtocolVersion  (400)
     -32020 HeaderMismatch              (400)
     -32601 Method not found            (404 modern / 200 legacy)
   ============================================================ */

import { REGISTRY, Relayer, detectionProbability, detectionOverProofs, sampleForTarget } from './registry.js';
import { MODELS, HOLDERS } from './custody.js';
import { canon, sha256, proofIdFor } from './core.js';
import { verify } from './verify.js';

export const SERVER_INFO = { name: 'proofchoice', version: '0.1.0' };
export const MODERN_VERSIONS = ['2026-07-28'];
export const LEGACY_VERSIONS = ['2025-11-25', '2025-06-18', '2025-03-26'];
export const SUPPORTED_VERSIONS = [...MODERN_VERSIONS, ...LEGACY_VERSIONS];

const VERSION_META = 'io.modelcontextprotocol/protocolVersion';

const INSTRUCTIONS = `ProofChoice commits an AI agent's supplier recommendation to a hash, signs it, and anchors it where the agent cannot later edit it.

Typical flow:
  1. pc_list_suppliers  — read the independent category registry
  2. decide a winner yourself, using whatever reasoning you like
  3. pc_attest          — commit to the candidate set you considered and the winner you picked
  4. pc_request_receipts— ask every registry supplier whether it was actually queried
  5. pc_verify          — recompute everything and return a verdict

The plugin commits to whatever candidate set you declare. If you leave a supplier
out of pc_attest, stages 2-4 will attest perfectly to the pruned pool and nothing
in the baseline layer can detect it — only the registry receipts in step 4 can.
That is the mechanism the product exists to demonstrate; try it deliberately.

Claims are deliberately bounded. A Merkle proof shows inclusion, never completeness.
Coverage shows what was asked, never what exists. Do not describe a PASS verdict as
proof that the recommendation was correct or optimal.`;

/* ============================================================
   Tool definitions
   ============================================================ */

const S = (type, description, extra = {}) => ({ type, description, ...extra });

export const TOOLS = [
  {
    name: 'pc_list_suppliers',
    description: 'List the independent category registry — every supplier in scope for this RFQ category. This is the pool an honest agent would consider. The auditor draws receipt requests from this list, never from the set the platform declares.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'pc_attest',
    description: 'Commit to a recommendation: build a salted Merkle tree over the declared candidates, hash the snapshot, sign it with ECDSA P-256, anchor it write-once, and distribute the evidence preimage to the holders named by the custody model. Returns a proof ID derived from the hash. Call this AFTER you have decided a winner.',
    inputSchema: {
      type: 'object',
      properties: {
        query: S('string', 'The buyer\'s procurement request, verbatim.'),
        candidate_ids: { type: 'array', items: { type: 'string' }, description: 'Supplier IDs you considered. Whatever you list here is what gets committed — omitting one is the "silent deletion" adversary and the baseline layer cannot see it.' },
        winner_id: S('string', 'The supplier you are recommending. Must be one of candidate_ids.'),
        ranking_rule_id: S('string', 'Version pointer for the ranking rule in force, e.g. rr.value-weighted.v2. A pointer only — it commits WHICH rule applied, never the rule\'s content.'),
        custody_model: S('string', `Who holds the evidence preimage. One of: ${Object.keys(MODELS).join(', ')}. Governs who can withhold it later.`, { enum: Object.keys(MODELS) }),
        retention_months: S('integer', 'Retention period committed in advance, default 24. Pre-committing this is what makes an "expired" verdict checkable rather than assertable after the fact.'),
      },
      required: ['query', 'candidate_ids', 'winner_id'],
      additionalProperties: false,
    },
  },
  {
    name: 'pc_get_proof',
    description: 'Look up an anchored proof by its proof ID: the anchor record, the custody manifest naming who acknowledged holding the preimage, and any receipts recorded so far.',
    inputSchema: { type: 'object', properties: { proof_id: S('string', 'e.g. PC-A1B2C3D4E5') }, required: ['proof_id'], additionalProperties: false },
  },
  {
    name: 'pc_request_receipts',
    description: 'Stage 5. Ask EVERY supplier in the category registry to sign a receipt stating whether it was queried in this window. A "deny" from a supplier the platform never declared is the silent-deletion signal. Set routing="legacy" to route receipts through the platform under audit instead of the neutral relayer, and watch the detection fail.',
    inputSchema: {
      type: 'object',
      properties: {
        proof_id: S('string', 'Proof to collect receipts for.'),
        routing: S('string', 'relayer (default, neutral) or legacy (through the platform being audited).', { enum: ['relayer', 'legacy'] }),
        sample_ids: { type: 'array', items: { type: 'string' }, description: 'Optional: ask only these supplier IDs. Everything not asked is recorded as uncovered, never as agreement. Defaults to the whole registry.' },
      },
      required: ['proof_id'], additionalProperties: false,
    },
  },
  {
    name: 'pc_verify',
    description: 'Stage 6. Run the full six-check verification: anchor exists, preimage available, recomputed hash matches, signature valid and key bound to a named operator, winner provably inside the committed set, registry coverage. Recomputes everything from the preimage; trusts nothing the platform asserts.',
    inputSchema: { type: 'object', properties: { proof_id: S('string', '') }, required: ['proof_id'], additionalProperties: false },
  },
  {
    name: 'pc_fetch_evidence',
    description: 'Fetch the off-chain evidence preimage for a proof: the raw query, every candidate with its price and salt, and the snapshot verbatim. Subject to the custody model — this is the call that fails when evidence is withheld, lost, expired, or when no holder answers.',
    inputSchema: { type: 'object', properties: { proof_id: S('string', '') }, required: ['proof_id'], additionalProperties: false },
  },
  {
    name: 'pc_inspect_schema',
    description: 'Show exactly what gets hashed: the snapshot object, the CANONICAL BYTE STRING that SHA-256 actually consumes (not the pretty JSON everyone assumes), the digest, the derivation trail from candidate to anchor, and what is deliberately NOT committed.',
    inputSchema: { type: 'object', properties: { proof_id: S('string', '') }, required: ['proof_id'], additionalProperties: false },
  },
  {
    name: 'pc_chain',
    description: 'Read the append-only anchor registry: key registrations, anchors, custody manifests and receipt batches, newest first.',
    inputSchema: { type: 'object', properties: { limit: S('integer', 'Max records, default 25.') }, additionalProperties: false },
  },
  {
    name: 'pc_custody_control',
    description: 'DEMO CONTROL — simulated adversary switches, not real outages. Make a named holder withhold the evidence, lose it, or go unresponsive; edit a holder\'s stored copy after anchoring; or advance the clock past the committed retention date. Then re-run pc_verify and see which failure state the verdict reports.',
    inputSchema: {
      type: 'object',
      properties: {
        holder: S('string', `Which holder to affect: ${Object.keys(HOLDERS).join(', ')}.`, { enum: Object.keys(HOLDERS) }),
        mode: S('string', 'serve | withhold | lost | unresponsive', { enum: ['serve', 'withhold', 'lost', 'unresponsive'] }),
        tamper_proof_id: S('string', 'Edit this proof\'s stored evidence at `holder`, after anchoring. Real write to real stored bytes.'),
        advance_months: S('integer', 'Advance the clock used to compare against retention_until. The manifest is never rewritten — pre-commitment is the point.'),
      },
      additionalProperties: false,
    },
  },
  {
    name: 'pc_detection_math',
    description: 'Sampled-coverage detection probability. A platform prunes k of n registry suppliers; the auditor samples s of them; detection is hypergeometric. Returns the per-proof probability, the sample size needed for a target, and how detection compounds across many proofs.',
    inputSchema: {
      type: 'object',
      properties: {
        n: S('integer', 'Registry size, default 8.'),
        k: S('integer', 'Suppliers pruned, default 1.'),
        s: S('integer', 'Suppliers sampled, default = n.'),
        proofs: S('integer', 'Compound detection over this many independently sampled proofs.'),
        target: S('number', 'Target per-proof detection for the required-sample figure, default 0.95.'),
      }, additionalProperties: false,
    },
  },
  {
    name: 'pc_reset',
    description: 'Reset the demo: clear all adversary switches and the clock offset. Does not erase the append-only chain — that is the point of an append-only chain.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  /* ---- ChatGPT compatibility ----------------------------------
     Without Developer Mode, ChatGPT rejects any connector lacking
     both `search` and `fetch`. They are thin wrappers over the
     tools above. */
  {
    name: 'search',
    description: 'Search ProofChoice proofs and registry suppliers. Returns matching records with IDs usable with `fetch`.',
    inputSchema: { type: 'object', properties: { query: S('string', 'Free text: a proof ID, a supplier name or ID, or a verdict.') }, required: ['query'], additionalProperties: false },
  },
  {
    name: 'fetch',
    description: 'Fetch the full record for an ID returned by `search` — a proof (with its verification verdict) or a registry supplier.',
    inputSchema: { type: 'object', properties: { id: S('string', '') }, required: ['id'], additionalProperties: false },
  },
];

/* ============================================================
   Tool execution
   ============================================================ */

const ok = (text, data) => ({ content: [{ type: 'text', text }], _data: data });

function fmt(o) { return JSON.stringify(o, null, 2); }

async function resolveProof(ctx, proof_id) {
  const anchor = ctx.chain.anchorByProofId(proof_id);
  if (!anchor) throw new Error(`no anchor for proof ID ${proof_id}`);
  const manifest = ctx.chain.getCustody(anchor.snapshot_hash);
  return { anchor, manifest };
}

export async function callTool(name, args = {}, ctx) {
  switch (name) {

    case 'pc_list_suppliers': {
      const rows = REGISTRY.map(s => `${s.id}  ${s.name.padEnd(20)} ¥${s.price}/night  score ${s.score}  commission ${s.comm}%`);
      return ok(
        `Category registry — ${REGISTRY.length} suppliers in scope.\n\n${rows.join('\n')}\n\n` +
        `These are the suppliers the auditor will ask for signed receipts. Whatever subset you declare to pc_attest is what gets committed.`,
        REGISTRY);
    }

    case 'pc_attest': {
      const ids = args.candidate_ids ?? [];
      const candidates = ids.map(id => {
        const s = REGISTRY.find(x => x.id === id);
        if (!s) throw new Error(`unknown supplier id: ${id}`);
        return s;
      });
      const r = await ctx.platform.attest({
        query: args.query,
        candidates,
        winner_id: args.winner_id,
        ranking_rule_id: args.ranking_rule_id,
        custody_model: args.custody_model ?? ctx.defaultCustodyModel,
        retention_months: args.retention_months ?? 24,
      });
      await ctx.setProof(r.proof_id, { receipts: [], coverage: null, declaredIds: ids });
      const omitted = REGISTRY.filter(s => !ids.includes(s.id));
      return ok(
        `Committed.\n\n` +
        `  proof_id       ${r.proof_id}\n` +
        `  snapshot_hash  ${r.snapshot_hash}\n` +
        `  merkle_root    ${r.merkle_root}\n` +
        `  anchored       block ${r.anchor.block} at ${r.anchor.block_timestamp}\n` +
        `  signed         ECDSA P-256, key ${r.anchor.signer_key_id}\n` +
        `  canonical      ${r.canonical_bytes} bytes — this byte string is what SHA-256 consumed\n` +
        `  custody        ${r.manifest.model} · holders ${r.manifest.holders.map(h => h.holder).join(', ')} · retained until ${r.manifest.retention_until}\n\n` +
        (omitted.length
          ? `NOTE: ${omitted.length} registry supplier${omitted.length === 1 ? '' : 's'} (${omitted.map(o => o.id).join(', ')}) ${omitted.length === 1 ? 'was' : 'were'} not in your declared set. The baseline layer has attested perfectly to the pool you declared and cannot see the omission. Run pc_request_receipts to find out whether it can be detected at all.\n\n`
          : `All ${REGISTRY.length} registry suppliers were declared.\n\n`) +
        `The proof ID is derived from the hash, so the holder can locate this anchor without asking the platform where it is.`,
        r);
    }

    case 'pc_get_proof': {
      const { anchor, manifest } = await resolveProof(ctx, args.proof_id);
      const rec = ctx.chain.receiptsFor(anchor.snapshot_hash);
      return ok(fmt({ anchor, custody_manifest: manifest, receipt_batches: rec }), { anchor, manifest, rec });
    }

    case 'pc_request_receipts': {
      const { anchor } = await resolveProof(ctx, args.proof_id);
      const declaredIds = await ctx.declaredIdsFor(args.proof_id, anchor.snapshot_hash);
      const receipts = await ctx.relayer.collect({
        snapshot_hash: anchor.snapshot_hash,
        anchor_block: anchor.block,
        declaredIds,
        routing: args.routing ?? 'relayer',
        sample: args.sample_ids ?? null,
      });
      const coverage = Relayer.coverage(receipts);
      const receipts_root = await Relayer.receiptsRoot(receipts);
      await ctx.chain.appendReceipts({
        snapshot_hash: anchor.snapshot_hash, receipts_root,
        coverage_bps: Math.round(coverage.coverage_rate * 10000),
        receipt_count: receipts.filter(r => r.delivered).length,
      });
      await ctx.setProof(args.proof_id, { receipts, coverage });

      const lines = receipts.map(r =>
        `  ${r.supplier_id}  ${r.name.padEnd(20)} ` +
        (!r.asked ? 'not asked (uncovered)'
          : r.suppressed ? 'SIGNED A DENIAL — dropped in transit by the platform'
          : r.status === 'affirm' ? 'affirms it was queried'
          : 'DENIES — never asked'));

      return ok(
        `Receipts requested from the category registry via the ${args.routing === 'legacy' ? 'PLATFORM (legacy routing)' : 'neutral relayer'}.\n\n` +
        lines.join('\n') + '\n\n' +
        `  affirm ${coverage.affirm} · deny ${coverage.deny} · uncovered ${coverage.uncovered} of ${coverage.total}\n\n` +
        (args.routing === 'legacy'
          ? `Legacy routing is on: denials were validly signed and then dropped by the party they indict. Coverage reads clean while the pruning stays invisible. This is why receipts must reach the registry through a neutral relayer.`
          : `Uncovered is recorded separately and never folded into agreement — "nobody objected" and "nobody was asked" are different facts.`),
        { receipts, coverage });
    }

    case 'pc_fetch_evidence': {
      const { anchor, manifest } = await resolveProof(ctx, args.proof_id);
      const res = await ctx.custody.fetch(anchor.snapshot_hash, manifest);
      if (res.state !== 'AVAILABLE') {
        return ok(
          `Evidence NOT available — state ${res.state}.\n\n` +
          res.holders.map(h => `  ${h.holder.padEnd(10)} ${h.state}${h.note ? ' — ' + h.note : ''}`).join('\n') +
          `\n\nThe anchor survives; the preimage does not. This is a custody failure, never a chain failure.`,
          res);
      }
      return ok(fmt(res.served[0].blob), res);
    }

    case 'pc_inspect_schema': {
      const { anchor, manifest } = await resolveProof(ctx, args.proof_id);
      const res = await ctx.custody.fetch(anchor.snapshot_hash, manifest);
      if (res.state !== 'AVAILABLE') throw new Error(`evidence unavailable (${res.state}) — nothing to inspect`);
      const blob = res.served[0].blob;
      const canonical = canon(blob.snapshot);
      const digest = await sha256(canonical);
      const leaf0 = blob.candidates[0];

      return ok(
        `WHAT GETS HASHED — ${blob.proof_id}\n\n` +
        `1. Snapshot object (pretty-printed — NOT what is hashed):\n${fmt(blob.snapshot)}\n\n` +
        `2. Canonical byte string — keys recursively sorted, no whitespace. THIS is the input to SHA-256:\n\n${canonical}\n\n` +
        `   length: ${Buffer.byteLength(canonical, 'utf8')} bytes\n\n` +
        `3. SHA-256(canonical) = ${digest}\n` +
        `   matches anchor:      ${digest === anchor.snapshot_hash}\n\n` +
        `4. proof_id = "PC-" + hash[0:10].toUpperCase() = ${proofIdFor(digest)}\n\n` +
        `5. One candidate leaf, canonical form:\n   ${canon({ id: leaf0.id, name: leaf0.name, unit_price_cny: leaf0.unit_price_cny, commission_disclosed: leaf0.commission_disclosed, salt: leaf0.salt })}\n` +
        `   leaf = SHA-256(that) — salted, so a shared Merkle path cannot be brute-forced back to a price.\n\n` +
        `DELIBERATELY NOT COMMITTED — not in the snapshot, not in the anchor, not in the blob:\n` +
        `  · commission rates and amounts (only a per-candidate binary and the disclosed-ID list)\n` +
        `  · ranking weights and the rule's content (only a version pointer)\n` +
        `  · buyer identity\n` +
        `  · supplier contact data\n` +
        `  · the agent's internal scores and reasoning\n\n` +
        `VISIBLE TO ANYONE HOLDING THE PREIMAGE — the privacy claim is about the anchor, not the blob:\n` +
        `  · every candidate name and unit price\n` +
        `  · every salt, and therefore the ability to reconstruct every leaf\n` +
        `  · the full pool, including who was not recommended\n` +
        `  · the raw query string\n\n` +
        `KNOWN LIMITATION: ranking_rule_id is a pointer chosen by the party under audit. Nothing binds the id to the rule's content, so the rule can be rewritten behind a stable label, or a fresh id minted per buyer. See MEMO-01 §2.6.`,
        { snapshot: blob.snapshot, canonical, digest });
    }

    case 'pc_chain':
      return ok(fmt(ctx.chain.tail(args.limit ?? 25)), ctx.chain.tail(args.limit ?? 25));

    case 'pc_custody_control': {
      const out = [];
      if (args.holder && args.mode) { ctx.custody.setMode(args.holder, args.mode); out.push(`${args.holder} → ${args.mode}`); }
      if (typeof args.advance_months === 'number') {
        ctx.custody.setClockOffsetMonths(args.advance_months);
        out.push(`clock advanced ${args.advance_months} months (manifest untouched — retention_until stays pre-committed)`);
      }
      if (args.tamper_proof_id) {
        const { anchor } = await resolveProof(ctx, args.tamper_proof_id);
        const holder = args.holder ?? 'platform';
        await ctx.custody.tamper(anchor.snapshot_hash, holder, b => {
          b.snapshot.winner_id = b.candidates.find(c => c.id !== b.snapshot.winner_id)?.id ?? b.snapshot.winner_id;
          b.candidates = b.candidates.slice(1);
          b.snapshot.candidate_count = b.candidates.length;
        });
        out.push(`edited the stored evidence held by ${holder} for ${args.tamper_proof_id}`);
      }
      return ok(`DEMO CONTROL (simulated, not a real outage):\n  ${out.join('\n  ') || 'no change'}\n\nHolder modes: ${fmt(ctx.custody.mode)}\n\nRe-run pc_verify to see which failure state the verdict reports.`, ctx.custody.mode);
    }

    case 'pc_detection_math': {
      const n = args.n ?? REGISTRY.length, k = args.k ?? 1, s = args.s ?? n;
      const target = args.target ?? 0.95;
      const p = detectionProbability(n, k, s);
      const need = sampleForTarget(n, k, target);
      const m = args.proofs ?? null;
      return ok(
        `Sampled-coverage detection (hypergeometric):\n\n` +
        `  P(detect) = 1 - C(n-k, s) / C(n, s)\n\n` +
        `  registry n = ${n}, pruned k = ${k}, sampled s = ${s}\n` +
        `  per-proof detection = ${(p * 100).toFixed(1)}%\n` +
        `  sample needed for ${(target * 100).toFixed(0)}% = ${need} of ${n}\n` +
        (m ? `  compounded over ${m} independently sampled proofs = ${(detectionOverProofs(p, m) * 100).toFixed(1)}%\n` : '') +
        `\nAgainst a single-supplier prune in a small registry, only near-total coverage gives high per-proof detection. Detection compounds across proofs — which is an argument for looking at a corpus, not for claiming more about any single proof.`,
        { n, k, s, p, need });
    }

    case 'pc_verify': {
      const { anchor, manifest } = await resolveProof(ctx, args.proof_id);
      const custody = await ctx.custody.fetch(anchor.snapshot_hash, manifest);
      const st = await ctx.getProof(args.proof_id);
      const keyRecord = ctx.keyRegistryEnabled ? ctx.chain.getKey(anchor.signer_key_id) : null;

      const result = await verify({
        anchor, custody,
        receipts: st.receipts ?? [], coverage: st.coverage ?? null,
        keyRecord,
        assertedPubkey: ctx.platform.key.pub_raw,
        supplierKeys: ctx.supplierPubs,
      });

      const icon = { ok: '[ok  ]', bad: '[FAIL]', warn: '[warn]', idle: '[skip]' };
      return ok(
        `VERDICT: ${result.verdict.toUpperCase()}${result.custody_state !== 'AVAILABLE' ? ` · evidence ${result.custody_state}` : ''}\n\n` +
        `${result.summary}\n\n` +
        result.checks.map((c, i) => `${icon[c.state]} ${i + 1}. ${c.title}\n        ${c.detail}`).join('\n\n') +
        `\n\nBounds: a Merkle proof shows inclusion, never completeness. Coverage shows what was asked, never what exists.`,
        result);
    }

    case 'pc_reset':
      ctx.custody.reset();
      return ok('Adversary switches cleared and clock offset reset. The append-only chain is unchanged — that is the point of an append-only chain.', ctx.custody.mode);

    /* ---- ChatGPT compatibility shims ---- */
    case 'search': {
      const q = String(args.query ?? '').toLowerCase();
      const results = [];
      for (const b of ctx.chain.blocks) {
        if (b.type !== 'anchor') continue;
        const pid = proofIdFor(b.snapshot_hash);
        if (!q || pid.toLowerCase().includes(q) || b.snapshot_hash.includes(q)) {
          results.push({ id: pid, title: `Proof ${pid} — anchored block ${b.block}`, url: `${ctx.publicUrl}/proof/${pid}` });
        }
      }
      for (const s of REGISTRY) {
        if (!q || s.id.toLowerCase().includes(q) || s.name.toLowerCase().includes(q)) {
          results.push({ id: s.id, title: `${s.name} (${s.id}) — registry supplier`, url: `${ctx.publicUrl}/supplier/${s.id}` });
        }
      }
      return ok(JSON.stringify({ results }), { results });
    }

    case 'fetch': {
      const id = String(args.id ?? '');
      if (/^PC-/i.test(id)) {
        const r = await callTool('pc_verify', { proof_id: id }, ctx);
        return ok(JSON.stringify({ id, title: `Proof ${id}`, text: r.content[0].text, url: `${ctx.publicUrl}/proof/${id}`, metadata: { verdict: r._data?.verdict } }));
      }
      const s = REGISTRY.find(x => x.id.toLowerCase() === id.toLowerCase());
      if (!s) throw new Error(`unknown id: ${id}`);
      return ok(JSON.stringify({ id: s.id, title: s.name, text: `${s.name} (${s.id}) — ¥${s.price} per room-night, quality score ${s.score}, pays ${s.comm}% commission to the platform.`, url: `${ctx.publicUrl}/supplier/${s.id}`, metadata: s }));
    }

    default:
      throw new Error(`unknown tool: ${name}`);
  }
}

/* ============================================================
   JSON-RPC dispatch
   ============================================================ */

const rpcError = (id, code, message, data) => ({
  jsonrpc: '2.0', ...(id === undefined ? {} : { id }),
  error: { code, message, ...(data ? { data } : {}) },
});

const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

function negotiateLegacy(requested) {
  if (LEGACY_VERSIONS.includes(requested)) return requested;
  if (MODERN_VERSIONS.includes(requested)) return requested;
  return LEGACY_VERSIONS[0];
}

/** @returns {{status:number, body:object|null, headers?:object}} */
export async function handleRpc(msg, { headers = {}, ctx }) {
  const id = msg?.id;
  const method = msg?.method;
  const params = msg?.params ?? {};
  const isNotification = id === undefined || id === null;

  const hdr = k => headers[k.toLowerCase()] ?? null;
  const metaVersion = params?._meta?.[VERSION_META] ?? null;
  const headerVersion = hdr('mcp-protocol-version');
  const modern = MODERN_VERSIONS.includes(metaVersion) ||
                 (method === 'server/discover') ||
                 (!!headerVersion && MODERN_VERSIONS.includes(headerVersion) && method !== 'initialize');

  /* ---- modern-era header validation ------------------------ */
  if (modern && method !== 'server/discover') {
    if (!headerVersion) {
      return { status: 400, body: rpcError(id, -32020, 'Header mismatch: MCP-Protocol-Version header is required') };
    }
    if (metaVersion && headerVersion !== metaVersion) {
      return { status: 400, body: rpcError(id, -32020, `Header mismatch: MCP-Protocol-Version header '${headerVersion}' does not match body _meta '${metaVersion}'`) };
    }
    const want = metaVersion ?? headerVersion;
    if (!SUPPORTED_VERSIONS.includes(want)) {
      return { status: 400, body: rpcError(id, -32022, 'Unsupported protocol version', { supported: SUPPORTED_VERSIONS, requested: want }) };
    }
    const mcpMethod = hdr('mcp-method');
    if (mcpMethod && mcpMethod !== method) {
      return { status: 400, body: rpcError(id, -32020, `Header mismatch: Mcp-Method header '${mcpMethod}' does not match body method '${method}'`) };
    }
    if (method === 'tools/call') {
      const mcpName = decodeSentinel(hdr('mcp-name'));
      if (mcpName && mcpName !== params?.name) {
        return { status: 400, body: rpcError(id, -32020, `Header mismatch: Mcp-Name header '${mcpName}' does not match body params.name '${params?.name}'`) };
      }
    }
  }

  switch (method) {

    /* modern: mandatory discovery */
    case 'server/discover':
      return {
        status: 200, body: rpcResult(id, {
          resultType: 'complete',
          supportedVersions: SUPPORTED_VERSIONS,
          capabilities: { tools: {} },
          instructions: INSTRUCTIONS,
          _meta: { 'io.modelcontextprotocol/serverInfo': SERVER_INFO },
        }),
      };

    /* legacy: handshake */
    case 'initialize': {
      const negotiated = negotiateLegacy(params?.protocolVersion);
      return {
        status: 200,
        body: rpcResult(id, {
          protocolVersion: negotiated,
          capabilities: { tools: { listChanged: false } },
          serverInfo: SERVER_INFO,
          instructions: INSTRUCTIONS,
        }),
        headers: { 'Mcp-Session-Id': ctx.sessionId },
      };
    }

    case 'notifications/initialized':
    case 'notifications/cancelled':
      return { status: 202, body: null };

    case 'ping':
      return { status: 200, body: rpcResult(id, {}) };

    case 'tools/list':
      return { status: 200, body: rpcResult(id, { tools: TOOLS }) };

    case 'tools/call': {
      const { name, arguments: a } = params ?? {};
      try {
        const r = await callTool(name, a ?? {}, ctx);
        return { status: 200, body: rpcResult(id, { content: r.content, isError: false }) };
      } catch (e) {
        /* Tool errors are reported IN the result, not as JSON-RPC
         * errors, so the model can see and react to them. */
        return {
          status: 200,
          body: rpcResult(id, { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true }),
        };
      }
    }

    default: {
      if (isNotification) return { status: 202, body: null };
      return { status: modern ? 404 : 200, body: rpcError(id, -32601, `Method not found: ${method}`) };
    }
  }
}

/** Mcp-Name / Mcp-Param-* values may arrive base64-wrapped when they
 *  are not safely representable as plain ASCII header values. */
function decodeSentinel(v) {
  if (!v) return v;
  const m = /^=\?base64\?(.*)\?=$/.exec(v);
  return m ? Buffer.from(m[1], 'base64').toString('utf8') : v;
}
