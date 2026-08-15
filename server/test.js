#!/usr/bin/env node
/* ============================================================
   ProofChoice — acceptance suite
   ------------------------------------------------------------
       node server/test.js

   Two halves:

   1. GOLDEN VECTORS. canon() is pinned byte-for-byte. If these
      fail, every hash the system has ever produced is invalid and
      the change that broke them must be reverted, not accommodated.

   2. THE SIX SCENARIOS from Design.md §8, plus the custody rows
      that the switchable custody model adds. A scenario whose
      verdict changes is a FINDING to report, never a table to
      quietly update.
   ============================================================ */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { canon, sha256, merkleRoot, merklePath, merkleCheck, leavesFor } from './core.js';
import { REGISTRY, Relayer, detectionProbability, sampleForTarget } from './registry.js';
import { boot } from './server.js';
import { callTool } from './mcp.js';
import { handleRpc, SUPPORTED_VERSIONS } from './mcp.js';
import { FsStore, MemoryStore, storeFromEnv } from './store.js';

let pass = 0, fail = 0;
const results = [];

function eq(actual, expected, label) {
  const okv = JSON.stringify(actual) === JSON.stringify(expected);
  okv ? pass++ : fail++;
  results.push({ okv, label, actual, expected });
  console.log(`  ${okv ? 'ok  ' : 'FAIL'}  ${label}`);
  if (!okv) console.log(`         expected ${JSON.stringify(expected)}\n         actual   ${JSON.stringify(actual)}`);
}

function section(t) { console.log(`\n\x1b[1m${t}\x1b[0m`); }

/* ============================================================
   1 — golden vectors
   ============================================================ */

async function goldenVectors() {
  section('Golden vectors — canon() is pinned. Do not "improve" it.');

  eq(canon(null), 'null', 'canon(null)');
  eq(canon(42), '42', 'canon(42)');
  eq(canon('a"b'), '"a\\"b"', 'canon(string) escapes');
  eq(canon([3, 1, 2]), '[3,1,2]', 'canon(array) preserves order');
  eq(canon({ b: 1, a: 2 }), '{"a":2,"b":1}', 'canon(object) sorts keys');
  eq(canon({ z: { y: 1, x: 2 }, a: [{ n: 1, m: 2 }] }),
     '{"a":[{"m":2,"n":1}],"z":{"x":2,"y":1}}', 'canon() sorts recursively, through arrays');
  eq(canon({ a: 1 }) === canon({ a: 1 }), true, 'canon() is deterministic');

  /* A fixed snapshot, its canonical form, and its digest. These
   * three lines are the contract a third-party verifier must
   * reproduce to agree with us. */
  const SNAPSHOT = {
    schema_version: 'pc.snapshot.v1',
    query_hash: 'a'.repeat(64),
    candidate_merkle_root: 'b'.repeat(64),
    candidate_count: 8,
    ranking_rule_id: 'rr.value-weighted.v2',
    commercial_disclosure: { paid_placement: false, disclosed_supplier_ids: ['SUP-02', 'SUP-05'] },
    winner_id: 'SUP-01',
    nonce: '00000000-0000-4000-8000-000000000000',
    signer_key_id: '0123456789abcdef',
  };
  const CANONICAL = '{"candidate_count":8,"candidate_merkle_root":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","commercial_disclosure":{"disclosed_supplier_ids":["SUP-02","SUP-05"],"paid_placement":false},"nonce":"00000000-0000-4000-8000-000000000000","query_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ranking_rule_id":"rr.value-weighted.v2","schema_version":"pc.snapshot.v1","signer_key_id":"0123456789abcdef","winner_id":"SUP-01"}';
  eq(canon(SNAPSHOT), CANONICAL, 'golden snapshot → canonical byte string');
  eq(Buffer.byteLength(CANONICAL, 'utf8'), 464, 'canonical byte length');
  eq(await sha256(CANONICAL), '153988950a43bac3c46c7ebccc8ecef8bac6bfe11a214f0ee3c03eda6d08e68c',
     'golden snapshot → SHA-256');

  /* Key order in the source object must not matter. */
  const shuffled = Object.fromEntries(Object.entries(SNAPSHOT).reverse());
  eq(canon(shuffled), CANONICAL, 'key order in the source object does not affect the hash');

  section('Golden vectors — Merkle');
  const leaves = ['1', '2', '3'].map(x => x.repeat(64));
  const root = await merkleRoot(leaves);
  eq(typeof root === 'string' && root.length === 64, true, 'root is 64 hex');
  eq(await merkleRoot([]), '0'.repeat(64), 'empty tree root');
  eq(await merkleRoot([leaves[0]]), leaves[0], 'single-leaf root is the leaf');

  /* Odd-node duplication is load-bearing and must not be "fixed":
   * it is why candidate_count has to be committed separately. */
  const three = await merkleRoot([leaves[0], leaves[1], leaves[2]]);
  const fourDup = await merkleRoot([leaves[0], leaves[1], leaves[2], leaves[2]]);
  eq(three, fourDup, 'odd-node duplication: n=3 and n=4-with-duplicate share a root (why candidate_count is committed)');

  for (let i = 0; i < leaves.length; i++) {
    const p = await merklePath(leaves, i);
    eq(await merkleCheck(leaves[i], p, root), true, `inclusion proof verifies for leaf ${i}`);
  }
  eq(await merkleCheck('f'.repeat(64), await merklePath(leaves, 0), root), false, 'a foreign leaf does not verify');

  section('Golden vectors — sampled coverage (hypergeometric)');
  eq(+detectionProbability(8, 1, 4).toFixed(4), 0.5, 'n=8 k=1 s=4 → 50.0%');
  eq(+detectionProbability(8, 2, 4).toFixed(4), 0.7857, 'n=8 k=2 s=4 → 78.57%');
  eq(+detectionProbability(8, 1, 8).toFixed(4), 1, 'full coverage → certain detection');
  eq(+detectionProbability(200, 5, 40).toFixed(3), 0.676, 'n=200 k=5 s=40 → 67.6%');
  eq(sampleForTarget(8, 1, 0.95), 8, 'a single-supplier prune in an 8-registry needs total coverage for 95%');
}

/* ============================================================
   2 — scenarios
   ============================================================ */

const QUERY = 'Annual room-block framework · Phuket · 4-star+ · 120 room-nights/month';

async function scenario({
  custody_model = 'platform-held',
  prune = false,
  tamper = null,          // holder id whose stored copy gets edited
  holderModes = {},
  routing = 'relayer',
  keyRegistry = true,
  advanceMonths = 0,
  sample_ids = null,
}) {
  const dir = await mkdtemp(join(tmpdir(), 'proofchoice-'));
  try {
    /* Store is pinned explicitly so the suite does not silently run
     * against a developer's real KV instance if those env vars exist. */
    const ctx = await boot({
      store: new FsStore(dir), custodyModel: custody_model, keyRegistryEnabled: keyRegistry,
    });

    const declared = prune ? REGISTRY.filter(s => s.id !== 'SUP-01') : REGISTRY.slice();
    const winner = declared.reduce((a, b) => (b.score > a.score ? b : a));

    const att = await callTool('pc_attest', {
      query: QUERY,
      candidate_ids: declared.map(s => s.id),
      winner_id: winner.id,
      custody_model,
    }, ctx);
    const proof_id = att._data.proof_id;

    if (tamper) {
      await ctx.custody.tamper(att._data.snapshot_hash, tamper, b => {
        b.snapshot.winner_id = 'SUP-02';
        b.candidates = b.candidates.filter(c => c.id !== 'SUP-01');
        b.snapshot.candidate_count = b.candidates.length;
      });
    }
    for (const [h, m] of Object.entries(holderModes)) ctx.custody.setMode(h, m);
    if (advanceMonths) ctx.custody.setClockOffsetMonths(advanceMonths);

    await callTool('pc_request_receipts', { proof_id, routing, sample_ids }, ctx);
    const v = await callTool('pc_verify', { proof_id }, ctx);
    return { ...v._data, proof_id, winner: winner.id };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function acceptance() {
  section('Design.md §8 — the six acceptance scenarios');

  const honest = await scenario({});
  eq(honest.verdict, 'pass', '1. Honest run → PASS');
  eq(honest.checks[5].detail.includes('All 8'), true, '   … 8 affirm, 0 deny');
  eq(honest.winner, 'SUP-01', '   … winner is the highest-scoring supplier');

  const pruned = await scenario({ prune: true });
  eq(pruned.verdict, 'fail', '2. Cheapest candidate pruned before snapshot → FAIL');
  eq(pruned.checks[4].state, 'ok', '   … baseline layer passes — it cannot see the pruning');
  eq(pruned.checks[5].state, 'bad', '   … only registry coverage detects it (silent deletion)');
  eq(pruned.summary.includes('never asked'), true, '   … reported as a supplier that was never asked');

  const edited = await scenario({ custody_model: 'platform-held', tamper: 'platform' });
  eq(edited.verdict, 'fail', '3. Evidence edited after anchoring → FAIL');
  eq(edited.checks[2].state, 'bad', '   … recompute mismatch');
  eq(edited.summary.includes('attributable'), true, '   … attributable to the signing key');

  const withheld = await scenario({ custody_model: 'platform-held', holderModes: { platform: 'withhold' } });
  eq(withheld.verdict, 'fail', '4. Evidence withheld from auditor → FAIL');
  eq(withheld.custody_state, 'WITHHELD', '   … custody state is WITHHELD, not a generic failure');
  eq(withheld.checks[0].state, 'ok', '   … the anchor is intact — this is a custody failure, not a chain failure');

  const legacy = await scenario({ prune: true, routing: 'legacy' });
  eq(legacy.checks[5].detail.includes('uncovered'), true, '5. Pruning + legacy receipt routing → pruning NOT detected');
  eq(legacy.verdict, 'partial', '   … verdict degrades to PARTIAL, not FAIL');
  eq(legacy.checks[5].state, 'warn', '   … the signed denial was dropped in transit; it reads as "no response"');

  const nokeyreg = await scenario({ keyRegistry: false });
  eq(nokeyreg.verdict, 'partial', '6. Key registry disabled → PARTIAL');
  eq(nokeyreg.checks[3].state, 'warn', '   … verifiable but repudiable');

  section('New rows — introduced by the switchable custody model (MEMO-01 Finding A)');

  const withheldHybrid = await scenario({ custody_model: 'hybrid', holderModes: { platform: 'withhold' } });
  eq(withheldHybrid.verdict, 'pass', '7. Withheld under hybrid custody → PASS (another holder serves)');
  eq(withheldHybrid.custody_state, 'AVAILABLE', '   … evidence available despite the platform refusing');
  eq(withheldHybrid.checks[1].holders.find(h => h.holder === 'platform').state, 'WITHHELD',
     '   … and the platform’s refusal is still named, per holder');

  const allWithheld = await scenario({
    custody_model: 'hybrid',
    holderModes: { platform: 'withhold', buyer: 'withhold', neutral: 'withhold' },
  });
  eq(allWithheld.verdict, 'fail', '8. All three holders withhold → FAIL');
  eq(allWithheld.custody_state, 'WITHHELD', '   … custody cannot defeat withholding, only raise its cost');

  const tamperHybrid = await scenario({ custody_model: 'hybrid', tamper: 'platform' });
  eq(tamperHybrid.verdict, 'partial', '9. Platform edits its copy under hybrid custody → PARTIAL');
  eq(tamperHybrid.divergent_holders, ['platform'], '   … divergence attributed to the platform by name');
  eq(tamperHybrid.checks[2].state, 'warn', '   … proof still verifies against an independent copy');

  const lost = await scenario({ custody_model: 'platform-held', holderModes: { platform: 'lost' } });
  eq(lost.verdict, 'fail', '10. Holder signs an admission of loss → FAIL');
  eq(lost.custody_state, 'LOST', '   … LOST is distinct from WITHHELD: a signed admission, not a refusal');

  const silent = await scenario({ custody_model: 'platform-held', holderModes: { platform: 'unresponsive' } });
  eq(silent.custody_state, 'UNRESPONSIVE', '11. Holder never answers → UNRESPONSIVE');
  eq(silent.summary.includes('worse than a refusal'), true, '   … ranked worse than a refusal');

  const expired = await scenario({ custody_model: 'hybrid', advanceMonths: 25 });
  eq(expired.verdict, 'inconclusive', '12. Retention period elapsed → INCONCLUSIVE, not FAIL');
  eq(expired.custody_state, 'EXPIRED', '   … policy-compliant deletion must not read as guilt');
  eq(expired.checks[3].state, 'ok', '   … the anchor and signature still verify');

  section('Sampling — reduced coverage must not be the default (MEMO-01 Finding B)');
  const sampled = await scenario({ prune: true, sample_ids: ['SUP-02', 'SUP-03', 'SUP-04', 'SUP-05'] });
  eq(sampled.checks[5].state, 'warn', '13. Pruned supplier outside the sample → not detected, recorded as uncovered');
  eq(sampled.verdict, 'partial', '   … which is why the acceptance suite samples the whole registry');
}

/* ============================================================
   3 — MCP protocol
   ============================================================ */

async function protocol() {
  section('MCP transport — dual-era');
  const dir = await mkdtemp(join(tmpdir(), 'proofchoice-mcp-'));
  try {
    const ctx = await boot({ store: new FsStore(dir) });
    const H = { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'tools/list' };

    const disc = await handleRpc({ jsonrpc: '2.0', id: 1, method: 'server/discover', params: {} }, { headers: {}, ctx });
    eq(disc.status, 200, 'server/discover responds 200');
    eq(disc.body.result.supportedVersions, SUPPORTED_VERSIONS, '   … advertises supported versions');
    eq(disc.body.result.resultType, 'complete', '   … resultType complete');

    const init = await handleRpc({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '2025-06-18' } }, { headers: {}, ctx });
    eq(init.body.result.protocolVersion, '2025-06-18', 'legacy initialize negotiates the requested version');

    const list = await handleRpc({ jsonrpc: '2.0', id: 3, method: 'tools/list', params: {} }, { headers: H, ctx });
    eq(list.body.result.tools.length >= 12, true, 'tools/list returns the tool set');
    eq(list.body.result.tools.every(t => t.inputSchema?.type === 'object'), true, '   … every tool has an object inputSchema');
    eq(list.body.result.tools.some(t => t.name === 'search') && list.body.result.tools.some(t => t.name === 'fetch'),
       true, '   … includes search + fetch for ChatGPT without Developer Mode');

    const mismatch = await handleRpc(
      { jsonrpc: '2.0', id: 4, method: 'tools/list', params: { _meta: { 'io.modelcontextprotocol/protocolVersion': '2026-07-28' } } },
      { headers: { 'mcp-protocol-version': '2025-06-18', 'mcp-method': 'tools/list' }, ctx });
    eq(mismatch.status, 400, 'header/body version mismatch → 400');
    eq(mismatch.body.error.code, -32020, '   … HeaderMismatch (-32020)');

    const badver = await handleRpc({ jsonrpc: '2.0', id: 5, method: 'tools/list', params: {} },
      { headers: { 'mcp-protocol-version': '1900-01-01' }, ctx });
    eq(badver.body.error?.code ?? null, null, 'an unknown version header alone falls through to legacy semantics');

    const unknown = await handleRpc({ jsonrpc: '2.0', id: 6, method: 'nope/nope', params: {} },
      { headers: { 'mcp-protocol-version': '2026-07-28', 'mcp-method': 'nope/nope' }, ctx });
    eq(unknown.body.error.code, -32601, 'unknown method → -32601');
    eq(unknown.status, 404, '   … 404 on the modern era, so a legacy client can tell the eras apart');

    const staleMethodHeader = await handleRpc({ jsonrpc: '2.0', id: 8, method: 'nope/nope', params: {} },
      { headers: H, ctx });
    eq(staleMethodHeader.body.error.code, -32020, 'Mcp-Method header not matching the body → HeaderMismatch');

    const notif = await handleRpc({ jsonrpc: '2.0', method: 'notifications/initialized' }, { headers: {}, ctx });
    eq(notif.status, 202, 'notification → 202 with no body');

    const toolErr = await handleRpc(
      { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'pc_verify', arguments: { proof_id: 'PC-NOPE' } } },
      { headers: { ...H, 'mcp-method': 'tools/call', 'mcp-name': 'pc_verify' }, ctx });
    eq(toolErr.body.result.isError, true, 'a failing tool reports isError in the result, not a JSON-RPC error');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/* ============================================================
   4 — storage adapters
   ============================================================ */

async function storage() {
  section('Storage adapters');

  for (const make of [() => new MemoryStore(), () => new FsStore(null)]) {
    const s = make();
    if (s.kind === 'fs') s.dir = await mkdtemp(join(tmpdir(), 'proofchoice-store-'));
    const tag = s.kind;

    eq(await s.get('missing'), null, `${tag}: get() of an absent key is null`);
    await s.set('a:b', 'one');
    eq(await s.get('a:b'), 'one', `${tag}: set/get round-trips`);
    eq(await s.has('a:b'), true, `${tag}: has()`);

    /* setNX is what keeps anchor() write-once across instances. */
    eq(await s.setNX('claim', 'first'), true, `${tag}: setNX succeeds on a free key`);
    eq(await s.setNX('claim', 'second'), false, `${tag}: setNX refuses an existing key`);
    eq(await s.get('claim'), 'first', `${tag}: setNX did not overwrite`);

    eq(await s.append('log', 'l1'), 1, `${tag}: append returns the new length (the block number)`);
    eq(await s.append('log', 'l2'), 2, `${tag}: append length increments`);
    eq(await s.list('log'), ['l1', 'l2'], `${tag}: list returns entries in order`);
    eq(await s.list('nolog'), [], `${tag}: list of an absent log is empty`);

    await s.del('a:b');
    eq(await s.has('a:b'), false, `${tag}: del()`);
    if (s.kind === 'fs') await rm(s.dir, { recursive: true, force: true });
  }

  eq(new MemoryStore().persistent, false, 'memory store declares itself non-persistent');
  eq(new MemoryStore().shared, false, '   … and non-shared, so it cannot back a history claim');

  /* Environment selection — the serverless default must never be a
   * filesystem that is read-only in production. */
  const saved = { ...process.env };
  process.env.PC_STORE = ''; delete process.env.PC_STORE;
  process.env.VERCEL = '1';
  delete process.env.KV_REST_API_URL; delete process.env.UPSTASH_REDIS_REST_URL;
  eq(storeFromEnv({ dataDir: '/tmp/x' }).kind, 'memory', 'on Vercel with no KV configured → memory store');
  process.env.KV_REST_API_URL = 'https://example.upstash.io';
  process.env.KV_REST_API_TOKEN = 'tok';
  eq(storeFromEnv({ dataDir: '/tmp/x' }).kind, 'redis', 'on Vercel with KV configured → redis store');
  delete process.env.VERCEL; delete process.env.KV_REST_API_URL; delete process.env.KV_REST_API_TOKEN;
  eq(storeFromEnv({ dataDir: '/tmp/x' }).kind, 'fs', 'locally with no KV → filesystem store');
  Object.assign(process.env, saved);
}

/* ============================================================
   5 — write-once anchoring survives the store swap
   ============================================================ */

async function writeOnce() {
  section('Write-once anchoring');
  const ctx = await boot({ store: new MemoryStore() });
  const declared = REGISTRY.slice();
  const a = await callTool('pc_attest', {
    query: QUERY, candidate_ids: declared.map(s => s.id), winner_id: 'SUP-01',
  }, ctx);

  let reverted = false;
  try {
    await ctx.chain.anchor({
      snapshot_hash: a._data.snapshot_hash,
      platform_signature: a._data.platform_signature,
      signer_key_id: ctx.keys.platform.key_id,
    });
  } catch (e) { reverted = e.code === 'ALREADY_ANCHORED'; }
  eq(reverted, true, 'anchor() reverts on a repeat snapshot_hash');

  eq(ctx.chain.blocks.map(b => b.block), ctx.chain.blocks.map((_, i) => i + 1),
     'block numbers are positions in the log, so concurrent writers cannot collide');

  /* A full round trip on the memory store, which is what an
   * unconfigured Vercel deployment would actually run. */
  await callTool('pc_request_receipts', { proof_id: a._data.proof_id }, ctx);
  const v = await callTool('pc_verify', { proof_id: a._data.proof_id }, ctx);
  eq(v._data.verdict, 'pass', 'full attest → receipts → verify round trip on a non-fs store');
}

/* ============================================================ */

section('ProofChoice acceptance suite');
await goldenVectors();
await acceptance();
await protocol();
await storage();
await writeOnce();

console.log(`\n${fail ? '\x1b[31m' : '\x1b[32m'}${pass} passed, ${fail} failed\x1b[0m\n`);
process.exit(fail ? 1 : 0);
