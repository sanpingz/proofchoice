#!/usr/bin/env node
/* ============================================================
   ProofChoice — server
   ------------------------------------------------------------
   Runs two ways from the same code:

     node server/server.js        long-lived process, filesystem store
     api/index.js                 Vercel serverless, Redis or memory

   Exposes:
     POST /mcp        MCP endpoint (dual-era: modern + legacy)
     GET  /health     liveness, store properties, trust disclosure
     GET  /registry   category registry
     GET  /chain      append-only anchor registry
     POST /attest     stages 2-4
     POST /receipts   stage 5
     GET  /verify/:proof_id    stage 6
     GET  /evidence/:proof_id  off-chain preimage (subject to custody)
     GET  /proof/:proof_id     anchor + manifest + receipts

   TRUST DISCLOSURE. Read this before demoing anything.
   The chain, the custodians, the relayer and the platform all run
   inside ONE process, under ONE operator. The separation between
   them is enforced by module boundaries, not by anything an
   adversary would have to defeat. A single-operator append-only
   log is not a consortium chain and must never be described as
   one. The cryptography is real; the decentralisation is not.
   /health returns this as a field so no UI has to paraphrase it.
   ============================================================ */

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, watch } from 'node:fs';
import { join, dirname, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { newKey, exportKeyPair, importKeyPair, proofIdFor } from './core.js';
import { Chain } from './chain.js';
import { Custody, HOLDERS, MODELS } from './custody.js';
import { REGISTRY, Relayer } from './registry.js';
import { Platform } from './platform.js';
import { storeFromEnv, storeDisclosure } from './store.js';
import { handleRpc, callTool, SERVER_INFO, SUPPORTED_VERSIONS } from './mcp.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const DATA = process.env.PC_DATA ?? join(HERE, 'data');
/* The console. On Vercel this directory is served statically before
 * any rewrite reaches the function, so these routes are local-only. */
const PUBLIC = resolve(HERE, '..', 'public');
const PORT = Number(process.env.PC_PORT ?? 8787);
const HOST = process.env.PC_HOST ?? '127.0.0.1';
const FORCE_SSE = process.env.PC_FORCE_SSE === '1';
const ALLOWED_ORIGINS = (process.env.PC_ALLOWED_ORIGINS ?? '').split(',').map(s => s.trim()).filter(Boolean);

/* ============================================================
   Dev mode
   ------------------------------------------------------------
   Opt-in, local only. Never enabled on serverless: it opens a
   long-lived SSE stream and watches the filesystem, neither of
   which a lambda can do, and an always-open stream would burn
   execution time for nothing.

       npm run dev     →  node --watch server/server.js --dev

   Node's own --watch restarts the process when anything in the
   module graph changes. This adds the other half: a reload channel
   the console subscribes to, so edits to public/ refresh the
   browser, and a restart refreshes it too (the stream drops, the
   browser reconnects, sees a new boot id, and reloads).

   No dependency, no injected script tag, no proxy.
   ============================================================ */
const IS_SERVERLESS = !!(process.env.VERCEL ?? process.env.AWS_LAMBDA_FUNCTION_NAME);
const DEV = (process.env.PC_DEV === '1' || process.argv.includes('--dev')) && !IS_SERVERLESS;

const BOOT_ID = globalThis.crypto.randomUUID();
const devClients = new Set();

function devBroadcast(event, data) {
  const frame = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of devClients) { try { res.write(frame); } catch { devClients.delete(res); } }
}

function startDevWatch(onChange) {
  let timer = null, pending = new Set();
  const fire = () => {
    const files = [...pending]; pending.clear(); timer = null;
    onChange(files);
  };
  const handler = (_ev, file) => {
    if (!file || /(^|[\\/])(\.|__)/.test(file)) return;   // editor temp files
    pending.add(file);
    clearTimeout(timer);
    timer = setTimeout(fire, 80);                          // debounce editor write bursts
  };
  for (const dir of [PUBLIC]) {
    if (!existsSync(dir)) continue;
    try { watch(dir, { recursive: true }, handler); }
    catch (e) { console.warn(`  dev: cannot watch ${dir} (${e.code}) — reload the browser manually`); }
  }
  /* Keep intermediaries and idle timeouts from closing the stream.
     unref'd so it never holds the process open. */
  setInterval(() => { for (const res of devClients) { try { res.write(':\n\n'); } catch {} } }, 25000).unref();
}

/* ============================================================
   Key material
   ------------------------------------------------------------
   Order of preference:
     1. PC_KEYS env var  — a stable identity across deployments.
                           REQUIRED for serverless, otherwise each
                           instance invents its own platform key and
                           signatures stop verifying against the
                           registry.
     2. the store        — generated once, claimed with setNX so
                           concurrent instances converge on one set
     3. freshly generated, ephemeral
   ============================================================ */

async function materialise(ser) {
  const out = { platform: await importKeyPair(ser.platform), holders: {}, suppliers: {} };
  for (const [k, v] of Object.entries(ser.holders)) out.holders[k] = await importKeyPair(v);
  for (const [k, v] of Object.entries(ser.suppliers)) out.suppliers[k] = await importKeyPair(v);
  return out;
}

export async function generateKeySet() {
  const ks = { platform: await newKey(), holders: {}, suppliers: {} };
  for (const h of Object.keys(HOLDERS)) ks.holders[h] = await newKey();
  for (const s of REGISTRY) ks.suppliers[s.id] = await newKey();

  const ser = { platform: await exportKeyPair(ks.platform), holders: {}, suppliers: {} };
  for (const [k, v] of Object.entries(ks.holders)) ser.holders[k] = await exportKeyPair(v);
  for (const [k, v] of Object.entries(ks.suppliers)) ser.suppliers[k] = await exportKeyPair(v);
  return { keys: ks, serialised: ser };
}

async function loadKeys(store) {
  if (process.env.PC_KEYS) {
    const raw = process.env.PC_KEYS.trim();
    const text = raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
    return { keys: await materialise(JSON.parse(text)), source: 'env' };
  }

  const existing = await store.get('keys');
  if (existing) return { keys: await materialise(JSON.parse(existing)), source: store.kind };

  const { keys, serialised } = await generateKeySet();
  const won = await store.setNX('keys', JSON.stringify(serialised));
  if (!won) {
    /* Another instance generated first — adopt theirs, so every
     * instance signs with the same identity. */
    const theirs = await store.get('keys');
    if (theirs) return { keys: await materialise(JSON.parse(theirs)), source: store.kind };
  }
  return { keys, source: store.persistent ? store.kind : 'ephemeral' };
}

/* ============================================================
   Boot
   ============================================================ */

export async function boot({ dataDir = DATA, store, custodyModel, keyRegistryEnabled } = {}) {
  const st = store ?? storeFromEnv({ dataDir });
  const { keys, source: keySource } = await loadKeys(st);

  const chain = await new Chain(st).load();
  const custody = new Custody(st, keys.holders);

  /* Genesis: bind the platform key to a named operator on chain.
   * Without this, a valid signature is still repudiable. */
  if (!chain.getKey(keys.platform.key_id)) {
    await chain.registerKey({
      key_id: keys.platform.key_id,
      pub_raw: keys.platform.pub_raw,
      operator: process.env.PC_OPERATOR ?? 'Doubao Travel Procurement Agent',
    });
  }

  const supplierPubs = {};
  for (const [id, k] of Object.entries(keys.suppliers)) supplierPubs[id] = k.pub_raw;

  const ctx = {
    store: st, chain, custody, keys, keySource,
    platform: new Platform({ chain, custody, key: keys.platform }),
    relayer: new Relayer(keys.suppliers),
    supplierPubs,
    keyRegistryEnabled: keyRegistryEnabled ?? (process.env.PC_NO_KEY_REGISTRY !== '1'),
    defaultCustodyModel: custodyModel ?? process.env.PC_CUSTODY_MODEL ?? 'hybrid',
    publicUrl: process.env.PC_PUBLIC_URL ?? `http://${HOST}:${PORT}`,
    sessionId: crypto.randomUUID(),

    /* Per-proof working state (declared candidate ids, receipts,
     * coverage). Kept in the store, not in a Map: on serverless the
     * instance that runs pc_verify is rarely the one that ran
     * pc_request_receipts. */
    async getProof(pid) {
      const s = await st.get('proof:' + String(pid).toUpperCase());
      return s ? JSON.parse(s) : {};
    },
    async setProof(pid, patch) {
      const key = 'proof:' + String(pid).toUpperCase();
      const prev = await ctx.getProof(pid);
      await st.set(key, JSON.stringify({ ...prev, ...patch }));
    },

    /* Which suppliers the platform actually queried. This is the
     * supplier's own ground truth about its own experience, so it is
     * deliberately NOT read back out of the evidence blob — a
     * withheld blob must not also silence the receipts. */
    async declaredIdsFor(proof_id, snapshot_hash) {
      const st0 = await ctx.getProof(proof_id);
      if (st0.declaredIds) return st0.declaredIds;
      const raw = await st.get(`blob:platform:${snapshot_hash}`);
      return raw ? JSON.parse(raw).candidates.map(c => c.id) : [];
    },
  };
  return ctx;
}

/* ============================================================
   HTTP
   ============================================================ */

const json = (res, status, obj, headers = {}) => {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...headers });
  res.end(body);
};

/* Origin validation, required by the transport spec to stop a remote
 * page driving a server on someone's private network.
 *
 * The rule that matters is SAME-ORIGIN: a page served by this very
 * deployment is legitimate by definition. Checking only for localhost
 * — as this did originally — works locally and then rejects the
 * console's own POSTs the moment it is deployed anywhere, because the
 * origin becomes https://<host> rather than http://localhost:8787.
 *
 * Browsers omit Origin on same-origin GETs but send it on POSTs, so
 * the failure showed up only on writes. */
export function originAllowed(origin, req = { headers: {} }) {
  if (!origin) return true;                       // non-browser client: ChatGPT, curl
  if (ALLOWED_ORIGINS.includes('*')) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;

  let host;
  try { host = new URL(origin).host.toLowerCase(); } catch { return false; }

  /* Same-origin. Behind Vercel's proxy the forwarded host is the one
   * the browser actually used. */
  const h = req.headers ?? {};
  const self = String(h['x-forwarded-host'] ?? h.host ?? '').toLowerCase();
  if (self && host === self) return true;

  /* Local development. */
  if (/^(localhost|127\.0\.0\.1)(:\d+)?$/.test(host)) return true;

  /* The deployment's own canonical hostnames, which differ from the
   * request host on preview/branch URLs. */
  for (const v of [process.env.VERCEL_URL, process.env.VERCEL_BRANCH_URL,
                   process.env.VERCEL_PROJECT_PRODUCTION_URL]) {
    if (v && host === String(v).toLowerCase()) return true;
  }
  return false;
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp',
};

/** Serve a file from public/, refusing anything that resolves outside
 *  it. Returns false when there is nothing to serve. */
async function serveStatic(res, path) {
  const rel = path === '/' ? '/index.html' : path;
  const file = resolve(PUBLIC, '.' + rel);
  if (!file.startsWith(PUBLIC + '/') && file !== PUBLIC) return false;
  if (!existsSync(file)) return false;
  const body = await readFile(file);
  res.writeHead(200, {
    'content-type': MIME[extname(file)] ?? 'application/octet-stream',
    'cache-control': 'no-cache',
  });
  res.end(body);
  return true;
}

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    return typeof req.body === 'string' ? JSON.parse(req.body) : req.body;   // Vercel pre-parses
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return null;
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

/** The bare request handler. Vercel mounts this directly; the local
 *  server wraps it in http.createServer. */
export function createHandler(ctx) {
  return async function handler(req, res) {
    const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
    /* Route resolution, deliberately independent of filename
     * conventions.
     *
     * Vercel's filesystem router for a plain (non-framework) project
     * did NOT honour an optional catch-all `api/[[...path]].js`: it
     * matched exactly one segment, so /health worked and
     * /verify/PC-XXXX returned a platform 404 that never reached this
     * code. Rather than guess at another filename form, vercel.json
     * rewrites every path to the single function `api/index.js` and
     * carries the original path in `__p`.
     *
     * Locally there is no rewrite, so `__p` is absent and the pathname
     * is used directly — one code path, both deployments. */
    const routed = url.searchParams.get('__p');
    const raw = routed || url.pathname;
    const path = raw.replace(/^\/api(?=\/|$)/, '').replace(/\/+$/, '') || '/';

    /* DNS-rebinding protection, required by the transport spec. */
    if (!originAllowed(req.headers.origin, req)) {
      return json(res, 403, {
        jsonrpc: '2.0',
        error: {
          code: -32600,
          message: `Origin not allowed: ${req.headers.origin}`,
          data: {
            request_host: req.headers['x-forwarded-host'] ?? req.headers.host ?? null,
            hint: 'Same-origin requests are allowed automatically. To permit another origin, set ' +
                  'PC_ALLOWED_ORIGINS to a comma-separated list (or "*" to disable the check).',
          },
        },
      });
    }

    /* Dev reload channel. Stays open; no chain refresh needed. */
    if (DEV && path === '/dev/events') {
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-transform',
        connection: 'keep-alive',
        'x-accel-buffering': 'no',
      });
      res.write(`retry: 500\nevent: hello\ndata: ${JSON.stringify({ boot: BOOT_ID })}\n\n`);
      devClients.add(res);
      req.on('close', () => devClients.delete(res));
      return;
    }

    try {
      /* Other instances may have appended since this one booted. */
      await ctx.chain.refresh();

      /* ---- MCP endpoint ---- */
      if (path === '/mcp') {
        if (req.method === 'GET' || req.method === 'DELETE') {
          /* The 2026-07-28 revision removed the GET stream and
           * protocol-level sessions. 405 is the specified answer. */
          return json(res, 405, { jsonrpc: '2.0', error: { code: -32601, message: 'Method Not Allowed — this endpoint accepts POST' } }, { allow: 'POST' });
        }
        if (req.method !== 'POST') { res.writeHead(405, { allow: 'POST' }); return res.end(); }

        const msg = await readBody(req);
        const headers = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), Array.isArray(v) ? v[0] : v]));
        const out = await handleRpc(msg, { headers, ctx });

        if (out.status === 202 || out.body === null) { res.writeHead(202); return res.end(); }

        const accept = String(headers.accept ?? '');
        const wantsSSE = FORCE_SSE || (accept.includes('text/event-stream') && !accept.includes('application/json'));

        if (wantsSSE) {
          res.writeHead(out.status, {
            'content-type': 'text/event-stream; charset=utf-8',
            'cache-control': 'no-cache, no-transform',
            connection: 'keep-alive',
            'x-accel-buffering': 'no',
            ...(out.headers ?? {}),
          });
          res.write(`event: message\ndata: ${JSON.stringify(out.body)}\n\n`);
          return res.end();
        }
        return json(res, out.status, out.body, out.headers ?? {});
      }

      /* ---- REST ---- */
      if (path === '/health') {
        return json(res, 200, {
          ok: true, server: SERVER_INFO,
          mcp_protocol_versions: SUPPORTED_VERSIONS,
          mcp_endpoint: `${ctx.publicUrl}/mcp`,
          dev: DEV,
          /* Unique per booted instance. Call /health twice: if this
           * changes, more than one instance is serving you, and any
           * non-shared store will lose proofs between requests. */
          instance: ctx.sessionId,
          anchors_visible: ctx.chain.blocks.filter(b => b.type === 'anchor').length,
          store: { kind: ctx.store.kind, persistent: ctx.store.persistent, shared: ctx.store.shared },
          key_source: ctx.keySource,
          platform_key_id: ctx.keys.platform.key_id,
          custody_models: Object.keys(MODELS),
          default_custody_model: ctx.defaultCustodyModel,
          key_registry_enabled: ctx.keyRegistryEnabled,
          blocks: ctx.chain.blocks.length,
          storage_disclosure: storeDisclosure(ctx.store),
          trust_disclosure:
            'Cryptography is real: SHA-256, ECDSA P-256, salted Merkle trees, all independently ' +
            'recomputable. The ledger is a single-operator append-only log, not a blockchain — it does ' +
            'not resist the operator deleting it. Chain, custodians, relayer and platform all run in ' +
            'one process; their separation is a module boundary, not an adversarial one.',
          ...(ctx.keySource === 'ephemeral'
            ? { warning: 'Keys are ephemeral: this instance generated its own platform key and will lose it on restart. Set PC_KEYS for a stable signing identity.' }
            : {}),
        });
      }

      if (path === '/registry') return json(res, 200, REGISTRY);
      if (path === '/chain') return json(res, 200, ctx.chain.tail(Number(url.searchParams.get('limit') ?? 50)));

      if (path === '/attest' && req.method === 'POST') {
        const b = await readBody(req);
        const candidates = (b.candidate_ids ?? []).map(id => {
          const s = REGISTRY.find(x => x.id === id);
          if (!s) throw Object.assign(new Error(`unknown supplier id: ${id}`), { status: 400 });
          return s;
        });
        const r = await ctx.platform.attest({
          query: b.query, candidates, winner_id: b.winner_id,
          ranking_rule_id: b.ranking_rule_id,
          custody_model: b.custody_model ?? ctx.defaultCustodyModel,
          retention_months: b.retention_months ?? 24,
        });
        await ctx.setProof(r.proof_id, { declaredIds: b.candidate_ids, receipts: [], coverage: null });
        return json(res, 200, {
          proof_id: r.proof_id, snapshot_hash: r.snapshot_hash, snapshot: r.snapshot,
          canonical: r.canonical, canonical_bytes: r.canonical_bytes,
          merkle_root: r.merkle_root, anchor: r.anchor, custody: r.manifest,
        });
      }

      if (path === '/receipts' && req.method === 'POST') {
        const b = await readBody(req);
        const r = await callTool('pc_request_receipts', {
          proof_id: b.proof_id, routing: b.routing, sample_ids: b.sample_ids,
        }, ctx);
        return json(res, 200, r._data);
      }

      /* Adversary switches. Simulated holders, not real outages — the
       * console labels them as such. */
      if (path === '/custody-control' && req.method === 'POST') {
        const b = await readBody(req);
        await callTool('pc_custody_control', b, ctx);
        return json(res, 200, { mode: ctx.custody.mode, clock_offset_ms: ctx.custody.clockOffsetMs });
      }

      if (path === '/reset' && req.method === 'POST') {
        ctx.custody.reset();
        return json(res, 200, { mode: ctx.custody.mode, note: 'Adversary switches cleared. The append-only log is unchanged — that is the point of an append-only log.' });
      }

      if (path === '/detection') {
        const q = k => (url.searchParams.get(k) == null ? undefined : Number(url.searchParams.get(k)));
        const r = await callTool('pc_detection_math', {
          n: q('n'), k: q('k'), s: q('s'), proofs: q('proofs'), target: q('target'),
        }, ctx);
        return json(res, 200, r._data);
      }

      let m;
      /* Stored receipts for a proof, so a console can re-open one it
       * did not create without re-requesting receipts (which would
       * append a second batch to the chain). */
      if ((m = /^\/receipts\/(.+)$/.exec(path)) && req.method === 'GET') {
        const st = await ctx.getProof(m[1]);
        return json(res, 200, { receipts: st.receipts ?? [], coverage: st.coverage ?? null });
      }
      if ((m = /^\/verify\/(.+)$/.exec(path))) {
        /* A missing anchor is far more often "this instance has a
         * different ledger" than "this proof is bad", and the two have
         * completely different remedies. Answer with what THIS instance
         * can actually see, so the difference is visible rather than
         * inferred. */
        if (!ctx.chain.anchorByProofId(m[1])) {
          const anchors = ctx.chain.blocks.filter(b => b.type === 'anchor');
          return json(res, 404, {
            error: `no anchor for proof ID ${m[1]}`,
            proof_id: m[1],
            instance: ctx.sessionId,
            store: { kind: ctx.store.kind, persistent: ctx.store.persistent, shared: ctx.store.shared },
            anchors_visible: anchors.length,
            newest_visible: anchors.length ? proofIdFor(anchors[anchors.length - 1].snapshot_hash) : null,
            hint: ctx.store.persistent
              ? 'This instance sees a persistent ledger. If the proof was anchored seconds ago, check every instance points at the SAME store.'
              : `The store is "${ctx.store.kind}": erased on restart and not shared between instances, so a proof anchored on one request can be invisible to the next. Attach Redis.`,
          });
        }
        const r = await callTool('pc_verify', { proof_id: m[1] }, ctx);
        return json(res, 200, r._data);
      }
      if ((m = /^\/evidence\/(.+)$/.exec(path))) {
        const anchor = ctx.chain.anchorByProofId(m[1]);
        if (!anchor) throw Object.assign(new Error('no anchor'), { status: 404 });
        const r = await ctx.custody.fetch(anchor.snapshot_hash, ctx.chain.getCustody(anchor.snapshot_hash));
        return json(res, r.state === 'AVAILABLE' ? 200 : 409, r);
      }
      if ((m = /^\/proof\/(.+)$/.exec(path))) {
        const anchor = ctx.chain.anchorByProofId(m[1]);
        if (!anchor) throw Object.assign(new Error('no anchor'), { status: 404 });
        return json(res, 200, {
          proof_id: proofIdFor(anchor.snapshot_hash), anchor,
          custody: ctx.chain.getCustody(anchor.snapshot_hash),
          receipts: ctx.chain.receiptsFor(anchor.snapshot_hash),
        });
      }
      if ((m = /^\/supplier\/(.+)$/.exec(path))) {
        const s = REGISTRY.find(x => x.id.toLowerCase() === m[1].toLowerCase());
        return s ? json(res, 200, s) : json(res, 404, { error: 'unknown supplier' });
      }

      /* The console. Last, so an API route always wins over a file. */
      if (req.method === 'GET' && await serveStatic(res, path)) return;

      if (path === '/') {
        return json(res, 200, {
          server: SERVER_INFO,
          mcp_endpoint: `${ctx.publicUrl}/mcp`,
          console: 'public/index.html not found — the console is not deployed',
          rest: ['/health', '/registry', '/chain', '/attest', '/receipts', '/verify/:proof_id', '/evidence/:proof_id', '/proof/:proof_id', '/custody-control', '/reset', '/detection'],
        });
      }

      return json(res, 404, { error: 'not found', path });
    } catch (e) {
      return json(res, e.status ?? 500, { error: e.message });
    }
  };
}

export function createApp(ctx) { return createServer(createHandler(ctx)); }

/* ============================================================
   Main — local only. Vercel uses api/index.js.
   ============================================================ */

if (import.meta.url === `file://${process.argv[1]}`) {
  const ctx = await boot();
  createApp(ctx).listen(PORT, HOST, () => {
    console.log(`\nProofChoice server`);
    console.log(`  REST          http://${HOST}:${PORT}/`);
    console.log(`  MCP endpoint  ${ctx.publicUrl}/mcp`);
    console.log(`  store         ${ctx.store.kind}  (persistent ${ctx.store.persistent}, shared ${ctx.store.shared})`);
    console.log(`  keys          ${ctx.keySource}`);
    console.log(`  platform key  ${ctx.keys.platform.key_id}  (${ctx.chain.blocks.length} blocks)`);
    console.log(`  custody       ${ctx.defaultCustodyModel}`);
    console.log(`  MCP versions  ${SUPPORTED_VERSIONS.join(', ')}`);
    if (DEV) {
      startDevWatch(files => {
        console.log(`  dev: ${files.join(', ')} changed — reloading ${devClients.size} browser${devClients.size === 1 ? '' : 's'}`);
        devBroadcast('reload', { files });
      });
      console.log(`  dev mode      on — watching public/, browsers reload automatically`);
    }
    console.log(`\n  Cryptography is real. The ledger is a single-operator append-only log,`);
    console.log(`  not a blockchain. Do not describe it as one.\n`);
    if (!ctx.publicUrl.startsWith('https://')) {
      console.log(`  ChatGPT needs a public HTTPS URL — deploy to Vercel or run a tunnel.`);
      console.log(`  See README.md § Deploying to Vercel.\n`);
    }
  });
}
