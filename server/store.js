/* ============================================================
   ProofChoice — storage adapter
   ------------------------------------------------------------
   The server runs in two very different places:

     · locally, as one long-lived process with a real filesystem
     · on Vercel, as short-lived serverless instances with a
       READ-ONLY filesystem and no shared memory between them

   That difference is not cosmetic. An append-only ledger that
   resets on cold start, or that forks into divergent copies across
   concurrent instances, does not support the claim the product
   makes about it. So each backend declares two properties and the
   server reports them at /health rather than assuming them:

     persistent — survives a restart
     shared     — safe when several instances run at once, which is
                  what makes write-once anchoring actually hold

   Backends:
     FsStore      persistent, shared (single host)   — local default
     RedisStore   persistent, shared                 — Vercel/Upstash
     MemoryStore  NEITHER                            — ephemeral demo

   MemoryStore is a legitimate choice for a throwaway demo, but a
   deployment running on it must say so. It is the one configuration
   where "append-only" is a statement about an API and not about
   history.
   ============================================================ */

import { appendFile, readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, dirname } from 'node:path';

const sanitize = s => String(s).replace(/[^A-Za-z0-9._-]/g, '_');

/* ------------------------------------------------------------
   Filesystem — keys map to a readable directory tree so the
   stored state stays inspectable during a demo. "a:b:c" becomes
   <dir>/a/b/c.
   ------------------------------------------------------------ */
export class FsStore {
  kind = 'fs';
  persistent = true;
  shared = true;

  constructor(dir) { this.dir = dir; this._queue = Promise.resolve(); }

  _path(key, ext = '') { return join(this.dir, ...String(key).split(':').map(sanitize)) + ext; }

  async get(key) {
    const p = this._path(key);
    return existsSync(p) ? readFile(p, 'utf8') : null;
  }

  async set(key, value) {
    const p = this._path(key);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, value);
  }

  /** Write-once. Returns false if the key already existed. */
  async setNX(key, value) {
    const p = this._path(key);
    if (existsSync(p)) return false;
    await this.set(key, value);
    return true;
  }

  async has(key) { return existsSync(this._path(key)); }
  async del(key) { await rm(this._path(key), { force: true }); }

  /** @returns {number} the new log length, which becomes the block
   *  number. Re-counting on every append is O(n) and irrelevant at
   *  demo scale.
   *
   *  Serialised through a queue: without it, concurrent callers each
   *  append and then re-count, and all of them read the SAME final
   *  length — so four concurrent appends would every one report
   *  position 4 and the block numbers would collide. The other
   *  backends get this for free (RPUSH returns the new length; the
   *  blob backend retries on a compare-and-swap failure). */
  async append(key, line) {
    const run = async () => {
      const p = this._path(key, '.jsonl');
      await mkdir(dirname(p), { recursive: true });
      await appendFile(p, line + '\n');
      return (await this.list(key)).length;
    };
    const next = this._queue.then(run, run);
    this._queue = next.then(() => {}, () => {});
    return next;
  }

  async list(key) {
    const p = this._path(key, '.jsonl');
    if (!existsSync(p)) return [];
    return (await readFile(p, 'utf8')).split('\n').filter(l => l.trim());
  }
}

/* ------------------------------------------------------------
   Redis over the Upstash REST API — plain fetch, no SDK, so the
   zero-dependency rule survives the move to serverless. Works with
   Vercel KV (KV_REST_API_*) and Upstash directly
   (UPSTASH_REDIS_REST_*).
   ------------------------------------------------------------ */
export class RedisStore {
  kind = 'redis';
  persistent = true;
  shared = true;
  /* Other instances can append between our requests, so the chain
   * index has to be re-read rather than cached for the process. */
  refreshBetweenRequests = true;

  constructor(url, token, prefix = 'pc:') {
    this.url = url.replace(/\/+$/, '');
    this.token = token;
    this.prefix = prefix;
  }

  async _cmd(...args) {
    const res = await fetch(this.url, {
      method: 'POST',
      headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
      body: JSON.stringify(args),
    });
    if (!res.ok) throw new Error(`redis ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const j = await res.json();
    if (j.error) throw new Error(`redis: ${j.error}`);
    return j.result;
  }

  _k(key) { return this.prefix + key; }

  async get(key) { return (await this._cmd('GET', this._k(key))) ?? null; }
  async set(key, value) { await this._cmd('SET', this._k(key), value); }

  /** SET .. NX is a genuine atomic write-once across concurrent
   *  instances, which is what keeps anchor() honest on serverless. */
  async setNX(key, value) { return (await this._cmd('SET', this._k(key), value, 'NX')) === 'OK'; }

  async has(key) { return (await this._cmd('EXISTS', this._k(key))) === 1; }
  async del(key) { await this._cmd('DEL', this._k(key)); }
  /** RPUSH returns the new list length, so block numbers stay
   *  correct even when several instances write concurrently. */
  async append(key, line) { return this._cmd('RPUSH', this._k(key + ':log'), line); }
  async list(key) { return (await this._cmd('LRANGE', this._k(key + ':log'), 0, -1)) ?? []; }

  async ping() { await this._cmd('PING'); return true; }
}

/* ------------------------------------------------------------
   Vercel Blob — object storage, via @vercel/blob.

   THE STORE MUST BE PRIVATE, for two independent reasons:

   1. Confidentiality. Evidence preimages carry every candidate
      price and every salt. On a public store anyone with the URL
      can read them, which defeats the salted-leaf design outright.

   2. Correctness. Overwrites take up to 60s to propagate through
      the CDN. The ledger is overwritten on every append, so a
      public store could serve a stale log and report "no anchor
      for this proof ID" for a proof written seconds earlier.
      Private blobs read through the function with useCache:false
      skip the cache entirely, which is the only way this is a
      ledger rather than an eventually-consistent guess.

   A public store is refused at the first write rather than
   silently accepted.

   Two distinct write primitives, and the SDK forbids combining
   them (ifMatch implies allowOverwrite):
     · allowOverwrite:false  → create-if-absent, i.e. setNX
     · ifMatch:<etag>        → compare-and-swap, used for append

   The SDK is imported dynamically so that the fs, memory and redis
   backends keep working with no node_modules present.
   ------------------------------------------------------------ */
export class BlobStore {
  kind = 'blob';
  persistent = true;
  shared = true;
  refreshBetweenRequests = true;

  constructor({ token, prefix = 'pc/', access = 'private' } = {}) {
    this.token = token;
    this.prefix = prefix;
    this.access = access;
    this._sdk = null;
  }

  async sdk() {
    if (!this._sdk) {
      try {
        this._sdk = await import('@vercel/blob');
      } catch (e) {
        throw new Error(
          'The blob store needs the @vercel/blob package: npm install @vercel/blob. ' +
          `(${e.message})`);
      }
    }
    return this._sdk;
  }

  _path(key) { return this.prefix + String(key).split(':').map(sanitize).join('/'); }
  _log(key) { return this._path(key) + '.log'; }
  _opts(extra = {}) {
    return { access: this.access, ...(this.token ? { token: this.token } : {}), ...extra };
  }

  /** A public store would publish every candidate price and every
   *  salt. Fail loudly the first time we can tell. */
  _assertPrivate(url) {
    if (this.access === 'private' && typeof url === 'string' && url.includes('.public.')) {
      throw new Error(
        'This Blob store is PUBLIC. Evidence preimages contain candidate prices and salts, ' +
        'and a public store also serves overwritten blobs up to 60s stale, which breaks the ' +
        'ledger. Access mode cannot be changed after creation — create a private store instead.');
    }
  }

  async _read(pathname) {
    const { get } = await this.sdk();
    const res = await get(pathname, this._opts({ useCache: false }));
    if (!res || res.statusCode !== 200) return null;
    return { text: await new Response(res.stream).text(), etag: res.blob?.etag ?? null };
  }

  async _write(pathname, value, extra) {
    const { put } = await this.sdk();
    const r = await put(pathname, value, this._opts({
      addRandomSuffix: false, contentType: 'application/json', cacheControlMaxAge: 60, ...extra,
    }));
    this._assertPrivate(r?.url);
    return r;
  }

  async get(key) { return (await this._read(this._path(key)))?.text ?? null; }

  async set(key, value) { await this._write(this._path(key), value, { allowOverwrite: true }); }

  /** Create-if-absent. Classified by observable state rather than
   *  by error text: the SDK has no dedicated already-exists error,
   *  and a real outage must not be misreported as "already taken". */
  async setNX(key, value) {
    try {
      await this._write(this._path(key), value, { allowOverwrite: false });
      return true;
    } catch (e) {
      const { BlobPreconditionFailedError } = await this.sdk();
      if (e instanceof BlobPreconditionFailedError) return false;
      if (await this.has(key)) return false;
      throw e;
    }
  }

  async _hasPath(pathname) {
    const { head, BlobNotFoundError } = await this.sdk();
    try { await head(pathname, this._opts()); return true; }
    catch (e) { if (e instanceof BlobNotFoundError) return false; throw e; }
  }

  async has(key) { return this._hasPath(this._path(key)); }

  async del(key) {
    const { del, BlobNotFoundError } = await this.sdk();
    try { await del(this._path(key), this._opts()); }
    catch (e) { if (!(e instanceof BlobNotFoundError)) throw e; }
  }

  /** Append by optimistic concurrency: read the log with its ETag,
   *  write it back with ifMatch. A concurrent writer invalidates the
   *  ETag and we retry, so no append is ever lost and block numbers
   *  stay equal to log positions. */
  async append(key, line, attempts = 8) {
    const { BlobPreconditionFailedError } = await this.sdk();
    const pathname = this._log(key);
    for (let i = 0; i < attempts; i++) {
      const cur = await this._read(pathname);
      const next = (cur?.text ?? '') + line + '\n';
      try {
        await this._write(pathname, next,
          cur ? { ifMatch: cur.etag } : { allowOverwrite: false });
        return next.split('\n').filter(l => l.trim()).length;
      } catch (e) {
        if (e instanceof BlobPreconditionFailedError) continue;   // someone else appended
        if (!cur && await this._hasPath(pathname)) continue;       // lost the create race
        throw e;
      }
    }
    throw new Error(`append(${key}): gave up after ${attempts} compare-and-swap attempts`);
  }

  async list(key) {
    const cur = await this._read(this._log(key));
    return cur ? cur.text.split('\n').filter(l => l.trim()) : [];
  }
}

/* ------------------------------------------------------------
   Memory — neither persistent nor shared. Correct for tests;
   honest only for a demo that says so out loud.
   ------------------------------------------------------------ */
export class MemoryStore {
  kind = 'memory';
  persistent = false;
  shared = false;

  constructor() { this.map = new Map(); this.logs = new Map(); }

  async get(key) { return this.map.has(key) ? this.map.get(key) : null; }
  async set(key, value) { this.map.set(key, value); }
  async setNX(key, value) {
    if (this.map.has(key)) return false;
    this.map.set(key, value); return true;
  }
  async has(key) { return this.map.has(key); }
  async del(key) { this.map.delete(key); }
  async append(key, line) {
    if (!this.logs.has(key)) this.logs.set(key, []);
    return this.logs.get(key).push(line);
  }
  async list(key) { return this.logs.get(key) ?? []; }
}

/* ------------------------------------------------------------
   Selection
   ------------------------------------------------------------ */

export function storeFromEnv({ dataDir } = {}) {
  const url = process.env.KV_REST_API_URL ?? process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN ?? process.env.UPSTASH_REDIS_REST_TOKEN;
  const forced = process.env.PC_STORE;

  /* A connected Blob store authenticates by OIDC (BLOB_STORE_ID +
   * VERCEL_OIDC_TOKEN, both injected by Vercel) or by a static
   * read-write token when running elsewhere. */
  const blobToken = process.env.BLOB_READ_WRITE_TOKEN;
  const blobOidc = process.env.BLOB_STORE_ID && process.env.VERCEL_OIDC_TOKEN;
  const blobOpts = { token: blobToken, access: process.env.PC_BLOB_ACCESS ?? 'private' };

  if (forced === 'memory') return new MemoryStore();
  if (forced === 'fs') return new FsStore(dataDir);
  if (forced === 'blob') return new BlobStore(blobOpts);
  if (forced === 'redis') return new RedisStore(url, token);

  if (blobToken || blobOidc) return new BlobStore(blobOpts);
  if (url && token) return new RedisStore(url, token);
  /* Serverless without a database: the filesystem is read-only, so
   * memory is the only thing that works — and it forgets. */
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) return new MemoryStore();
  return new FsStore(dataDir);
}

/** One sentence describing what this deployment can and cannot
 *  claim about its own history. Surfaced at /health. */
export function storeDisclosure(store) {
  if (store.kind === 'memory') {
    return 'EPHEMERAL STORE. The ledger lives in process memory: it is erased on restart and is not ' +
      'shared between concurrent instances, so anchors can be lost and the write-once guarantee does ' +
      'not hold across instances. Usable for a walkthrough; it cannot support any claim about history. ' +
      'Attach a Redis/KV store to fix this.';
  }
  if (store.kind === 'blob') {
    return 'Ledger persisted to a private Vercel Blob store. Write-once anchoring uses create-if-absent; ' +
      'the log is appended by ETag compare-and-swap and read with useCache:false, so a proof is ' +
      'verifiable the moment it is anchored. Still a single-operator store: it does not resist the ' +
      'operator deleting blobs.';
  }
  if (store.kind === 'redis') {
    return 'Ledger persisted to Redis. Write-once anchoring is enforced atomically with SET NX, so it ' +
      'holds across concurrent instances. Still a single-operator store: it does not resist the ' +
      'operator deleting keys.';
  }
  return 'Ledger persisted to an append-only file on one host. Single-operator: it does not resist the ' +
    'operator editing the file.';
}
