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

  constructor(dir) { this.dir = dir; }

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
   *  demo scale; it stays correct even if a second process appends. */
  async append(key, line) {
    const p = this._path(key, '.jsonl');
    await mkdir(dirname(p), { recursive: true });
    await appendFile(p, line + '\n');
    return (await this.list(key)).length;
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

  if (forced === 'memory') return new MemoryStore();
  if (forced === 'fs') return new FsStore(dataDir);
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
  if (store.kind === 'redis') {
    return 'Ledger persisted to Redis. Write-once anchoring is enforced atomically with SET NX, so it ' +
      'holds across concurrent instances. Still a single-operator store: it does not resist the ' +
      'operator deleting keys.';
  }
  return 'Ledger persisted to an append-only file on one host. Single-operator: it does not resist the ' +
    'operator editing the file.';
}
