/* ============================================================
   Vercel serverless entry point
   ------------------------------------------------------------
   Every request is rewritten to /api/* by vercel.json, so this
   single catch-all serves both the MCP endpoint and the REST API.

   boot() is memoised per warm instance: key material, the chain
   index and the custody layer are rebuilt only on a cold start. A
   failed boot is NOT cached — otherwise one transient store error
   would poison the instance for its whole lifetime.

   The chain re-reads itself per request when the store is shared
   (see Chain.refresh), so a warm instance cannot serve a stale view
   of a log another instance has appended to.
   ============================================================ */

import { boot, createHandler } from '../server/server.js';

let ready = null;

function init() {
  return boot()
    .then(createHandler)
    .catch(err => { ready = null; throw err; });   // never cache a failure
}

export default async function handler(req, res) {
  try {
    ready ??= init();
    return (await ready)(req, res);
  } catch (err) {
    res.statusCode = 500;
    res.setHeader('content-type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({
      error: 'boot failed',
      message: err.message,
      hint: 'Check KV_REST_API_URL / KV_REST_API_TOKEN and PC_KEYS. See server/README.md § Deploying to Vercel.',
    }, null, 2));
  }
}
