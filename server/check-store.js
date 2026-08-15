#!/usr/bin/env node
/* ============================================================
   ProofChoice — live storage check
   ------------------------------------------------------------
       npm run check:store

   Runs the full Store contract against whatever backend the
   environment selects, then cleans up after itself.

   This exists because the unit tests cover fs and memory only:
   the Blob and Redis backends talk to a real service and cannot
   be verified without credentials. Run this once after wiring a
   store up, before trusting a deployment with anything.

   The two properties that actually matter are the last two:
   create-if-absent must REFUSE a second write (that is what makes
   anchor() write-once), and append must return log positions (that
   is what makes block numbers correct under concurrency).

   Locally:  vercel env pull .env.local  then  node --env-file=.env.local server/check-store.js
   ============================================================ */

import { storeFromEnv, storeDisclosure } from './store.js';

const store = storeFromEnv({ dataDir: './server/data' });
const NS = `__check_${Date.now()}`;
let pass = 0, fail = 0;

const ok = (cond, label, detail = '') => {
  cond ? pass++ : fail++;
  console.log(`  ${cond ? 'ok  ' : 'FAIL'}  ${label}${detail ? ' — ' + detail : ''}`);
};

console.log(`\nStore: ${store.kind}  (persistent ${store.persistent}, shared ${store.shared})`);
console.log(`${storeDisclosure(store)}\n`);

try {
  ok(await store.get(`${NS}:absent`) === null, 'get() of an absent key returns null');

  await store.set(`${NS}:a`, 'one');
  ok(await store.get(`${NS}:a`) === 'one', 'set() then get() round-trips');
  ok(await store.has(`${NS}:a`) === true, 'has() sees it');

  await store.set(`${NS}:a`, 'two');
  ok(await store.get(`${NS}:a`) === 'two', 'overwrite is visible immediately',
     store.kind === 'blob' ? 'this is the useCache:false path — a public store would fail here' : '');

  /* Write-once. anchor() rests entirely on this. */
  ok(await store.setNX(`${NS}:claim`, 'first') === true, 'setNX() succeeds on a free key');
  ok(await store.setNX(`${NS}:claim`, 'second') === false, 'setNX() REFUSES an existing key');
  ok(await store.get(`${NS}:claim`) === 'first', 'setNX() did not overwrite');

  /* Append. Block numbers are log positions, so these must be exact. */
  ok(await store.append(`${NS}:log`, 'l1') === 1, 'append() returns 1 for the first entry');
  ok(await store.append(`${NS}:log`, 'l2') === 2, 'append() returns 2 for the second');
  const lines = await store.list(`${NS}:log`);
  ok(JSON.stringify(lines) === JSON.stringify(['l1', 'l2']), 'list() returns entries in order',
     JSON.stringify(lines));
  ok((await store.list(`${NS}:nolog`)).length === 0, 'list() of an absent log is empty');

  /* Concurrent appends must not lose writes — the property that
     makes the compare-and-swap loop worth having. */
  const before = (await store.list(`${NS}:conc`)).length;
  const got = await Promise.all([1, 2, 3, 4].map(i => store.append(`${NS}:conc`, `c${i}`)));
  const after = await store.list(`${NS}:conc`);
  ok(after.length === before + 4, '4 concurrent appends all land', `${after.length} entries`);
  ok(new Set(got).size === got.length, 'each concurrent append gets a distinct position',
     got.join(','));

  await store.del(`${NS}:a`);
  ok(await store.has(`${NS}:a`) === false, 'del() removes it');
} catch (e) {
  fail++;
  console.log(`\n  FAIL  threw: ${e.message}`);
  if (/PUBLIC/.test(e.message)) {
    console.log('\n  The store\'s access mode cannot be changed after creation.');
    console.log('  Create a private store and reconnect it to the project.');
  }
  if (/@vercel\/blob/.test(e.message)) {
    console.log('\n  Run: npm install');
  }
}

/* Best-effort cleanup. */
for (const k of ['a', 'claim', 'log', 'conc', 'nolog']) {
  try { await store.del(`${NS}:${k}`); } catch {}
  try { await store.del(`${NS}:${k}.log`); } catch {}
}

console.log(`\n${fail ? '\x1b[31m' : '\x1b[32m'}${pass} passed, ${fail} failed\x1b[0m\n`);
process.exit(fail ? 1 : 0);
