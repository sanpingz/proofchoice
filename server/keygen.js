#!/usr/bin/env node
/* ============================================================
   ProofChoice — key generator
   ------------------------------------------------------------
       node server/keygen.js

   Emits a PC_KEYS value: the platform signing key, the three
   custody holder keys, and one key per registry supplier, as
   base64-encoded JSON.

   Why this exists. On serverless there is no stable filesystem, so
   without PC_KEYS every cold start would mint a NEW platform key.
   Old anchors would then reference a signer_key_id that no longer
   resolves, and check 4 would report every historical proof as
   signed by an unregistered key. The identity has to outlive the
   instance.

   THIS OUTPUT IS PRIVATE KEY MATERIAL. Anyone holding it can sign
   snapshots as the platform and receipts as any supplier. Paste it
   into an encrypted environment variable, never into the repo.
   ============================================================ */

import { generateKeySet } from './server.js';

const { keys, serialised } = await generateKeySet();
const b64 = Buffer.from(JSON.stringify(serialised)).toString('base64');

const bare = process.argv.includes('--raw');
if (bare) {
  console.log(b64);
} else {
  console.error(`\nProofChoice key set`);
  console.error(`  platform key_id  ${keys.platform.key_id}`);
  console.error(`  custody holders  ${Object.keys(serialised.holders).join(', ')}`);
  console.error(`  supplier keys    ${Object.keys(serialised.suppliers).length}`);
  console.error(`  encoded length   ${b64.length} chars\n`);
  console.error(`Set this as PC_KEYS (Vercel: Settings -> Environment Variables, all environments).`);
  console.error(`It is PRIVATE key material — treat it like a password.\n`);
  console.log(b64);
}
