/* ============================================================
   ProofChoice — cryptographic core
   ------------------------------------------------------------
   PORTED VERBATIM from prototype/prototype.html, and mirrored again
   in public/demo.html so the console can verify independently.
   All three must agree byte-for-byte. This file is the single
   most security-critical thing in the repository.

   canon() must never be "improved". Any change to it — including
   ones that look like pure refactors — silently invalidates every
   hash ever produced, on every proof, forever.

   merkleRoot()/merklePath() must keep the odd-node duplication
   semantics (`lvl[i+1] ?? lvl[i]`) exactly as written. "Fixing"
   the duplication changes every root.

   key_id hashes the HEX STRING of the raw public key, not the
   raw bytes. That is what the prototype does; keep it.

   test.js pins all of the above with golden vectors.
   ============================================================ */

import { webcrypto } from 'node:crypto';

const subtle = webcrypto.subtle;
const enc = new TextEncoder();

export const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
export const unhex = h => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
export const sha256 = async s => hex(await subtle.digest('SHA-256', enc.encode(s)));
export const short = (h, n = 10) => (h ? h.slice(0, n) : '');
export const uuid = () => webcrypto.randomUUID();

/* deterministic JSON — key order must never affect the hash */
export function canon(o) {
  if (o === null || typeof o !== 'object') return JSON.stringify(o);
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']';
  return '{' + Object.keys(o).sort().map(k => JSON.stringify(k) + ':' + canon(o[k])).join(',') + '}';
}

/* ---------- merkle ---------- */

export async function merkleRoot(leaves) {
  if (!leaves.length) return '0'.repeat(64);
  let lvl = leaves.slice();
  while (lvl.length > 1) {
    const nxt = [];
    for (let i = 0; i < lvl.length; i += 2) nxt.push(await sha256(lvl[i] + (lvl[i + 1] ?? lvl[i])));
    lvl = nxt;
  }
  return lvl[0];
}

export async function merklePath(leaves, idx) {
  let lvl = leaves.slice(), i = idx, path = [];
  while (lvl.length > 1) {
    const nxt = [];
    for (let j = 0; j < lvl.length; j += 2) {
      const a = lvl[j], b = lvl[j + 1] ?? lvl[j];
      if (j === i - (i % 2)) path.push(i % 2 === 0 ? { sib: b, side: 'right' } : { sib: a, side: 'left' });
      nxt.push(await sha256(a + b));
    }
    i = Math.floor(i / 2); lvl = nxt;
  }
  return path;
}

export async function merkleCheck(leaf, path, root) {
  let h = leaf;
  for (const s of path) h = s.side === 'right' ? await sha256(h + s.sib) : await sha256(s.sib + h);
  return h === root;
}

/* ---------- candidate leaves ----------
   A leaf commits id, name, price, the commission BINARY (never the
   rate, never the amount) and a per-candidate salt. Name+price is
   low-entropy; without the salt a shared Merkle path is
   brute-forceable back to a price.                                */

export function leafObject(c) {
  return {
    id: c.id,
    name: c.name,
    unit_price_cny: c.unit_price_cny ?? c.price,
    commission_disclosed: c.commission_disclosed ?? (c.comm > 0),
    salt: c.salt,
  };
}

export const leafHash = c => sha256(canon(leafObject(c)));

/** Leaves are ordered by id ascending so the root is reproducible
 *  from an unordered set. */
export async function leavesFor(candidates) {
  const sorted = candidates.slice().sort((a, b) => a.id.localeCompare(b.id));
  const leaves = [];
  for (const c of sorted) leaves.push(await leafHash(c));
  return { sorted, leaves };
}

/* ---------- keys ---------- */

export async function newKey() {
  const kp = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const raw = await subtle.exportKey('raw', kp.publicKey);
  const id = (await sha256(hex(raw))).slice(0, 16);
  return { kp, key_id: id, pub_raw: hex(raw) };
}

export async function signMsg(k, msg) {
  return hex(await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, k.kp.privateKey, enc.encode(msg)));
}

export async function verifyMsg(pub, msg, sigHex) {
  if (!pub || !sigHex || !/^[0-9a-f]+$/i.test(sigHex) || sigHex.length % 2) return false;
  try {
    return await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, unhex(sigHex), enc.encode(msg));
  } catch {
    return false;
  }
}

/** Import a raw P-256 public key for verification. The auditor uses
 *  this to resolve a key from the on-chain registry by signer_key_id,
 *  rather than being handed a key by the party under audit. */
export async function importPublic(pubRawHex) {
  return subtle.importKey('raw', unhex(pubRawHex), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
}

/* ---------- key persistence ---------- */

export async function exportKeyPair(k) {
  const priv = hex(await subtle.exportKey('pkcs8', k.kp.privateKey));
  return { key_id: k.key_id, pub_raw: k.pub_raw, priv_pkcs8: priv };
}

export async function importKeyPair(rec) {
  const privateKey = await subtle.importKey(
    'pkcs8', unhex(rec.priv_pkcs8), { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
  const publicKey = await importPublic(rec.pub_raw);
  return { kp: { privateKey, publicKey }, key_id: rec.key_id, pub_raw: rec.pub_raw };
}

/* ---------- ids ---------- */

/** Derived, not assigned — the holder can locate their own anchor
 *  without asking the platform where it is. */
export const proofIdFor = snapshotHash => 'PC-' + snapshotHash.slice(0, 10).toUpperCase();
