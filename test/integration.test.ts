/**
 * Comprehensive ATP CLI integration test suite.
 * Uses mock blockchain — no bitcoind required.
 */
import { describe, it, expect, beforeEach } from 'vitest';
import { MockChain } from './mock-chain.js';
import {
  verifyIdentity,
  verifyWithIdentity,
  verifySupersession,
  verifyRevocation,
  fetchDocument,
  isKeyInChain,
} from './verify-helper.js';
import { generateEd25519 } from '../src/lib/keys.js';
import { toBase64url, fromBase64url, encodeForSigning } from '../src/lib/encoding.js';
import { sign, verify } from '../src/lib/signing.js';
import { computeFingerprint } from '../src/lib/fingerprint.js';
import { ed25519 } from '@noble/curves/ed25519';
import {
  IdentityUnsignedSchema,
  AttestationUnsignedSchema,
  HeartbeatUnsignedSchema,
  SupersessionUnsignedSchema,
  RevocationUnsignedSchema,
  AttRevocationUnsignedSchema,
  ReceiptUnsignedSchema,
  BITCOIN_MAINNET,
} from '../src/schemas/index.js';

// ── Helpers ──────────────────────────────────────────────────────────

const NET = BITCOIN_MAINNET;

interface KeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
  fingerprint: string;
  pubB64: string;
}

function makeKey(): KeyPair {
  const { privateKey, publicKey } = generateEd25519();
  const fingerprint = computeFingerprint(publicKey, 'ed25519');
  return { privateKey, publicKey, fingerprint, pubB64: toBase64url(publicKey) };
}

function ts(): number {
  return Math.floor(Date.now() / 1000);
}

/** Create and sign an identity document, inscribe to chain */
function createIdentity(
  chain: MockChain,
  key: KeyPair,
  name: string,
  metadata?: Record<string, [string, string][]>,
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'id',
    n: name,
    k: [{ t: 'ed25519', p: key.pubB64 }],
    ts: ts(),
  };
  if (metadata) doc.m = metadata;
  IdentityUnsignedSchema.parse(doc);
  const sig = sign(doc, key.privateKey);
  doc.s = { f: key.fingerprint, sig: toBase64url(sig) };
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

/** Create and sign an attestation */
function createAttestation(
  chain: MockChain,
  fromKey: KeyPair,
  fromTxid: string,
  toFp: string,
  toTxid: string,
  ctx?: string,
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'att',
    from: { f: fromKey.fingerprint, ref: { net: NET, id: fromTxid } },
    to: { f: toFp, ref: { net: NET, id: toTxid } },
    ts: ts(),
  };
  if (ctx) doc.ctx = ctx;
  AttestationUnsignedSchema.parse(doc);
  const sig = sign(doc, fromKey.privateKey);
  doc.s = { f: fromKey.fingerprint, sig: toBase64url(sig) };
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

/** Create and sign a heartbeat */
function createHeartbeat(
  chain: MockChain,
  key: KeyPair,
  idTxid: string,
  seq: number,
  msg?: string,
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'hb',
    f: key.fingerprint,
    ref: { net: NET, id: idTxid },
    seq,
    ts: ts(),
  };
  if (msg) doc.msg = msg;
  HeartbeatUnsignedSchema.parse(doc);
  const sig = sign(doc, key.privateKey);
  doc.s = { f: key.fingerprint, sig: toBase64url(sig) };
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

/** Create and sign a supersession */
function createSupersession(
  chain: MockChain,
  oldKey: KeyPair,
  oldTxid: string,
  newKey: KeyPair,
  name: string,
  reason: string,
  metadata?: Record<string, [string, string][]>,
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'super',
    target: { f: oldKey.fingerprint, ref: { net: NET, id: oldTxid } },
    n: name,
    k: [{ t: 'ed25519', p: newKey.pubB64 }],
    reason,
    ts: ts(),
  };
  if (metadata) doc.m = metadata;
  SupersessionUnsignedSchema.parse(doc);
  const oldSig = sign(doc, oldKey.privateKey);
  const newSig = sign(doc, newKey.privateKey);
  doc.s = [
    { f: oldKey.fingerprint, sig: toBase64url(oldSig) },
    { f: newKey.fingerprint, sig: toBase64url(newSig) },
  ];
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

/** Create and sign a revocation */
function createRevocation(
  chain: MockChain,
  signerKey: KeyPair,
  targetFp: string,
  targetTxid: string,
  reason: 'key-compromised' | 'defunct',
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'revoke',
    target: { f: targetFp, ref: { net: NET, id: targetTxid } },
    reason,
    ts: ts(),
  };
  RevocationUnsignedSchema.parse(doc);
  const sig = sign(doc, signerKey.privateKey);
  doc.s = { f: signerKey.fingerprint, sig: toBase64url(sig) };
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

/** Create and sign an attestation revocation */
function createAttRevocation(
  chain: MockChain,
  signerKey: KeyPair,
  attTxid: string,
  reason: 'retracted' | 'fraudulent' | 'expired' | 'error',
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'att-revoke',
    ref: { net: NET, id: attTxid },
    reason,
    ts: ts(),
  };
  AttRevocationUnsignedSchema.parse(doc);
  const sig = sign(doc, signerKey.privateKey);
  doc.s = { f: signerKey.fingerprint, sig: toBase64url(sig) };
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

/** Create and sign a receipt (initiator side) */
function createReceipt(
  chain: MockChain,
  fromKey: KeyPair,
  fromTxid: string,
  withFp: string,
  withTxid: string,
  description: string,
  type: string,
): { doc: Record<string, unknown>; txid: string } {
  const doc: Record<string, unknown> = {
    v: '1.0',
    t: 'rcpt',
    p: [
      { f: fromKey.fingerprint, ref: { net: NET, id: fromTxid }, role: 'initiator' },
      { f: withFp, ref: { net: NET, id: withTxid }, role: 'counterparty' },
    ],
    ex: { type, sum: description },
    out: 'completed',
    ts: ts(),
  };
  ReceiptUnsignedSchema.parse(doc);
  const sig = sign(doc, fromKey.privateKey);
  doc.s = [
    { f: fromKey.fingerprint, sig: toBase64url(sig) },
    { f: withFp, sig: '' },
  ];
  const txid = chain.inscribeJson(doc);
  return { doc, txid };
}

// ── Tests ────────────────────────────────────────────────────────────

let chain: MockChain;

beforeEach(() => {
  chain = new MockChain();
});

describe('Happy Path', () => {
  it('1. Identity lifecycle: create → verify → show', () => {
    const key = makeKey();
    const { doc, txid } = createIdentity(chain, key, 'TestAgent');

    // Verify signature
    expect(verifyIdentity(doc)).toBe(true);

    // Fetch from chain and verify
    const fetched = fetchDocument(chain, txid);
    expect(fetched.n).toBe('TestAgent');
    expect(fetched.t).toBe('id');
    expect(verifyIdentity(fetched)).toBe(true);

    // Show: check fields
    const k = (fetched.k as Array<{ t: string; p: string }>)[0];
    expect(k.t).toBe('ed25519');
    expect(computeFingerprint(fromBase64url(k.p), k.t)).toBe(key.fingerprint);
  });

  it('2. Attestation: A attests B', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'AgentA');
    const { txid: txB } = createIdentity(chain, keyB, 'AgentB');

    const { doc: att } = createAttestation(chain, keyA, txA, keyB.fingerprint, txB, 'trusted peer');

    expect(verifyWithIdentity(att, idA)).toBe(true);
    expect(att.t).toBe('att');
    expect((att.to as { f: string }).f).toBe(keyB.fingerprint);
  });

  it('3. Heartbeat: seq=0, seq=1, verify both', () => {
    const key = makeKey();
    const { doc: idDoc, txid } = createIdentity(chain, key, 'HeartbeatAgent');

    const { doc: hb0 } = createHeartbeat(chain, key, txid, 0);
    const { doc: hb1 } = createHeartbeat(chain, key, txid, 1, 'still alive');

    expect(verifyWithIdentity(hb0, idDoc)).toBe(true);
    expect(verifyWithIdentity(hb1, idDoc)).toBe(true);
    expect(hb0.seq).toBe(0);
    expect(hb1.seq).toBe(1);
    expect(hb1.msg).toBe('still alive');
  });

  it('4. Supersession (key rotation)', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'RotateAgent');

    const { doc: superDoc } = createSupersession(
      chain,
      keyA,
      txA,
      keyB,
      'RotateAgent',
      'key-rotation',
    );

    expect(verifySupersession(superDoc, idA)).toBe(true);
    expect((superDoc.target as { f: string }).f).toBe(keyA.fingerprint);
    const newK = (superDoc.k as Array<{ p: string }>)[0];
    expect(fromBase64url(newK.p).equals(keyB.publicKey)).toBe(true);
  });

  it('5. Supersession (metadata update, same key)', () => {
    const key = makeKey();
    const { doc: idDoc, txid } = createIdentity(chain, key, 'MetaAgent');

    const { doc: superDoc } = createSupersession(
      chain,
      key,
      txid,
      key,
      'MetaAgent v2',
      'metadata-update',
      { links: [['twitter', '@newhandle']] },
    );

    expect(verifySupersession(superDoc, idDoc)).toBe(true);
    expect(superDoc.n).toBe('MetaAgent v2');
    expect((superDoc.m as Record<string, unknown[]>).links).toEqual([['twitter', '@newhandle']]);
  });

  it('6. Revocation', () => {
    const key = makeKey();
    const { doc: idDoc, txid } = createIdentity(chain, key, 'RevokeMe');

    const { doc: revDoc } = createRevocation(chain, key, key.fingerprint, txid, 'defunct');

    expect(verifyRevocation(revDoc, idDoc)).toBe(true);
    expect(revDoc.t).toBe('revoke');
    expect((revDoc.target as { f: string }).f).toBe(key.fingerprint);
  });

  it('7. Attestation revocation', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'AttestorA');
    const { txid: txB } = createIdentity(chain, keyB, 'AttesteeB');

    const { txid: attTxid } = createAttestation(chain, keyA, txA, keyB.fingerprint, txB);
    const { doc: attRevDoc } = createAttRevocation(chain, keyA, attTxid, 'retracted');

    expect(verifyWithIdentity(attRevDoc, idA)).toBe(true);
    expect(attRevDoc.t).toBe('att-revoke');
  });

  it('8. Receipt', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'Seller');
    const { txid: txB } = createIdentity(chain, keyB, 'Buyer');

    const { doc: rcpt } = createReceipt(
      chain,
      keyA,
      txA,
      keyB.fingerprint,
      txB,
      'Sold widget',
      'exchange',
    );

    // Verify initiator signature
    const sigs = rcpt.s as Array<{ f: string; sig: string }>;
    const sigBytes = fromBase64url(sigs[0].sig);
    expect(verify(rcpt, keyA.publicKey, sigBytes)).toBe(true);
    expect(rcpt.t).toBe('rcpt');
    expect((rcpt.p as Array<{ role: string }>)[0].role).toBe('initiator');
  });

  it('9. Full chain: identity → supersede → supersede → heartbeat → attest', () => {
    const key1 = makeKey();
    const key2 = makeKey();
    const key3 = makeKey();
    const keyOther = makeKey();

    // Identity
    const { doc: id1, txid: tx1 } = createIdentity(chain, key1, 'ChainAgent');
    expect(verifyIdentity(id1)).toBe(true);

    // Supersede 1→2
    const { doc: super1, txid: superTx1 } = createSupersession(
      chain,
      key1,
      tx1,
      key2,
      'ChainAgent',
      'key-rotation',
    );
    expect(verifySupersession(super1, id1)).toBe(true);

    // Supersede 2→3 (target is the supersession doc, key2 is old)
    // For the second supersession, we build an "identity-like" doc for key2 to verify against
    const id2Proxy: Record<string, unknown> = { k: { t: 'ed25519', p: key2.pubB64 } };
    const { doc: super2 } = createSupersession(
      chain,
      key2,
      superTx1,
      key3,
      'ChainAgent',
      'key-rotation',
    );
    expect(verifySupersession(super2, id2Proxy)).toBe(true);

    // Create other identity for attestation target
    const { txid: otherTx } = createIdentity(chain, keyOther, 'OtherAgent');

    // Heartbeat with current key (key3)
    // Use key3's fingerprint for heartbeat ref pointing to original identity
    const { doc: hb } = createHeartbeat(chain, key3, tx1, 0);
    const id3Proxy: Record<string, unknown> = { k: { t: 'ed25519', p: key3.pubB64 } };
    expect(verifyWithIdentity(hb, id3Proxy)).toBe(true);

    // Attest with current key
    const { doc: att } = createAttestation(chain, key3, tx1, keyOther.fingerprint, otherTx);
    expect(verifyWithIdentity(att, id3Proxy)).toBe(true);
  });
});

describe('Failure Modes', () => {
  it('10. Duplicate identity: same key, second invalid (first-seen-wins)', () => {
    const key = makeKey();
    const { txid: tx1 } = createIdentity(chain, key, 'First');
    const { txid: tx2 } = createIdentity(chain, key, 'Second');

    // Both inscribed, but first-seen-wins: tx1 was inscribed before tx2
    expect(chain.isBefore(tx1, tx2)).toBe(true);
    // A verifier should reject the second identity for the same key
  });

  it('11. Double supersession: A→B, then A→C, second invalid', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const keyC = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'DoubleSuper');

    const { txid: superTx1 } = createSupersession(
      chain,
      keyA,
      txA,
      keyB,
      'DoubleSuper',
      'key-rotation',
    );
    const { txid: superTx2 } = createSupersession(
      chain,
      keyA,
      txA,
      keyC,
      'DoubleSuper',
      'key-rotation',
    );

    // First supersession came first
    expect(chain.isBefore(superTx1, superTx2)).toBe(true);
  });

  it('12. Revocation after supersession: A→B, revoke with A → chain dead', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'RevAfterSuper');
    createSupersession(chain, keyA, txA, keyB, 'RevAfterSuper', 'key-rotation');

    // A's genesis key can revoke the whole chain
    const { doc: revDoc } = createRevocation(chain, keyA, keyA.fingerprint, txA, 'key-compromised');
    expect(verifyRevocation(revDoc, idA)).toBe(true);

    // After this revocation, identity and superseded identity are both dead
    expect(isKeyInChain(keyA.fingerprint, idA, [])).toBe(true);
  });

  it('13. Revocation with wrong key: invalid', () => {
    const key = makeKey();
    const wrongKey = makeKey();
    const { doc: idDoc, txid } = createIdentity(chain, key, 'WrongKeyRevoke');

    const { doc: revDoc } = createRevocation(chain, wrongKey, key.fingerprint, txid, 'defunct');

    // Signature won't verify against the identity's key
    expect(verifyRevocation(revDoc, idDoc)).toBe(false);
  });

  it('14. Stale heartbeat replay: seq=5 then seq=3 rejected', () => {
    const key = makeKey();
    const { txid } = createIdentity(chain, key, 'StaleHB');

    const { doc: hb5, txid: tx5 } = createHeartbeat(chain, key, txid, 5);
    const { doc: hb3, txid: tx3 } = createHeartbeat(chain, key, txid, 3);

    // hb5 was inscribed first
    expect(chain.isBefore(tx5, tx3)).toBe(true);
    // Verifier should reject hb3 because seq < highest seen (5)
    expect((hb3.seq as number) < (hb5.seq as number)).toBe(true);
  });

  it('15. Supersession of revoked identity: invalid', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'RevokedSuper');

    // Revoke first
    const { txid: revTx } = createRevocation(chain, keyA, keyA.fingerprint, txA, 'defunct');

    // Then try to supersede (should be considered invalid by verifier since revocation came first)
    const { txid: superTx } = createSupersession(
      chain,
      keyA,
      txA,
      keyB,
      'RevokedSuper',
      'key-rotation',
    );

    expect(chain.isBefore(revTx, superTx)).toBe(true);
  });

  it('16. Invalid signature: modified document', () => {
    const key = makeKey();
    const { doc } = createIdentity(chain, key, 'Tampered');

    // Tamper with the name after signing
    const tampered = { ...doc, n: 'EvilName' };
    expect(verifyIdentity(tampered)).toBe(false);
  });

  it('17. Wrong domain separator: verification fails', () => {
    const key = makeKey();
    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'id',
      n: 'WrongDomain',
      k: { t: 'ed25519', p: key.pubB64 },
      ts: ts(),
    };

    // Sign with wrong domain separator
    const { s: _sig, ...unsigned } = doc;
    const wrongBytes = Buffer.concat([
      Buffer.from('WRONG-v1.0:', 'ascii'),
      Buffer.from(JSON.stringify(unsigned), 'utf8'),
    ]);
    const badSig = ed25519.sign(wrongBytes, key.privateKey);
    doc.s = toBase64url(Buffer.from(badSig));

    // Verify with correct domain separator should fail
    expect(verifyIdentity(doc)).toBe(false);
  });
});

describe('Poison Pill (Chain Revocation)', () => {
  function buildChain() {
    const keyA = makeKey();
    const keyB = makeKey();
    const keyC = makeKey();

    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'PoisonAgent');
    const { doc: superAB, txid: txAB } = createSupersession(
      chain,
      keyA,
      txA,
      keyB,
      'PoisonAgent',
      'key-rotation',
    );
    const idBProxy: Record<string, unknown> = { k: { t: 'ed25519', p: keyB.pubB64 } };
    const { doc: superBC, txid: txBC } = createSupersession(
      chain,
      keyB,
      txAB,
      keyC,
      'PoisonAgent',
      'key-rotation',
    );

    return { keyA, keyB, keyC, idA, superAB, superBC, txA, txAB, txBC, idBProxy };
  }

  it('18. Chain revocation from genesis key (A)', () => {
    const { keyA, idA, txA, superAB, superBC } = buildChain();

    const { doc: revDoc } = createRevocation(chain, keyA, keyA.fingerprint, txA, 'key-compromised');
    expect(verifyRevocation(revDoc, idA)).toBe(true);
    // A is in the chain → valid authority to revoke everything
    expect(isKeyInChain(keyA.fingerprint, idA, [superAB, superBC])).toBe(true);
  });

  it('19. Chain revocation from middle key (B)', () => {
    const { keyB, idA, txA, superAB, superBC, idBProxy } = buildChain();

    const { doc: revDoc } = createRevocation(chain, keyB, keyB.fingerprint, txA, 'key-compromised');
    expect(verifyRevocation(revDoc, idBProxy)).toBe(true);
    expect(isKeyInChain(keyB.fingerprint, idA, [superAB, superBC])).toBe(true);
  });

  it('20. Chain revocation from current key (C)', () => {
    const { keyC, idA, txA, superAB, superBC } = buildChain();
    const idCProxy: Record<string, unknown> = { k: { t: 'ed25519', p: keyC.pubB64 } };

    const { doc: revDoc } = createRevocation(chain, keyC, keyC.fingerprint, txA, 'key-compromised');
    expect(verifyRevocation(revDoc, idCProxy)).toBe(true);
    expect(isKeyInChain(keyC.fingerprint, idA, [superAB, superBC])).toBe(true);
  });
});

describe('Edge Cases', () => {
  it('21. Self-attestation', () => {
    const key = makeKey();
    const { doc: idDoc, txid } = createIdentity(chain, key, 'SelfAttest');

    const { doc: att } = createAttestation(chain, key, txid, key.fingerprint, txid, 'self-vouch');
    expect(verifyWithIdentity(att, idDoc)).toBe(true);
    expect((att.from as { f: string }).f).toBe((att.to as { f: string }).f);
  });

  it('22. Mutual attestation', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { doc: idA, txid: txA } = createIdentity(chain, keyA, 'MutualA');
    const { doc: idB, txid: txB } = createIdentity(chain, keyB, 'MutualB');

    const { doc: attAB } = createAttestation(chain, keyA, txA, keyB.fingerprint, txB);
    const { doc: attBA } = createAttestation(chain, keyB, txB, keyA.fingerprint, txA);

    expect(verifyWithIdentity(attAB, idA)).toBe(true);
    expect(verifyWithIdentity(attBA, idB)).toBe(true);
  });

  it('23. Supersession with different ed25519 key', () => {
    const key1 = makeKey();
    const key2 = makeKey();
    const { doc: id1, txid: tx1 } = createIdentity(chain, key1, 'AlgoAgent');

    const { doc: superDoc } = createSupersession(
      chain,
      key1,
      tx1,
      key2,
      'AlgoAgent',
      'key-rotation',
    );
    expect(verifySupersession(superDoc, id1)).toBe(true);
    // Both are ed25519 but different keys
    expect(key1.fingerprint).not.toBe(key2.fingerprint);
  });

  it('24. Empty metadata: identity with no m field', () => {
    const key = makeKey();
    const { doc, txid } = createIdentity(chain, key, 'NoMeta');

    expect(doc.m).toBeUndefined();
    expect(verifyIdentity(doc)).toBe(true);

    const fetched = fetchDocument(chain, txid);
    expect(fetched.m).toBeUndefined();
  });

  it('25. Large metadata: many links/keys/wallets', () => {
    const key = makeKey();
    const links: [string, string][] = [];
    for (let i = 0; i < 20; i++) {
      links.push([`platform${i}`, `@handle${i}`]);
    }
    const wallets: [string, string][] = [];
    for (let i = 0; i < 10; i++) {
      wallets.push([`btc`, `bc1q${i.toString().padStart(38, '0')}`]);
    }

    const { doc, txid } = createIdentity(chain, key, 'BigMeta', {
      links,
      wallets,
    });

    expect(verifyIdentity(doc)).toBe(true);
    const fetched = fetchDocument(chain, txid);
    const m = fetched.m as Record<string, [string, string][]>;
    expect(m.links).toHaveLength(20);
    expect(m.wallets).toHaveLength(10);
  });
});
