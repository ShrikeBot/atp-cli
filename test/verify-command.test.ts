/**
 * Tests for the verify command's full signature verification across all document types.
 * Uses temp files to simulate document resolution.
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { execSync } from 'node:child_process';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { generateEd25519 } from '../src/lib/keys.js';
import { toBase64url, fromBase64url } from '../src/lib/encoding.js';
import { sign } from '../src/lib/signing.js';
import { computeFingerprint } from '../src/lib/fingerprint.js';
import {
  BITCOIN_MAINNET,
} from '../src/schemas/index.js';

const NET = BITCOIN_MAINNET;
const CLI = join(import.meta.dirname, '..', 'dist', 'index.js');
const TMP = join(import.meta.dirname, '..', '.test-tmp');

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

function writeDoc(name: string, doc: Record<string, unknown>): string {
  const path = join(TMP, name);
  writeFileSync(path, JSON.stringify(doc, null, 2));
  return path;
}

function runVerify(path: string): string {
  try {
    return execSync(`node ${CLI} verify ${path}`, { encoding: 'utf8', timeout: 10000 });
  } catch (e: any) {
    return e.stdout + e.stderr;
  }
}

describe('Verify command - full verification', () => {
  beforeEach(() => {
    mkdirSync(TMP, { recursive: true });
  });

  afterEach(() => {
    rmSync(TMP, { recursive: true, force: true });
  });

  it('verifies identity document', () => {
    const key = makeKey();
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'TestAgent',
      k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
    };
    doc.s = toBase64url(sign(doc, key.privateKey));
    const path = writeDoc('id.json', doc);
    const out = runVerify(path);
    expect(out).toContain('✓ VALID');
    expect(out).toContain('Schema validation: ✓');
  });

  it('detects invalid identity signature', () => {
    const key = makeKey();
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'TestAgent',
      k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
    };
    doc.s = toBase64url(sign(doc, key.privateKey));
    // Tamper
    doc.n = 'TamperedAgent';
    const path = writeDoc('id-bad.json', doc);
    const out = runVerify(path);
    expect(out).toContain('✗ INVALID');
  });

  it('verifies attestation with file-based identity resolution', () => {
    const keyA = makeKey();
    // Create attestor identity doc and save to file
    const idDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'Attestor',
      k: { t: 'ed25519', p: keyA.pubB64 }, ts: ts(),
    };
    idDoc.s = toBase64url(sign(idDoc, keyA.privateKey));
    const idPath = writeDoc('attestor-id.json', idDoc);

    // Create attestation that references the file path
    const keyB = makeKey();
    const att: Record<string, unknown> = {
      v: '1.0', t: 'att',
      from: { f: keyA.fingerprint, ref: { net: NET, id: idPath } },
      to: { f: keyB.fingerprint, ref: { net: NET, id: 'some-txid' } },
      ts: ts(),
    };
    att.s = toBase64url(sign(att, keyA.privateKey));
    const attPath = writeDoc('att.json', att);
    const out = runVerify(attPath);
    expect(out).toContain('✓ VALID');
    expect(out).toContain('Fingerprint match: ✓');
  });

  it('verifies heartbeat with file-based identity resolution', () => {
    const key = makeKey();
    const idDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'HBAgent',
      k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
    };
    idDoc.s = toBase64url(sign(idDoc, key.privateKey));
    const idPath = writeDoc('hb-id.json', idDoc);

    const hb: Record<string, unknown> = {
      v: '1.0', t: 'hb',
      f: key.fingerprint,
      ref: { net: NET, id: idPath },
      seq: 0, ts: ts(),
    };
    hb.s = toBase64url(sign(hb, key.privateKey));
    const hbPath = writeDoc('hb.json', hb);
    const out = runVerify(hbPath);
    expect(out).toContain('✓ VALID');
    expect(out).toContain('Fingerprint match: ✓');
  });

  it('verifies supersession with file-based identity resolution', () => {
    const oldKey = makeKey();
    const newKey = makeKey();
    const idDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'SuperAgent',
      k: { t: 'ed25519', p: oldKey.pubB64 }, ts: ts(),
    };
    idDoc.s = toBase64url(sign(idDoc, oldKey.privateKey));
    const idPath = writeDoc('super-old-id.json', idDoc);

    const superDoc: Record<string, unknown> = {
      v: '1.0', t: 'super',
      target: { f: oldKey.fingerprint, ref: { net: NET, id: idPath } },
      n: 'SuperAgent', k: { t: 'ed25519', p: newKey.pubB64 },
      reason: 'key-rotation', ts: ts(),
    };
    const oldSig = toBase64url(sign(superDoc, oldKey.privateKey));
    const newSig = toBase64url(sign(superDoc, newKey.privateKey));
    superDoc.s = [oldSig, newSig];
    const superPath = writeDoc('super.json', superDoc);
    const out = runVerify(superPath);
    expect(out).toContain('Old key signature');
    expect(out).toContain('New key signature');
    expect(out).toContain('✓ VALID');
    expect(out).not.toContain('✗ INVALID');
  });

  it('verifies revocation with file-based identity resolution', () => {
    const key = makeKey();
    const idDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'RevokeMe',
      k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
    };
    idDoc.s = toBase64url(sign(idDoc, key.privateKey));
    const idPath = writeDoc('revoke-id.json', idDoc);

    const revDoc: Record<string, unknown> = {
      v: '1.0', t: 'revoke',
      target: { f: key.fingerprint, ref: { net: NET, id: idPath } },
      reason: 'defunct', ts: ts(),
    };
    revDoc.s = toBase64url(sign(revDoc, key.privateKey));
    const revPath = writeDoc('revoke.json', revDoc);
    const out = runVerify(revPath);
    expect(out).toContain('✓ VALID');
  });

  it('verifies attestation revocation with file-based resolution', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    // Create attestor identity
    const idDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'AttRevAttestor',
      k: { t: 'ed25519', p: keyA.pubB64 }, ts: ts(),
    };
    idDoc.s = toBase64url(sign(idDoc, keyA.privateKey));
    const idPath = writeDoc('attrev-id.json', idDoc);

    // Create attestation
    const att: Record<string, unknown> = {
      v: '1.0', t: 'att',
      from: { f: keyA.fingerprint, ref: { net: NET, id: idPath } },
      to: { f: keyB.fingerprint, ref: { net: NET, id: 'some-txid' } },
      ts: ts(),
    };
    att.s = toBase64url(sign(att, keyA.privateKey));
    const attPath = writeDoc('attrev-att.json', att);

    // Create att-revoke referencing the attestation file
    const attRev: Record<string, unknown> = {
      v: '1.0', t: 'att-revoke',
      ref: { net: NET, id: attPath },
      reason: 'retracted', ts: ts(),
    };
    attRev.s = toBase64url(sign(attRev, keyA.privateKey));
    const attRevPath = writeDoc('attrev.json', attRev);
    const out = runVerify(attRevPath);
    expect(out).toContain('✓ VALID');
    expect(out).toContain('Resolved attestor identity');
  });

  it('verifies receipt with file-based resolution (initiator only)', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const idA: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'Seller',
      k: { t: 'ed25519', p: keyA.pubB64 }, ts: ts(),
    };
    idA.s = toBase64url(sign(idA, keyA.privateKey));
    const idAPath = writeDoc('rcpt-idA.json', idA);

    const idB: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'Buyer',
      k: { t: 'ed25519', p: keyB.pubB64 }, ts: ts(),
    };
    idB.s = toBase64url(sign(idB, keyB.privateKey));
    const idBPath = writeDoc('rcpt-idB.json', idB);

    const rcpt: Record<string, unknown> = {
      v: '1.0', t: 'rcpt',
      p: [
        { f: keyA.fingerprint, ref: { net: NET, id: idAPath }, role: 'initiator' },
        { f: keyB.fingerprint, ref: { net: NET, id: idBPath }, role: 'counterparty' },
      ],
      ex: { type: 'exchange', sum: 'Sold widget' },
      out: 'completed', ts: ts(),
    };
    const sigA = toBase64url(sign(rcpt, keyA.privateKey));
    const sigB = toBase64url(sign(rcpt, keyB.privateKey));
    rcpt.s = [sigA, sigB];
    const rcptPath = writeDoc('rcpt.json', rcpt);
    const out = runVerify(rcptPath);
    expect(out).toContain('Party 0 (initiator)');
    expect(out).toContain('Party 1 (counterparty)');
    expect(out).toContain('✓ VALID');
    expect(out).not.toContain('✗ INVALID');
  });

  it('shows fingerprint mismatch for attestation', () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const idDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'WrongFP',
      k: { t: 'ed25519', p: keyA.pubB64 }, ts: ts(),
    };
    idDoc.s = toBase64url(sign(idDoc, keyA.privateKey));
    const idPath = writeDoc('wrongfp-id.json', idDoc);

    // Attestation with wrong fingerprint
    const att: Record<string, unknown> = {
      v: '1.0', t: 'att',
      from: { f: 'wrong-fingerprint', ref: { net: NET, id: idPath } },
      to: { f: keyB.fingerprint, ref: { net: NET, id: 'some-txid' } },
      ts: ts(),
    };
    att.s = toBase64url(sign(att, keyA.privateKey));
    const attPath = writeDoc('wrongfp-att.json', att);
    const out = runVerify(attPath);
    expect(out).toContain('Fingerprint mismatch');
  });
});
