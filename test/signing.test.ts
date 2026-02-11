import { describe, it, expect } from 'vitest';
import { generateEd25519 } from '../src/lib/keys.js';
import { sign, verify } from '../src/lib/signing.js';
import { toBase64url } from '../src/lib/encoding.js';
import { computeFingerprint } from '../src/lib/fingerprint.js';

describe('Signing and Verification', () => {
  it('signs and verifies a JSON document', () => {
    const { privateKey, publicKey } = generateEd25519();
    const doc = {
      v: '1.0' as const,
      t: 'id',
      n: 'TestAgent',
      k: { t: 'ed25519', p: toBase64url(publicKey) },
      c: Math.floor(Date.now() / 1000),
    };

    const sig = sign(doc, privateKey, 'json');
    expect(sig).toBeInstanceOf(Buffer);
    expect(sig.length).toBe(64); // Ed25519 signature is 64 bytes

    const valid = verify(doc, publicKey, sig, 'json');
    expect(valid).toBe(true);
  });

  it('rejects a tampered document', () => {
    const { privateKey, publicKey } = generateEd25519();
    const doc = {
      v: '1.0' as const,
      t: 'id',
      n: 'TestAgent',
      k: { t: 'ed25519', p: toBase64url(publicKey) },
      c: Math.floor(Date.now() / 1000),
    };

    const sig = sign(doc, privateKey, 'json');
    const tampered = { ...doc, n: 'EvilAgent' };
    const valid = verify(tampered, publicKey, sig, 'json');
    expect(valid).toBe(false);
  });

  it('rejects verification with wrong key', () => {
    const alice = generateEd25519();
    const bob = generateEd25519();
    const doc = {
      v: '1.0' as const,
      t: 'id',
      n: 'Alice',
      k: { t: 'ed25519', p: toBase64url(alice.publicKey) },
      c: Math.floor(Date.now() / 1000),
    };

    const sig = sign(doc, alice.privateKey, 'json');
    const valid = verify(doc, bob.publicKey, sig, 'json');
    expect(valid).toBe(false);
  });

  it('signs and verifies a CBOR document', () => {
    const { privateKey, publicKey } = generateEd25519();
    const doc = {
      v: '1.0' as const,
      t: 'id',
      n: 'TestAgent',
      k: { t: 'ed25519', p: toBase64url(publicKey) },
      c: Math.floor(Date.now() / 1000),
    };

    const sig = sign(doc, privateKey, 'cbor');
    const valid = verify(doc, publicKey, sig, 'cbor');
    expect(valid).toBe(true);
  });

  it('JSON and CBOR signatures differ for same document', () => {
    const { privateKey, publicKey } = generateEd25519();
    const doc = {
      v: '1.0' as const,
      t: 'id',
      n: 'TestAgent',
      k: { t: 'ed25519', p: toBase64url(publicKey) },
      c: Math.floor(Date.now() / 1000),
    };

    const jsonSig = sign(doc, privateKey, 'json');
    const cborSig = sign(doc, privateKey, 'cbor');
    expect(jsonSig.equals(cborSig)).toBe(false);
  });
});
