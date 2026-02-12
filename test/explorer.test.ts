import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { MockExplorer } from './mock-explorer.js';
import { ExplorerClient } from '../src/lib/explorer.js';
import { generateEd25519 } from '../src/lib/keys.js';
import { computeFingerprint } from '../src/lib/fingerprint.js';
import { toBase64url } from '../src/lib/encoding.js';

describe('MockExplorer', () => {
  let explorer: MockExplorer;
  let client: ExplorerClient;

  beforeAll(async () => {
    explorer = new MockExplorer();
    const url = await explorer.start();
    client = new ExplorerClient(url);
  });

  afterAll(async () => {
    await explorer.stop();
  });

  it('serves explorer info', async () => {
    const info = await client.getInfo();
    expect(info.name).toBe('Mock ATP Explorer');
    expect(info.chains).toContain('bip122:000000000019d6689c085ae165831e93');
  });

  it('resolves a single identity', async () => {
    const { publicKey } = generateEd25519();
    const fp = computeFingerprint(publicKey, 'ed25519');
    const pubB64 = toBase64url(publicKey);

    explorer.addIdentity({
      v: '1.0', t: 'id', n: 'TestAgent', f: fp,
      k: { t: 'ed25519', p: pubB64 },
    });

    const identity = await client.getIdentity(fp);
    expect(identity.genesis_fingerprint).toBe(fp);
    expect(identity.current_fingerprint).toBe(fp);
    expect(identity.name).toBe('TestAgent');
    expect(identity.status).toBe('active');
    expect(identity.chain_depth).toBe(1);
    expect(identity.key.public).toBe(pubB64);
  });

  it('resolves supersession chain', async () => {
    const key1 = generateEd25519();
    const key2 = generateEd25519();
    const fp1 = computeFingerprint(key1.publicKey, 'ed25519');
    const fp2 = computeFingerprint(key2.publicKey, 'ed25519');

    explorer.addIdentity({
      v: '1.0', t: 'id', n: 'ChainAgent', f: fp1,
      k: { t: 'ed25519', p: toBase64url(key1.publicKey) },
    });

    explorer.addSupersession(fp1, fp2, {
      v: '1.0', t: 'super', n: 'ChainAgent', reason: 'key-rotation',
      k: { t: 'ed25519', p: toBase64url(key2.publicKey) },
      target: { f: fp1 },
    });

    // Current identity should resolve to key2
    const identity = await client.getIdentity(fp1);
    expect(identity.current_fingerprint).toBe(fp2);
    expect(identity.chain_depth).toBe(2);
    expect(identity.key.public).toBe(toBase64url(key2.publicKey));

    // Also resolvable by fp2
    const identity2 = await client.getIdentity(fp2);
    expect(identity2.genesis_fingerprint).toBe(fp1);
    expect(identity2.current_fingerprint).toBe(fp2);

    // Chain should have both entries
    const chain = await client.getChain(fp1);
    expect(chain.chain).toHaveLength(2);
    expect(chain.chain[0].fingerprint).toBe(fp1);
    expect(chain.chain[1].fingerprint).toBe(fp2);
    expect(chain.revocation).toBeNull();
  });

  it('resolves revoked identity', async () => {
    const { publicKey } = generateEd25519();
    const fp = computeFingerprint(publicKey, 'ed25519');

    explorer.addIdentity({
      v: '1.0', t: 'id', n: 'RevokedAgent', f: fp,
      k: { t: 'ed25519', p: toBase64url(publicKey) },
    });

    explorer.addRevocation(fp, {
      v: '1.0', t: 'revoke', reason: 'key-compromised',
      target: { f: fp },
    }, fp);

    const identity = await client.getIdentity(fp);
    expect(identity.status).toBe('revoked:key-compromised');

    const chain = await client.getChain(fp);
    expect(chain.revocation).not.toBeNull();
    expect(chain.revocation!.reason).toBe('key-compromised');
  });

  it('returns 404 for unknown fingerprint', async () => {
    await expect(client.getIdentity('nonexistent')).rejects.toThrow('Not found');
  });

  it('stores and retrieves documents', async () => {
    const doc = { v: '1.0', t: 'hb', f: 'test', seq: 0 };
    const txid = explorer.addDocument(doc);

    const result = await client.getDocument(txid);
    expect(result.txid).toBe(txid);
    expect(result.document.t).toBe('hb');
    expect(result.valid).toBe(true);
  });

  it('resolves multi-hop supersession chain', async () => {
    const key1 = generateEd25519();
    const key2 = generateEd25519();
    const key3 = generateEd25519();
    const fp1 = computeFingerprint(key1.publicKey, 'ed25519');
    const fp2 = computeFingerprint(key2.publicKey, 'ed25519');
    const fp3 = computeFingerprint(key3.publicKey, 'ed25519');

    explorer.addIdentity({
      v: '1.0', t: 'id', n: 'HopAgent', f: fp1,
      k: { t: 'ed25519', p: toBase64url(key1.publicKey) },
    });
    explorer.addSupersession(fp1, fp2, {
      v: '1.0', t: 'super', n: 'HopAgent', reason: 'key-rotation',
      k: { t: 'ed25519', p: toBase64url(key2.publicKey) },
      target: { f: fp1 },
    });
    explorer.addSupersession(fp2, fp3, {
      v: '1.0', t: 'super', n: 'HopAgent', reason: 'key-rotation',
      k: { t: 'ed25519', p: toBase64url(key3.publicKey) },
      target: { f: fp2 },
    });

    const identity = await client.getIdentity(fp1);
    expect(identity.current_fingerprint).toBe(fp3);
    expect(identity.chain_depth).toBe(3);

    const chain = await client.getChain(fp1);
    expect(chain.chain).toHaveLength(3);
    expect(chain.chain[0].fingerprint).toBe(fp1);
    expect(chain.chain[1].fingerprint).toBe(fp2);
    expect(chain.chain[2].fingerprint).toBe(fp3);
  });
});
