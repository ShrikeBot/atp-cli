import { Command } from 'commander';
import { readFile } from 'node:fs/promises';
import { fromBase64url, cborDecode } from '../lib/encoding.js';
import { verify } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { BitcoinRPC } from '../lib/rpc.js';
import { extractInscriptionFromWitness } from '../lib/inscription.js';
import { validateTimestamp } from '../lib/timestamp.js';
import { AtpDocumentSchema } from '../schemas/index.js';

interface RpcOpts {
  rpcUrl: string;
  rpcUser: string;
  rpcPass: string;
}

interface ResolvedKey {
  pubBytes: Buffer;
  keyType: string;
  fingerprint: string;
}

/**
 * Fetch and decode an ATP document from a TXID (via RPC) or local file path.
 */
async function fetchDoc(
  ref: { net: string; id: string },
  rpcOpts: RpcOpts,
): Promise<Record<string, unknown>> {
  const id = ref.id;
  if (/^[0-9a-f]{64}$/i.test(id)) {
    const rpc = new BitcoinRPC(rpcOpts.rpcUrl, rpcOpts.rpcUser, rpcOpts.rpcPass);
    const tx = (await rpc.getRawTransaction(id)) as {
      vin: Array<{ txinwitness?: string[] }>;
    };
    const witness = tx.vin[0]?.txinwitness;
    if (!witness || witness.length === 0) throw new Error('No witness data in referenced tx');
    const { contentType, data } = extractInscriptionFromWitness(witness[witness.length - 1]!);
    if (contentType.includes('cbor')) {
      return cborDecode(data) as Record<string, unknown>;
    }
    return JSON.parse(data.toString('utf8'));
  }
  // Try as local file
  const raw = await readFile(id, 'utf8');
  return JSON.parse(raw);
}

/**
 * Resolve a reference to an identity's public key.
 */
async function resolveIdentity(
  ref: { net: string; id: string },
  rpcOpts: RpcOpts,
): Promise<ResolvedKey> {
  const doc = await fetchDoc(ref, rpcOpts);
  if (doc.t !== 'id' && doc.t !== 'super') {
    throw new Error(`Referenced document is type '${doc.t}', expected 'id' or 'super'`);
  }
  const k = doc.k as { t: string; p: string };
  const pubBytes = fromBase64url(k.p);
  const keyType = k.t;
  const fingerprint = computeFingerprint(pubBytes, keyType);
  return { pubBytes, keyType, fingerprint };
}

function sigValid(label: string, valid: boolean, fingerprint?: string): void {
  const fpStr = fingerprint ? ` (${fingerprint})` : '';
  console.log(`  ${label}${fpStr}: ${valid ? '✓ VALID' : '✗ INVALID'}`);
}

const verifyCmd = new Command('verify')
  .description('Verify an ATP document from file or TXID')
  .argument('<source>', 'File path or TXID')
  .option('--rpc-url <url>', 'Bitcoin RPC URL', 'http://localhost:8332')
  .option('--rpc-user <user>', 'RPC username', 'bitcoin')
  .option('--rpc-pass <pass>', 'RPC password', '')
  .action(async (source: string, opts: Record<string, string>) => {
    let doc: Record<string, unknown>;
    let format: string;

    if (/^[0-9a-f]{64}$/i.test(source)) {
      const rpc = new BitcoinRPC(opts.rpcUrl, opts.rpcUser, opts.rpcPass);
      const tx = (await rpc.getRawTransaction(source)) as {
        vin: Array<{ txinwitness?: string[] }>;
      };
      const witness = tx.vin[0]?.txinwitness;
      if (!witness || witness.length === 0) {
        console.error('No witness data found in transaction');
        process.exit(1);
      }
      const { contentType, data } = extractInscriptionFromWitness(witness[witness.length - 1]!);
      format = contentType.includes('cbor') ? 'cbor' : 'json';
      if (format === 'cbor') {
        doc = cborDecode(data) as Record<string, unknown>;
      } else {
        doc = JSON.parse(data.toString('utf8'));
      }
    } else {
      const raw = await readFile(source, 'utf8');
      doc = JSON.parse(raw);
      format = 'json';
    }

    // Validate against schema
    AtpDocumentSchema.parse(doc);
    console.log(`Schema validation: ✓`);

    if (doc.v !== '1.0') {
      console.error(`Unsupported version: ${doc.v}`);
      process.exit(1);
    }

    if (doc.ts != null) {
      try {
        validateTimestamp(doc.ts as number, 'Document');
        console.log(`Timestamp: ${new Date((doc.ts as number) * 1000).toISOString()} ✓`);
      } catch (e) {
        console.warn(`⚠ ${(e as Error).message}`);
      }
    } else {
      console.log(`Timestamp: not present (optional)`);
    }

    console.log(`Document type: ${doc.t}`);

    const rpcOpts: RpcOpts = {
      rpcUrl: opts.rpcUrl,
      rpcUser: opts.rpcUser,
      rpcPass: opts.rpcPass,
    };

    try {
      switch (doc.t) {
        case 'id': {
          const k = doc.k as { t: string; p: string };
          const pubBytes = fromBase64url(k.p);
          const sigBytes = typeof doc.s === 'string' ? fromBase64url(doc.s as string) : (doc.s as Uint8Array);
          const fp = computeFingerprint(pubBytes, k.t);
          const valid = verify(doc, pubBytes, sigBytes, format);
          sigValid('Signature', valid, fp);
          break;
        }

        case 'att': {
          const from = doc.from as { f: string; ref: { net: string; id: string } };
          const to = doc.to as { f: string };
          console.log(`  Attestation: ${from.f} → ${to.f}`);
          try {
            const resolved = await resolveIdentity(from.ref, rpcOpts);
            console.log(`  Resolved attestor identity: ${resolved.fingerprint}`);
            // Verify fingerprint match
            if (from.f !== resolved.fingerprint) {
              console.log(`  ✗ Fingerprint mismatch: doc says ${from.f}, resolved ${resolved.fingerprint}`);
            } else {
              console.log(`  Fingerprint match: ✓`);
            }
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch {
            console.log("  Could not resolve attestor's identity. To verify, provide the attestor's public key via their identity document.");
          }
          break;
        }

        case 'hb': {
          const ref = doc.ref as { net: string; id: string };
          const f = doc.f as string;
          console.log(`  Heartbeat from ${f}, seq=${doc.seq}`);
          if (doc.msg) console.log(`  Message: ${doc.msg}`);
          try {
            const resolved = await resolveIdentity(ref, rpcOpts);
            console.log(`  Resolved identity: ${resolved.fingerprint}`);
            if (f !== resolved.fingerprint) {
              console.log(`  ✗ Fingerprint mismatch: doc says ${f}, resolved ${resolved.fingerprint}`);
            } else {
              console.log(`  Fingerprint match: ✓`);
            }
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch {
            console.log('  Could not resolve identity. To verify, confirm the signature matches the identity with this fingerprint.');
          }
          break;
        }

        case 'super': {
          const target = doc.target as { f: string; ref: { net: string; id: string } };
          const k = doc.k as { t: string; p: string };
          const newPubBytes = fromBase64url(k.p);
          const newFp = computeFingerprint(newPubBytes, k.t);
          console.log(`  Supersession: ${target.f} → ${newFp} (${doc.n})`);
          console.log(`  Reason: ${doc.reason}`);
          try {
            const oldKey = await resolveIdentity(target.ref, rpcOpts);
            console.log(`  Resolved old identity: ${oldKey.fingerprint}`);
            if (target.f !== oldKey.fingerprint) {
              console.log(`  ✗ Target fingerprint mismatch: doc says ${target.f}, resolved ${oldKey.fingerprint}`);
            } else {
              console.log(`  Target fingerprint match: ✓`);
            }
            const sigs = doc.s as string[];
            const oldSigBytes = fromBase64url(sigs[0]);
            const newSigBytes = fromBase64url(sigs[1]);
            const oldValid = verify(doc, oldKey.pubBytes, oldSigBytes, format);
            sigValid('Old key signature', oldValid, oldKey.fingerprint);
            const newValid = verify(doc, newPubBytes, newSigBytes, format);
            sigValid('New key signature', newValid, newFp);
          } catch {
            console.log('  Could not resolve old identity. Both old and new key signatures must be verified against their identity documents.');
          }
          break;
        }

        case 'revoke': {
          const target = doc.target as { f: string; ref: { net: string; id: string } };
          console.log(`  Revocation of ${target.f}`);
          console.log(`  Reason: ${doc.reason}`);
          try {
            const resolved = await resolveIdentity(target.ref, rpcOpts);
            console.log(`  Resolved target identity: ${resolved.fingerprint}`);
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format);
            sigValid('Signature', valid, resolved.fingerprint);
            if (!valid) {
              console.log('  Note: signer may be any key in the supersession chain. The target key was tried but failed.');
            }
          } catch {
            console.log('  Could not resolve target identity. Note: signer may be any key in the supersession chain.');
          }
          break;
        }

        case 'att-revoke': {
          const ref = doc.ref as { net: string; id: string };
          console.log(`  Attestation revocation`);
          console.log(`  Reason: ${doc.reason}`);
          try {
            // Resolve the original attestation to find the attestor
            const attDoc = await fetchDoc(ref, rpcOpts);
            if (attDoc.t !== 'att') {
              console.log(`  ✗ Referenced document is type '${attDoc.t}', expected 'att'`);
              break;
            }
            const from = attDoc.from as { f: string; ref: { net: string; id: string } };
            console.log(`  Original attestor: ${from.f}`);
            const resolved = await resolveIdentity(from.ref, rpcOpts);
            console.log(`  Resolved attestor identity: ${resolved.fingerprint}`);
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch {
            console.log("  Could not resolve original attestation. To verify, confirm the signature matches the original attestor's key.");
          }
          break;
        }

        case 'rcpt': {
          const parties = doc.p as Array<{ f: string; ref: { net: string; id: string }; role: string }>;
          const sigs = doc.s as string[];
          console.log(`  Receipt with ${parties.length} parties`);
          for (let i = 0; i < parties.length; i++) {
            const party = parties[i];
            console.log(`  Party ${i} (${party.role}): ${party.f}`);
            if (sigs[i] && !sigs[i].startsWith('<')) {
              try {
                const resolved = await resolveIdentity(party.ref, rpcOpts);
                if (party.f !== resolved.fingerprint) {
                  console.log(`    ✗ Fingerprint mismatch: doc says ${party.f}, resolved ${resolved.fingerprint}`);
                } else {
                  console.log(`    Fingerprint match: ✓`);
                }
                const sigBytes = fromBase64url(sigs[i]);
                const valid = verify(doc, resolved.pubBytes, sigBytes, format);
                sigValid(`  Party ${i} signature`, valid, resolved.fingerprint);
              } catch {
                console.log(`    Could not resolve party ${i}'s identity.`);
              }
            } else {
              console.log(`    Signature: <not yet provided>`);
            }
          }
          break;
        }

        default:
          console.error(`Unknown document type: ${doc.t}`);
      }
    } catch (e) {
      console.error(`Verification error: ${(e as Error).message}`);
      process.exit(1);
    }
  });

export { fetchDoc, resolveIdentity };
export default verifyCmd;
