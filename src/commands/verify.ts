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
    let extracted: { contentType: string; data: Buffer } | null = null;
    for (let i = witness.length - 1; i >= 0; i--) {
      try {
        extracted = extractInscriptionFromWitness(witness[i]!);
        break;
      } catch { /* try next */ }
    }
    if (!extracted) throw new Error('No inscription found in any witness element');
    const { contentType, data } = extracted;
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
  if (valid) {
    console.log(`  ${label}${fpStr}: ✓ VALID`);
  } else {
    console.error(`  ${label}${fpStr}: ✗ INVALID`);
    process.exit(1);
  }
}

const CHAIN_STATE_WARNING =
  '\n⚠  Document signature verified. Chain state NOT checked — verify revocation/supersession status via an explorer.';

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
      // Search all witness elements for an inscription (last element may be control block)
      let extracted: { contentType: string; data: Buffer } | null = null;
      for (let i = witness.length - 1; i >= 0; i--) {
        try {
          extracted = extractInscriptionFromWitness(witness[i]!);
          break;
        } catch { /* try next */ }
      }
      if (!extracted) {
        console.error('No inscription found in any witness element');
        process.exit(1);
      }
      const { contentType, data } = extracted;
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
    try {
      AtpDocumentSchema.parse(doc);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error(`Schema validation failed: ${msg}`);
      process.exit(1);
    }
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
        console.error(`Warning: ${(e as Error).message} (ts is advisory — block time is authoritative)`);
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
              console.error(`  ✗ Fingerprint mismatch: doc says ${from.f}, resolved ${resolved.fingerprint}`);
              process.exit(1);
            } else {
              console.log(`  Fingerprint match: ✓`);
            }
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch (e) {
            console.error(`Error: could not resolve attestor's identity via ref: ${(e as Error).message}`);
            process.exit(1);
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
              console.error(`  ✗ Fingerprint mismatch: doc says ${f}, resolved ${resolved.fingerprint}`);
              process.exit(1);
            } else {
              console.log(`  Fingerprint match: ✓`);
            }
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch (e) {
            console.error(`Error: could not resolve identity via ref: ${(e as Error).message}`);
            process.exit(1);
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
              console.error(`  ✗ Target fingerprint mismatch: doc says ${target.f}, resolved ${oldKey.fingerprint}`);
              process.exit(1);
            } else {
              console.log(`  Target fingerprint match: ✓`);
            }
            const sigs = doc.s as string[];
            const oldSigBytes = fromBase64url(sigs[0]);
            const newSigBytes = fromBase64url(sigs[1]);
            const oldValid = verify(doc, oldKey.pubBytes, oldSigBytes, format, oldKey.keyType);
            sigValid('Old key signature', oldValid, oldKey.fingerprint);
            const newValid = verify(doc, newPubBytes, newSigBytes, format, k.t);
            sigValid('New key signature', newValid, newFp);
          } catch (e) {
            console.error(`Error: could not resolve old identity via target.ref: ${(e as Error).message}`);
            process.exit(1);
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
            const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch (e) {
            console.error(`Error: could not resolve target identity via target.ref: ${(e as Error).message}`);
            process.exit(1);
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
              console.error(`  ✗ Referenced document is type '${attDoc.t}', expected 'att'`);
              process.exit(1);
            }
            const from = attDoc.from as { f: string; ref: { net: string; id: string } };
            console.log(`  Original attestor: ${from.f}`);
            const resolved = await resolveIdentity(from.ref, rpcOpts);
            console.log(`  Resolved attestor identity: ${resolved.fingerprint}`);
            const sigBytes = fromBase64url(doc.s as string);
            const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
            sigValid('Signature', valid, resolved.fingerprint);
          } catch (e) {
            console.error(`Error: could not resolve original attestation or attestor identity: ${(e as Error).message}`);
            process.exit(1);
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
                  console.error(`    ✗ Fingerprint mismatch: doc says ${party.f}, resolved ${resolved.fingerprint}`);
                  process.exit(1);
                } else {
                  console.log(`    Fingerprint match: ✓`);
                }
                const sigBytes = fromBase64url(sigs[i]);
                const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
                sigValid(`  Party ${i} signature`, valid, resolved.fingerprint);
              } catch (e) {
                console.error(`Error: could not resolve party ${i}'s identity: ${(e as Error).message}`);
                process.exit(1);
              }
            } else {
              console.log(`    Signature: <not yet provided>`);
            }
          }
          break;
        }

        default:
          console.error(`Unknown document type: ${doc.t}`);
          process.exit(1);
      }
      console.log(CHAIN_STATE_WARNING);
    } catch (e) {
      console.error(`Verification error: ${(e as Error).message}`);
      process.exit(1);
    }
  });

export { fetchDoc, resolveIdentity };
export default verifyCmd;
