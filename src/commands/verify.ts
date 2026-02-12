import { Command } from 'commander';
import { readFile } from 'node:fs/promises';
import { fromBase64url, cborDecode } from '../lib/encoding.js';
import { verify } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { BitcoinRPC } from '../lib/rpc.js';
import { extractInscriptionFromWitness } from '../lib/inscription.js';
import { validateTimestamp } from '../lib/timestamp.js';
import { AtpDocumentSchema } from '../schemas/index.js';

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

    if (doc.t === 'id') {
      const k = doc.k as { t: string; p: string };
      const sig = doc.s;
      const pubBytes = fromBase64url(k.p);
      const sigBytes = typeof sig === 'string' ? fromBase64url(sig) : (sig as Uint8Array);
      const fp = computeFingerprint(pubBytes, k.t);
      const valid = verify(doc, pubBytes, sigBytes, format);
      console.log(`Key (${k.t}, ${fp}): ${valid ? '✓ VALID' : '✗ INVALID'}`);
    } else if (doc.t === 'att') {
      console.log(
        `Attestation from ${(doc.from as { f: string }).f} to ${(doc.to as { f: string }).f}`,
      );
      console.log("To verify, provide the attestor's public key via their identity document.");
    } else if (doc.t === 'super') {
      const target = doc.target as { f: string; ref: { net: string; id: string } };
      const k = doc.k as { t: string; p: string };
      const pubBytes = fromBase64url(k.p);
      const newFp = computeFingerprint(pubBytes, k.t);
      console.log(
        `Supersession: ${target.f} → ${newFp} (${doc.n})`,
      );
      console.log(`Reason: ${doc.reason}`);
      console.log(`Target ref: ${target.ref.net} / ${target.ref.id}`);
      console.log(
        'Both old and new key signatures must be verified against their identity documents.',
      );
    } else if (doc.t === 'revoke') {
      const target = doc.target as { f: string; ref: { net: string; id: string } };
      console.log(`Revocation of ${target.f}`);
      console.log(`Reason: ${doc.reason}`);
      console.log(`Target ref: ${target.ref.net} / ${target.ref.id}`);
      console.log('Note: signer may be any key in the supersession chain.');
    } else if (doc.t === 'att-revoke') {
      const ref = doc.ref as { net: string; id: string };
      console.log(`Attestation revocation`);
      console.log(`Ref: ${ref.net} / ${ref.id}`);
      console.log(`Reason: ${doc.reason}`);
      console.log("To verify, confirm the signature matches the original attestor's key.");
    } else if (doc.t === 'hb') {
      const ref = doc.ref as { net: string; id: string };
      console.log(`Heartbeat from ${doc.f}`);
      console.log(`Ref: ${ref.net} / ${ref.id}`);
      if (doc.msg) console.log(`Message: ${doc.msg}`);
      console.log('To verify, confirm the signature matches the identity with this fingerprint.');
    } else {
      console.error(`Unknown document type: ${doc.t}`);
    }
  });

export default verifyCmd;
