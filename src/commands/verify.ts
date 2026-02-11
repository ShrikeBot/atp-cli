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

    try {
      validateTimestamp(doc.c as number, 'Document');
      console.log(`Timestamp: ${new Date((doc.c as number) * 1000).toISOString()} ✓`);
    } catch (e) {
      console.warn(`⚠ ${(e as Error).message}`);
    }

    console.log(`Document type: ${doc.t}`);

    if (doc.t === 'id') {
      const k = Array.isArray(doc.k) ? doc.k : [doc.k];
      const sigs = Array.isArray(doc.s) ? doc.s : [doc.s];

      for (let i = 0; i < k.length; i++) {
        const pubBytes = fromBase64url(k[i].p);
        const sigBytes = typeof sigs[i] === 'string' ? fromBase64url(sigs[i]) : sigs[i];
        const fp = computeFingerprint(pubBytes, k[i].t);
        const valid = verify(doc, pubBytes, sigBytes, format);
        console.log(`Key ${i} (${k[i].t}, ${fp}): ${valid ? '✓ VALID' : '✗ INVALID'}`);
      }
    } else if (doc.t === 'att') {
      console.log(
        `Attestation from ${(doc.from as { f: string }).f} to ${(doc.to as { f: string }).f}`,
      );
      console.log("To verify, provide the attestor's public key via their identity document.");
    } else if (doc.t === 'super') {
      console.log(
        `Supersession: ${(doc.old as { f: string }).f} → ${(doc.new as { f: string }).f}`,
      );
      console.log(`Reason: ${doc.reason}`);
      console.log(
        'Both old and new key signatures must be verified against their identity documents.',
      );
    } else if (doc.t === 'revoke') {
      console.log(`Revocation of ${(doc.subject as { f: string }).f}`);
      console.log(`Reason: ${doc.reason}`);
    } else if (doc.t === 'att-revoke') {
      console.log(`Attestation revocation`);
      console.log(`Ref: ${doc.ref}`);
      console.log(`Reason: ${doc.reason}`);
      console.log("To verify, confirm the signature matches the original attestor's key.");
    } else if (doc.t === 'hb') {
      console.log(`Heartbeat from ${doc.f}`);
      if (doc.msg) console.log(`Message: ${doc.msg}`);
      console.log('To verify, confirm the signature matches the identity with this fingerprint.');
    } else {
      console.error(`Unknown document type: ${doc.t}`);
    }
  });

export default verifyCmd;
