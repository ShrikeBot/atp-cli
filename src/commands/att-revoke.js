import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile } from '../lib/keys.js';

const attRevoke = new Command('att-revoke')
  .description('Revoke a previously issued attestation')
  .argument('<txid>', 'TXID of the attestation to revoke')
  .requiredOption('--from <file>', 'Your identity file (must be the original attestor)')
  .requiredOption('--reason <reason>', 'Reason: retracted, fraudulent, expired, error')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (txid, opts) => {
    const validReasons = ['retracted', 'fraudulent', 'expired', 'error'];
    if (!validReasons.includes(opts.reason)) {
      console.error(`Invalid reason: ${opts.reason}. Must be one of: ${validReasons.join(', ')}`);
      process.exit(1);
    }

    if (!/^[0-9a-f]{64}$/i.test(txid)) {
      console.error('TXID must be 64 hex characters');
      process.exit(1);
    }

    const fromDoc = JSON.parse(await readFile(opts.from, 'utf8'));
    const fromK = Array.isArray(fromDoc.k) ? fromDoc.k[0] : fromDoc.k;

    const doc = {
      v: '1.0',
      t: 'att-revoke',
      ref: txid,
      reason: opts.reason,
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c, 'Attestation revocation');

    const key = await loadPrivateKeyByFile(opts.from);
    const format = opts.encoding;
    const sig = sign(doc, key.privateKey, format);
    doc.s = format === 'cbor' ? sig : toBase64url(sig);

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Attestation revocation written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default attRevoke;
