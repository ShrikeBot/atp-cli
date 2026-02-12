import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { loadPrivateKeyByFile, loadPrivateKeyFromFile } from '../lib/keys.js';
import { AttRevocationUnsignedSchema } from '../schemas/index.js';

const attRevoke = new Command('att-revoke')
  .description('Revoke a previously issued attestation')
  .argument('<txid>', 'TXID of the attestation to revoke')
  .requiredOption('--from <file>', 'Your identity file (must be the original attestor)')
  .requiredOption('--reason <reason>', 'Reason: retracted, fraudulent, expired, error')
  .option('--private-key <file>', 'Private key file (overrides key lookup from identity)')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (txid: string, opts: Record<string, string | undefined>) => {
    if (!/^[0-9a-f]{64}$/i.test(txid)) {
      console.error('TXID must be 64 hex characters');
      process.exit(1);
    }

    // Read identity to load key (needed for signing)
    await readFile(opts.from!, 'utf8');

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'att-revoke',
      ref: txid,
      reason: opts.reason,
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c as number, 'Attestation revocation');

    // Validate before signing
    AttRevocationUnsignedSchema.parse(doc);

    const key = opts.privateKey
      ? await loadPrivateKeyFromFile(opts.privateKey)
      : await loadPrivateKeyByFile(opts.from!);
    const format = opts.encoding ?? 'json';
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
