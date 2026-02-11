import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile } from '../lib/keys.js';
import { ReceiptUnsignedSchema } from '../schemas/index.js';

const receipt = new Command('receipt').description('Receipt management');

receipt
  .command('create')
  .description('Create a receipt document (initiator side)')
  .requiredOption('--from <file>', 'Your identity file')
  .requiredOption('--with <fingerprint>', 'Other party fingerprint')
  .option('--with-key-type <type>', 'Other party key type', 'ed25519')
  .requiredOption('--description <text>', 'Exchange description')
  .requiredOption('--type <type>', 'Exchange type: service, exchange, agreement')
  .option('--value <sats>', 'Value in sats', parseInt)
  .option('--outcome <outcome>', 'Outcome', 'completed')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts: Record<string, string | number | undefined>) => {
    const fromDoc = JSON.parse(await readFile(opts.from as string, 'utf8'));
    const fromK = Array.isArray(fromDoc.k) ? fromDoc.k[0] : fromDoc.k;
    const fromPub = fromBase64url(fromK.p);
    const fromFp = computeFingerprint(fromPub, fromK.t);

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'rcpt',
      p: [
        { t: fromK.t, f: fromFp, role: 'initiator' },
        { t: opts.withKeyType ?? 'ed25519', f: opts.with, role: 'counterparty' },
      ],
      ex: {
        type: opts.type,
        sum: opts.description,
        ...(opts.value && { val: opts.value }),
      },
      out: opts.outcome ?? 'completed',
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c as number, 'Receipt');

    // Validate before signing
    ReceiptUnsignedSchema.parse(doc);

    const key = await loadPrivateKeyByFile(opts.from as string);
    const format = (opts.encoding as string) ?? 'json';
    const sig = sign(doc, key.privateKey, format);

    doc.s =
      format === 'cbor'
        ? [sig, Buffer.alloc(0)]
        : [toBase64url(sig), '<awaiting-counterparty-signature>'];

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output as string, output);
      console.error(`Receipt (partial) written to: ${opts.output}`);
      console.error('Send to counterparty for co-signing.');
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default receipt;
