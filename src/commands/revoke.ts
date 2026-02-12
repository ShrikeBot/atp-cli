import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile } from '../lib/keys.js';
import { RevocationUnsignedSchema } from '../schemas/index.js';

const revoke = new Command('revoke')
  .description('Revoke an identity permanently')
  .requiredOption('--identity <file>', 'Identity file to revoke')
  .requiredOption('--reason <reason>', 'Reason: key-compromised, defunct')
  .option('--key <file>', 'Key file to sign with (for chain revocation with an old key)')
  .option('--txid <txid>', 'Identity inscription TXID')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts: Record<string, string | undefined>) => {
    const idDoc = JSON.parse(await readFile(opts.identity!, 'utf8'));
    const k = Array.isArray(idDoc.k) ? idDoc.k[0] : idDoc.k;
    const pubBytes = fromBase64url(k.p);
    const fp = computeFingerprint(pubBytes, k.t);

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'revoke',
      subject: { t: k.t, f: fp, ...(opts.txid && { txid: opts.txid }) },
      reason: opts.reason,
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c as number, 'Revocation');

    // Validate before signing
    RevocationUnsignedSchema.parse(doc);

    const key = opts.key
      ? await loadPrivateKeyByFile(opts.key)
      : await loadPrivateKeyByFile(opts.identity!);
    const format = opts.encoding ?? 'json';
    const sig = sign(doc, key.privateKey, format);
    doc.s = format === 'cbor' ? sig : toBase64url(sig);

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Revocation written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default revoke;
