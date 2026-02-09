import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile } from '../lib/keys.js';

const heartbeat = new Command('heartbeat')
  .description('Create a signed heartbeat proving liveness')
  .requiredOption('--from <file>', 'Your identity file')
  .option('--msg <text>', 'Optional status message')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts) => {
    const fromDoc = JSON.parse(await readFile(opts.from, 'utf8'));
    const fromK = Array.isArray(fromDoc.k) ? fromDoc.k[0] : fromDoc.k;
    const fromPub = fromBase64url(fromK.p);
    const fp = computeFingerprint(fromPub, fromK.t);

    const doc = {
      v: '1.0',
      t: 'hb',
      f: fp,
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c, 'Heartbeat');

    if (opts.msg) doc.msg = opts.msg;

    const key = await loadPrivateKeyByFile(opts.from);
    const format = opts.encoding;
    const sig = sign(doc, key.privateKey, format);
    doc.s = format === 'cbor' ? sig : toBase64url(sig);

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Heartbeat written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default heartbeat;
