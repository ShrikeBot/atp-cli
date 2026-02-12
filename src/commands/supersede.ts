import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile, loadPrivateKeyFromFile } from '../lib/keys.js';
import { SupersessionUnsignedSchema } from '../schemas/index.js';

const supersede = new Command('supersede')
  .description('Create a supersession document (key rotation or metadata update with same key)')
  .requiredOption('--old <file>', 'Old identity file')
  .requiredOption('--new <file>', 'New identity file')
  .requiredOption('--reason <reason>', 'Reason: key-rotation, algorithm-upgrade, key-compromised')
  .option('--old-private-key <file>', 'Old private key file (overrides key lookup)')
  .option('--new-private-key <file>', 'New private key file (overrides key lookup)')
  .option('--private-key <file>', 'Private key file for old key (alias for --old-private-key)')
  .option('--old-txid <txid>', 'Old identity inscription TXID')
  .option('--new-txid <txid>', 'New identity inscription TXID')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts: Record<string, string | undefined>) => {
    const oldDoc = JSON.parse(await readFile(opts.old!, 'utf8'));
    const newDoc = JSON.parse(await readFile(opts.new!, 'utf8'));

    const oldK = Array.isArray(oldDoc.k) ? oldDoc.k[0] : oldDoc.k;
    const newK = Array.isArray(newDoc.k) ? newDoc.k[0] : newDoc.k;

    const oldPub = fromBase64url(oldK.p);
    const newPub = fromBase64url(newK.p);
    const oldFp = computeFingerprint(oldPub, oldK.t);
    const newFp = computeFingerprint(newPub, newK.t);

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'super',
      old: { t: oldK.t, f: oldFp, ...(opts.oldTxid && { txid: opts.oldTxid }) },
      new: { t: newK.t, f: newFp, ...(opts.newTxid && { txid: opts.newTxid }) },
      reason: opts.reason,
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c as number, 'Supersession');

    // Validate before signing
    SupersessionUnsignedSchema.parse(doc);

    const oldPrivKeyFile = opts.oldPrivateKey ?? opts.privateKey;
    const oldKey = oldPrivKeyFile
      ? await loadPrivateKeyFromFile(oldPrivKeyFile, oldK.t)
      : await loadPrivateKeyByFile(opts.old!);
    const newKey = opts.newPrivateKey
      ? await loadPrivateKeyFromFile(opts.newPrivateKey, newK.t)
      : await loadPrivateKeyByFile(opts.new!);

    const format = opts.encoding ?? 'json';
    const oldSig = sign(doc, oldKey.privateKey, format);
    const newSig = sign(doc, newKey.privateKey, format);

    doc.s = format === 'cbor' ? [oldSig, newSig] : [toBase64url(oldSig), toBase64url(newSig)];

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Supersession written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default supersede;
