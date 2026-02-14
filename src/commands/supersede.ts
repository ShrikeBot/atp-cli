import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile, loadPrivateKeyFromFile, generateKeypair } from '../lib/keys.js';
import { SupersessionUnsignedSchema, BITCOIN_MAINNET } from '../schemas/index.js';

/** Collect --meta collection:key:value into array of [collection, key, value] */
function collectMeta(val: string, prev: string[][]) {
  const parts = val.split(':');
  if (parts.length < 3) {
    console.error('Error: --meta requires format collection:key:value');
    process.exit(1);
  }
  const [collection, key, ...rest] = parts;
  prev.push([collection, key, rest.join(':')]);
  return prev;
}

/** Create a collector for shorthand flags */
function collectPair(collection: string) {
  return (val: string, prev: string[][]) => {
    const idx = val.indexOf(':');
    if (idx === -1) {
      console.error(`Error: expected format key:value, got "${val}"`);
      process.exit(1);
    }
    prev.push([collection, val.slice(0, idx), val.slice(idx + 1)]);
    return prev;
  };
}

/** Build structured metadata object from collected tuples */
function buildMetadata(tuples: string[][]): Record<string, [string, string][]> | undefined {
  if (tuples.length === 0) return undefined;
  const m: Record<string, [string, string][]> = {};
  for (const [collection, key, value] of tuples) {
    if (!m[collection]) m[collection] = [];
    m[collection].push([key, value]);
  }
  return m;
}

const supersede = new Command('supersede')
  .description('Create a supersession document (key rotation or metadata update)')
  .requiredOption('--old <file>', 'Old identity file')
  .requiredOption('--old-txid <txid>', 'Old identity inscription TXID')
  .requiredOption(
    '--reason <reason>',
    'Reason: key-rotation, algorithm-upgrade, key-compromised, metadata-update',
  )
  .requiredOption('--name <name>', 'Agent name for the new identity')
  .option('--old-private-key <file>', 'Old private key file (overrides key lookup)')
  .option('--new-private-key <file>', 'New private key file (if reusing an existing key)')
  .option('--private-key <file>', 'Private key file for old key (alias for --old-private-key)')
  .option('--new-key-type <type>', 'Key type for new identity', 'ed25519')
  .option('--net <caip2>', 'CAIP-2 network identifier', BITCOIN_MAINNET)
  .option('--meta <collection:key:value>', 'Add metadata tuple', collectMeta, [])
  .option('--link <platform:handle>', 'Add link', collectPair('links'), [])
  .option('--key-ref <type:fingerprint>', 'Add key reference', collectPair('keys'), [])
  .option('--wallet <type:address>', 'Add wallet', collectPair('wallets'), [])
  .option('--vnb <n>', 'Version number before', parseInt)
  .option('--vna <n>', 'Version number after', parseInt)
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts: Record<string, string | undefined>) => {
    const oldDoc = JSON.parse(await readFile(opts.old!, 'utf8'));
    const oldK = (Array.isArray(oldDoc.k) ? oldDoc.k : [oldDoc.k])[0];
    const oldPub = fromBase64url(oldK.p);
    const oldFp = computeFingerprint(oldPub, oldK.t);
    const net = opts.net ?? BITCOIN_MAINNET;

    // Generate or load new keypair
    const newKeyType = opts.newKeyType ?? 'ed25519';
    let newPrivateKey: Buffer;
    let newPublicKey: Buffer;

    if (opts.newPrivateKey) {
      const newKeyData = await loadPrivateKeyFromFile(opts.newPrivateKey, newKeyType);
      newPrivateKey = newKeyData.privateKey;
      newPublicKey = newKeyData.publicKey;
    } else if (opts.reason === 'metadata-update') {
      // Same key for metadata updates
      const oldKeyData =
        (opts.oldPrivateKey ?? opts.privateKey)
          ? await loadPrivateKeyFromFile((opts.oldPrivateKey ?? opts.privateKey)!, oldK.t)
          : await loadPrivateKeyByFile(opts.old!);
      newPrivateKey = oldKeyData.privateKey;
      newPublicKey = oldKeyData.publicKey;
    } else {
      // Generate new keypair
      const kp = await generateKeypair(newKeyType);
      newPrivateKey = kp.privateKey;
      newPublicKey = kp.publicKey;
      console.error(`New key generated. Fingerprint: ${kp.fingerprint}`);
      console.error(`Private key saved to: ${kp.keyFile}`);
    }

    // Validate name
    const name = opts.name!;
    if (!/^[\x20-\x7E]{1,64}$/.test(name)) {
      console.error('Error: Name must be 1-64 ASCII characters');
      process.exit(1);
    }

    // Collect metadata
    const allTuples: string[][] = [
      ...((opts.meta as unknown as string[][]) || []),
      ...((opts.link as unknown as string[][]) || []),
      ...((opts.keyRef as unknown as string[][]) || []),
      ...((opts.wallet as unknown as string[][]) || []),
    ];
    const m = buildMetadata(allTuples);

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'super',
      target: { f: oldFp, ref: { net, id: opts.oldTxid as string } },
      n: name,
      k: [{ t: newKeyType, p: toBase64url(newPublicKey) }],
      reason: opts.reason,
      ts: Math.floor(Date.now() / 1000),
    };
    if (m) doc.m = m;
    if (opts.vnb) doc.vnb = opts.vnb;
    if (opts.vna) doc.vna = opts.vna;
    validateTimestamp(doc.ts as number, 'Supersession');

    // Validate before signing
    SupersessionUnsignedSchema.parse(doc);

    const oldPrivKeyFile = opts.oldPrivateKey ?? opts.privateKey;
    const oldKey = oldPrivKeyFile
      ? await loadPrivateKeyFromFile(oldPrivKeyFile, oldK.t)
      : await loadPrivateKeyByFile(opts.old!);

    const format = opts.encoding ?? 'json';
    const oldSig = sign(doc, oldKey.privateKey, format);
    const newSig = sign(doc, newPrivateKey, format);
    const newFp = computeFingerprint(newPublicKey, newKeyType);

    doc.s = [
      { f: oldFp, sig: format === 'cbor' ? oldSig : toBase64url(oldSig) },
      { f: newFp, sig: format === 'cbor' ? newSig : toBase64url(newSig) },
    ];

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Supersession written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default supersede;
