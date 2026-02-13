import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile, loadPrivateKeyFromFile } from '../lib/keys.js';
import { AttestationUnsignedSchema, BITCOIN_MAINNET } from '../schemas/index.js';

const attest = new Command('attest')
  .description('Attest (vouch for) another agent')
  .argument('<fingerprint>', 'Target agent fingerprint')
  .requiredOption('--from <file>', 'Your identity file')
  .option('--private-key <file>', 'Private key file (overrides key lookup from identity)')
  .requiredOption('--from-txid <txid>', 'Your identity inscription TXID')
  .requiredOption('--to-txid <txid>', 'Target identity inscription TXID')
  .option('--net <caip2>', 'CAIP-2 network identifier', BITCOIN_MAINNET)
  .option('--stake <sats>', 'Sats staked to protocol treasury (bc1q6z4rlakqvsfzmfp3304wfl364rugsjxcj6wleg)', parseInt)
  .option('--claim <type>', 'Claim type: identity, capability, reliability', 'identity')
  .option('--context <text>', 'Context/reason for attestation')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (fingerprint: string, opts: Record<string, string | number | undefined>) => {
    const fromDoc = JSON.parse(await readFile(opts.from as string, 'utf8'));
    const fromK = (Array.isArray(fromDoc.k) ? fromDoc.k : [fromDoc.k])[0];
    const fromPub = fromBase64url(fromK.p);
    const fromFp = computeFingerprint(fromPub, fromK.t);
    const net = (opts.net as string) ?? BITCOIN_MAINNET;

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'att',
      from: { f: fromFp, ref: { net, id: opts.fromTxid as string } },
      to: { f: fingerprint, ref: { net, id: opts.toTxid as string } },
      ts: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.ts as number, 'Attestation');

    if (opts.stake) doc.stake = opts.stake;
    if (opts.context) doc.ctx = opts.context;

    // Validate before signing
    AttestationUnsignedSchema.parse(doc);

    const key = opts.privateKey
      ? await loadPrivateKeyFromFile(opts.privateKey as string, fromK.t)
      : await loadPrivateKeyByFile(opts.from as string);
    const format = (opts.encoding as string) ?? 'json';
    const sig = sign(doc, key.privateKey, format);
    doc.s = { f: fromFp, sig: format === 'cbor' ? sig : toBase64url(sig) };

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output as string, output);
      console.error(`Attestation written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default attest;
