import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { fromBase64url, toBase64url, encodeDocument } from '../lib/encoding.js';
import { sign, verify as verifySig } from '../lib/signing.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { loadPrivateKeyByFile, loadPrivateKeyFromFile } from '../lib/keys.js';
import { ReceiptUnsignedSchema, BITCOIN_MAINNET } from '../schemas/index.js';
import { resolveIdentity } from './verify.js';

const receipt = new Command('receipt').description('Receipt management');

receipt
  .command('create')
  .description('Create a receipt document (initiator side)')
  .requiredOption('--from <file>', 'Your identity file')
  .requiredOption('--with <fingerprint>', 'Other party fingerprint')
  .requiredOption('--from-txid <txid>', 'Your identity inscription TXID')
  .requiredOption('--with-txid <txid>', 'Other party identity inscription TXID')
  .option('--private-key <file>', 'Private key file (overrides key lookup from identity)')
  .option('--net <caip2>', 'CAIP-2 network identifier', BITCOIN_MAINNET)
  .requiredOption('--description <text>', 'Exchange description')
  .requiredOption('--type <type>', 'Exchange type: service, exchange, agreement')
  .option('--value <sats>', 'Value in sats', parseInt)
  .option('--outcome <outcome>', 'Outcome', 'completed')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts: Record<string, string | number | undefined>) => {
    const fromDoc = JSON.parse(await readFile(opts.from as string, 'utf8'));
    const fromK = (Array.isArray(fromDoc.k) ? fromDoc.k : [fromDoc.k])[0];
    const fromPub = fromBase64url(fromK.p);
    const fromFp = computeFingerprint(fromPub, fromK.t);
    const net = (opts.net as string) ?? BITCOIN_MAINNET;

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'rcpt',
      p: [
        { f: fromFp, ref: { net, id: opts.fromTxid as string }, role: 'initiator' },
        { f: opts.with as string, ref: { net, id: opts.withTxid as string }, role: 'counterparty' },
      ],
      ex: {
        type: opts.type,
        sum: opts.description,
        ...(opts.value && { val: opts.value }),
      },
      out: opts.outcome ?? 'completed',
      ts: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.ts as number, 'Receipt');

    // Validate before signing
    ReceiptUnsignedSchema.parse(doc);

    const key = opts.privateKey
      ? await loadPrivateKeyFromFile(opts.privateKey as string, fromK.t)
      : await loadPrivateKeyByFile(opts.from as string);
    const format = (opts.encoding as string) ?? 'json';
    const sig = sign(doc, key.privateKey, format);

    doc.s = [
      { f: fromFp, sig: format === 'cbor' ? sig : toBase64url(sig) },
      { f: opts.with as string, sig: '' },
    ];

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output as string, output);
      console.error(`Receipt (partial) written to: ${opts.output}`);
      console.error('Send to counterparty for co-signing.');
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

receipt
  .command('countersign')
  .description('Verify first signature and add counterparty signature to a receipt')
  .requiredOption('--receipt <file>', 'Partial receipt file (with first signature)')
  .requiredOption('--identity <file>', 'Your identity file')
  .option('--private-key <file>', 'Private key file (overrides key lookup from identity)')
  .option('--rpc-url <url>', 'Bitcoin RPC URL', 'http://localhost:8332')
  .option('--rpc-user <user>', 'RPC username', 'bitcoin')
  .option('--rpc-pass <pass>', 'RPC password', '')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file')
  .action(async (opts: Record<string, string | undefined>) => {
    const format = opts.encoding ?? 'json';
    const doc = JSON.parse(await readFile(opts.receipt!, 'utf8'));

    // Validate structure
    if (doc.t !== 'rcpt' || !Array.isArray(doc.p) || !Array.isArray(doc.s)) {
      console.error('Error: not a valid receipt document');
      process.exit(1);
    }

    const parties = doc.p as Array<{ f: string; ref: { net: string; id: string }; role: string }>;
    const sigs = doc.s as Array<{ f: string; sig: string }>;

    // Load our identity to find which party we are
    const myDoc = JSON.parse(await readFile(opts.identity!, 'utf8'));
    const myK = (Array.isArray(myDoc.k) ? myDoc.k : [myDoc.k])[0];
    const myPub = fromBase64url(myK.p);
    const myFp = computeFingerprint(myPub, myK.t);

    const myIndex = parties.findIndex((p) => p.f === myFp);
    if (myIndex === -1) {
      console.error(`Error: your fingerprint (${myFp}) not found in receipt parties`);
      process.exit(1);
    }

    const rpcOpts = {
      rpcUrl: opts.rpcUrl ?? 'http://localhost:8332',
      rpcUser: opts.rpcUser ?? 'bitcoin',
      rpcPass: opts.rpcPass ?? '',
    };

    // Verify ALL other parties' signatures before countersigning
    const { s: _sigs, ...unsigned } = doc;
    for (let i = 0; i < parties.length; i++) {
      if (i === myIndex) continue;
      if (!sigs[i] || !sigs[i].sig) {
        console.error(`Error: party ${i} (${parties[i].role}) has not signed yet`);
        process.exit(1);
      }

      // Resolve identity via RPC — no local file fallback
      let resolved;
      try {
        resolved = await resolveIdentity(parties[i].ref, rpcOpts);
      } catch (e) {
        console.error(
          `Error: could not resolve party ${i}'s identity (${parties[i].f}): ${(e as Error).message}`,
        );
        console.error('Refusing to countersign without verified first signature.');
        process.exit(1);
      }

      // Verify fingerprint match
      if (resolved.fingerprint !== parties[i].f) {
        console.error(
          `Error: party ${i} fingerprint mismatch — expected ${parties[i].f}, resolved ${resolved.fingerprint}`,
        );
        process.exit(1);
      }

      // Verify signature
      const otherSigBytes = fromBase64url(sigs[i].sig as string);
      const valid = verifySig(
        unsigned as Record<string, unknown>,
        resolved.pubBytes,
        otherSigBytes,
        format,
        resolved.keyType,
      );
      if (!valid) {
        console.error(
          `Error: party ${i} (${parties[i].role}) signature is INVALID — refusing to countersign`,
        );
        process.exit(1);
      }
      console.error(`Party ${i} (${parties[i].role}) signature: ✓ VALID`);
    }

    // Sign
    const key = opts.privateKey
      ? await loadPrivateKeyFromFile(opts.privateKey, myK.t)
      : await loadPrivateKeyByFile(opts.identity!);
    const sig = sign(unsigned as Record<string, unknown>, key.privateKey, format);
    sigs[myIndex] = {
      f: myFp,
      sig: format === 'cbor' ? (sig as unknown as string) : toBase64url(sig),
    };
    doc.s = sigs;

    const output = encodeDocument(doc, format);
    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Receipt (countersigned) written to: ${opts.output}`);
    } else {
      console.log(format === 'cbor' ? output.toString('hex') : output.toString('utf8'));
    }
  });

export default receipt;
