import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { generateKeypair } from '../lib/keys.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { toBase64url, fromBase64url, encodeDocument, jsonCanonical, cborEncode } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { buildInscriptionEnvelope } from '../lib/inscription.js';
import { BitcoinRPC } from '../lib/rpc.js';

const identity = new Command('identity').description('Identity management');

identity
  .command('create')
  .description('Generate Ed25519 keypair and build identity document')
  .requiredOption('--name <name>', 'Agent name')
  .option('--key <type>', 'Key type', 'ed25519')
  .option('--handle-twitter <handle>', 'Twitter handle')
  .option('--handle-moltbook <handle>', 'Moltbook handle')
  .option('--handle-github <handle>', 'GitHub handle')
  .option('--handle-nostr <handle>', 'Nostr handle')
  .option('--wallet <address>', 'Bitcoin payment address')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file (default: stdout)')
  .action(async (opts) => {
    const { privateKey, publicKey, fingerprint, keyFile } = await generateKeypair(opts.key);
    console.error(`Key generated. Fingerprint: ${fingerprint}`);
    console.error(`Private key saved to: ${keyFile}`);

    const doc = {
      v: '1.0',
      t: 'id',
      n: opts.name,
      k: {
        t: opts.key,
        p: toBase64url(publicKey),
      },
      c: Math.floor(Date.now() / 1000),
    };

    // Optional wallet
    if (opts.wallet) doc.w = opts.wallet;

    // Optional metadata (handles)
    const meta = {};
    if (opts.handleTwitter) meta.twitter = opts.handleTwitter;
    if (opts.handleMoltbook) meta.moltbook = opts.handleMoltbook;
    if (opts.handleGithub) meta.github = opts.handleGithub;
    if (opts.handleNostr) meta.nostr = opts.handleNostr;
    if (Object.keys(meta).length > 0) doc.m = meta;

    // Sign
    const format = opts.encoding;
    const sig = sign(doc, privateKey, format);
    doc.s = format === 'cbor' ? sig : toBase64url(sig);

    const output = encodeDocument(doc, format);

    if (opts.output) {
      await writeFile(opts.output, output);
      console.error(`Identity written to: ${opts.output}`);
    } else {
      if (format === 'cbor') {
        process.stdout.write(output);
      } else {
        console.log(output.toString('utf8'));
      }
    }
  });

identity
  .command('show')
  .description('Display identity from file')
  .argument('<file>', 'Identity file path')
  .action(async (file) => {
    const raw = await readFile(file, 'utf8');
    const doc = JSON.parse(raw);

    console.log(`Agent Trust Protocol — Identity Document`);
    console.log(`─────────────────────────────────────────`);
    console.log(`Name:        ${doc.n}`);
    console.log(`Version:     ${doc.v}`);
    console.log(`Type:        ${doc.t}`);

    const k = Array.isArray(doc.k) ? doc.k[0] : doc.k;
    const pubBytes = fromBase64url(k.p);
    const fp = computeFingerprint(pubBytes, k.t);
    console.log(`Key Type:    ${k.t}`);
    console.log(`Fingerprint: ${fp}`);
    console.log(`Public Key:  ${k.p}`);

    if (doc.w) console.log(`Wallet:      ${doc.w}`);
    if (doc.m) {
      console.log(`Handles:`);
      for (const [platform, handle] of Object.entries(doc.m)) {
        console.log(`  ${platform}: ${handle}`);
      }
    }
    console.log(`Created:     ${new Date(doc.c * 1000).toISOString()}`);
    console.log(`Signature:   ${typeof doc.s === 'string' ? doc.s.slice(0, 32) + '...' : '(binary)'}`);
  });

identity
  .command('inscribe')
  .description('Create inscription transaction for identity')
  .requiredOption('--file <path>', 'Identity document file')
  .option('--fee-rate <sat/vB>', 'Fee rate in sat/vB')
  .option('--broadcast', 'Broadcast the transaction')
  .option('--rpc-url <url>', 'Bitcoin RPC URL', 'http://localhost:8332')
  .option('--rpc-user <user>', 'RPC username', 'bitcoin')
  .option('--rpc-pass <pass>', 'RPC password', '')
  .action(async (opts) => {
    const raw = await readFile(opts.file);
    let contentType, data;

    // Detect format
    try {
      JSON.parse(raw.toString('utf8'));
      contentType = 'application/json';
      data = raw;
    } catch {
      contentType = 'application/cbor';
      data = raw;
    }

    const envelope = buildInscriptionEnvelope(data, contentType);
    console.log(`Inscription envelope (${data.length} bytes payload, ${contentType}):`);
    console.log(`Envelope hex: ${envelope.toString('hex')}`);
    console.log(`\nTo inscribe, use the 'ord' tool or construct commit/reveal transactions.`);
    console.log(`Full inscription creation requires a Bitcoin wallet with UTXOs.`);

    if (opts.broadcast) {
      console.error('Direct broadcast requires commit/reveal tx construction.');
      console.error('Use `ord wallet inscribe` for a complete workflow.');
    }
  });

export default identity;
