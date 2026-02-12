import { validateTimestamp } from '../lib/timestamp.js';
import { Command } from 'commander';
import { readFile, writeFile } from 'node:fs/promises';
import { generateKeypair, loadPrivateKeyFromFile, loadPublicKeyFromFile, saveKeypair } from '../lib/keys.js';
import { computeFingerprint } from '../lib/fingerprint.js';
import { toBase64url, fromBase64url, encodeDocument } from '../lib/encoding.js';
import { sign } from '../lib/signing.js';
import { buildInscriptionEnvelope } from '../lib/inscription.js';
import { IdentityUnsignedSchema } from '../schemas/index.js';
import { ed25519 } from '@noble/curves/ed25519';

const identity = new Command('identity').description('Identity management');

identity
  .command('create')
  .description('Generate Ed25519 keypair and build identity document')
  .requiredOption('--name <name>', 'Agent name')
  .option('--key <type>', 'Key type', 'ed25519')
  .option('--private-key <file>', 'Use existing private key file instead of generating one')
  .option('--public-key <file>', 'Use existing public key file')
  .option('--no-save', 'Do not save keypair to ~/.atp/keys/')
  .option('--handle-twitter <handle>', 'Twitter handle')
  .option('--handle-moltbook <handle>', 'Moltbook handle')
  .option('--handle-github <handle>', 'GitHub handle')
  .option('--handle-nostr <handle>', 'Nostr handle')
  .option('--wallet <address>', 'Bitcoin payment address')
  .option('--ssh-key <fingerprint>', 'SSH key fingerprint (added to external keys)')
  .option('--gpg-key <fingerprint>', 'GPG key fingerprint (added to external keys)')
  .option('--bitcoin-key <address>', 'Bitcoin address (added to external keys)')
  .option('--nostr-key <npub>', 'Nostr npub (added to external keys)')
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file (default: stdout)')
  .action(async (opts: Record<string, string | boolean | undefined>) => {
    const keyType = (opts.key as string) ?? 'ed25519';
    let privateKey: Buffer;
    let publicKey: Buffer;
    let fingerprint: string;

    if (opts.publicKey && !opts.privateKey) {
      console.error('Error: --public-key requires --private-key (need private key to sign)');
      process.exit(1);
    }

    if (opts.privateKey) {
      // Load from provided private key file
      const keyData = await loadPrivateKeyFromFile(opts.privateKey as string, keyType);
      privateKey = keyData.privateKey;
      publicKey = keyData.publicKey;
      fingerprint = keyData.fingerprint;

      // Validate against public key if provided
      if (opts.publicKey) {
        const pubData = await loadPublicKeyFromFile(opts.publicKey as string, keyType);
        if (!pubData.publicKey.equals(publicKey)) {
          console.error('Error: --public-key does not match the public key derived from --private-key');
          process.exit(1);
        }
      }

      if (opts.save !== false) {
        const keyFile = await saveKeypair(privateKey, publicKey, keyType);
        console.error(`Key saved to: ${keyFile}`);
      }
      console.error(`Using provided key. Fingerprint: ${fingerprint}`);
    } else {
      // Generate new keypair
      const kp = await generateKeypair(keyType);
      privateKey = kp.privateKey;
      publicKey = kp.publicKey;
      fingerprint = kp.fingerprint;
      console.error(`Key generated. Fingerprint: ${fingerprint}`);
      console.error(`Private key saved to: ${kp.keyFile}`);
    }

    // Validate name: ASCII only, 1-64 chars
    const name = opts.name as string;
    if (!/^[\x20-\x7E]{1,64}$/.test(name)) {
      console.error('Error: Name must be 1-64 ASCII characters (no Unicode/homoglyphs)');
      process.exit(1);
    }

    const doc: Record<string, unknown> = {
      v: '1.0',
      t: 'id',
      n: name,
      k: {
        t: keyType,
        p: toBase64url(publicKey),
      },
      c: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.c as number, 'Identity');

    if (opts.wallet) doc.w = opts.wallet;

    const meta: Record<string, string> = {};
    if (opts.handleTwitter) meta.twitter = opts.handleTwitter as string;
    if (opts.handleMoltbook) meta.moltbook = opts.handleMoltbook as string;
    if (opts.handleGithub) meta.github = opts.handleGithub as string;
    if (opts.handleNostr) meta.nostr = opts.handleNostr as string;
    if (Object.keys(meta).length > 0) doc.m = meta;

    const externalKeys: Array<{ t: string; f: string }> = [];
    if (opts.sshKey) externalKeys.push({ t: 'ssh-ed25519', f: opts.sshKey as string });
    if (opts.gpgKey) externalKeys.push({ t: 'gpg', f: opts.gpgKey as string });
    if (opts.bitcoinKey) externalKeys.push({ t: 'bitcoin', f: opts.bitcoinKey as string });
    if (opts.nostrKey) externalKeys.push({ t: 'nostr', f: opts.nostrKey as string });
    if (externalKeys.length > 0) doc.keys = externalKeys;

    // Validate before signing
    IdentityUnsignedSchema.parse(doc);

    const format = (opts.encoding as string) ?? 'json';
    const sig = sign(doc, privateKey, format);
    doc.s = format === 'cbor' ? sig : toBase64url(sig);

    const output = encodeDocument(doc, format);

    if (opts.output) {
      await writeFile(opts.output as string, output);
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
  .action(async (file: string) => {
    const raw = await readFile(file, 'utf8');
    const doc = JSON.parse(raw);

    console.log(`Agent Trust Protocol — Identity Document`);
    console.log(`─────────────────────────────────────────`);
    console.log(`Name:        ${doc.n}`);
    console.log(`Version:     ${doc.v}`);
    console.log(`Type:        ${doc.t}`);

    const k = doc.k;
    const pubBytes = fromBase64url(k.p);
    const fp = computeFingerprint(pubBytes, k.t);
    console.log(`Key Type:    ${k.t}`);
    console.log(`Fingerprint: ${fp}`);
    console.log(`Public Key:  ${k.p}`);

    if (doc.w) console.log(`Wallet:      ${doc.w}`);
    if (doc.m) {
      console.log(`Handles:`);
      for (const [platform, handle] of Object.entries(doc.m as Record<string, string>)) {
        console.log(`  ${platform}: ${handle}`);
      }
    }
    console.log(`Created:     ${new Date(doc.c * 1000).toISOString()}`);
    console.log(
      `Signature:   ${typeof doc.s === 'string' ? doc.s.slice(0, 32) + '...' : '(binary)'}`,
    );
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
  .action(async (opts: Record<string, string | boolean | undefined>) => {
    const raw = await readFile(opts.file as string);
    let contentType: string, data: Buffer;

    try {
      JSON.parse(raw.toString('utf8'));
      contentType = 'application/atp.v1+json';
      data = raw;
    } catch {
      contentType = 'application/atp.v1+cbor';
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
