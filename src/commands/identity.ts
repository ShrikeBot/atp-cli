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

/** Create a collector for shorthand flags like --link, --key-ref, --wallet */
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

const identity = new Command('identity').description('Identity management');

identity
  .command('create')
  .description('Generate Ed25519 keypair and build identity document')
  .requiredOption('--name <name>', 'Agent name')
  .option('--key <type>', 'Key type', 'ed25519')
  .option('--private-key <file>', 'Use existing private key file instead of generating one')
  .option('--public-key <file>', 'Use existing public key file')
  .option('--no-save', 'Do not save keypair to ~/.atp/keys/')
  .option('--meta <collection:key:value>', 'Add metadata tuple (repeatable, e.g. --meta links:twitter:@shrikey_)', collectMeta, [])
  .option('--link <platform:handle>', 'Add link (shorthand for --meta links:platform:handle)', collectPair('links'), [])
  .option('--key-ref <type:fingerprint>', 'Add key reference (shorthand for --meta keys:type:fp)', collectPair('keys'), [])
  .option('--wallet <type:address>', 'Add wallet (shorthand for --meta wallets:type:address)', collectPair('wallets'), [])
  .option('--vna <n>', 'Version number (ascending)', parseInt)
  .option('--encoding <format>', 'json or cbor', 'json')
  .option('--output <file>', 'Output file (default: stdout)')
  .action(async (opts: Record<string, string | boolean | number | undefined>) => {
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
      k: [{ t: keyType, p: toBase64url(publicKey) }],
      ts: Math.floor(Date.now() / 1000),
    };
    validateTimestamp(doc.ts as number, 'Identity');

    // Collect all metadata tuples from --meta, --link, --key-ref, --wallet
    const allTuples: string[][] = [
      ...((opts.meta as unknown as string[][]) || []),
      ...((opts.link as unknown as string[][]) || []),
      ...((opts.keyRef as unknown as string[][]) || []),
      ...((opts.wallet as unknown as string[][]) || []),
    ];
    const m = buildMetadata(allTuples);
    if (m) doc.m = m;

    // Validate before signing
    IdentityUnsignedSchema.parse(doc);

    if (opts.vna) doc.vna = opts.vna;

    const format = (opts.encoding as string) ?? 'json';
    const sig = sign(doc, privateKey, format);
    doc.s = { f: fingerprint, sig: format === 'cbor' ? sig : toBase64url(sig) };

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

    const keys = Array.isArray(doc.k) ? doc.k : [doc.k];
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      const pubBytes = fromBase64url(k.p);
      const fp = computeFingerprint(pubBytes, k.t);
      const prefix = keys.length > 1 ? `Key ${i}: ` : '';
      console.log(`${prefix}Key Type:    ${k.t}`);
      console.log(`${prefix}Fingerprint: ${fp}`);
      console.log(`${prefix}Public Key:  ${k.p}`);
    }

    if (doc.m) {
      console.log(`Metadata:`);
      for (const [collection, entries] of Object.entries(doc.m as Record<string, [string, string][]>)) {
        console.log(`  ${collection}:`);
        for (const [key, value] of entries) {
          console.log(`    ${key}: ${value}`);
        }
      }
    }
    console.log(`Created:     ${new Date(doc.ts * 1000).toISOString()}`);
    const sig = doc.s;
    if (sig && typeof sig === 'object' && 'f' in sig && 'sig' in sig) {
      console.log(`Signer:      ${sig.f}`);
      console.log(`Signature:   ${typeof sig.sig === 'string' ? sig.sig.slice(0, 32) + '...' : '(binary)'}`);
    } else {
      console.log(`Signature:   ${typeof sig === 'string' ? sig.slice(0, 32) + '...' : '(binary)'}`);
    }
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
