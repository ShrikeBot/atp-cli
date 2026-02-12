import { Command } from 'commander';
import { readdir, readFile, unlink, access } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { loadPrivateKeyFromFile, saveKeypair, ensureKeysDir } from '../lib/keys.js';
import { toBase64url, fromBase64url } from '../lib/encoding.js';

const KEYS_DIR = join(homedir(), '.atp', 'keys');

const key = new Command('key').description('Key management');

key
  .command('import')
  .description('Import an existing private key into the local key store')
  .requiredOption('--private-key <file>', 'Path to private key file')
  .option('--type <keytype>', 'Key type', 'ed25519')
  .option('--force', 'Overwrite if key already exists')
  .action(async (opts) => {
    const keyData = await loadPrivateKeyFromFile(opts.privateKey, opts.type);
    const keyFile = join(KEYS_DIR, `${keyData.fingerprint}.json`);

    if (!opts.force) {
      try {
        await access(keyFile);
        console.error(`Error: Key ${keyData.fingerprint} already exists in store. Use --force to overwrite.`);
        process.exit(1);
      } catch {
        // doesn't exist, good
      }
    }

    await saveKeypair(keyData.privateKey, keyData.publicKey, keyData.type);
    console.log(keyData.fingerprint);
  });

key
  .command('list')
  .description('List all keys in the local store')
  .action(async () => {
    await ensureKeysDir();
    const files = (await readdir(KEYS_DIR)).filter((f) => f.endsWith('.json'));
    if (files.length === 0) {
      console.log('No keys found in store.');
      return;
    }
    for (const file of files) {
      const filePath = join(KEYS_DIR, file);
      try {
        const data = JSON.parse(await readFile(filePath, 'utf8'));
        console.log(`${data.fingerprint}\t${data.type}\t${filePath}`);
      } catch {
        console.error(`Warning: could not read ${filePath}`);
      }
    }
  });

key
  .command('export <fingerprint>')
  .description('Export a key from the store')
  .option('--format <format>', 'Output format: json, hex, base64url', 'json')
  .option('--public-only', 'Only output the public key')
  .action(async (fingerprint: string, opts) => {
    const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
    const data = JSON.parse(await readFile(keyFile, 'utf8'));

    const keyBytes = opts.publicOnly
      ? fromBase64url(data.publicKey)
      : fromBase64url(data.privateKey);

    switch (opts.format) {
      case 'json':
        if (opts.publicOnly) {
          console.log(JSON.stringify({ type: data.type, fingerprint: data.fingerprint, publicKey: data.publicKey }, null, 2));
        } else {
          console.log(JSON.stringify(data, null, 2));
        }
        break;
      case 'hex':
        console.log(keyBytes.toString('hex'));
        break;
      case 'base64url':
        console.log(toBase64url(keyBytes));
        break;
      default:
        console.error(`Unknown format: ${opts.format}`);
        process.exit(1);
    }
  });

key
  .command('delete <fingerprint>')
  .description('Remove a key from the store')
  .option('--force', 'Required to confirm deletion')
  .action(async (fingerprint: string, opts) => {
    if (!opts.force) {
      console.error('Error: Deleting a key is irreversible. Use --force to confirm.');
      process.exit(1);
    }
    const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
    await unlink(keyFile);
    console.log(`Deleted key ${fingerprint}`);
  });

export default key;
