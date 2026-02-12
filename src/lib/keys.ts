import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { toBase64url, fromBase64url } from './encoding.js';
import { computeFingerprint } from './fingerprint.js';

const KEYS_DIR = join(homedir(), '.atp', 'keys');

interface KeyFileData {
  type: string;
  fingerprint: string;
  publicKey: string;
  privateKey: string;
}

export interface KeyData {
  type: string;
  fingerprint: string;
  publicKey: Buffer;
  privateKey: Buffer;
}

export async function ensureKeysDir(): Promise<void> {
  await mkdir(KEYS_DIR, { recursive: true, mode: 0o700 });
}

export function generateEd25519(): { privateKey: Buffer; publicKey: Buffer } {
  const privBytes = randomBytes(32);
  const pubBytes = ed25519.getPublicKey(privBytes);
  return { privateKey: Buffer.from(privBytes), publicKey: Buffer.from(pubBytes) };
}

export async function generateKeypair(
  keyType = 'ed25519',
): Promise<{ privateKey: Buffer; publicKey: Buffer; fingerprint: string; keyFile: string }> {
  if (keyType !== 'ed25519') {
    throw new Error(`Key type "${keyType}" not yet supported. Use ed25519.`);
  }
  const { privateKey, publicKey } = generateEd25519();
  const fingerprint = computeFingerprint(publicKey, keyType);

  await ensureKeysDir();
  const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
  const content = JSON.stringify(
    {
      type: keyType,
      fingerprint,
      publicKey: toBase64url(publicKey),
      privateKey: toBase64url(privateKey),
    },
    null,
    2,
  );
  await writeFile(keyFile, content, { mode: 0o600 });

  return { privateKey, publicKey, fingerprint, keyFile };
}

export async function loadPrivateKey(fingerprint: string): Promise<KeyData> {
  const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
  const data: KeyFileData = JSON.parse(await readFile(keyFile, 'utf8'));
  return {
    type: data.type,
    fingerprint: data.fingerprint,
    publicKey: fromBase64url(data.publicKey),
    privateKey: fromBase64url(data.privateKey),
  };
}

export async function loadPrivateKeyByFile(filePath: string): Promise<KeyData> {
  const doc = JSON.parse(await readFile(filePath, 'utf8'));
  const k = doc.k;
  const keyObj = Array.isArray(k) ? k[0] : k;
  const pubBytes = fromBase64url(keyObj.p);
  const keyType: string = keyObj.t;
  const fp = computeFingerprint(pubBytes, keyType);
  return loadPrivateKey(fp);
}

/**
 * Load a private key from a raw key file. Auto-detects format:
 * - 32 bytes raw binary (Ed25519 seed)
 * - 64-char hex string
 * - base64url string
 * - JSON file with a `privateKey` field (base64url)
 */
export async function loadPrivateKeyFromFile(
  filePath: string,
  keyType = 'ed25519',
): Promise<KeyData> {
  const raw = await readFile(filePath);

  let privBytes: Buffer;

  // Try JSON first
  try {
    const json = JSON.parse(raw.toString('utf8'));
    if (json.privateKey) {
      privBytes = fromBase64url(json.privateKey);
    } else if (json.k) {
      // It's an identity file – delegate to existing loader
      const keyObj = Array.isArray(json.k) ? json.k[0] : json.k;
      const pubBytes = fromBase64url(keyObj.p);
      const fp = computeFingerprint(pubBytes, keyObj.t);
      return loadPrivateKey(fp);
    } else {
      throw new Error('JSON key file must have a "privateKey" field');
    }
  } catch (e) {
    if (e instanceof SyntaxError) {
      // Not JSON – try other formats
      const text = raw.toString('utf8').trim();

      if (raw.length === 32) {
        // Raw 32-byte binary
        privBytes = Buffer.from(raw);
      } else if (/^[0-9a-fA-F]{64}$/.test(text)) {
        // 64-char hex
        privBytes = Buffer.from(text, 'hex');
      } else {
        // Try base64url
        try {
          privBytes = fromBase64url(text);
          if (privBytes.length !== 32) {
            throw new Error(
              `Decoded key is ${privBytes.length} bytes, expected 32 for Ed25519`,
            );
          }
        } catch {
          throw new Error(
            'Cannot detect key format. Expected: 32 raw bytes, 64-char hex, base64url, or JSON with privateKey field',
          );
        }
      }
    } else {
      throw e;
    }
  }

  if (privBytes!.length !== 32) {
    throw new Error(`Private key is ${privBytes!.length} bytes, expected 32 for Ed25519`);
  }

  const pubBytes = Buffer.from(ed25519.getPublicKey(privBytes!));
  const fingerprint = computeFingerprint(pubBytes, keyType);

  return {
    type: keyType,
    fingerprint,
    publicKey: pubBytes,
    privateKey: privBytes!,
  };
}

/**
 * Load a public key from a file. Auto-detects format (same as private key formats but for 32-byte public keys).
 */
export async function loadPublicKeyFromFile(
  filePath: string,
  keyType = 'ed25519',
): Promise<{ publicKey: Buffer; fingerprint: string }> {
  const raw = await readFile(filePath);

  let pubBytes: Buffer;

  try {
    const json = JSON.parse(raw.toString('utf8'));
    if (json.publicKey) {
      pubBytes = fromBase64url(json.publicKey);
    } else if (json.k) {
      const keyObj = Array.isArray(json.k) ? json.k[0] : json.k;
      pubBytes = fromBase64url(keyObj.p);
    } else {
      throw new Error('JSON key file must have a "publicKey" field');
    }
  } catch (e) {
    if (e instanceof SyntaxError) {
      const text = raw.toString('utf8').trim();
      if (raw.length === 32) {
        pubBytes = Buffer.from(raw);
      } else if (/^[0-9a-fA-F]{64}$/.test(text)) {
        pubBytes = Buffer.from(text, 'hex');
      } else {
        try {
          pubBytes = fromBase64url(text);
          if (pubBytes.length !== 32) {
            throw new Error(`Decoded key is ${pubBytes.length} bytes, expected 32`);
          }
        } catch {
          throw new Error('Cannot detect public key format');
        }
      }
    } else {
      throw e;
    }
  }

  const fingerprint = computeFingerprint(pubBytes!, keyType);
  return { publicKey: pubBytes!, fingerprint };
}

/**
 * Save a keypair to ~/.atp/keys/
 */
export async function saveKeypair(
  privateKey: Buffer,
  publicKey: Buffer,
  keyType = 'ed25519',
): Promise<string> {
  const fingerprint = computeFingerprint(publicKey, keyType);
  await ensureKeysDir();
  const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
  const content = JSON.stringify(
    {
      type: keyType,
      fingerprint,
      publicKey: toBase64url(publicKey),
      privateKey: toBase64url(privateKey),
    },
    null,
    2,
  );
  await writeFile(keyFile, content, { mode: 0o600 });
  return keyFile;
}
