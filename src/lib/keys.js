import { ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { toBase64url, fromBase64url } from './encoding.js';
import { computeFingerprint } from './fingerprint.js';

const KEYS_DIR = join(homedir(), '.atp', 'keys');

export async function ensureKeysDir() {
  await mkdir(KEYS_DIR, { recursive: true });
}

export function generateEd25519() {
  const privBytes = randomBytes(32);
  const pubBytes = ed25519.getPublicKey(privBytes);
  return { privateKey: Buffer.from(privBytes), publicKey: Buffer.from(pubBytes) };
}

export async function generateKeypair(keyType = 'ed25519') {
  if (keyType !== 'ed25519') {
    throw new Error(`Key type "${keyType}" not yet supported. Use ed25519.`);
  }
  const { privateKey, publicKey } = generateEd25519();
  const fingerprint = computeFingerprint(publicKey, keyType);

  await ensureKeysDir();
  const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
  await writeFile(keyFile, JSON.stringify({
    type: keyType,
    fingerprint,
    publicKey: toBase64url(publicKey),
    privateKey: toBase64url(privateKey),
  }, null, 2));

  return { privateKey, publicKey, fingerprint, keyFile };
}

export async function loadPrivateKey(fingerprint) {
  const keyFile = join(KEYS_DIR, `${fingerprint}.json`);
  const data = JSON.parse(await readFile(keyFile, 'utf8'));
  return {
    type: data.type,
    fingerprint: data.fingerprint,
    publicKey: fromBase64url(data.publicKey),
    privateKey: fromBase64url(data.privateKey),
  };
}

export async function loadPrivateKeyByFile(filePath) {
  // Load identity doc, extract fingerprint, then load key
  const doc = JSON.parse(await readFile(filePath, 'utf8'));
  const k = doc.k;
  const pubBytes = fromBase64url(Array.isArray(k) ? k[0].p : k.p);
  const keyType = Array.isArray(k) ? k[0].t : k.t;
  const fp = computeFingerprint(pubBytes, keyType);
  return loadPrivateKey(fp);
}
