import { ed25519 } from '@noble/curves/ed25519';
import { secp256k1 } from '@noble/curves/secp256k1';
import { encodeForSigning } from './encoding.js';
import { createHash } from 'node:crypto';

function detectKeyType(doc: Record<string, unknown>): string {
  const k = doc.k as { t?: string } | undefined;
  return k?.t ?? 'ed25519';
}

export function sign(
  doc: Record<string, unknown>,
  privateKey: Uint8Array,
  format = 'json',
  keyType?: string,
): Buffer {
  const type = keyType ?? detectKeyType(doc);
  const bytes = encodeForSigning(doc, format);

  if (type === 'secp256k1') {
    const hash = createHash('sha256').update(bytes).digest();
    const sig = secp256k1.sign(hash, privateKey);
    const normalised = sig.normalizeS();
    return Buffer.from(normalised.toCompactRawBytes());
  }

  const sig = ed25519.sign(bytes, privateKey);
  return Buffer.from(sig);
}

export function verify(
  doc: Record<string, unknown>,
  publicKey: Uint8Array,
  signature: Uint8Array,
  format = 'json',
  keyType?: string,
): boolean {
  const type = keyType ?? detectKeyType(doc);
  const bytes = encodeForSigning(doc, format);

  if (type === 'secp256k1') {
    const hash = createHash('sha256').update(bytes).digest();
    try {
      return secp256k1.verify(signature, hash, publicKey);
    } catch {
      return false;
    }
  }

  return ed25519.verify(signature, bytes, publicKey);
}
