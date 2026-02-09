import { ed25519 } from '@noble/curves/ed25519';
import { encodeForSigning } from './encoding.js';

export function sign(doc: Record<string, unknown>, privateKey: Uint8Array, format = 'json'): Buffer {
  const bytes = encodeForSigning(doc, format);
  const sig = ed25519.sign(bytes, privateKey);
  return Buffer.from(sig);
}

export function verify(doc: Record<string, unknown>, publicKey: Uint8Array, signature: Uint8Array, format = 'json'): boolean {
  const bytes = encodeForSigning(doc, format);
  return ed25519.verify(signature, bytes, publicKey);
}
