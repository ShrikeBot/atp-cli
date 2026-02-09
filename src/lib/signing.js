import { ed25519 } from '@noble/curves/ed25519';
import { encodeForSigning } from './encoding.js';

export function sign(doc, privateKey, format = 'json') {
  const bytes = encodeForSigning(doc, format);
  const sig = ed25519.sign(bytes, privateKey);
  return Buffer.from(sig);
}

export function verify(doc, publicKey, signature, format = 'json') {
  const bytes = encodeForSigning(doc, format);
  return ed25519.verify(signature, bytes, publicKey);
}
