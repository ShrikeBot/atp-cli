import { createHash } from 'node:crypto';
import { toBase64url } from './encoding.js';

const PQ_TYPES = new Set(['dilithium', 'falcon']);

export function computeFingerprint(publicKeyBytes: Uint8Array, keyType: string): string {
  if (PQ_TYPES.has(keyType)) {
    const hash = createHash('sha384').update(publicKeyBytes).digest();
    return toBase64url(hash);
  }
  const hash = createHash('sha256').update(publicKeyBytes).digest();
  return toBase64url(hash);
}
