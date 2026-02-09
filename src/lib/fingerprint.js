import { createHash } from 'node:crypto';
import { toBase64url } from './encoding.js';

const PQ_TYPES = new Set(['dilithium', 'falcon']);

export function computeFingerprint(publicKeyBytes, keyType) {
  if (PQ_TYPES.has(keyType)) {
    const hash = createHash('sha384').update(publicKeyBytes).digest();
    return toBase64url(hash); // 64 chars
  }
  const hash = createHash('sha256').update(publicKeyBytes).digest();
  return toBase64url(hash); // 43 chars
}
