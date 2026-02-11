import { Encoder, decode as cborDecode } from 'cbor-x';

const cborEncoder = new Encoder({ mapsAsObjects: true, useRecords: false });

export function toBase64url(buf: Uint8Array | Buffer): string {
  return Buffer.from(buf).toString('base64url');
}

export function fromBase64url(str: string): Buffer {
  return Buffer.from(str, 'base64url');
}

/** Deterministic JSON: sorted keys, compact, UTF-8 */
export function jsonCanonical(obj: unknown): Buffer {
  return Buffer.from(JSON.stringify(sortKeys(obj)), 'utf8');
}

function sortKeys(val: unknown): unknown {
  if (val === null || typeof val !== 'object') return val;
  if (Array.isArray(val)) return val.map(sortKeys);
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(val as Record<string, unknown>).sort()) {
    sorted[k] = sortKeys((val as Record<string, unknown>)[k]);
  }
  return sorted;
}

/** Deterministic CBOR encoding */
export function cborEncode(obj: unknown): Buffer {
  return Buffer.from(cborEncoder.encode(obj));
}

export { cborDecode };

/** Domain separator to prevent cross-protocol signature reuse */
const DOMAIN_SEPARATOR = Buffer.from('ATP-v1.0:', 'ascii');

/** Encode document for signing (without `s` field, with domain separator) */
export function encodeForSigning(doc: Record<string, unknown>, format = 'json'): Buffer {
  const { s: _sig, ...unsigned } = doc;
  const encoded = format === 'cbor' ? cborEncode(unsigned) : jsonCanonical(unsigned);
  return Buffer.concat([DOMAIN_SEPARATOR, encoded]);
}

/** Encode complete document */
export function encodeDocument(doc: Record<string, unknown>, format = 'json'): Buffer {
  if (format === 'cbor') return cborEncode(doc);
  return Buffer.from(JSON.stringify(sortKeys(doc), null, 2), 'utf8');
}
