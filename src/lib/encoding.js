import { Encoder, decode as cborDecode } from 'cbor-x';

const cborEncoder = new Encoder({ mapsAsObjects: true, useRecords: false });

export function toBase64url(buf) {
  return Buffer.from(buf).toString('base64url');
}

export function fromBase64url(str) {
  return Buffer.from(str, 'base64url');
}

/** Deterministic JSON: sorted keys, compact, UTF-8 */
export function jsonCanonical(obj) {
  return Buffer.from(JSON.stringify(sortKeys(obj)), 'utf8');
}

function sortKeys(val) {
  if (val === null || typeof val !== 'object') return val;
  if (Array.isArray(val)) return val.map(sortKeys);
  const sorted = {};
  for (const k of Object.keys(val).sort()) {
    sorted[k] = sortKeys(val[k]);
  }
  return sorted;
}

/** Deterministic CBOR encoding */
export function cborEncode(obj) {
  return Buffer.from(cborEncoder.encode(obj));
}

export { cborDecode };

/** Encode document for signing (without `s` field) */
export function encodeForSigning(doc, format = 'json') {
  const { s, ...unsigned } = doc;
  return format === 'cbor' ? cborEncode(unsigned) : jsonCanonical(unsigned);
}

/** Encode complete document */
export function encodeDocument(doc, format = 'json') {
  if (format === 'cbor') return cborEncode(doc);
  return Buffer.from(JSON.stringify(sortKeys(doc), null, 2), 'utf8');
}
