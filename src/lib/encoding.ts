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

/** Build domain separator from document type: ATP-v1.0:{t}: */
function domainSeparator(docType: string): Buffer {
  const typeMap: Record<string, string> = {
    id: 'id',
    att: 'att',
    super: 'super',
    revoke: 'revoke',
    hb: 'hb',
    rcpt: 'rcpt',
    'att-revoke': 'att-revoke',
  };
  const sep = typeMap[docType];
  if (!sep) throw new Error(`Unknown document type for domain separator: ${docType}`);
  return Buffer.from(`ATP-v1.0:${sep}:`, 'ascii');
}

/** Known binary fields that must be byte strings in CBOR */
const BINARY_FIELDS = new Set(['p', 's', 'f']);

/** Convert known binary fields from base64url strings to Buffers for CBOR encoding */
export function binaryFieldsToBuffers(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Uint8Array || Buffer.isBuffer(obj)) return obj;
  if (Array.isArray(obj)) return obj.map(binaryFieldsToBuffers);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (BINARY_FIELDS.has(k) && typeof v === 'string') {
      result[k] = fromBase64url(v);
    } else if (BINARY_FIELDS.has(k) && Array.isArray(v)) {
      result[k] = v.map((item) =>
        typeof item === 'string' ? fromBase64url(item) : item instanceof Uint8Array || Buffer.isBuffer(item) ? item : item,
      );
    } else {
      result[k] = binaryFieldsToBuffers(v);
    }
  }
  return result;
}

/** Convert byte string fields back to base64url strings after CBOR decoding */
export function buffersToBase64url(obj: unknown): unknown {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Uint8Array || Buffer.isBuffer(obj)) return toBase64url(obj);
  if (Array.isArray(obj)) return obj.map(buffersToBase64url);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (BINARY_FIELDS.has(k) && (v instanceof Uint8Array || Buffer.isBuffer(v))) {
      result[k] = toBase64url(v);
    } else if (BINARY_FIELDS.has(k) && Array.isArray(v)) {
      result[k] = v.map((item) =>
        item instanceof Uint8Array || Buffer.isBuffer(item) ? toBase64url(item) : item,
      );
    } else {
      result[k] = buffersToBase64url(v);
    }
  }
  return result;
}

/** Encode document for signing (without `s` field, with domain separator) */
export function encodeForSigning(doc: Record<string, unknown>, format = 'json'): Buffer {
  const { s: _sig, ...unsigned } = doc;
  const separator = domainSeparator(doc.t as string);
  if (format === 'cbor') {
    const withBinaries = binaryFieldsToBuffers(unsigned);
    return Buffer.concat([separator, cborEncode(withBinaries)]);
  }
  return Buffer.concat([separator, jsonCanonical(unsigned)]);
}

/** Encode complete document */
export function encodeDocument(doc: Record<string, unknown>, format = 'json'): Buffer {
  if (format === 'cbor') return cborEncode(binaryFieldsToBuffers(doc));
  return Buffer.from(JSON.stringify(sortKeys(doc), null, 2), 'utf8');
}
