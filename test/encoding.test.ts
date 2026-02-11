import { describe, it, expect } from 'vitest';
import { jsonCanonical, cborEncode, cborDecode, encodeForSigning } from '../src/lib/encoding.js';

describe('JSON Canonical Encoding', () => {
  it('sorts keys deterministically', () => {
    const result = jsonCanonical({ z: 1, a: 2, m: 3 });
    expect(result.toString('utf8')).toBe('{"a":2,"m":3,"z":1}');
  });

  it('sorts nested keys', () => {
    const result = jsonCanonical({ b: { z: 1, a: 2 }, a: 1 });
    expect(result.toString('utf8')).toBe('{"a":1,"b":{"a":2,"z":1}}');
  });

  it('preserves arrays in order', () => {
    const result = jsonCanonical({ arr: [3, 1, 2] });
    expect(result.toString('utf8')).toBe('{"arr":[3,1,2]}');
  });

  it('handles null values', () => {
    const result = jsonCanonical({ a: null, b: 1 });
    expect(result.toString('utf8')).toBe('{"a":null,"b":1}');
  });
});

describe('CBOR Encoding', () => {
  it('round-trips a document', () => {
    const doc = { v: '1.0', t: 'id', n: 'Test', c: 1234567890 };
    const encoded = cborEncode(doc);
    const decoded = cborDecode(encoded);
    expect(decoded).toEqual(doc);
  });
});

describe('encodeForSigning', () => {
  it('strips the signature field', () => {
    const doc = { v: '1.0', t: 'id', n: 'Test', c: 123, s: 'fakesig' };
    const bytes = encodeForSigning(doc, 'json');
    const parsed = JSON.parse(bytes.toString('utf8'));
    expect(parsed).not.toHaveProperty('s');
    expect(parsed).toHaveProperty('v', '1.0');
  });

  it('produces deterministic output', () => {
    const doc = { c: 123, v: '1.0', t: 'id', n: 'Test' };
    const a = encodeForSigning(doc, 'json');
    const b = encodeForSigning(doc, 'json');
    expect(a.equals(b)).toBe(true);
  });
});
