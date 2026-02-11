import { describe, it, expect } from 'vitest';
import { buildInscriptionEnvelope, extractInscriptionFromWitness } from '../src/lib/inscription.js';

describe('Inscription Envelope', () => {
  it('builds a valid inscription envelope', () => {
    const data = Buffer.from('{"v":"1.0","t":"id","n":"Test"}');
    const contentType = 'application/atp.v1+json';
    const envelope = buildInscriptionEnvelope(data, contentType);

    expect(envelope).toBeInstanceOf(Buffer);
    expect(envelope.length).toBeGreaterThan(data.length);
    // Should contain OP_FALSE (0x00), OP_IF (0x63), "ord", OP_ENDIF (0x68)
    expect(envelope.includes(Buffer.from('ord'))).toBe(true);
    expect(envelope[0]).toBe(0x00); // OP_FALSE
    expect(envelope[1]).toBe(0x63); // OP_IF
    expect(envelope[envelope.length - 1]).toBe(0x68); // OP_ENDIF
  });

  it('round-trips through build and extract', () => {
    const data = Buffer.from('{"v":"1.0","t":"id","n":"RoundTrip","c":1234567890}');
    const contentType = 'application/atp.v1+json';
    const envelope = buildInscriptionEnvelope(data, contentType);

    // Simulate witness: the envelope is the witness script
    const witnessHex = envelope.toString('hex');
    const extracted = extractInscriptionFromWitness(witnessHex);

    expect(extracted.contentType).toBe(contentType);
    expect(extracted.data.toString('utf8')).toBe(data.toString('utf8'));
  });

  it('handles CBOR content type', () => {
    const data = Buffer.from([0xa3, 0x61, 0x76, 0x63, 0x31, 0x2e, 0x30]); // minimal CBOR
    const contentType = 'application/atp.v1+cbor';
    const envelope = buildInscriptionEnvelope(data, contentType);

    expect(envelope).toBeInstanceOf(Buffer);
    expect(envelope.includes(Buffer.from('ord'))).toBe(true);
  });
});
