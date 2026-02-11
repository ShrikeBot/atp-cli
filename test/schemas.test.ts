import { describe, it, expect } from 'vitest';
import {
  IdentitySchema,
  IdentityUnsignedSchema,
  AttestationUnsignedSchema,
  RevocationUnsignedSchema,
  SupersessionUnsignedSchema,
  HeartbeatUnsignedSchema,
  ReceiptUnsignedSchema,
  AttRevocationUnsignedSchema,
  AtpDocumentSchema,
} from '../src/schemas/index.js';

const FAKE_FP = 'erAHnt8G_oV4ANOborNzsAm2qSG_ikaQGA5cLpz8nVQ';
const FAKE_PUB = 'WhIcbyU-rzgEPkPr8mFPTyEhBpmDpz877NS_UGaOi4k';
const FAKE_SIG =
  'NHDEGlU4HW5C54b5OWP8s_esxb3A2OQ594Cz3AW9pNYdVRB6hF2j8prlefrZYAwfe2gkhRieEXhzXDRZ0WrGAw';
const NOW = Math.floor(Date.now() / 1000);

describe('Identity Schema', () => {
  it('validates a correct identity document', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      n: 'Shrike',
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
      s: FAKE_SIG,
    };
    expect(() => IdentitySchema.parse(doc)).not.toThrow();
  });

  it('rejects Unicode homoglyph names', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      n: 'Ѕhrike', // Cyrillic Ѕ
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
      s: FAKE_SIG,
    };
    expect(() => IdentitySchema.parse(doc)).toThrow();
  });

  it('rejects names over 64 characters', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      n: 'a'.repeat(65),
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
      s: FAKE_SIG,
    };
    expect(() => IdentitySchema.parse(doc)).toThrow();
  });

  it('rejects missing name', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
      s: FAKE_SIG,
    };
    expect(() => IdentitySchema.parse(doc)).toThrow();
  });

  it('validates unsigned identity', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      n: 'Shrike',
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
    };
    expect(() => IdentityUnsignedSchema.parse(doc)).not.toThrow();
  });

  it('accepts optional metadata', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      n: 'Shrike',
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
      s: FAKE_SIG,
      w: 'bc1qtest',
      m: { twitter: '@shrikey_', github: 'ShrikeBot' },
    };
    expect(() => IdentitySchema.parse(doc)).not.toThrow();
  });
});

describe('Attestation Schema', () => {
  it('validates a correct attestation', () => {
    const doc = {
      v: '1.0' as const,
      t: 'att' as const,
      from: { t: 'ed25519', f: FAKE_FP },
      to: { t: 'ed25519', f: FAKE_FP },
      c: NOW,
    };
    expect(() => AttestationUnsignedSchema.parse(doc)).not.toThrow();
  });
});

describe('Revocation Schema', () => {
  it('validates a correct revocation', () => {
    const doc = {
      v: '1.0' as const,
      t: 'revoke' as const,
      subject: { t: 'ed25519', f: FAKE_FP },
      reason: 'key-compromised' as const,
      c: NOW,
    };
    expect(() => RevocationUnsignedSchema.parse(doc)).not.toThrow();
  });

  it('rejects invalid reason', () => {
    const doc = {
      v: '1.0' as const,
      t: 'revoke' as const,
      subject: { t: 'ed25519', f: FAKE_FP },
      reason: 'bored',
      c: NOW,
    };
    expect(() => RevocationUnsignedSchema.parse(doc)).toThrow();
  });
});

describe('Supersession Schema', () => {
  it('validates a correct supersession', () => {
    const doc = {
      v: '1.0' as const,
      t: 'super' as const,
      old: { t: 'ed25519', f: FAKE_FP },
      new: { t: 'ed25519', f: FAKE_FP },
      reason: 'key-rotation' as const,
      c: NOW,
    };
    expect(() => SupersessionUnsignedSchema.parse(doc)).not.toThrow();
  });
});

describe('Heartbeat Schema', () => {
  it('validates a correct heartbeat', () => {
    const doc = {
      v: '1.0' as const,
      t: 'hb' as const,
      f: FAKE_FP,
      c: NOW,
    };
    expect(() => HeartbeatUnsignedSchema.parse(doc)).not.toThrow();
  });

  it('accepts optional message', () => {
    const doc = {
      v: '1.0' as const,
      t: 'hb' as const,
      f: FAKE_FP,
      c: NOW,
      msg: 'still alive',
    };
    expect(() => HeartbeatUnsignedSchema.parse(doc)).not.toThrow();
  });
});

describe('Receipt Schema', () => {
  it('validates a correct receipt', () => {
    const doc = {
      v: '1.0' as const,
      t: 'rcpt' as const,
      p: [
        { t: 'ed25519', f: FAKE_FP, role: 'initiator' },
        { t: 'ed25519', f: FAKE_FP, role: 'counterparty' },
      ],
      ex: { type: 'service', sum: 'Test exchange' },
      out: 'completed',
      c: NOW,
    };
    expect(() => ReceiptUnsignedSchema.parse(doc)).not.toThrow();
  });
});

describe('Attestation Revocation Schema', () => {
  it('validates a correct attestation revocation', () => {
    const doc = {
      v: '1.0' as const,
      t: 'att-revoke' as const,
      ref: 'a'.repeat(64),
      reason: 'retracted' as const,
      c: NOW,
    };
    expect(() => AttRevocationUnsignedSchema.parse(doc)).not.toThrow();
  });

  it('rejects invalid TXID', () => {
    const doc = {
      v: '1.0' as const,
      t: 'att-revoke' as const,
      ref: 'not-a-txid',
      reason: 'retracted' as const,
      c: NOW,
    };
    expect(() => AttRevocationUnsignedSchema.parse(doc)).toThrow();
  });
});

describe('AtpDocumentSchema (discriminated union)', () => {
  it('accepts identity documents', () => {
    const doc = {
      v: '1.0' as const,
      t: 'id' as const,
      n: 'Test',
      k: { t: 'ed25519', p: FAKE_PUB },
      c: NOW,
      s: FAKE_SIG,
    };
    expect(() => AtpDocumentSchema.parse(doc)).not.toThrow();
  });

  it('accepts heartbeat documents', () => {
    const doc = {
      v: '1.0' as const,
      t: 'hb' as const,
      f: FAKE_FP,
      c: NOW,
      s: FAKE_SIG,
    };
    expect(() => AtpDocumentSchema.parse(doc)).not.toThrow();
  });
});
