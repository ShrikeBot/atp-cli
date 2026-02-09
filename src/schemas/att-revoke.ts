import { z } from 'zod';
import { VersionSchema, TimestampSchema, SignatureSchema } from './common.js';

export const AttRevocationSchema = z.object({
  v: VersionSchema,
  t: z.literal('att-revoke'),
  ref: z.string().regex(/^[0-9a-f]{64}$/i, 'Must be 64 hex characters'),
  reason: z.enum(['retracted', 'fraudulent', 'expired', 'error']),
  c: TimestampSchema,
  s: SignatureSchema,
});

export const AttRevocationUnsignedSchema = AttRevocationSchema.omit({ s: true });

export type AttRevocation = z.infer<typeof AttRevocationSchema>;
export type AttRevocationUnsigned = z.infer<typeof AttRevocationUnsignedSchema>;
