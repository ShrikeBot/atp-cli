import { z } from 'zod';
import { VersionSchema, TimestampSchema, ReferenceSchema, SignatureSchema } from './common.js';

export const RevocationSchema = z.object({
  v: VersionSchema,
  t: z.literal('revoke'),
  subject: ReferenceSchema,
  reason: z.enum(['key-compromised', 'defunct']),
  c: TimestampSchema,
  s: SignatureSchema,
});

export const RevocationUnsignedSchema = RevocationSchema.omit({ s: true });

export type Revocation = z.infer<typeof RevocationSchema>;
export type RevocationUnsigned = z.infer<typeof RevocationUnsignedSchema>;
