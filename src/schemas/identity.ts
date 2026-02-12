import { z } from 'zod';
import { VersionSchema, TimestampSchema, KeySchema, SignatureSchema } from './common.js';

/** Structured metadata: named collections of key-value tuples */
export const MetadataSchema = z.record(z.string(), z.array(z.tuple([z.string(), z.string()]))).optional();

export const IdentitySchema = z.object({
  v: VersionSchema,
  t: z.literal('id'),
  n: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[\x20-\x7E]+$/, 'Name must be ASCII only (no Unicode homoglyphs)'),
  k: KeySchema,
  c: TimestampSchema,
  s: SignatureSchema,
  m: MetadataSchema,
  sup: z.string().optional(),
});

/** Identity document without signature (for pre-sign validation) */
export const IdentityUnsignedSchema = IdentitySchema.omit({ s: true });

export type Identity = z.infer<typeof IdentitySchema>;
export type IdentityUnsigned = z.infer<typeof IdentityUnsignedSchema>;
