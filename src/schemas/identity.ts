import { z } from 'zod';
import { VersionSchema, TimestampSchema, KeySchema, SignatureSchema } from './common.js';

/** External key reference for cross-platform identity linking */
export const ExternalKeyRefSchema = z.object({
  t: z.string(),
  f: z.string(),
});

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
  w: z.string().optional(),
  m: z.record(z.string(), z.string()).optional(),
  sup: z.string().optional(),
  keys: z.array(ExternalKeyRefSchema).optional(),
});

/** Identity document without signature (for pre-sign validation) */
export const IdentityUnsignedSchema = IdentitySchema.omit({ s: true });

export type Identity = z.infer<typeof IdentitySchema>;
export type IdentityUnsigned = z.infer<typeof IdentityUnsignedSchema>;
