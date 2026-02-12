import { z } from 'zod';
import {
  VersionSchema,
  TimestampSchema,
  ReferenceSchema,
  KeySchema,
  SignatureSchema,
} from './common.js';
import { MetadataSchema } from './identity.js';

export const SupersessionSchema = z.object({
  v: VersionSchema,
  t: z.literal('super'),
  target: ReferenceSchema,
  n: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[\x20-\x7E]+$/, 'Name must be ASCII only'),
  k: KeySchema,
  m: MetadataSchema,
  reason: z.enum(['key-rotation', 'algorithm-upgrade', 'key-compromised', 'metadata-update']),
  c: TimestampSchema,
  s: z.union([SignatureSchema, z.array(SignatureSchema)]),
});

export const SupersessionUnsignedSchema = SupersessionSchema.omit({ s: true });

export type Supersession = z.infer<typeof SupersessionSchema>;
export type SupersessionUnsigned = z.infer<typeof SupersessionUnsignedSchema>;
