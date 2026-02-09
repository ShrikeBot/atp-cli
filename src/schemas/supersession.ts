import { z } from 'zod';
import { VersionSchema, TimestampSchema, ReferenceSchema, SignatureSchema } from './common.js';

export const SupersessionSchema = z.object({
  v: VersionSchema,
  t: z.literal('super'),
  old: ReferenceSchema,
  new: ReferenceSchema,
  reason: z.enum(['key-rotation', 'algorithm-upgrade', 'key-compromised']),
  c: TimestampSchema,
  s: z.union([SignatureSchema, z.array(SignatureSchema)]),
});

export const SupersessionUnsignedSchema = SupersessionSchema.omit({ s: true });

export type Supersession = z.infer<typeof SupersessionSchema>;
export type SupersessionUnsigned = z.infer<typeof SupersessionUnsignedSchema>;
