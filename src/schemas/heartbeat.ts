import { z } from 'zod';
import { VersionSchema, TimestampSchema, SignatureSchema } from './common.js';

export const HeartbeatSchema = z.object({
  v: VersionSchema,
  t: z.literal('hb'),
  f: z.string(),
  seq: z.number().int().nonnegative(),
  c: TimestampSchema,
  s: SignatureSchema,
  msg: z.string().optional(),
});

export const HeartbeatUnsignedSchema = HeartbeatSchema.omit({ s: true });

export type Heartbeat = z.infer<typeof HeartbeatSchema>;
export type HeartbeatUnsigned = z.infer<typeof HeartbeatUnsignedSchema>;
