import { z } from 'zod';
import {
  VersionSchema,
  TimestampSchema,
  LocationRefSchema,
  SignatureObjectSchema,
} from './common.js';

export const HeartbeatSchema = z.object({
  v: VersionSchema,
  t: z.literal('hb'),
  f: z.string(),
  ref: LocationRefSchema,
  seq: z.number().int().nonnegative(),
  ts: TimestampSchema.optional(),
  s: SignatureObjectSchema,
  msg: z.string().optional(),
});

export const HeartbeatUnsignedSchema = HeartbeatSchema.omit({ s: true });

export type Heartbeat = z.infer<typeof HeartbeatSchema>;
export type HeartbeatUnsigned = z.infer<typeof HeartbeatUnsignedSchema>;
