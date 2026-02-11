import { z } from 'zod';
import {
  VersionSchema,
  TimestampSchema,
  PartySchema,
  ExchangeSchema,
  SignatureSchema,
} from './common.js';

export const ReceiptSchema = z.object({
  v: VersionSchema,
  t: z.literal('rcpt'),
  p: z.array(PartySchema).min(2),
  ex: ExchangeSchema,
  out: z.string(),
  c: TimestampSchema,
  s: z.union([SignatureSchema, z.array(SignatureSchema)]),
});

export const ReceiptUnsignedSchema = ReceiptSchema.omit({ s: true });

export type Receipt = z.infer<typeof ReceiptSchema>;
export type ReceiptUnsigned = z.infer<typeof ReceiptUnsignedSchema>;
