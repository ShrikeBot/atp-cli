import { z } from "zod";
import {
    VersionSchema,
    TimestampSchema,
    PartySchema,
    ExchangeSchema,
    SignatureObjectSchema,
} from "./common.js";

export const ReceiptSchema = z.object({
    v: VersionSchema,
    t: z.literal("rcpt"),
    p: z.array(PartySchema).min(2),
    ex: ExchangeSchema,
    out: z.enum(["completed", "partial", "cancelled", "disputed"]),
    ts: TimestampSchema.optional(),
    s: z.array(SignatureObjectSchema),
});

export const ReceiptUnsignedSchema = ReceiptSchema.omit({ s: true });

export type Receipt = z.infer<typeof ReceiptSchema>;
export type ReceiptUnsigned = z.infer<typeof ReceiptUnsignedSchema>;
