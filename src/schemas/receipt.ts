import { z } from "zod";
import { VersionSchema, TimestampSchema, PartySchema, ExchangeSchema, SignatureObjectSchema } from "./common.js";

/** Parties array with uniqueness constraint (§3.2: no self-dealing) */
const UniquePartiesSchema = z
    .array(PartySchema)
    .min(2)
    .refine(
        (parties) => new Set(parties.map((p) => p.f)).size === parties.length,
        "Duplicate party fingerprints not allowed (no self-dealing)",
    );

/** Base receipt object (used for discriminated union) */
export const ReceiptBaseSchema = z.object({
    v: VersionSchema,
    t: z.literal("rcpt"),
    p: UniquePartiesSchema,
    ex: ExchangeSchema,
    out: z.enum(["completed", "partial", "cancelled", "disputed"]),
    ts: TimestampSchema.optional(),
    s: z.array(SignatureObjectSchema),
});

/** Full receipt schema with cross-field validation */
export const ReceiptSchema = ReceiptBaseSchema;

export const ReceiptUnsignedSchema = ReceiptBaseSchema.omit({ s: true });

export type Receipt = z.infer<typeof ReceiptSchema>;
export type ReceiptUnsigned = z.infer<typeof ReceiptUnsignedSchema>;
