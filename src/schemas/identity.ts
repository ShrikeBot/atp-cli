import { z } from "zod";
import { VersionSchema, TimestampSchema, KeySchema, SignatureObjectSchema } from "./common.js";

/** Structured metadata: named collections of key-value tuples */
export const MetadataSchema = z.record(z.string(), z.array(z.tuple([z.string(), z.string()]))).optional();

export const IdentitySchema = z.object({
    v: VersionSchema,
    t: z.literal("id"),
    n: z
        .string()
        .min(1)
        .max(64)
        .regex(/^[a-zA-Z0-9 _\-.]+$/, "Name must contain only alphanumeric, space, underscore, hyphen, dot"),
    k: z.array(KeySchema).min(1),
    ts: TimestampSchema.optional(),
    s: SignatureObjectSchema,
    m: MetadataSchema,
    sup: z.string().optional(),
    vna: z.number().int().positive().optional(),
});

/** Identity document without signature (for pre-sign validation) */
export const IdentityUnsignedSchema = IdentitySchema.omit({ s: true });

export type Identity = z.infer<typeof IdentitySchema>;
export type IdentityUnsigned = z.infer<typeof IdentityUnsignedSchema>;
