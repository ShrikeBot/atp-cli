import { z } from "zod";
import { VersionSchema, TimestampSchema, KeySchema, SignatureObjectSchema } from "./common.js";

/** Structured metadata: named collections of key-value tuples */
export const MetadataSchema = z.record(z.string(), z.array(z.tuple([z.string(), z.string()]))).optional();

export const NameSchema = z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-zA-Z0-9 _\-.]+$/, "Name must contain only alphanumeric, space, underscore, hyphen, dot");

/** Key array with uniqueness check (§2.4: MUST NOT contain duplicate public keys) */
export const KeyArraySchema = z
    .array(KeySchema)
    .min(1)
    .refine((keys) => new Set(keys.map((k) => k.p)).size === keys.length, "Duplicate public keys not allowed in k array");

export const IdentitySchema = z.object({
    v: VersionSchema,
    t: z.literal("id"),
    n: NameSchema,
    k: KeyArraySchema,
    ts: TimestampSchema.optional(),
    s: SignatureObjectSchema,
    m: MetadataSchema,
    vna: z.number().int().positive().optional(),
});

/** Identity document without signature (for pre-sign validation) */
export const IdentityUnsignedSchema = IdentitySchema.omit({ s: true });

export type Identity = z.infer<typeof IdentitySchema>;
export type IdentityUnsigned = z.infer<typeof IdentityUnsignedSchema>;
