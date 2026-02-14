import { z } from "zod";
import { VersionSchema, TimestampSchema, ReferenceSchema, KeySchema, SignatureObjectSchema } from "./common.js";
import { MetadataSchema } from "./identity.js";

export const SupersessionSchema = z.object({
    v: VersionSchema,
    t: z.literal("super"),
    target: ReferenceSchema,
    n: z
        .string()
        .min(1)
        .max(64)
        .regex(/^[\x20-\x7E]+$/, "Name must be ASCII only"),
    k: z.array(KeySchema).min(1),
    m: MetadataSchema,
    reason: z.enum(["key-rotation", "algorithm-upgrade", "key-compromised", "metadata-update"]),
    ts: TimestampSchema.optional(),
    s: z.array(SignatureObjectSchema).length(2),
    vnb: z.number().int().positive().optional(),
    vna: z.number().int().positive().optional(),
});

export const SupersessionUnsignedSchema = SupersessionSchema.omit({ s: true });

export type Supersession = z.infer<typeof SupersessionSchema>;
export type SupersessionUnsigned = z.infer<typeof SupersessionUnsignedSchema>;
