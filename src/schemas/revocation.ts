import { z } from "zod";
import {
    VersionSchema,
    TimestampSchema,
    ReferenceSchema,
    SignatureObjectSchema,
} from "./common.js";

export const RevocationSchema = z.object({
    v: VersionSchema,
    t: z.literal("revoke"),
    target: ReferenceSchema,
    reason: z.enum(["key-compromised", "defunct"]),
    ts: TimestampSchema.optional(),
    s: SignatureObjectSchema,
    vnb: z.number().int().positive().optional(),
});

export const RevocationUnsignedSchema = RevocationSchema.omit({ s: true });

export type Revocation = z.infer<typeof RevocationSchema>;
export type RevocationUnsigned = z.infer<typeof RevocationUnsignedSchema>;
