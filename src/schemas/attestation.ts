import { z } from "zod";
import {
    VersionSchema,
    TimestampSchema,
    ReferenceSchema,
    SignatureObjectSchema,
} from "./common.js";

export const AttestationSchema = z.object({
    v: VersionSchema,
    t: z.literal("att"),
    from: ReferenceSchema,
    to: ReferenceSchema,
    ts: TimestampSchema.optional(),
    s: SignatureObjectSchema,
    stake: z.number().optional(),
    ctx: z.string().optional(),
    exp: z.number().optional(),
});

export const AttestationUnsignedSchema = AttestationSchema.omit({ s: true });

export type Attestation = z.infer<typeof AttestationSchema>;
export type AttestationUnsigned = z.infer<typeof AttestationUnsignedSchema>;
