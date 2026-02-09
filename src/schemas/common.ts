import { z } from 'zod';

/** ATP protocol version */
export const VersionSchema = z.literal('1.0');

/** Unix timestamp in seconds */
export const TimestampSchema = z.number().int().positive();

/** Base64url-encoded string */
export const Base64urlSchema = z.string().regex(/^[A-Za-z0-9_-]+$/, 'Invalid base64url');

/** Base64url-encoded signature (single) */
export const SignatureSchema = z.union([Base64urlSchema, z.instanceof(Uint8Array)]);

/** Key object */
export const KeySchema = z.object({
  t: z.string(),
  p: Base64urlSchema,
  role: z.string().optional(),
});

/** Array of keys or single key */
export const KeyOrKeysSchema = z.union([KeySchema, z.array(KeySchema).min(1)]);

/** Reference object (points to another identity) */
export const ReferenceSchema = z.object({
  t: z.string(),
  f: z.string(),
  txid: z.string().optional(),
});

/** Party in a receipt */
export const PartySchema = z.object({
  t: z.string(),
  f: z.string(),
  role: z.string(),
});

/** Exchange details in a receipt */
export const ExchangeSchema = z.object({
  type: z.string(),
  sum: z.string(),
  val: z.number().optional(),
});

/** MIME types for ATP documents */
export const ATP_MIME_JSON = 'application/atp.v1+json' as const;
export const ATP_MIME_CBOR = 'application/atp.v1+cbor' as const;

export type Key = z.infer<typeof KeySchema>;
export type Reference = z.infer<typeof ReferenceSchema>;
export type Party = z.infer<typeof PartySchema>;
export type Exchange = z.infer<typeof ExchangeSchema>;
