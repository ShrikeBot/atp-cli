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

/** Location reference (platform-agnostic document locator) */
export const LocationRefSchema = z.object({
  net: z.string().min(1).max(2048).regex(/^[a-z0-9]+:.+$/, 'Invalid CAIP-2 format (expected namespace:reference)'),
  id: z.string().min(1).max(2048),
});

/** Reference object (points to another identity) */
export const ReferenceSchema = z.object({
  f: z.string(),
  ref: LocationRefSchema,
});

/** Party in a receipt */
export const PartySchema = z.object({
  f: z.string(),
  ref: LocationRefSchema,
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

/** Bitcoin mainnet CAIP-2 identifier */
export const BITCOIN_MAINNET = 'bip122:000000000019d6689c085ae165831e93' as const;

export type Key = z.infer<typeof KeySchema>;
export type LocationRef = z.infer<typeof LocationRefSchema>;
export type Reference = z.infer<typeof ReferenceSchema>;
export type Party = z.infer<typeof PartySchema>;
export type Exchange = z.infer<typeof ExchangeSchema>;
