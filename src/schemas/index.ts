import { z } from 'zod';

export * from './common.js';
export * from './identity.js';
export * from './attestation.js';
export * from './att-revoke.js';
export * from './receipt.js';
export * from './supersession.js';
export * from './revocation.js';
export * from './heartbeat.js';

import { IdentitySchema } from './identity.js';
import { AttestationSchema } from './attestation.js';
import { AttRevocationSchema } from './att-revoke.js';
import { ReceiptSchema } from './receipt.js';
import { SupersessionSchema } from './supersession.js';
import { RevocationSchema } from './revocation.js';
import { HeartbeatSchema } from './heartbeat.js';

/** Discriminated union of all ATP document types */
export const AtpDocumentSchema = z.discriminatedUnion('t', [
  IdentitySchema,
  AttestationSchema,
  AttRevocationSchema,
  ReceiptSchema,
  SupersessionSchema,
  RevocationSchema,
  HeartbeatSchema,
]);

export type AtpDocument = z.infer<typeof AtpDocumentSchema>;
