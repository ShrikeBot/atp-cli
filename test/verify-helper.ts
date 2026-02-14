/**
 * Full signature verification for all ATP document types using the mock chain.
 */
import { MockChain } from "./mock-chain.js";
import { extractInscriptionFromWitness } from "../src/lib/inscription.js";
import { verify } from "../src/lib/signing.js";
import { fromBase64url } from "../src/lib/encoding.js";
import { computeFingerprint } from "../src/lib/fingerprint.js";

/** Fetch and parse an ATP document from the mock chain */
export function fetchDocument(chain: MockChain, txid: string): Record<string, unknown> {
    const tx = chain.getRawTransaction(txid) as {
        vin: Array<{ txinwitness: string[] }>;
    };
    const witnessHex = tx.vin[0].txinwitness[tx.vin[0].txinwitness.length - 1];
    const { data } = extractInscriptionFromWitness(witnessHex);
    return JSON.parse(data.toString("utf8"));
}

/** Get public key bytes from an identity document */
function getPubKeyFromIdentity(doc: Record<string, unknown>): {
    pubBytes: Buffer;
    keyType: string;
} {
    const kRaw = doc.k;
    const k = (Array.isArray(kRaw) ? kRaw[0] : kRaw) as { t: string; p: string };
    return { pubBytes: fromBase64url(k.p), keyType: k.t };
}

/** Extract signature bytes from a signature field (string or {f, sig}) */
function getSigBytes(s: unknown): Buffer {
    if (typeof s === "string") return fromBase64url(s);
    if (s && typeof s === "object" && "sig" in (s as any)) {
        const sig = (s as { sig: string | Uint8Array }).sig;
        return typeof sig === "string" ? fromBase64url(sig) : Buffer.from(sig);
    }
    throw new Error("Unknown signature format");
}

/** Verify signature on an identity document */
export function verifyIdentity(doc: Record<string, unknown>): boolean {
    const { pubBytes } = getPubKeyFromIdentity(doc);
    const sigBytes = getSigBytes(doc.s);
    return verify(doc, pubBytes, sigBytes);
}

/** Verify signature on a document signed by a known identity (attestation, heartbeat, att-revoke) */
export function verifyWithIdentity(doc: Record<string, unknown>, identityDoc: Record<string, unknown>): boolean {
    const { pubBytes } = getPubKeyFromIdentity(identityDoc);
    const sigBytes = getSigBytes(doc.s);
    return verify(doc, pubBytes, sigBytes);
}

/** Verify a supersession document (needs both old and new key) */
export function verifySupersession(doc: Record<string, unknown>, oldIdentityDoc: Record<string, unknown>): boolean {
    const { pubBytes: oldPub } = getPubKeyFromIdentity(oldIdentityDoc);
    const kRaw = doc.k;
    const newK = (Array.isArray(kRaw) ? kRaw[0] : kRaw) as { t: string; p: string };
    const newPub = fromBase64url(newK.p);
    const sigs = doc.s as Array<unknown>;
    const oldSigBytes = getSigBytes(sigs[0]);
    const newSigBytes = getSigBytes(sigs[1]);
    return verify(doc, oldPub, oldSigBytes) && verify(doc, newPub, newSigBytes);
}

/** Verify a revocation - signer must be any key in the supersession chain */
export function verifyRevocation(doc: Record<string, unknown>, signerIdentityDoc: Record<string, unknown>): boolean {
    const { pubBytes } = getPubKeyFromIdentity(signerIdentityDoc);
    const sigBytes = getSigBytes(doc.s);
    return verify(doc, pubBytes, sigBytes);
}

/**
 * Resolve the current identity for a fingerprint by walking the supersession chain.
 * Returns the final identity doc and all docs in the chain.
 */
export function resolveIdentityChain(
    chain: MockChain,
    startTxid: string,
    supersessionTxids: string[],
): { docs: Record<string, unknown>[]; finalDoc: Record<string, unknown> } {
    const startDoc = fetchDocument(chain, startTxid);
    const docs = [startDoc];

    // Walk supersessions in order
    for (const superTxid of supersessionTxids) {
        const superDoc = fetchDocument(chain, superTxid);
        docs.push(superDoc);
    }

    return { docs, finalDoc: docs[docs.length - 1] };
}

/**
 * Check if a fingerprint belongs to any key in a supersession chain.
 * Used for validating revocation authority.
 */
export function isKeyInChain(
    fingerprint: string,
    genesisDoc: Record<string, unknown>,
    supersessionDocs: Record<string, unknown>[],
): boolean {
    // Check genesis key
    const { pubBytes, keyType } = getPubKeyFromIdentity(genesisDoc);
    if (computeFingerprint(pubBytes, keyType) === fingerprint) return true;

    // Check each supersession's new key
    for (const doc of supersessionDocs) {
        const kRaw = doc.k;
        const k = (Array.isArray(kRaw) ? kRaw[0] : kRaw) as { t: string; p: string };
        const fp = computeFingerprint(fromBase64url(k.p), k.t);
        if (fp === fingerprint) return true;
    }

    return false;
}
