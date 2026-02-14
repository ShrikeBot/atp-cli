import { Encoder, decode as cborDecode } from "cbor-x";

const cborEncoder = new Encoder({ mapsAsObjects: true, useRecords: false });

export function toBase64url(buf: Uint8Array | Buffer): string {
    return Buffer.from(buf).toString("base64url");
}

export function fromBase64url(str: string): Buffer {
    return Buffer.from(str, "base64url");
}

/** Deterministic JSON: sorted keys, compact, UTF-8 */
export function jsonCanonical(obj: unknown): Buffer {
    return Buffer.from(JSON.stringify(sortKeys(obj)), "utf8");
}

function sortKeys(val: unknown): unknown {
    if (val === null || typeof val !== "object") {
        return val;
    }
    if (Array.isArray(val)) {
        return val.map(sortKeys);
    }
    const sorted: Record<string, unknown> = {};
    for (const k of Object.keys(val as Record<string, unknown>).sort()) {
        sorted[k] = sortKeys((val as Record<string, unknown>)[k]);
    }
    return sorted;
}

/** Deterministic CBOR encoding */
export function cborEncode(obj: unknown): Buffer {
    return Buffer.from(cborEncoder.encode(obj));
}

export { cborDecode };

/** Domain separator: prevents cross-protocol signature reuse */
const DOMAIN_SEPARATOR = Buffer.from("ATP-v1.0:", "ascii");

/** Known binary fields that must be byte strings in CBOR */
const BINARY_FIELDS = new Set(["p", "s", "f"]);

/** Convert known binary fields from base64url strings to Buffers for CBOR encoding */
export function binaryFieldsToBuffers(obj: unknown): unknown {
    if (obj === null || typeof obj !== "object") {
        return obj;
    }
    if (obj instanceof Uint8Array || Buffer.isBuffer(obj)) {
        return obj;
    }
    if (Array.isArray(obj)) {
        return obj.map(binaryFieldsToBuffers);
    }
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        if (BINARY_FIELDS.has(k) && typeof v === "string") {
            result[k] = fromBase64url(v);
        } else if (BINARY_FIELDS.has(k) && Array.isArray(v)) {
            result[k] = v.map((item) => {
                if (typeof item === "string") {
                    return fromBase64url(item);
                }
                return item;
            });
        } else {
            result[k] = binaryFieldsToBuffers(v);
        }
    }
    return result;
}

/** Convert byte string fields back to base64url strings after CBOR decoding */
export function buffersToBase64url(obj: unknown): unknown {
    if (obj === null || typeof obj !== "object") {
        return obj;
    }
    if (obj instanceof Uint8Array || Buffer.isBuffer(obj)) {
        return toBase64url(obj);
    }
    if (Array.isArray(obj)) {
        return obj.map(buffersToBase64url);
    }
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
        if (BINARY_FIELDS.has(k) && (v instanceof Uint8Array || Buffer.isBuffer(v))) {
            result[k] = toBase64url(v);
        } else if (BINARY_FIELDS.has(k) && Array.isArray(v)) {
            result[k] = v.map((item) =>
                item instanceof Uint8Array || Buffer.isBuffer(item) ? toBase64url(item) : item,
            );
        } else {
            result[k] = buffersToBase64url(v);
        }
    }
    return result;
}

/** Encode document for signing (without `s` field, with domain separator) */
export function encodeForSigning(doc: Record<string, unknown>, format = "json"): Buffer {
    const { s: _sig, ...unsigned } = doc;
    const separator = DOMAIN_SEPARATOR;
    if (format === "cbor") {
        const withBinaries = binaryFieldsToBuffers(unsigned);
        return Buffer.concat([separator, cborEncode(withBinaries)]);
    }
    return Buffer.concat([separator, jsonCanonical(unsigned)]);
}

/** Maximum encoded document size (16 KB) */
const MAX_DOCUMENT_SIZE = 16384;

/** Encode complete document */
export function encodeDocument(doc: Record<string, unknown>, format = "json"): Buffer {
    let output: Buffer;
    if (format === "cbor") {
        output = cborEncode(binaryFieldsToBuffers(doc));
    } else {
        output = Buffer.from(JSON.stringify(sortKeys(doc), null, 2), "utf8");
    }
    if (output.length > MAX_DOCUMENT_SIZE) {
        throw new Error(`Document exceeds maximum size: ${output.length} bytes (limit: ${MAX_DOCUMENT_SIZE})`);
    }
    return output;
}
