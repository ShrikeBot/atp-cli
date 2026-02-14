import { describe, it, expect } from "vitest";
import { generateEd25519 } from "../src/lib/keys.js";
import { computeFingerprint } from "../src/lib/fingerprint.js";
import { toBase64url, fromBase64url } from "../src/lib/encoding.js";

describe("Key Generation", () => {
    it("generates a valid Ed25519 keypair", () => {
        const { privateKey, publicKey } = generateEd25519();
        expect(privateKey).toBeInstanceOf(Buffer);
        expect(publicKey).toBeInstanceOf(Buffer);
        expect(privateKey.length).toBe(32);
        expect(publicKey.length).toBe(32);
    });

    it("generates different keys each time", () => {
        const a = generateEd25519();
        const b = generateEd25519();
        expect(a.publicKey.equals(b.publicKey)).toBe(false);
        expect(a.privateKey.equals(b.privateKey)).toBe(false);
    });
});

describe("Fingerprint", () => {
    it("computes a SHA-256 fingerprint for ed25519 keys", () => {
        const { publicKey } = generateEd25519();
        const fp = computeFingerprint(publicKey, "ed25519");
        expect(fp).toMatch(/^[A-Za-z0-9_-]+$/);
        // SHA-256 = 32 bytes = 43 base64url chars (no padding)
        expect(fp.length).toBe(43);
    });

    it("computes a SHA-384 fingerprint for PQC key types", () => {
        const fakeKey = Buffer.alloc(64, 0xab);
        const fp = computeFingerprint(fakeKey, "dilithium");
        // SHA-384 = 48 bytes = 64 base64url chars
        expect(fp.length).toBe(64);
    });

    it("is deterministic", () => {
        const { publicKey } = generateEd25519();
        const fp1 = computeFingerprint(publicKey, "ed25519");
        const fp2 = computeFingerprint(publicKey, "ed25519");
        expect(fp1).toBe(fp2);
    });
});

describe("Base64url Encoding", () => {
    it("round-trips correctly", () => {
        const original = Buffer.from("hello world");
        const encoded = toBase64url(original);
        const decoded = fromBase64url(encoded);
        expect(decoded.equals(original)).toBe(true);
    });

    it("produces URL-safe characters only", () => {
        const buf = Buffer.from([0xff, 0xfe, 0xfd, 0xfc]);
        const encoded = toBase64url(buf);
        expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
        expect(encoded).not.toContain("+");
        expect(encoded).not.toContain("/");
        expect(encoded).not.toContain("=");
    });
});
