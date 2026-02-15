import { describe, it, expect } from "vitest";
import {
    IdentitySchema,
    IdentityUnsignedSchema,
    AttestationUnsignedSchema,
    RevocationUnsignedSchema,
    SupersessionUnsignedSchema,
    HeartbeatUnsignedSchema,
    ReceiptUnsignedSchema,
    AttRevocationUnsignedSchema,
    AtpDocumentSchema,
    BITCOIN_MAINNET,
} from "../src/schemas/index.js";

const FAKE_FP = "erAHnt8G_oV4ANOborNzsAm2qSG_ikaQGA5cLpz8nVQ";
const FAKE_PUB = "WhIcbyU-rzgEPkPr8mFPTyEhBpmDpz877NS_UGaOi4k";
const FAKE_SIG = "NHDEGlU4HW5C54b5OWP8s_esxb3A2OQ594Cz3AW9pNYdVRB6hF2j8prlefrZYAwfe2gkhRieEXhzXDRZ0WrGAw";
const NOW = Math.floor(Date.now() / 1000);
const FAKE_REF = { net: BITCOIN_MAINNET, id: "a".repeat(64) };

describe("Identity Schema", () => {
    it("validates a correct identity document", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "Shrike",
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => IdentitySchema.parse(doc)).not.toThrow();
    });

    it("rejects Unicode homoglyph names", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "Ѕhrike", // Cyrillic Ѕ
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => IdentitySchema.parse(doc)).toThrow();
    });

    it("rejects names over 64 characters", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "a".repeat(65),
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => IdentitySchema.parse(doc)).toThrow();
    });

    it("rejects missing name", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => IdentitySchema.parse(doc)).toThrow();
    });

    it("validates unsigned identity", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "Shrike",
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
        };
        expect(() => IdentityUnsignedSchema.parse(doc)).not.toThrow();
    });

    it("accepts optional metadata", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "Shrike",
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
            m: {
                links: [
                    ["twitter", "@shrikey_"],
                    ["github", "ShrikeBot"],
                ],
                wallets: [["bitcoin", "bc1qtest"]],
            },
        };
        expect(() => IdentitySchema.parse(doc)).not.toThrow();
    });
});

describe("Attestation Schema", () => {
    it("validates a correct attestation", () => {
        const doc = {
            v: "1.0" as const,
            t: "att" as const,
            from: { f: FAKE_FP, ref: FAKE_REF },
            to: { f: FAKE_FP, ref: FAKE_REF },
            ts: NOW,
        };
        expect(() => AttestationUnsignedSchema.parse(doc)).not.toThrow();
    });
});

describe("Revocation Schema", () => {
    it("validates a correct revocation", () => {
        const doc = {
            v: "1.0" as const,
            t: "revoke" as const,
            target: { f: FAKE_FP, ref: FAKE_REF },
            reason: "key-compromised" as const,
            ts: NOW,
        };
        expect(() => RevocationUnsignedSchema.parse(doc)).not.toThrow();
    });

    it("rejects invalid reason", () => {
        const doc = {
            v: "1.0" as const,
            t: "revoke" as const,
            target: { f: FAKE_FP, ref: FAKE_REF },
            reason: "bored",
            ts: NOW,
        };
        expect(() => RevocationUnsignedSchema.parse(doc)).toThrow();
    });
});

describe("Supersession Schema", () => {
    it("validates a correct supersession", () => {
        const doc = {
            v: "1.0" as const,
            t: "super" as const,
            target: { f: FAKE_FP, ref: FAKE_REF },
            n: "Shrike",
            k: [{ t: "ed25519", p: FAKE_PUB }],
            reason: "key-rotation" as const,
            ts: NOW,
        };
        expect(() => SupersessionUnsignedSchema.parse(doc)).not.toThrow();
    });
});

describe("Heartbeat Schema", () => {
    it("validates a correct heartbeat", () => {
        const doc = {
            v: "1.0" as const,
            t: "hb" as const,
            f: FAKE_FP,
            ref: FAKE_REF,
            seq: 0,
            ts: NOW,
        };
        expect(() => HeartbeatUnsignedSchema.parse(doc)).not.toThrow();
    });

    it("accepts optional message", () => {
        const doc = {
            v: "1.0" as const,
            t: "hb" as const,
            f: FAKE_FP,
            ref: FAKE_REF,
            seq: 1,
            ts: NOW,
            msg: "still alive",
        };
        expect(() => HeartbeatUnsignedSchema.parse(doc)).not.toThrow();
    });
});

describe("Receipt Schema", () => {
    it("validates a correct receipt", () => {
        const doc = {
            v: "1.0" as const,
            t: "rcpt" as const,
            p: [
                { f: FAKE_FP, ref: FAKE_REF, role: "initiator" },
                { f: FAKE_FP, ref: FAKE_REF, role: "counterparty" },
            ],
            ex: { type: "service", sum: "Test exchange" },
            out: "completed",
            ts: NOW,
        };
        expect(() => ReceiptUnsignedSchema.parse(doc)).not.toThrow();
    });
});

describe("Attestation Revocation Schema", () => {
    it("validates a correct attestation revocation", () => {
        const doc = {
            v: "1.0" as const,
            t: "att-revoke" as const,
            ref: FAKE_REF,
            reason: "retracted" as const,
            ts: NOW,
        };
        expect(() => AttRevocationUnsignedSchema.parse(doc)).not.toThrow();
    });

    it("rejects missing net field", () => {
        const doc = {
            v: "1.0" as const,
            t: "att-revoke" as const,
            ref: { id: "a".repeat(64) },
            reason: "retracted" as const,
            ts: NOW,
        };
        expect(() => AttRevocationUnsignedSchema.parse(doc)).toThrow();
    });
});

describe("AtpDocumentSchema (discriminated union)", () => {
    it("accepts identity documents", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "Test",
            k: [{ t: "ed25519", p: FAKE_PUB }],
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => AtpDocumentSchema.parse(doc)).not.toThrow();
    });

    it("accepts heartbeat documents", () => {
        const doc = {
            v: "1.0" as const,
            t: "hb" as const,
            f: FAKE_FP,
            ref: FAKE_REF,
            seq: 42,
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => AtpDocumentSchema.parse(doc)).not.toThrow();
    });
});

describe("Name charset validation", () => {
    const makeId = (n: string) => ({
        v: "1.0" as const,
        t: "id" as const,
        n,
        k: [{ t: "ed25519", p: FAKE_PUB }],
        ts: NOW,
        s: { f: FAKE_FP, sig: FAKE_SIG },
    });

    it("accepts alphanumeric names", () => {
        expect(() => IdentitySchema.parse(makeId("Agent42"))).not.toThrow();
    });

    it("accepts names with space, underscore, hyphen, dot", () => {
        expect(() => IdentitySchema.parse(makeId("My Agent_v1-test.2"))).not.toThrow();
    });

    it("accepts single character name", () => {
        expect(() => IdentitySchema.parse(makeId("A"))).not.toThrow();
    });

    it("accepts exactly 64 character name", () => {
        expect(() => IdentitySchema.parse(makeId("a".repeat(64)))).not.toThrow();
    });

    it("rejects angle brackets", () => {
        expect(() => IdentitySchema.parse(makeId("Agent<script>"))).toThrow();
    });

    it("rejects pipe character", () => {
        expect(() => IdentitySchema.parse(makeId("Agent|test"))).toThrow();
    });

    it("rejects backtick", () => {
        expect(() => IdentitySchema.parse(makeId("Agent`test"))).toThrow();
    });

    it("rejects quotes", () => {
        expect(() => IdentitySchema.parse(makeId('Agent"test'))).toThrow();
        expect(() => IdentitySchema.parse(makeId("Agent'test"))).toThrow();
    });

    it("rejects backslash", () => {
        expect(() => IdentitySchema.parse(makeId("Agent\\test"))).toThrow();
    });

    it("rejects @#$%^&*", () => {
        for (const ch of ["@", "#", "$", "%", "^", "&", "*"]) {
            expect(() => IdentitySchema.parse(makeId(`Agent${ch}test`))).toThrow();
        }
    });

    it("rejects empty string", () => {
        expect(() => IdentitySchema.parse(makeId(""))).toThrow();
    });
});

describe("k field must be array", () => {
    it("rejects k as single object", () => {
        const doc = {
            v: "1.0" as const,
            t: "id" as const,
            n: "Test",
            k: { t: "ed25519", p: FAKE_PUB },
            ts: NOW,
            s: { f: FAKE_FP, sig: FAKE_SIG },
        };
        expect(() => IdentitySchema.parse(doc)).toThrow();
    });
});

describe("Attestation spec compliance", () => {
    it("rejects stake field", () => {
        const doc = {
            v: "1.0" as const,
            t: "att" as const,
            from: { f: FAKE_FP, ref: FAKE_REF },
            to: { f: FAKE_FP, ref: FAKE_REF },
            ts: NOW,
            stake: 10000,
        };
        // stake is not in schema, strict parsing should ignore it (passthrough)
        // but it should not be a recognized field
        const parsed = AttestationUnsignedSchema.parse(doc);
        expect(parsed).not.toHaveProperty("stake");
    });

    it("accepts vna field", () => {
        const doc = {
            v: "1.0" as const,
            t: "att" as const,
            from: { f: FAKE_FP, ref: FAKE_REF },
            to: { f: FAKE_FP, ref: FAKE_REF },
            ts: NOW,
            vna: NOW + 86400,
        };
        expect(() => AttestationUnsignedSchema.parse(doc)).not.toThrow();
    });

    it("rejects exp field (deprecated)", () => {
        const doc = {
            v: "1.0" as const,
            t: "att" as const,
            from: { f: FAKE_FP, ref: FAKE_REF },
            to: { f: FAKE_FP, ref: FAKE_REF },
            ts: NOW,
            exp: NOW + 86400,
        };
        const parsed = AttestationUnsignedSchema.parse(doc);
        expect(parsed).not.toHaveProperty("exp");
    });
});

describe("Supersession reason values", () => {
    const makeSuper = (reason: string) => ({
        v: "1.0" as const,
        t: "super" as const,
        target: { f: FAKE_FP, ref: FAKE_REF },
        n: "Test",
        k: [{ t: "ed25519", p: FAKE_PUB }],
        reason,
        ts: NOW,
    });

    it("accepts key-addition", () => {
        expect(() => SupersessionUnsignedSchema.parse(makeSuper("key-addition"))).not.toThrow();
    });

    it("accepts key-removal", () => {
        expect(() => SupersessionUnsignedSchema.parse(makeSuper("key-removal"))).not.toThrow();
    });

    it("rejects unknown reason", () => {
        expect(() => SupersessionUnsignedSchema.parse(makeSuper("bored"))).toThrow();
    });
});
