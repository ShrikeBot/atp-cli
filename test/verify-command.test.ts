/**
 * Tests for the verify command across all document types.
 * Tests both RPC-only (no explorer) and RPC+explorer paths.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from "vitest";
import { exec as execCb } from "node:child_process";
import { promisify } from "node:util";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

const execAsync = promisify(execCb);
import { generateEd25519 } from "../src/lib/keys.js";
import { toBase64url } from "../src/lib/encoding.js";
import { sign } from "../src/lib/signing.js";
import { computeFingerprint } from "../src/lib/fingerprint.js";
import { BITCOIN_MAINNET } from "../src/schemas/index.js";
import { MockRPC } from "./mock-rpc.js";
import { MockExplorer } from "./mock-explorer.js";

const NET = BITCOIN_MAINNET;
const CLI = join(import.meta.dirname, "..", "dist", "index.js");
const TMP = join(import.meta.dirname, "..", ".test-tmp");

interface KeyPair {
    privateKey: Buffer;
    publicKey: Buffer;
    fingerprint: string;
    pubB64: string;
}

function makeKey(): KeyPair {
    const { privateKey, publicKey } = generateEd25519();
    const fingerprint = computeFingerprint(publicKey, "ed25519");
    return { privateKey, publicKey, fingerprint, pubB64: toBase64url(publicKey) };
}

function ts(): number {
    return Math.floor(Date.now() / 1000);
}

function writeDoc(name: string, doc: Record<string, unknown>): string {
    const path = join(TMP, name);
    writeFileSync(path, JSON.stringify(doc, null, 2));
    return path;
}

async function runVerify(path: string, rpcUrl: string, explorerUrl?: string): Promise<string> {
    const explorerFlag = explorerUrl ? ` --explorer-url ${explorerUrl}` : "";
    try {
        const { stdout, stderr } = await execAsync(
            `node ${CLI} verify ${path} --rpc-url ${rpcUrl} --rpc-user test --rpc-pass test${explorerFlag}`,
            { encoding: "utf8", timeout: 10000, env: { ...process.env, NODE_NO_WARNINGS: "1" } },
        );
        return stdout + stderr;
    } catch (e: any) {
        return (e.stdout || "") + (e.stderr || "");
    }
}

/** Build identity doc with new format */
function buildIdDoc(key: KeyPair, name: string): Record<string, unknown> {
    const doc: Record<string, unknown> = {
        v: "1.0",
        t: "id",
        n: name,
        k: [{ t: "ed25519", p: key.pubB64 }],
        ts: ts(),
    };
    doc.s = { f: key.fingerprint, sig: toBase64url(sign(doc, key.privateKey)) };
    return doc;
}

describe("Verify command", () => {
    let rpc: MockRPC;
    let explorer: MockExplorer;

    beforeAll(async () => {
        rpc = new MockRPC();
        await rpc.start();
        explorer = new MockExplorer();
        await explorer.start();
    });

    afterAll(async () => {
        await rpc.stop();
        await explorer.stop();
    });

    beforeEach(() => mkdirSync(TMP, { recursive: true }));
    afterEach(() => rmSync(TMP, { recursive: true, force: true }));

    // ── Identity (self-contained, no ref resolution needed) ──

    describe("identity document", () => {
        it("verifies valid identity (no explorer)", async () => {
            const key = makeKey();
            const doc = buildIdDoc(key, "TestAgent");
            const out = await runVerify(writeDoc("id.json", doc), rpc.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state NOT checked");
        });

        it("verifies valid identity (with explorer)", async () => {
            const key = makeKey();
            const doc = buildIdDoc(key, "TestAgent2");
            const out = await runVerify(writeDoc("id2.json", doc), rpc.url, explorer.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state verified via explorer");
        });

        it("detects tampered identity", async () => {
            const key = makeKey();
            const doc = buildIdDoc(key, "TestAgent");
            doc.n = "Tampered";
            const out = await runVerify(writeDoc("id-bad.json", doc), rpc.url);
            expect(out).toContain("✗ INVALID");
        });
    });

    // ── Attestation (needs ref resolution for attestor identity) ──

    describe("attestation", () => {
        it("verifies attestation via RPC (no explorer)", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const idDoc = buildIdDoc(keyA, "Attestor");
            const idTxid = rpc.addInscription(idDoc);

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: idTxid } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "a".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const out = await runVerify(writeDoc("att.json", att), rpc.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Fingerprint match: ✓");
            expect(out).toContain("Chain state NOT checked");
        });

        it("verifies attestation via RPC + explorer", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const idDoc = buildIdDoc(keyA, "Attestor");
            const idTxid = rpc.addInscription(idDoc);

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: idTxid } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "b".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const out = await runVerify(writeDoc("att-exp.json", att), rpc.url, explorer.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state verified via explorer");
        });

        it("detects fingerprint mismatch", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const idDoc = buildIdDoc(keyA, "WrongFP");
            const idTxid = rpc.addInscription(idDoc);

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: "wrong-fingerprint", ref: { net: NET, id: idTxid } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "c".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const out = await runVerify(writeDoc("att-fp.json", att), rpc.url);
            expect(out).toContain("Fingerprint mismatch");
        });
    });

    // ── Heartbeat ──

    describe("heartbeat", () => {
        it("verifies heartbeat via RPC (no explorer)", async () => {
            const key = makeKey();
            const idDoc = buildIdDoc(key, "HBAgent");
            const idTxid = rpc.addInscription(idDoc);

            const hb: Record<string, unknown> = {
                v: "1.0",
                t: "hb",
                f: key.fingerprint,
                ref: { net: NET, id: idTxid },
                seq: 0,
                ts: ts(),
            };
            hb.s = { f: key.fingerprint, sig: toBase64url(sign(hb, key.privateKey)) };
            const out = await runVerify(writeDoc("hb.json", hb), rpc.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Fingerprint match: ✓");
        });

        it("verifies heartbeat via RPC + explorer", async () => {
            const key = makeKey();
            const idDoc = buildIdDoc(key, "HBAgent2");
            const idTxid = rpc.addInscription(idDoc);

            const hb: Record<string, unknown> = {
                v: "1.0",
                t: "hb",
                f: key.fingerprint,
                ref: { net: NET, id: idTxid },
                seq: 1,
                ts: ts(),
            };
            hb.s = { f: key.fingerprint, sig: toBase64url(sign(hb, key.privateKey)) };
            const out = await runVerify(writeDoc("hb-exp.json", hb), rpc.url, explorer.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state verified via explorer");
        });
    });

    // ── Supersession ──

    describe("supersession", () => {
        it("verifies supersession via RPC (no explorer)", async () => {
            const oldKey = makeKey();
            const newKey = makeKey();

            const idDoc = buildIdDoc(oldKey, "SuperAgent");
            const idTxid = rpc.addInscription(idDoc);

            const superDoc: Record<string, unknown> = {
                v: "1.0",
                t: "super",
                target: { f: oldKey.fingerprint, ref: { net: NET, id: idTxid } },
                n: "SuperAgent",
                k: [{ t: "ed25519", p: newKey.pubB64 }],
                reason: "key-rotation",
                ts: ts(),
            };
            superDoc.s = [
                { f: oldKey.fingerprint, sig: toBase64url(sign(superDoc, oldKey.privateKey)) },
                { f: newKey.fingerprint, sig: toBase64url(sign(superDoc, newKey.privateKey)) },
            ];
            const out = await runVerify(writeDoc("super.json", superDoc), rpc.url);
            expect(out).toContain("Old key signature");
            expect(out).toContain("New key signature");
            expect(out).toContain("✓ VALID");
        });

        it("verifies supersession via RPC + explorer", async () => {
            const oldKey = makeKey();
            const newKey = makeKey();

            const idDoc = buildIdDoc(oldKey, "SuperAgent2");
            const idTxid = rpc.addInscription(idDoc);

            const superDoc: Record<string, unknown> = {
                v: "1.0",
                t: "super",
                target: { f: oldKey.fingerprint, ref: { net: NET, id: idTxid } },
                n: "SuperAgent2",
                k: [{ t: "ed25519", p: newKey.pubB64 }],
                reason: "key-rotation",
                ts: ts(),
            };
            superDoc.s = [
                { f: oldKey.fingerprint, sig: toBase64url(sign(superDoc, oldKey.privateKey)) },
                { f: newKey.fingerprint, sig: toBase64url(sign(superDoc, newKey.privateKey)) },
            ];
            const out = await runVerify(
                writeDoc("super-exp.json", superDoc),
                rpc.url,
                explorer.url,
            );
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state verified via explorer");
        });
    });

    // ── Revocation ──

    describe("revocation", () => {
        it("verifies revocation via RPC (no explorer)", async () => {
            const key = makeKey();
            const idDoc = buildIdDoc(key, "RevokeMe");
            const idTxid = rpc.addInscription(idDoc);

            const rev: Record<string, unknown> = {
                v: "1.0",
                t: "revoke",
                target: { f: key.fingerprint, ref: { net: NET, id: idTxid } },
                reason: "defunct",
                ts: ts(),
            };
            rev.s = { f: key.fingerprint, sig: toBase64url(sign(rev, key.privateKey)) };
            const out = await runVerify(writeDoc("revoke.json", rev), rpc.url);
            expect(out).toContain("✓ VALID");
        });

        it("verifies revocation via RPC + explorer", async () => {
            const key = makeKey();
            const idDoc = buildIdDoc(key, "RevokeMe2");
            const idTxid = rpc.addInscription(idDoc);

            const rev: Record<string, unknown> = {
                v: "1.0",
                t: "revoke",
                target: { f: key.fingerprint, ref: { net: NET, id: idTxid } },
                reason: "defunct",
                ts: ts(),
            };
            rev.s = { f: key.fingerprint, sig: toBase64url(sign(rev, key.privateKey)) };
            const out = await runVerify(writeDoc("revoke-exp.json", rev), rpc.url, explorer.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state verified via explorer");
        });
    });

    // ── Attestation revocation ──

    describe("attestation revocation", () => {
        it("verifies att-revoke with original key via RPC (no explorer)", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const idDoc = buildIdDoc(keyA, "AttRevoker");
            const idTxid = rpc.addInscription(idDoc);

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: idTxid } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "d".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const attTxid = rpc.addInscription(att);

            const attRev: Record<string, unknown> = {
                v: "1.0",
                t: "att-revoke",
                ref: { net: NET, id: attTxid },
                reason: "retracted",
                ts: ts(),
            };
            attRev.s = { f: keyA.fingerprint, sig: toBase64url(sign(attRev, keyA.privateKey)) };
            const out = await runVerify(writeDoc("attrev.json", attRev), rpc.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state NOT checked");
        });

        it("verifies att-revoke with SUCCESSOR key via explorer (chain walking)", async () => {
            const keyA = makeKey();
            const keyB = makeKey();
            const keyNew = makeKey();

            const idDoc = buildIdDoc(keyA, "ChainRevoker");
            const idTxid = rpc.addInscription(idDoc);

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: idTxid } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "e".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const attTxid = rpc.addInscription(att);

            const superDoc: Record<string, unknown> = {
                v: "1.0",
                t: "super",
                n: "ChainRevoker",
                k: [{ t: "ed25519", p: keyNew.pubB64 }],
                target: { f: keyA.fingerprint, ref: { net: NET, id: idTxid } },
                reason: "key-rotation",
                ts: ts(),
            };
            superDoc.s = [
                { f: keyA.fingerprint, sig: toBase64url(sign(superDoc, keyA.privateKey)) },
                { f: keyNew.fingerprint, sig: toBase64url(sign(superDoc, keyNew.privateKey)) },
            ];
            const superTxid = rpc.addInscription(superDoc);

            // Register chain in mock explorer
            explorer.addIdentity({
                v: "1.0",
                t: "id",
                n: "ChainRevoker",
                f: keyA.fingerprint,
                k: [{ t: "ed25519", p: keyA.pubB64 }],
            });
            const identity = (explorer as any).identities.get(keyA.fingerprint);
            identity.chain[0].inscription_id = idTxid;
            identity.chain[0].public_key = keyA.pubB64;

            explorer.addSupersession(keyA.fingerprint, keyNew.fingerprint, {
                v: "1.0",
                t: "super",
                n: "ChainRevoker",
                k: [{ t: "ed25519", p: keyNew.pubB64 }],
                target: { f: keyA.fingerprint },
                reason: "key-rotation",
            });
            const lastEntry = identity.chain[identity.chain.length - 1];
            lastEntry.inscription_id = superTxid;

            const attRev: Record<string, unknown> = {
                v: "1.0",
                t: "att-revoke",
                ref: { net: NET, id: attTxid },
                reason: "retracted",
                ts: ts(),
            };
            attRev.s = { f: keyNew.fingerprint, sig: toBase64url(sign(attRev, keyNew.privateKey)) };
            const out = await runVerify(
                writeDoc("attrev-chain.json", attRev),
                rpc.url,
                explorer.url,
            );
            expect(out).toContain("✓ VALID");
            expect(out).toContain("chain key");
            expect(out).toContain("Chain state verified via explorer");
        });

        it("rejects att-revoke with successor key when no explorer (cannot chain walk)", async () => {
            const keyA = makeKey();
            const keyB = makeKey();
            const keyNew = makeKey();

            const idDoc = buildIdDoc(keyA, "NoExplorerRevoker");
            const idTxid = rpc.addInscription(idDoc);

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: idTxid } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "f".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const attTxid = rpc.addInscription(att);

            const attRev: Record<string, unknown> = {
                v: "1.0",
                t: "att-revoke",
                ref: { net: NET, id: attTxid },
                reason: "retracted",
                ts: ts(),
            };
            attRev.s = { f: keyNew.fingerprint, sig: toBase64url(sign(attRev, keyNew.privateKey)) };
            const out = await runVerify(writeDoc("attrev-noexp.json", attRev), rpc.url);
            expect(out).toContain("does not match original attestor key");
            expect(out).toContain("requires --explorer-url");
        });
    });

    // ── Receipt ──

    describe("receipt", () => {
        it("verifies fully-signed receipt via RPC (no explorer)", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const idA = buildIdDoc(keyA, "Seller");
            const idATxid = rpc.addInscription(idA);

            const idB = buildIdDoc(keyB, "Buyer");
            const idBTxid = rpc.addInscription(idB);

            const rcpt: Record<string, unknown> = {
                v: "1.0",
                t: "rcpt",
                p: [
                    { f: keyA.fingerprint, ref: { net: NET, id: idATxid }, role: "initiator" },
                    { f: keyB.fingerprint, ref: { net: NET, id: idBTxid }, role: "counterparty" },
                ],
                ex: { type: "exchange", sum: "Sold widget" },
                out: "completed",
                ts: ts(),
            };
            rcpt.s = [
                { f: keyA.fingerprint, sig: toBase64url(sign(rcpt, keyA.privateKey)) },
                { f: keyB.fingerprint, sig: toBase64url(sign(rcpt, keyB.privateKey)) },
            ];
            const out = await runVerify(writeDoc("rcpt.json", rcpt), rpc.url);
            expect(out).toContain("Party 0 (initiator)");
            expect(out).toContain("Party 1 (counterparty)");
            expect(out).toContain("✓ VALID");
            expect(out).not.toContain("✗ INVALID");
        });

        it("verifies receipt via RPC + explorer", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const idA = buildIdDoc(keyA, "Seller2");
            const idATxid = rpc.addInscription(idA);

            const idB = buildIdDoc(keyB, "Buyer2");
            const idBTxid = rpc.addInscription(idB);

            const rcpt: Record<string, unknown> = {
                v: "1.0",
                t: "rcpt",
                p: [
                    { f: keyA.fingerprint, ref: { net: NET, id: idATxid }, role: "initiator" },
                    { f: keyB.fingerprint, ref: { net: NET, id: idBTxid }, role: "counterparty" },
                ],
                ex: { type: "exchange", sum: "Sold another widget" },
                out: "completed",
                ts: ts(),
            };
            rcpt.s = [
                { f: keyA.fingerprint, sig: toBase64url(sign(rcpt, keyA.privateKey)) },
                { f: keyB.fingerprint, sig: toBase64url(sign(rcpt, keyB.privateKey)) },
            ];
            const out = await runVerify(writeDoc("rcpt-exp.json", rcpt), rpc.url, explorer.url);
            expect(out).toContain("✓ VALID");
            expect(out).toContain("Chain state verified via explorer");
        });
    });

    // ── Security ──

    describe("security", () => {
        it("rejects file path in document ref.id", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: "/etc/passwd" } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "a".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const out = await runVerify(writeDoc("att-path.json", att), rpc.url);
            expect(out).toContain("Invalid TXID");
        });

        it("rejects relative file path in ref.id", async () => {
            const keyA = makeKey();
            const keyB = makeKey();

            const att: Record<string, unknown> = {
                v: "1.0",
                t: "att",
                from: { f: keyA.fingerprint, ref: { net: NET, id: "../../../etc/shadow" } },
                to: { f: keyB.fingerprint, ref: { net: NET, id: "a".repeat(64) } },
                ts: ts(),
            };
            att.s = { f: keyA.fingerprint, sig: toBase64url(sign(att, keyA.privateKey)) };
            const out = await runVerify(writeDoc("att-rel.json", att), rpc.url);
            expect(out).toContain("Invalid TXID");
        });
    });
}); // end Verify command
