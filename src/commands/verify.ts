import { Command } from "commander";
import { readFile } from "node:fs/promises";
import { fromBase64url, cborDecode, buffersToBase64url } from "../lib/encoding.js";
import { verify } from "../lib/signing.js";
import { computeFingerprint } from "../lib/fingerprint.js";
import { BitcoinRPC } from "../lib/rpc.js";
import { extractInscriptionFromWitness } from "../lib/inscription.js";
import { validateTimestamp } from "../lib/timestamp.js";
import { AtpDocumentSchema } from "../schemas/index.js";
import { ExplorerClient } from "../lib/explorer.js";

interface RpcOpts {
    rpcUrl: string;
    rpcUser: string;
    rpcPass: string;
}

interface VerifyOpts extends RpcOpts {
    explorerUrl?: string;
}

interface ResolvedKey {
    pubBytes: Buffer;
    keyType: string;
    fingerprint: string;
}

/**
 * Fetch and decode an ATP document from a TXID via RPC.
 * ref.id MUST be a valid TXID — no local file fallback.
 * Document references are attacker-controlled input; never treat them as file paths.
 */
async function fetchDoc(ref: { net: string; id: string }, rpcOpts: RpcOpts): Promise<Record<string, unknown>> {
    const id = ref.id;
    if (!/^[0-9a-f]{64}$/i.test(id)) {
        throw new Error(`Invalid TXID in document reference: '${id}'`);
    }
    const rpc = new BitcoinRPC(rpcOpts.rpcUrl, rpcOpts.rpcUser, rpcOpts.rpcPass);
    const tx = (await rpc.getRawTransaction(id)) as {
        vin: Array<{ txinwitness?: string[] }>;
    };
    const witness = tx.vin[0]?.txinwitness;
    if (!witness || witness.length === 0) {
        throw new Error("No witness data in referenced tx");
    }
    let extracted: { contentType: string; data: Buffer } | null = null;
    for (let i = witness.length - 1; i >= 0; i--) {
        try {
            extracted = extractInscriptionFromWitness(witness[i]!);
            break;
        } catch {
            /* try next */
        }
    }
    if (!extracted) {
        throw new Error("No inscription found in any witness element");
    }
    const { contentType, data } = extracted;
    if (contentType.includes("cbor")) {
        // Normalize CBOR byte strings back to base64url for schema compatibility
        return buffersToBase64url(cborDecode(data)) as Record<string, unknown>;
    }
    return JSON.parse(data.toString("utf8"));
}

/**
 * Resolve a reference to an identity's public key (RPC-only).
 * Returns the key from the document at the given ref.
 */
async function resolveIdentity(ref: { net: string; id: string }, rpcOpts: RpcOpts): Promise<ResolvedKey> {
    const doc = await fetchDoc(ref, rpcOpts);
    if (doc.t !== "id" && doc.t !== "super") {
        throw new Error(`Referenced document is type '${doc.t}', expected 'id' or 'super'`);
    }
    // Schema-validate referenced docs (enforces k-array, name charset, etc.)
    AtpDocumentSchema.parse(doc);
    const keys = doc.k as Array<{ t: string; p: string }>;
    if (!Array.isArray(keys)) throw new Error("Referenced document k field must be an array");
    const k = keys[0];
    const pubBytes = fromBase64url(k.p);
    const keyType = k.t;
    const fingerprint = computeFingerprint(pubBytes, keyType);
    return { pubBytes, keyType, fingerprint };
}

/**
 * Resolve the CURRENT active key for a genesis fingerprint via explorer,
 * then verify the explorer's answer against Bitcoin RPC.
 *
 * Falls back to direct RPC resolution (ref-only) if no explorer is configured.
 */
async function resolveCurrentKey(
    genesisFingerprint: string,
    ref: { net: string; id: string },
    opts: VerifyOpts,
): Promise<ResolvedKey> {
    if (!opts.explorerUrl) {
        // No explorer — fall back to resolving the ref directly
        return resolveIdentity(ref, opts);
    }

    const explorer = new ExplorerClient(opts.explorerUrl);
    const identity = await explorer.getIdentity(genesisFingerprint);

    if (identity.status.startsWith("revoked")) {
        console.log(`  ⚠ Identity is ${identity.status} (per explorer)`);
    }

    // Explorer says the current key is at this TXID — verify it on-chain
    const currentTxid = identity.ref.id;
    console.log(`  Explorer: current identity at ${currentTxid} (chain depth ${identity.chain_depth})`);

    // Fetch and verify the document from RPC (trust anchor)
    const doc = await fetchDoc({ net: identity.ref.net, id: currentTxid }, opts);
    if (doc.t !== "id" && doc.t !== "super") {
        throw new Error(`Explorer pointed to document type '${doc.t}', expected 'id' or 'super'`);
    }
    AtpDocumentSchema.parse(doc);

    const keys = doc.k as Array<{ t: string; p: string }>;
    if (!Array.isArray(keys)) throw new Error("Referenced document k field must be an array");
    const k = keys[0];
    const pubBytes = fromBase64url(k.p);
    const keyType = k.t;
    const fingerprint = computeFingerprint(pubBytes, keyType);

    // Verify the explorer's claimed fingerprint matches what's on-chain
    if (fingerprint !== identity.current_fingerprint) {
        throw new Error(
            `Explorer claims current fingerprint is ${identity.current_fingerprint} ` +
                `but on-chain document has ${fingerprint}`,
        );
    }

    return { pubBytes, keyType, fingerprint };
}

/**
 * Walk the full supersession chain via explorer, verifying each link on-chain.
 * Returns all chain keys (for revocation/att-revoke authority checks).
 */
async function resolveChainKeys(genesisFingerprint: string, opts: VerifyOpts): Promise<ResolvedKey[]> {
    if (!opts.explorerUrl) {
        throw new Error("Chain walking requires --explorer-url");
    }

    const explorer = new ExplorerClient(opts.explorerUrl);
    const chain = await explorer.getChain(genesisFingerprint);

    const keys: ResolvedKey[] = [];
    for (const entry of chain.chain) {
        // Verify each chain entry on-chain
        const doc = await fetchDoc({ net: "bip122:000000000019d6689c085ae165831e93", id: entry.inscription_id }, opts);
        AtpDocumentSchema.parse(doc);
        const docKeys = doc.k as Array<{ t: string; p: string }>;
        if (!Array.isArray(docKeys)) throw new Error("Chain entry k field must be an array");
        const k = docKeys[0];
        const pubBytes = fromBase64url(k.p);
        const keyType = k.t;
        const fingerprint = computeFingerprint(pubBytes, keyType);

        if (fingerprint !== entry.fingerprint) {
            throw new Error(
                `Chain entry claims fingerprint ${entry.fingerprint} but on-chain document has ${fingerprint}`,
            );
        }
        keys.push({ pubBytes, keyType, fingerprint });
    }

    return keys;
}

function sigValid(label: string, valid: boolean, fingerprint?: string): void {
    const fpStr = fingerprint ? ` (${fingerprint})` : "";
    if (valid) {
        console.log(`  ${label}${fpStr}: ✓ VALID`);
    } else {
        console.error(`  ${label}${fpStr}: ✗ INVALID`);
        process.exit(1);
    }
}

const CHAIN_STATE_WARNING =
    "\n⚠  Document signature verified. Chain state NOT checked — verify revocation/supersession status via an explorer.";
const CHAIN_STATE_CHECKED =
    "\n✓  Document signature verified. Chain state verified via explorer (each TXID confirmed on-chain).";

const verifyCmd = new Command("verify")
    .description("Verify an ATP document from file or TXID")
    .argument("<source>", "File path or TXID")
    .option("--rpc-url <url>", "Bitcoin RPC URL", "http://localhost:8332")
    .option("--rpc-user <user>", "RPC username", "bitcoin")
    .option("--rpc-pass <pass>", "RPC password", "")
    .option("--explorer-url <url>", "ATP Explorer API URL (enables chain walking)")
    .action(async (source: string, opts: Record<string, string>) => {
        let doc: Record<string, unknown>;
        let format: string;

        if (/^[0-9a-f]{64}$/i.test(source)) {
            const rpc = new BitcoinRPC(opts.rpcUrl, opts.rpcUser, opts.rpcPass);
            const tx = (await rpc.getRawTransaction(source)) as {
                vin: Array<{ txinwitness?: string[] }>;
            };
            const witness = tx.vin[0]?.txinwitness;
            if (!witness || witness.length === 0) {
                console.error("No witness data found in transaction");
                process.exit(1);
            }
            // Search all witness elements for an inscription (last element may be control block)
            let extracted: { contentType: string; data: Buffer } | null = null;
            for (let i = witness.length - 1; i >= 0; i--) {
                try {
                    extracted = extractInscriptionFromWitness(witness[i]!);
                    break;
                } catch {
                    /* try next */
                }
            }
            if (!extracted) {
                console.error("No inscription found in any witness element");
                process.exit(1);
            }
            const { contentType, data } = extracted;
            format = contentType.includes("cbor") ? "cbor" : "json";
            if (format === "cbor") {
                doc = buffersToBase64url(cborDecode(data)) as Record<string, unknown>;
            } else {
                doc = JSON.parse(data.toString("utf8"));
            }
        } else {
            const raw = await readFile(source, "utf8");
            doc = JSON.parse(raw);
            format = "json";
        }

        // Validate against schema — use parsed result to strip unknown fields
        try {
            doc = AtpDocumentSchema.parse(doc) as Record<string, unknown>;
        } catch (e: unknown) {
            const msg = e instanceof Error ? e.message : String(e);
            console.error(`Schema validation failed: ${msg}`);
            process.exit(1);
        }
        console.log(`Schema validation: ✓`);

        if (doc.v !== "1.0") {
            console.error(`Unsupported version: ${doc.v}`);
            process.exit(1);
        }

        if (doc.ts !== null && doc.ts !== undefined) {
            try {
                validateTimestamp(doc.ts as number, "Document");
                console.log(`Timestamp: ${new Date((doc.ts as number) * 1000).toISOString()} ✓`);
            } catch (e) {
                console.error(`Warning: ${(e as Error).message} (ts is advisory — block time is authoritative)`);
            }
        } else {
            console.log(`Timestamp: not present (optional)`);
        }

        console.log(`Document type: ${doc.t}`);

        const verifyOpts: VerifyOpts = {
            rpcUrl: opts.rpcUrl,
            rpcUser: opts.rpcUser,
            rpcPass: opts.rpcPass,
            explorerUrl: opts.explorerUrl,
        };
        const hasExplorer = Boolean(opts.explorerUrl);

        try {
            switch (doc.t) {
                case "id": {
                    const keys = doc.k as Array<{ t: string; p: string }>;
                    const s = doc.s as { f: string; sig: string | Uint8Array };
                    const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;
                    // Find the key matching s.f
                    let matched = false;
                    for (const k of keys) {
                        const pubBytes = fromBase64url(k.p);
                        const fp = computeFingerprint(pubBytes, k.t);
                        if (fp === s.f) {
                            const valid = verify(doc, pubBytes, sigBytes, format);
                            sigValid("Signature", valid, fp);
                            matched = true;
                            break;
                        }
                    }
                    if (!matched) {
                        console.error(`  ✗ s.f '${s.f}' does not match any key in k array`);
                        process.exit(1);
                    }
                    break;
                }

                case "att": {
                    const from = doc.from as { f: string; ref: { net: string; id: string } };
                    const to = doc.to as { f: string };
                    const s = doc.s as { f: string; sig: string | Uint8Array };
                    console.log(`  Attestation: ${from.f} → ${to.f}`);
                    try {
                        const resolved = await resolveIdentity(from.ref, verifyOpts);
                        console.log(`  Resolved attestor identity: ${resolved.fingerprint}`);
                        if (from.f !== resolved.fingerprint) {
                            console.error(
                                `  ✗ Fingerprint mismatch: doc says ${from.f}, resolved ${resolved.fingerprint}`,
                            );
                            process.exit(1);
                        } else {
                            console.log(`  Fingerprint match: ✓`);
                        }
                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;
                        const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
                        sigValid("Signature", valid, resolved.fingerprint);
                    } catch (e) {
                        console.error(`Error: could not resolve attestor's identity via ref: ${(e as Error).message}`);
                        process.exit(1);
                    }
                    break;
                }

                case "hb": {
                    const ref = doc.ref as { net: string; id: string };
                    const f = doc.f as string;
                    const s = doc.s as { f: string; sig: string | Uint8Array };
                    console.log(`  Heartbeat from ${f}, seq=${doc.seq}`);
                    if (doc.msg) {
                        console.log(`  Message: ${doc.msg}`);
                    }
                    try {
                        const resolved = await resolveIdentity(ref, verifyOpts);
                        console.log(`  Resolved identity: ${resolved.fingerprint}`);
                        if (f !== resolved.fingerprint) {
                            console.error(`  ✗ Fingerprint mismatch: doc says ${f}, resolved ${resolved.fingerprint}`);
                            process.exit(1);
                        } else {
                            console.log(`  Fingerprint match: ✓`);
                        }
                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;
                        const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
                        sigValid("Signature", valid, resolved.fingerprint);
                    } catch (e) {
                        console.error(`Error: could not resolve identity via ref: ${(e as Error).message}`);
                        process.exit(1);
                    }
                    break;
                }

                case "super": {
                    const target = doc.target as { f: string; ref: { net: string; id: string } };
                    const keys = doc.k as Array<{ t: string; p: string }>;
                    const k = keys[0];
                    const newPubBytes = fromBase64url(k.p);
                    const newFp = computeFingerprint(newPubBytes, k.t);
                    console.log(`  Supersession: ${target.f} → ${newFp} (${doc.n})`);
                    console.log(`  Reason: ${doc.reason}`);
                    try {
                        const oldKey = await resolveIdentity(target.ref, verifyOpts);
                        console.log(`  Resolved old identity: ${oldKey.fingerprint}`);
                        if (target.f !== oldKey.fingerprint) {
                            console.error(
                                `  ✗ Target fingerprint mismatch: doc says ${target.f}, resolved ${oldKey.fingerprint}`,
                            );
                            process.exit(1);
                        } else {
                            console.log(`  Target fingerprint match: ✓`);
                        }
                        const sigs = doc.s as Array<{ f: string; sig: string | Uint8Array }>;
                        const oldSigBytes = typeof sigs[0].sig === "string" ? fromBase64url(sigs[0].sig) : sigs[0].sig;
                        const newSigBytes = typeof sigs[1].sig === "string" ? fromBase64url(sigs[1].sig) : sigs[1].sig;
                        const oldValid = verify(doc, oldKey.pubBytes, oldSigBytes, format, oldKey.keyType);
                        sigValid("Old key signature", oldValid, oldKey.fingerprint);
                        const newValid = verify(doc, newPubBytes, newSigBytes, format, k.t);
                        sigValid("New key signature", newValid, newFp);
                    } catch (e) {
                        console.error(`Error: could not resolve old identity via target.ref: ${(e as Error).message}`);
                        process.exit(1);
                    }
                    break;
                }

                case "revoke": {
                    const target = doc.target as { f: string; ref: { net: string; id: string } };
                    const s = doc.s as { f: string; sig: string | Uint8Array };
                    console.log(`  Revocation of ${target.f}`);
                    console.log(`  Reason: ${doc.reason}`);
                    try {
                        // Verify target.f matches the resolved identity
                        const resolved = await resolveIdentity(target.ref, verifyOpts);
                        console.log(`  Resolved target identity: ${resolved.fingerprint}`);
                        if (target.f !== resolved.fingerprint) {
                            console.error(
                                `  ✗ Target fingerprint mismatch: doc says ${target.f}, resolved ${resolved.fingerprint}`,
                            );
                            process.exit(1);
                        } else {
                            console.log(`  Target fingerprint match: ✓`);
                        }

                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;

                        // Check if s.f matches the resolved (target ref) key
                        if (s.f === resolved.fingerprint) {
                            const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
                            sigValid("Signature", valid, resolved.fingerprint);
                        } else if (hasExplorer) {
                            // s.f doesn't match target ref key — walk supersession chain (poison pill)
                            console.log(`  s.f '${s.f}' differs from target key — walking chain...`);
                            const chainKeys = await resolveChainKeys(target.f, verifyOpts);
                            let matched = false;
                            for (const chainKey of chainKeys) {
                                if (chainKey.fingerprint === s.f) {
                                    const valid = verify(doc, chainKey.pubBytes, sigBytes, format, chainKey.keyType);
                                    sigValid("Signature (chain key)", valid, chainKey.fingerprint);
                                    matched = true;
                                    break;
                                }
                            }
                            if (!matched) {
                                console.error(
                                    "  ✗ s.f does not match any key in the identity's supersession chain.",
                                );
                                process.exit(1);
                            }
                        } else {
                            // No explorer and s.f doesn't match — can't verify chain authority
                            console.error(
                                `  ✗ s.f '${s.f}' does not match target key '${resolved.fingerprint}'.`,
                            );
                            console.error(
                                "  Full chain verification requires --explorer-url.",
                            );
                            process.exit(1);
                        }
                    } catch (e) {
                        console.error(
                            `Error: could not resolve target identity via target.ref: ${(e as Error).message}`,
                        );
                        process.exit(1);
                    }
                    break;
                }

                case "att-revoke": {
                    const ref = doc.ref as { net: string; id: string };
                    const s = doc.s as { f: string; sig: string | Uint8Array };
                    console.log(`  Attestation revocation`);
                    console.log(`  Reason: ${doc.reason}`);
                    try {
                        // Resolve the original attestation to find the attestor
                        const attDoc = await fetchDoc(ref, verifyOpts);
                        if (attDoc.t !== "att") {
                            console.error(`  ✗ Referenced document is type '${attDoc.t}', expected 'att'`);
                            process.exit(1);
                        }
                        const from = attDoc.from as { f: string; ref: { net: string; id: string } };
                        console.log(`  Original attestor: ${from.f}`);

                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;

                        if (hasExplorer) {
                            // Walk the full supersession chain — try each key
                            const chainKeys = await resolveChainKeys(from.f, verifyOpts);
                            let matched = false;
                            for (const chainKey of chainKeys) {
                                const valid = verify(doc, chainKey.pubBytes, sigBytes, format, chainKey.keyType);
                                if (valid) {
                                    sigValid("Signature (chain key)", valid, chainKey.fingerprint);
                                    matched = true;
                                    break;
                                }
                            }
                            if (!matched) {
                                console.error(
                                    "  ✗ Signature does not match any key in the attestor's supersession chain.",
                                );
                                process.exit(1);
                            }
                        } else {
                            // No explorer — verify against the ref'd key only
                            const resolved = await resolveIdentity(from.ref, verifyOpts);
                            console.log(`  Resolved attestor identity: ${resolved.fingerprint}`);
                            const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
                            if (!valid) {
                                console.error("  Signature does not match original attestor key.");
                                console.error(
                                    "  Note: spec §4.6 allows successor keys in the supersession chain to revoke.",
                                );
                                console.error("  Full chain verification requires --explorer-url. Failing.");
                                process.exit(1);
                            }
                            sigValid("Signature", valid, resolved.fingerprint);
                        }
                    } catch (e) {
                        console.error(
                            `Error: could not resolve original attestation or attestor identity: ${(e as Error).message}`,
                        );
                        process.exit(1);
                    }
                    break;
                }

                case "rcpt": {
                    const parties = doc.p as Array<{
                        f: string;
                        ref: { net: string; id: string };
                        role: string;
                    }>;
                    const sigs = doc.s as Array<{ f: string; sig: string | Uint8Array }>;
                    console.log(`  Receipt with ${parties.length} parties`);
                    for (let i = 0; i < parties.length; i++) {
                        const party = parties[i];
                        console.log(`  Party ${i} (${party.role}): ${party.f}`);
                        if (
                            sigs[i] &&
                            sigs[i].sig &&
                            (typeof sigs[i].sig !== "string" || (sigs[i].sig as string).length > 0)
                        ) {
                            try {
                                const resolved = await resolveIdentity(party.ref, verifyOpts);
                                if (party.f !== resolved.fingerprint) {
                                    console.error(
                                        `    ✗ Fingerprint mismatch: doc says ${party.f}, resolved ${resolved.fingerprint}`,
                                    );
                                    process.exit(1);
                                } else {
                                    console.log(`    Fingerprint match: ✓`);
                                }
                                const sigBytes =
                                    typeof sigs[i].sig === "string"
                                        ? fromBase64url(sigs[i].sig as string)
                                        : (sigs[i].sig as Uint8Array);
                                const valid = verify(doc, resolved.pubBytes, sigBytes, format, resolved.keyType);
                                sigValid(`  Party ${i} signature`, valid, resolved.fingerprint);
                            } catch (e) {
                                console.error(
                                    `Error: could not resolve party ${i}'s identity: ${(e as Error).message}`,
                                );
                                process.exit(1);
                            }
                        } else {
                            console.log(`    Signature: <not yet provided>`);
                        }
                    }
                    break;
                }

                default:
                    console.error(`Unknown document type: ${doc.t}`);
                    process.exit(1);
            }
            console.log(hasExplorer ? CHAIN_STATE_CHECKED : CHAIN_STATE_WARNING);
        } catch (e) {
            console.error(`Verification error: ${(e as Error).message}`);
            process.exit(1);
        }
    });

export { fetchDoc, resolveIdentity, resolveCurrentKey, resolveChainKeys };
export default verifyCmd;
