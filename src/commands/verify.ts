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
 * Resolve a reference to an identity's full key set (RPC-only).
 * Returns all keys from the document at the given ref.
 */
async function resolveKeySet(ref: { net: string; id: string }, rpcOpts: RpcOpts): Promise<ResolvedKey[]> {
    const doc = await fetchDoc(ref, rpcOpts);
    if (doc.t !== "id" && doc.t !== "super") {
        throw new Error(`Referenced document is type '${doc.t}', expected 'id' or 'super'`);
    }
    // Schema-validate referenced docs (enforces k-array, name charset, etc.)
    AtpDocumentSchema.parse(doc);
    const keys = doc.k as Array<{ t: string; p: string }>;
    if (!Array.isArray(keys)) throw new Error("Referenced document k field must be an array");
    return keys.map((k) => {
        const pubBytes = fromBase64url(k.p);
        const keyType = k.t;
        const fingerprint = computeFingerprint(pubBytes, keyType);
        return { pubBytes, keyType, fingerprint };
    });
}

/**
 * Find the key in a key set whose fingerprint matches the given fingerprint.
 * Rejects if no match found (§5.1: s.f MUST match exactly one key).
 */
function findKeyByFingerprint(keySet: ResolvedKey[], fingerprint: string, label: string): ResolvedKey {
    const match = keySet.find((k) => k.fingerprint === fingerprint);
    if (!match) {
        throw new Error(`${label}: s.f '${fingerprint}' does not match any key in key set`);
    }
    return match;
}

/**
 * Legacy single-key resolver (wraps resolveKeySet, returns primary key).
 * Used only where we need the identity fingerprint (k[0]), not for signature verification.
 */
async function resolveIdentity(ref: { net: string; id: string }, rpcOpts: RpcOpts): Promise<ResolvedKey> {
    const keySet = await resolveKeySet(ref, rpcOpts);
    return keySet[0];
}

/**
 * Resolve the CURRENT active key for a genesis fingerprint via explorer,
 * then verify the explorer's answer against Bitcoin RPC.
 *
 * Falls back to direct RPC resolution (ref-only) if no explorer is configured.
 */
async function resolveCurrentKeySet(
    genesisFingerprint: string,
    ref: { net: string; id: string },
    opts: VerifyOpts,
): Promise<ResolvedKey[]> {
    if (!opts.explorerUrl) {
        return resolveKeySet(ref, opts);
    }

    const explorer = new ExplorerClient(opts.explorerUrl);
    const identity = await explorer.getIdentity(genesisFingerprint);

    if (identity.status.startsWith("revoked")) {
        console.log(`  ⚠ Identity is ${identity.status} (per explorer)`);
    }

    const currentTxid = identity.ref.id;
    console.log(`  Explorer: current identity at ${currentTxid} (chain depth ${identity.chain_depth})`);

    const doc = await fetchDoc({ net: identity.ref.net, id: currentTxid }, opts);
    if (doc.t !== "id" && doc.t !== "super") {
        throw new Error(`Explorer pointed to document type '${doc.t}', expected 'id' or 'super'`);
    }
    AtpDocumentSchema.parse(doc);

    const keys = doc.k as Array<{ t: string; p: string }>;
    if (!Array.isArray(keys)) throw new Error("Referenced document k field must be an array");

    const keySet = keys.map((k) => {
        const pubBytes = fromBase64url(k.p);
        const keyType = k.t;
        const fingerprint = computeFingerprint(pubBytes, keyType);
        return { pubBytes, keyType, fingerprint };
    });

    // Verify explorer's claimed fingerprint matches k[0] on-chain
    if (keySet[0].fingerprint !== identity.current_fingerprint) {
        throw new Error(
            `Explorer claims current fingerprint is ${identity.current_fingerprint} ` +
                `but on-chain document has ${keySet[0].fingerprint}`,
        );
    }

    return keySet;
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

    const allKeys: ResolvedKey[] = [];
    for (const entry of chain.chain) {
        // Verify each chain entry on-chain
        const doc = await fetchDoc({ net: "bip122:000000000019d6689c085ae165831e93", id: entry.inscription_id }, opts);
        AtpDocumentSchema.parse(doc);
        const docKeys = doc.k as Array<{ t: string; p: string }>;
        if (!Array.isArray(docKeys)) throw new Error("Chain entry k field must be an array");

        // Add ALL keys from this chain entry (not just k[0])
        const entryKeys = docKeys.map((k) => {
            const pubBytes = fromBase64url(k.p);
            const keyType = k.t;
            const fingerprint = computeFingerprint(pubBytes, keyType);
            return { pubBytes, keyType, fingerprint };
        });

        // Verify primary key matches explorer's claim
        if (entryKeys[0].fingerprint !== entry.fingerprint) {
            throw new Error(
                `Chain entry claims fingerprint ${entry.fingerprint} but on-chain document has ${entryKeys[0].fingerprint}`,
            );
        }
        allKeys.push(...entryKeys);
    }

    return allKeys;
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
                        const keySet = await resolveKeySet(from.ref, verifyOpts);
                        const primaryFp = keySet[0].fingerprint;
                        console.log(`  Resolved attestor identity: ${primaryFp}`);
                        if (from.f !== primaryFp) {
                            console.error(
                                `  ✗ Fingerprint mismatch: doc says ${from.f}, resolved ${primaryFp}`,
                            );
                            process.exit(1);
                        } else {
                            console.log(`  Fingerprint match: ✓`);
                        }
                        const sigKey = findKeyByFingerprint(keySet, s.f, "Attestation");
                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;
                        const valid = verify(doc, sigKey.pubBytes, sigBytes, format, sigKey.keyType);
                        sigValid("Signature", valid, sigKey.fingerprint);
                    } catch (e) {
                        console.error(`Error: ${(e as Error).message}`);
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
                        const keySet = await resolveKeySet(ref, verifyOpts);
                        const primaryFp = keySet[0].fingerprint;
                        console.log(`  Resolved identity: ${primaryFp}`);
                        if (f !== primaryFp) {
                            console.error(`  ✗ Fingerprint mismatch: doc says ${f}, resolved ${primaryFp}`);
                            process.exit(1);
                        } else {
                            console.log(`  Fingerprint match: ✓`);
                        }
                        const sigKey = findKeyByFingerprint(keySet, s.f, "Heartbeat");
                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;
                        const valid = verify(doc, sigKey.pubBytes, sigBytes, format, sigKey.keyType);
                        sigValid("Signature", valid, sigKey.fingerprint);
                    } catch (e) {
                        console.error(`Error: ${(e as Error).message}`);
                        process.exit(1);
                    }
                    break;
                }

                case "super": {
                    const target = doc.target as { f: string; ref: { net: string; id: string } };
                    const newKeys = doc.k as Array<{ t: string; p: string }>;
                    // Build new key set from the supersession doc itself
                    const newKeySet = newKeys.map((k) => {
                        const pubBytes = fromBase64url(k.p);
                        const keyType = k.t;
                        const fingerprint = computeFingerprint(pubBytes, keyType);
                        return { pubBytes, keyType, fingerprint };
                    });
                    console.log(`  Supersession: ${target.f} → ${newKeySet[0].fingerprint} (${doc.n})`);
                    console.log(`  Reason: ${doc.reason}`);
                    try {
                        // Resolve old identity's full key set
                        const oldKeySet = await resolveKeySet(target.ref, verifyOpts);
                        const oldPrimaryFp = oldKeySet[0].fingerprint;
                        console.log(`  Resolved old identity: ${oldPrimaryFp}`);
                        if (target.f !== oldPrimaryFp) {
                            console.error(
                                `  ✗ Target fingerprint mismatch: doc says ${target.f}, resolved ${oldPrimaryFp}`,
                            );
                            process.exit(1);
                        } else {
                            console.log(`  Target fingerprint match: ✓`);
                        }
                        const sigs = doc.s as Array<{ f: string; sig: string | Uint8Array }>;

                        // s[0].f must match a key in the OLD key set
                        const oldSigKey = findKeyByFingerprint(oldKeySet, sigs[0].f, "Supersession old key");
                        const oldSigBytes = typeof sigs[0].sig === "string" ? fromBase64url(sigs[0].sig) : sigs[0].sig;
                        const oldValid = verify(doc, oldSigKey.pubBytes, oldSigBytes, format, oldSigKey.keyType);
                        sigValid("Old key signature", oldValid, oldSigKey.fingerprint);

                        // s[1].f must match a key in the NEW key set
                        const newSigKey = findKeyByFingerprint(newKeySet, sigs[1].f, "Supersession new key");
                        const newSigBytes = typeof sigs[1].sig === "string" ? fromBase64url(sigs[1].sig) : sigs[1].sig;
                        const newValid = verify(doc, newSigKey.pubBytes, newSigBytes, format, newSigKey.keyType);
                        sigValid("New key signature", newValid, newSigKey.fingerprint);
                    } catch (e) {
                        console.error(`Error: ${(e as Error).message}`);
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
                        // Resolve target identity's full key set
                        const keySet = await resolveKeySet(target.ref, verifyOpts);
                        const primaryFp = keySet[0].fingerprint;
                        console.log(`  Resolved target identity: ${primaryFp}`);
                        if (target.f !== primaryFp) {
                            console.error(
                                `  ✗ Target fingerprint mismatch: doc says ${target.f}, resolved ${primaryFp}`,
                            );
                            process.exit(1);
                        } else {
                            console.log(`  Target fingerprint match: ✓`);
                        }

                        const sigBytes = typeof s.sig === "string" ? fromBase64url(s.sig) : s.sig;

                        // Try to match s.f against the target identity's key set first
                        const localMatch = keySet.find((k) => k.fingerprint === s.f);
                        if (localMatch) {
                            const valid = verify(doc, localMatch.pubBytes, sigBytes, format, localMatch.keyType);
                            sigValid("Signature", valid, localMatch.fingerprint);
                        } else if (hasExplorer) {
                            // s.f not in target key set — walk supersession chain (poison pill: any chain key can revoke)
                            console.log(`  s.f '${s.f}' not in target key set — walking chain...`);
                            const chainKeys = await resolveChainKeys(target.f, verifyOpts);
                            const chainMatch = findKeyByFingerprint(chainKeys, s.f, "Revocation chain");
                            const valid = verify(doc, chainMatch.pubBytes, sigBytes, format, chainMatch.keyType);
                            sigValid("Signature (chain key)", valid, chainMatch.fingerprint);
                        } else {
                            console.error(
                                `  ✗ s.f '${s.f}' does not match any key in target identity's key set.`,
                            );
                            console.error(
                                "  Full chain verification requires --explorer-url.",
                            );
                            process.exit(1);
                        }
                    } catch (e) {
                        console.error(`Error: ${(e as Error).message}`);
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
                            // Walk the full supersession chain — match s.f then verify
                            const chainKeys = await resolveChainKeys(from.f, verifyOpts);
                            const chainMatch = findKeyByFingerprint(chainKeys, s.f, "Attestation revocation chain");
                            const valid = verify(doc, chainMatch.pubBytes, sigBytes, format, chainMatch.keyType);
                            sigValid("Signature (chain key)", valid, chainMatch.fingerprint);
                        } else {
                            // No explorer — resolve attestor's key set, match s.f
                            const keySet = await resolveKeySet(from.ref, verifyOpts);
                            console.log(`  Resolved attestor identity: ${keySet[0].fingerprint}`);
                            const sigKey = findKeyByFingerprint(keySet, s.f, "Attestation revocation");
                            const valid = verify(doc, sigKey.pubBytes, sigBytes, format, sigKey.keyType);
                            if (!valid) {
                                console.error("  Signature does not match attestor key.");
                                console.error(
                                    "  Note: spec §4.6 allows successor keys in the supersession chain to revoke.",
                                );
                                console.error("  Full chain verification requires --explorer-url. Failing.");
                                process.exit(1);
                            }
                            sigValid("Signature", valid, sigKey.fingerprint);
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
                    // Validate s.length === p.length
                    if (sigs.length !== parties.length) {
                        console.error(
                            `  ✗ Signature count (${sigs.length}) does not match party count (${parties.length})`,
                        );
                        process.exit(1);
                    }
                    for (let i = 0; i < parties.length; i++) {
                        const party = parties[i];
                        console.log(`  Party ${i} (${party.role}): ${party.f}`);
                        try {
                            const keySet = await resolveKeySet(party.ref, verifyOpts);
                            const primaryFp = keySet[0].fingerprint;
                            if (party.f !== primaryFp) {
                                console.error(
                                    `    ✗ Fingerprint mismatch: doc says ${party.f}, resolved ${primaryFp}`,
                                );
                                process.exit(1);
                            } else {
                                console.log(`    Fingerprint match: ✓`);
                            }
                            // s[i].f must match a key in party i's key set
                            const sigKey = findKeyByFingerprint(keySet, sigs[i].f, `Receipt party ${i}`);
                            const sigBytes =
                                typeof sigs[i].sig === "string"
                                    ? fromBase64url(sigs[i].sig as string)
                                    : (sigs[i].sig as Uint8Array);
                            const valid = verify(doc, sigKey.pubBytes, sigBytes, format, sigKey.keyType);
                            sigValid(`  Party ${i} signature`, valid, sigKey.fingerprint);
                        } catch (e) {
                            console.error(
                                `Error: could not verify party ${i}: ${(e as Error).message}`,
                            );
                            process.exit(1);
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

export { fetchDoc, resolveKeySet, resolveIdentity, resolveCurrentKeySet, resolveChainKeys, findKeyByFingerprint };
export default verifyCmd;
