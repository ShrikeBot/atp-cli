import { validateTimestamp } from "../lib/timestamp.js";
import { Command } from "commander";
import { readFile, writeFile } from "node:fs/promises";
import { fromBase64url, toBase64url, encodeDocument } from "../lib/encoding.js";
import { sign } from "../lib/signing.js";
import { computeFingerprint } from "../lib/fingerprint.js";
import { loadPrivateKeyByFile, loadPrivateKeyFromFile } from "../lib/keys.js";
import { HeartbeatUnsignedSchema, BITCOIN_MAINNET } from "../schemas/index.js";

const heartbeat = new Command("heartbeat")
    .description("Create a signed heartbeat proving liveness")
    .requiredOption("--from <file>", "Your identity file")
    .requiredOption("--seq <n>", "Sequence number (monotonically increasing)", parseInt)
    .requiredOption("--txid <txid>", "Your identity inscription TXID")
    .option("--private-key <file>", "Private key file (overrides key lookup from identity)")
    .option("--net <caip2>", "CAIP-2 network identifier", BITCOIN_MAINNET)
    .option("--msg <text>", "Optional status message")
    .option("--encoding <format>", "json or cbor", "json")
    .option("--output <file>", "Output file")
    .action(async (opts: Record<string, string | undefined>) => {
        const fromDoc = JSON.parse(await readFile(opts.from!, "utf8"));
        const fromK = (Array.isArray(fromDoc.k) ? fromDoc.k : [fromDoc.k])[0];
        const fromPub = fromBase64url(fromK.p);
        const fp = computeFingerprint(fromPub, fromK.t);
        const net = opts.net ?? BITCOIN_MAINNET;

        const doc: Record<string, unknown> = {
            v: "1.0",
            t: "hb",
            f: fp,
            ref: { net, id: opts.txid as string },
            seq: opts.seq as unknown as number,
            ts: Math.floor(Date.now() / 1000),
        };
        validateTimestamp(doc.ts as number, "Heartbeat");

        if (opts.msg) doc.msg = opts.msg;

        // Validate before signing
        HeartbeatUnsignedSchema.parse(doc);

        const key = opts.privateKey
            ? await loadPrivateKeyFromFile(opts.privateKey, fromK.t)
            : await loadPrivateKeyByFile(opts.from!);
        const format = opts.encoding ?? "json";
        const sig = sign(doc, key.privateKey, format);
        doc.s = { f: fp, sig: format === "cbor" ? sig : toBase64url(sig) };

        const output = encodeDocument(doc, format);
        if (opts.output) {
            await writeFile(opts.output, output);
            console.error(`Heartbeat written to: ${opts.output}`);
        } else {
            console.log(format === "cbor" ? output.toString("hex") : output.toString("utf8"));
        }
    });

export default heartbeat;
