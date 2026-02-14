/**
 * Mock Bitcoin RPC for testing.
 * Serves inscription data from in-memory store via HTTP JSON-RPC.
 */
import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { buildInscriptionEnvelope } from "../src/lib/inscription.js";

interface StoredTx {
    txid: string;
    witnessHex: string;
}

export class MockRPC {
    private transactions = new Map<string, StoredTx>();
    private server: ReturnType<typeof createServer> | null = null;
    public port = 0;
    public url = "";

    /**
     * Store a document as an inscription at a fake TXID.
     * Returns the TXID.
     */
    addInscription(doc: Record<string, unknown>, txid?: string): string {
        const id = txid ?? this.fakeTxid();
        const json = JSON.stringify(doc);
        const data = Buffer.from(json, "utf8");
        const envelope = buildInscriptionEnvelope(data, "application/atp.v1+json");
        this.transactions.set(id, {
            txid: id,
            witnessHex: envelope.toString("hex"),
        });
        return id;
    }

    private fakeTxid(): string {
        const bytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
        return Buffer.from(bytes).toString("hex");
    }

    async start(): Promise<string> {
        return new Promise((resolve) => {
            this.server = createServer((req, res) => this.handle(req, res));
            this.server.listen(0, "127.0.0.1", () => {
                const addr = this.server!.address() as { port: number };
                this.port = addr.port;
                this.url = `http://127.0.0.1:${this.port}`;
                resolve(this.url);
            });
        });
    }

    async stop(): Promise<void> {
        return new Promise((resolve) => {
            if (this.server) this.server.close(() => resolve());
            else resolve();
        });
    }

    private handle(req: IncomingMessage, res: ServerResponse): void {
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
            try {
                const rpcReq = JSON.parse(body);
                const method = rpcReq.method;
                const params = rpcReq.params;

                if (method === "getrawtransaction") {
                    const txid = params[0] as string;
                    const tx = this.transactions.get(txid);
                    if (!tx) {
                        return this.rpcError(res, rpcReq.id, -5, `No such transaction: ${txid}`);
                    }
                    // Return a minimal tx structure with witness data
                    return this.rpcResult(res, rpcReq.id, {
                        txid: tx.txid,
                        vin: [
                            {
                                txinwitness: [tx.witnessHex],
                            },
                        ],
                    });
                }

                this.rpcError(res, rpcReq.id, -32601, `Method not found: ${method}`);
            } catch {
                res.writeHead(400);
                res.end("Bad request");
            }
        });
    }

    private rpcResult(res: ServerResponse, id: unknown, result: unknown): void {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ result, error: null, id }));
    }

    private rpcError(res: ServerResponse, id: unknown, code: number, message: string): void {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ result: null, error: { code, message }, id }));
    }
}
