/**
 * Mock ATP Explorer for testing.
 * Implements the explorer API spec in-memory with HTTP server.
 */
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import type {
  ExplorerIdentity,
  ExplorerChain,
  ChainEntry,
  ExplorerDocument,
  ExplorerInfo,
} from '../src/lib/explorer.js';

interface StoredIdentity {
  genesis_fingerprint: string;
  chain: ChainEntry[];
  revocation: ExplorerChain['revocation'];
  metadata: Record<string, unknown>;
}

interface StoredDocument {
  txid: string;
  block: number;
  block_hash: string;
  confirmations: number;
  content_type: string;
  document: Record<string, unknown>;
}

export class MockExplorer {
  private identities = new Map<string, StoredIdentity>();
  private documents = new Map<string, StoredDocument>();
  private server: ReturnType<typeof createServer> | null = null;
  private nextBlock = 100;
  public port = 0;
  public url = '';

  /** Register an identity document. Returns a fake TXID. */
  addIdentity(doc: Record<string, unknown>): string {
    const k = doc.k as { t: string; p: string };
    const fingerprint = (doc.f as string) || this.computeFp(k);
    const txid = this.fakeTxid();
    const block = this.nextBlock++;

    const entry: ChainEntry = {
      fingerprint,
      name: doc.n as string,
      key_type: k.t,
      public_key: k.p,
      inscription_id: txid,
      block,
      type: 'id',
    };

    this.identities.set(fingerprint, {
      genesis_fingerprint: fingerprint,
      chain: [entry],
      revocation: null,
      metadata: (doc.m as Record<string, unknown>) ?? {},
    });

    this.storeDoc(txid, block, doc);
    return txid;
  }

  /** Register a supersession. Links old fingerprint chain to new. */
  addSupersession(
    oldFingerprint: string,
    newFingerprint: string,
    doc: Record<string, unknown>,
  ): string {
    const identity = this.identities.get(oldFingerprint);
    if (!identity) throw new Error(`Identity ${oldFingerprint} not found`);

    const txid = this.fakeTxid();
    const block = this.nextBlock++;
    const k = doc.k as { t: string; p: string };

    const entry: ChainEntry = {
      fingerprint: newFingerprint,
      name: doc.n as string,
      key_type: k.t,
      public_key: k.p,
      inscription_id: txid,
      block,
      type: 'super',
      reason: doc.reason as string,
    };

    identity.chain.push(entry);
    // Also index by new fingerprint pointing to same identity
    this.identities.set(newFingerprint, identity);

    this.storeDoc(txid, block, doc);
    return txid;
  }

  /** Register a revocation. */
  addRevocation(fingerprint: string, doc: Record<string, unknown>, signedByFp: string): string {
    const identity = this.identities.get(fingerprint);
    if (!identity) throw new Error(`Identity ${fingerprint} not found`);

    const txid = this.fakeTxid();
    const block = this.nextBlock++;

    identity.revocation = {
      inscription_id: txid,
      reason: doc.reason as string,
      block,
      signed_by: signedByFp,
    };

    this.storeDoc(txid, block, doc);
    return txid;
  }

  /** Store an arbitrary document (attestation, receipt, etc.) */
  addDocument(doc: Record<string, unknown>): string {
    const txid = this.fakeTxid();
    const block = this.nextBlock++;
    this.storeDoc(txid, block, doc);
    return txid;
  }

  private storeDoc(txid: string, block: number, doc: Record<string, unknown>): void {
    this.documents.set(txid, {
      txid,
      block,
      block_hash: this.fakeTxid(),
      confirmations: 6,
      content_type: 'application/atp.v1+json',
      document: doc,
    });
  }

  private computeFp(_k: { t: string; p: string }): string {
    // Placeholder — tests should provide fingerprint explicitly
    return this.fakeTxid().slice(0, 16);
  }

  private fakeTxid(): string {
    const bytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) bytes[i] = Math.floor(Math.random() * 256);
    return Buffer.from(bytes).toString('hex');
  }

  private getCurrentState(identity: StoredIdentity): { entry: ChainEntry; status: string } {
    const current = identity.chain[identity.chain.length - 1]!;
    const status = identity.revocation ? `revoked:${identity.revocation.reason}` : 'active';
    return { entry: current, status };
  }

  /** Start the mock HTTP server. */
  async start(): Promise<string> {
    return new Promise((resolve) => {
      this.server = createServer((req, res) => this.handle(req, res));
      this.server.listen(0, '127.0.0.1', () => {
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
    const url = new URL(req.url!, `http://${req.headers.host}`);
    const path = url.pathname;

    // GET /api/v1/info
    if (path === '/api/v1/info') {
      return this.json(res, {
        name: 'Mock ATP Explorer',
        version: '1.0.0-test',
        chains: ['bip122:000000000019d6689c085ae165831e93'],
        latest_block: this.nextBlock - 1,
        indexed_identities: this.identities.size,
        indexed_documents: this.documents.size,
        policies: {
          revocation_depth_limit: null,
          supersession_rate_flag_blocks: 250,
          min_confirmations_for_finality: 6,
        },
      } satisfies ExplorerInfo);
    }

    // GET /api/v1/identity/:fingerprint/chain
    const chainMatch = path.match(/^\/api\/v1\/identity\/([^/]+)\/chain$/);
    if (chainMatch) {
      const fp = chainMatch[1]!;
      const identity = this.identities.get(fp);
      if (!identity) return this.notFound(res, fp);
      return this.json(res, {
        genesis_fingerprint: identity.genesis_fingerprint,
        chain: identity.chain,
        revocation: identity.revocation,
      } satisfies ExplorerChain);
    }

    // GET /api/v1/identity/:fingerprint
    const idMatch = path.match(/^\/api\/v1\/identity\/([^/]+)$/);
    if (idMatch) {
      const fp = idMatch[1]!;
      const identity = this.identities.get(fp);
      if (!identity) return this.notFound(res, fp);
      const { entry: current, status } = this.getCurrentState(identity);
      return this.json(res, {
        genesis_fingerprint: identity.genesis_fingerprint,
        current_fingerprint: current.fingerprint,
        name: current.name,
        key: { type: current.key_type, public: current.public_key },
        metadata: identity.metadata,
        status,
        chain_depth: identity.chain.length,
        created_block: identity.chain[0]!.block,
        last_supersession_block: identity.chain.length > 1 ? current.block : null,
        inscription_id: current.inscription_id,
        ref: {
          net: 'bip122:000000000019d6689c085ae165831e93',
          id: current.inscription_id,
        },
      } satisfies ExplorerIdentity);
    }

    // GET /api/v1/document/:txid
    const docMatch = path.match(/^\/api\/v1\/document\/([^/]+)$/);
    if (docMatch) {
      const txid = docMatch[1]!;
      const doc = this.documents.get(txid);
      if (!doc) return this.notFound(res, txid);
      return this.json(res, { ...doc, valid: true } satisfies ExplorerDocument);
    }

    res.writeHead(404);
    res.end(JSON.stringify({ error: { code: 'not_found', message: 'Unknown endpoint' } }));
  }

  private json(res: ServerResponse, data: unknown): void {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
  }

  private notFound(res: ServerResponse, id: string): void {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { code: 'not_found', message: `Not found: ${id}` } }));
  }
}
