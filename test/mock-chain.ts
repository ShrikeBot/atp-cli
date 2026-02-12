/**
 * In-memory mock Bitcoin blockchain for ATP integration testing.
 */
import { createHash } from 'node:crypto';
import { buildInscriptionEnvelope } from '../src/lib/inscription.js';

export interface MockTransaction {
  txid: string;
  witnessHex: string;
  blockHeight: number;
  blockIndex: number; // ordering within block
}

export class MockChain {
  private transactions = new Map<string, MockTransaction>();
  private currentHeight = 100;
  private blockIndex = 0;

  /** Reset chain state */
  reset(): void {
    this.transactions.clear();
    this.currentHeight = 100;
    this.blockIndex = 0;
  }

  /** Inscribe an ATP document onto the mock chain. Returns the TXID. */
  inscribe(data: Buffer, contentType = 'application/atp.v1+json'): string {
    const envelope = buildInscriptionEnvelope(data, contentType);
    const witnessHex = envelope.toString('hex');
    const txid = createHash('sha256').update(data).update(String(Date.now() + Math.random())).digest('hex');

    this.transactions.set(txid, {
      txid,
      witnessHex,
      blockHeight: this.currentHeight,
      blockIndex: this.blockIndex++,
    });

    return txid;
  }

  /** Inscribe a JSON document */
  inscribeJson(doc: Record<string, unknown>): string {
    const data = Buffer.from(JSON.stringify(doc, null, 2), 'utf8');
    return this.inscribe(data, 'application/atp.v1+json');
  }

  /** Get raw transaction (mimics bitcoind getrawtransaction verbose) */
  getRawTransaction(txid: string): unknown {
    const tx = this.transactions.get(txid);
    if (!tx) throw new Error(`Transaction ${txid} not found`);
    return {
      txid: tx.txid,
      confirmations: this.currentHeight - tx.blockHeight + 1,
      vin: [{ txinwitness: [tx.witnessHex] }],
    };
  }

  /** Accept a raw transaction hex (stub) */
  sendRawTransaction(_hex: string): string {
    const txid = createHash('sha256').update(_hex).digest('hex');
    return txid;
  }

  /** Advance block height */
  mine(blocks = 1): void {
    this.currentHeight += blocks;
    this.blockIndex = 0;
  }

  /** Check if TXID exists */
  has(txid: string): boolean {
    return this.transactions.has(txid);
  }

  /** Get transaction details */
  get(txid: string): MockTransaction | undefined {
    return this.transactions.get(txid);
  }

  /** Compare inscription ordering (which came first) */
  isBefore(txidA: string, txidB: string): boolean {
    const a = this.transactions.get(txidA);
    const b = this.transactions.get(txidB);
    if (!a || !b) throw new Error('TXID not found');
    if (a.blockHeight !== b.blockHeight) return a.blockHeight < b.blockHeight;
    return a.blockIndex < b.blockIndex;
  }
}
