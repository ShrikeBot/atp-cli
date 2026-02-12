/**
 * Mock BitcoinRPC that delegates to MockChain instead of HTTP.
 */
import { MockChain } from './mock-chain.js';

export class MockBitcoinRPC {
  constructor(public chain: MockChain) {}

  async call(method: string, params: unknown[] = []): Promise<unknown> {
    switch (method) {
      case 'getrawtransaction':
        return this.chain.getRawTransaction(params[0] as string);
      case 'sendrawtransaction':
        return this.chain.sendRawTransaction(params[0] as string);
      default:
        throw new Error(`Unsupported RPC method: ${method}`);
    }
  }

  async getRawTransaction(txid: string, _verbose = true): Promise<unknown> {
    return this.chain.getRawTransaction(txid);
  }

  async sendRawTransaction(hex: string): Promise<unknown> {
    return this.chain.sendRawTransaction(hex);
  }
}
