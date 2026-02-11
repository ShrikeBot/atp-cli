import { request } from 'node:http';
import { request as httpsRequest } from 'node:https';

export class BitcoinRPC {
  private url: URL;
  private auth: string;

  constructor(url: string, user: string, pass: string) {
    this.url = new URL(url);
    this.auth = Buffer.from(`${user}:${pass}`).toString('base64');
  }

  async call(method: string, params: unknown[] = []): Promise<unknown> {
    const body = JSON.stringify({ jsonrpc: '2.0', id: 1, method, params });
    const reqFn = this.url.protocol === 'https:' ? httpsRequest : request;

    return new Promise((resolve, reject) => {
      const req = reqFn(
        this.url,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Basic ${this.auth}`,
          },
        },
        (res) => {
          let data = '';
          res.on('data', (chunk: string) => (data += chunk));
          res.on('end', () => {
            try {
              const json = JSON.parse(data);
              if (json.error) reject(new Error(json.error.message));
              else resolve(json.result);
            } catch (e) {
              reject(e);
            }
          });
        },
      );
      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }

  async getRawTransaction(txid: string, verbose = true): Promise<unknown> {
    return this.call('getrawtransaction', [txid, verbose]);
  }

  async sendRawTransaction(hex: string): Promise<unknown> {
    return this.call('sendrawtransaction', [hex]);
  }
}
