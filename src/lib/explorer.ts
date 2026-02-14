/**
 * ATP Explorer API client.
 * Used for identity resolution, chain walking, and document discovery.
 * All data returned by the explorer is verified against Bitcoin RPC before use.
 */

export interface ExplorerIdentity {
  genesis_fingerprint: string;
  current_fingerprint: string;
  name: string;
  key: {
    type: string;
    public: string; // base64url
  };
  metadata: Record<string, unknown>;
  status: string;
  chain_depth: number;
  created_block: number;
  last_supersession_block: number | null;
  inscription_id: string;
  ref: {
    net: string;
    id: string;
  };
}

export interface ChainEntry {
  fingerprint: string;
  name: string;
  key_type: string;
  public_key: string; // base64url
  inscription_id: string;
  block: number;
  type: 'id' | 'super';
  reason?: string;
}

export interface ExplorerChain {
  genesis_fingerprint: string;
  chain: ChainEntry[];
  revocation: {
    inscription_id: string;
    reason: string;
    block: number;
    signed_by: string; // fingerprint of the revoking key
  } | null;
}

export interface ExplorerDocument {
  txid: string;
  block: number;
  block_hash: string;
  confirmations: number;
  content_type: string;
  document: Record<string, unknown>;
  valid: boolean;
}

export interface ExplorerInfo {
  name: string;
  version: string;
  chains: string[];
  latest_block: number;
  indexed_identities: number;
  indexed_documents: number;
  policies: {
    revocation_depth_limit: number | null;
    supersession_rate_flag_blocks: number;
    min_confirmations_for_finality: number;
  };
}

export class ExplorerClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    // Strip trailing slash
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async fetch<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const res = await globalThis.fetch(url);
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      let errorMsg = `Explorer API error: ${res.status}`;
      try {
        const parsed = JSON.parse(body);
        if (parsed.error?.message) errorMsg = `Explorer: ${parsed.error.message}`;
      } catch {
        /* use default */
      }
      throw new Error(errorMsg);
    }
    return res.json() as Promise<T>;
  }

  async getIdentity(fingerprint: string): Promise<ExplorerIdentity> {
    return this.fetch<ExplorerIdentity>(`/api/v1/identity/${fingerprint}`);
  }

  async getChain(fingerprint: string): Promise<ExplorerChain> {
    return this.fetch<ExplorerChain>(`/api/v1/identity/${fingerprint}/chain`);
  }

  async getDocument(txid: string): Promise<ExplorerDocument> {
    return this.fetch<ExplorerDocument>(`/api/v1/document/${txid}`);
  }

  async getInfo(): Promise<ExplorerInfo> {
    return this.fetch<ExplorerInfo>(`/api/v1/info`);
  }
}
