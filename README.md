# atp-cli

Command-line tool for the [Agent Trust Protocol](https://atprotocol.io) — cryptographic identity and trust for AI agents, anchored to Bitcoin.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What is ATP?

ATP gives AI agents verifiable, decentralised identity. No central authority. No accounts. Just Ed25519 keys and Bitcoin inscriptions.

- **Identity** — Generate a keypair, build an identity document, inscribe it to Bitcoin
- **Attestation** — Vouch for other agents cryptographically
- **Verification** — Verify any ATP document from file or directly from a Bitcoin TXID
- **Supersession** — Rotate keys with dual-signed proof of continuity
- **Revocation** — Permanently revoke a compromised or defunct identity
- **Heartbeat** — Prove liveness with signed timestamps
- **Receipts** — Record exchanges between agents with co-signed proofs

Full spec: [atprotocol.io](https://atprotocol.io)

## Install

```bash
npm install -g atp-cli
```

Or use directly:

```bash
npx atp-cli <command>
```

## Quick Start

### Create an identity

```bash
atp identity create --name "MyAgent" --wallet bc1q...
```

This generates an Ed25519 keypair, saves the private key to `~/.atp/keys/<fingerprint>.json`, and outputs the signed identity document.

### Verify a document

From a file:

```bash
atp verify identity.json
```

From a Bitcoin inscription (requires Bitcoin RPC):

```bash
atp verify <txid> --rpc-url http://localhost:8332 --rpc-user bitcoin --rpc-pass secret
```

### Attest to another agent

```bash
atp attest <their-fingerprint> --from identity.json --claim identity --context "Met on Moltbook"
```

### Create a heartbeat

```bash
atp heartbeat --from identity.json --msg "still here"
```

### Supersede (key rotation)

```bash
atp identity create --name "MyAgent"  # generates new key
atp supersede --old old-identity.json --new new-identity.json --reason key-rotation
```

### Revoke an identity

```bash
atp revoke --identity identity.json --reason key-compromised
```

### Record an exchange

```bash
atp receipt create --from identity.json --with <counterparty-fp> --type service --description "Code review"
```

## Commands

| Command | Description |
|---------|-------------|
| `identity create` | Generate Ed25519 keypair and signed identity document |
| `identity show` | Display an identity document |
| `identity inscribe` | Build inscription envelope for Bitcoin |
| `verify` | Verify any ATP document (file or TXID) |
| `attest` | Create a signed attestation for another agent |
| `att-revoke` | Revoke a previously issued attestation |
| `supersede` | Create a dual-signed key rotation document |
| `revoke` | Permanently revoke an identity |
| `heartbeat` | Create a signed liveness proof |
| `receipt create` | Record a co-signed exchange between agents |

## Options

All document commands support:

- `--encoding <json|cbor>` — Output format (default: json)
- `--output <file>` — Write to file instead of stdout

Identity creation supports:

- `--handle-twitter <handle>` — Link Twitter handle
- `--handle-moltbook <handle>` — Link Moltbook handle
- `--handle-github <handle>` — Link GitHub handle
- `--handle-nostr <handle>` — Link Nostr handle
- `--wallet <address>` — Bitcoin payment address

## Document Types

| Type | Field | Description |
|------|-------|-------------|
| Identity | `id` | Agent identity with public key(s) |
| Attestation | `att` | Cryptographic vouch for another agent |
| Attestation Revocation | `att-revoke` | Revoke a previous attestation |
| Supersession | `super` | Key rotation with dual signatures |
| Revocation | `revoke` | Permanent identity revocation |
| Heartbeat | `hb` | Signed liveness proof |
| Receipt | `rcpt` | Co-signed exchange record |

## Key Storage

Private keys are stored in `~/.atp/keys/<fingerprint>.json`. Back these up securely — there is no recovery mechanism.

## MIME Types

- JSON: `application/atp.v1+json`
- CBOR: `application/atp.v1+cbor`

## Development

```bash
npm install
npm run build
npm test
npm run lint
npm run format
```

## First ATP Identity on Bitcoin

The first agent identity published to Bitcoin mainnet:

```
TXID: 6ffcca0cc29da514e784b27155e68c3d4c1ca2deeb6dc9ce020a4d7e184eaa1c
Fingerprint: erAHnt8G_oV4ANOborNzsAm2qSG_ikaQGA5cLpz8nVQ
```

## License

MIT

## Links

- [ATP Specification](https://atprotocol.io)
- [ATP Explorer](https://explorer.atprotocol.io)
- [Built by Shrike](https://shrikebot.io) 🪶
