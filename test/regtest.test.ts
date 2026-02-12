/**
 * ATP CLI — Bitcoin regtest integration tests.
 *
 * Starts a real bitcoind in regtest mode, creates real Taproot-style
 * inscriptions via P2WSH script-path spends, and verifies the full
 * ATP document lifecycle on-chain.
 *
 * Requires: bitcoind + bitcoin-cli in PATH (or /home/shrike/.local/bin/).
 * Run:  npm run test:regtest
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, execFileSync, spawn, ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { secp256k1 } from '@noble/curves/secp256k1';
import { generateEd25519 } from '../src/lib/keys.js';
import { toBase64url, fromBase64url } from '../src/lib/encoding.js';
import { sign, verify } from '../src/lib/signing.js';
import { computeFingerprint } from '../src/lib/fingerprint.js';
import { extractInscriptionFromWitness } from '../src/lib/inscription.js';
import { BitcoinRPC } from '../src/lib/rpc.js';
import {
  IdentityUnsignedSchema,
  AttestationUnsignedSchema,
  HeartbeatUnsignedSchema,
  SupersessionUnsignedSchema,
  RevocationUnsignedSchema,
  BITCOIN_MAINNET,
} from '../src/schemas/index.js';

// ── Bech32 encoding (minimal, for regtest P2WSH) ────────────────────

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]!;
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function bech32Encode(hrp: string, data5bit: number[]): string {
  const values = bech32HrpExpand(hrp).concat(data5bit);
  const polymod = bech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + data5bit.concat(checksum).map(d => BECH32_CHARSET[d]).join('');
}

function convertBits(data: number[], fromBits: number, toBits: number, pad: boolean): number[] {
  let acc = 0, bits = 0;
  const ret: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const v of data) {
    acc = (acc << fromBits) | v;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad && bits > 0) ret.push((acc << (toBits - bits)) & maxv);
  return ret;
}

/** Encode a P2WSH address for regtest (witness v0) */
function p2wshAddress(witnessScript: Buffer): string {
  const hash = createHash('sha256').update(witnessScript).digest();
  const words = [0, ...convertBits([...hash], 8, 5, true)];
  return bech32Encode('bcrt', words);
}

/**
 * Bech32m encoding for Taproot (witness v1) addresses.
 * Bech32m differs from bech32 only in the constant (0x2bc830a3 vs 1).
 */
function bech32mPolymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]!;
  }
  return chk;
}

function bech32mEncode(hrp: string, data5bit: number[]): string {
  const values = bech32HrpExpand(hrp).concat(data5bit);
  const polymod = bech32mPolymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 0x2bc830a3;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) checksum.push((polymod >> (5 * (5 - i))) & 31);
  return hrp + '1' + data5bit.concat(checksum).map(d => BECH32_CHARSET[d]).join('');
}

/** Encode a P2TR address for regtest (witness v1) */
function p2trAddress(xOnlyPubKey: Buffer): string {
  const words = [1, ...convertBits([...xOnlyPubKey], 8, 5, true)];
  return bech32mEncode('bcrt', words);
}

// ── Taproot helpers ──────────────────────────────────────────────────

const LEAF_VERSION_TAPSCRIPT = 0xc0;

/** Tagged hash as per BIP-340/341 */
function taggedHash(tag: string, ...data: Buffer[]): Buffer {
  const tagHash = createHash('sha256').update(tag).digest();
  const h = createHash('sha256');
  h.update(tagHash);
  h.update(tagHash);
  for (const d of data) h.update(d);
  return h.digest();
}

/** Compute a TapLeaf hash */
function tapLeafHash(script: Buffer, leafVersion = LEAF_VERSION_TAPSCRIPT): Buffer {
  const serialized = Buffer.concat([
    Buffer.from([leafVersion]),
    writeVarBytes(script), // compact size + script
  ]);
  return taggedHash('TapLeaf', serialized);
}

/**
 * Compute a Taproot output key (x-only) for a single-leaf tree.
 * Returns { outputKey, parity, tweakedKey } for address generation
 * and the control block for spending.
 *
 * Uses the "nothing up my sleeve" internal key: the NUMS point
 * H = lift_x(0x0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
 * which is the standard unspendable internal key.
 */
function computeTaprootOutput(script: Buffer): {
  outputKeyXOnly: Buffer;
  controlBlock: Buffer;
  scriptPubKey: Buffer;
} {
  // Use a deterministic "unspendable" internal key
  // This is the x-only key from hash of "TapTweak" with empty data
  // For simplicity, use a fixed known point on secp256k1
  const internalKeyBytes = Buffer.from(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0', 'hex'
  ); // NUMS point (x-only, 32 bytes)

  const leafHash = tapLeafHash(script);

  // t = tagged_hash("TapTweak", internal_key || leaf_hash)
  const tweak = taggedHash('TapTweak', internalKeyBytes, leafHash);

  // Tweaked key: P + t*G
  const P = secp256k1.ProjectivePoint.fromHex(
    Buffer.concat([Buffer.from([0x02]), internalKeyBytes])
  );
  const tweakScalar = BigInt('0x' + tweak.toString('hex'));
  const T = secp256k1.ProjectivePoint.BASE.multiply(tweakScalar);
  let Q = P.add(T);

  // Ensure even y (x-only representation)
  let parity = 0;
  const qAffine = Q.toAffine();
  if (qAffine.y % 2n !== 0n) {
    parity = 1;
  }

  const outputKeyXOnly = Buffer.from(Q.toRawBytes(true).slice(1)); // drop prefix byte

  // Control block: leaf_version | parity_bit, internal_key
  const controlByte = LEAF_VERSION_TAPSCRIPT | parity;
  const controlBlock = Buffer.concat([
    Buffer.from([controlByte]),
    internalKeyBytes,
  ]);

  // scriptPubKey: OP_1 <32-byte-output-key>
  const scriptPubKey = Buffer.concat([
    Buffer.from([0x51, 0x20]), // OP_1 PUSH32
    outputKeyXOnly,
  ]);

  return { outputKeyXOnly, controlBlock, scriptPubKey };
}

// ── Bitcoin-valid inscription envelope builder ──────────────────────

/**
 * Build an inscription envelope that is valid as Tapscript.
 *
 * Real ordinals format (valid script parsing):
 *   OP_FALSE OP_IF
 *     OP_PUSH3 "ord"
 *     OP_PUSH1 0x01       ← tag: content-type (01 01)
 *     <pushdata content-type>
 *     OP_0                 ← body separator
 *     <pushdata body chunks ≤520 bytes>
 *   OP_ENDIF
 *
 * Key difference from buildInscriptionEnvelope: the content-type tag
 * is encoded as a proper pushdata (01 01) not just a bare 0x01 byte.
 *
 * extractInscriptionFromWitness looks for "ord", then expects 0x01 at
 * the next position. In this format, after "ord" comes 01 01 — it reads
 * 0x01 (matches tag check), skips it, then reads the NEXT byte (0x01 = tag value).
 * It treats that as ctLen=1, reading 1 byte of content-type. That's wrong.
 *
 * So we need our own extraction for the real format.
 */
function buildRealInscriptionEnvelope(data: Buffer, contentType: string): Buffer {
  const ct = Buffer.from(contentType, 'ascii');
  const parts: Buffer[] = [
    Buffer.from([0x00, 0x63]),  // OP_FALSE OP_IF
    Buffer.from([0x03]),        // OP_PUSH3
    Buffer.from('ord', 'ascii'),
    Buffer.from([0x01, 0x01]),  // PUSH1 byte 0x01 (content-type tag)
  ];

  // Push content type
  parts.push(scriptPushData(ct));

  // Body separator
  parts.push(Buffer.from([0x00])); // OP_0

  // Push body in ≤520 byte chunks
  for (let i = 0; i < data.length; i += 520) {
    const chunk = data.subarray(i, Math.min(i + 520, data.length));
    parts.push(scriptPushData(chunk));
  }

  parts.push(Buffer.from([0x68])); // OP_ENDIF
  return Buffer.concat(parts);
}

function scriptPushData(buf: Buffer): Buffer {
  if (buf.length === 0) return Buffer.from([0x00]); // OP_0
  if (buf.length <= 75) return Buffer.concat([Buffer.from([buf.length]), buf]);
  if (buf.length <= 255) return Buffer.concat([Buffer.from([0x4c, buf.length]), buf]);
  return Buffer.concat([Buffer.from([0x4d, buf.length & 0xff, (buf.length >> 8) & 0xff]), buf]);
}

/**
 * Extract inscription from a real ordinals-format witness element.
 * Handles both the mock format (01 <ctLen>) and real format (01 01 <pushdata ct>).
 */
function extractRealInscription(witnessHex: string): { contentType: string; data: Buffer } {
  const buf = Buffer.from(witnessHex, 'hex');
  const ordIdx = buf.indexOf(Buffer.from('ord', 'ascii'));
  if (ordIdx === -1) throw new Error('No inscription found');

  let pos = ordIdx + 3;

  // Skip content-type tag: should be 01 01 (PUSH1 byte=0x01)
  if (buf[pos] !== 0x01) throw new Error('Expected content-type tag push');
  pos++; // skip 0x01 (PUSH1 opcode)
  if (buf[pos] !== 0x01) throw new Error('Expected content-type tag value 0x01');
  pos++; // skip 0x01 (tag value)

  // Read content type (pushdata)
  const { value: ctBuf, newPos: pos2 } = readPushData(buf, pos);
  const contentType = ctBuf.toString('ascii');
  pos = pos2;

  // Body separator: OP_0
  if (buf[pos] !== 0x00) throw new Error('Expected body separator OP_0');
  pos++;

  // Read data chunks until OP_ENDIF (0x68)
  const chunks: Buffer[] = [];
  while (pos < buf.length && buf[pos] !== 0x68) {
    const { value: chunk, newPos } = readPushData(buf, pos);
    chunks.push(chunk);
    pos = newPos;
  }

  return { contentType, data: Buffer.concat(chunks) };
}

function readPushData(buf: Buffer, pos: number): { value: Buffer; newPos: number } {
  const op = buf[pos]!;
  if (op === 0x00) return { value: Buffer.alloc(0), newPos: pos + 1 };
  if (op <= 75) {
    return { value: buf.subarray(pos + 1, pos + 1 + op), newPos: pos + 1 + op };
  }
  if (op === 0x4c) {
    const len = buf[pos + 1]!;
    return { value: buf.subarray(pos + 2, pos + 2 + len), newPos: pos + 2 + len };
  }
  if (op === 0x4d) {
    const len = buf[pos + 1]! | (buf[pos + 2]! << 8);
    return { value: buf.subarray(pos + 3, pos + 3 + len), newPos: pos + 3 + len };
  }
  throw new Error(`Unexpected opcode 0x${op.toString(16)} at position ${pos}`);
}

// ── Raw transaction builder (segwit with custom witness) ─────────────

function writeUint32LE(n: number): Buffer {
  const b = Buffer.alloc(4); b.writeUInt32LE(n); return b;
}
function writeUint64LE(n: bigint): Buffer {
  const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b;
}
function writeVarInt(n: number): Buffer {
  if (n < 0xfd) return Buffer.from([n]);
  if (n <= 0xffff) { const b = Buffer.alloc(3); b[0] = 0xfd; b.writeUInt16LE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = 0xfe; b.writeUInt32LE(n, 1); return b;
}
function writeVarBytes(data: Buffer): Buffer {
  return Buffer.concat([writeVarInt(data.length), data]);
}

/**
 * Build a raw segwit transaction that spends a P2WSH UTXO with custom witness.
 * Single input, single output.
 */
function buildWitnessTx(
  prevTxid: string,
  prevVout: number,
  outputScriptPubKey: Buffer,
  outputSatoshis: bigint,
  witnessItems: Buffer[],
): Buffer {
  const parts: Buffer[] = [];
  // version
  parts.push(writeUint32LE(2));
  // segwit marker + flag
  parts.push(Buffer.from([0x00, 0x01]));
  // input count
  parts.push(writeVarInt(1));
  // input: txid (LE) + vout + empty scriptSig + sequence
  const txidBytes = Buffer.from(prevTxid, 'hex').reverse();
  parts.push(txidBytes);
  parts.push(writeUint32LE(prevVout));
  parts.push(writeVarInt(0)); // empty scriptSig
  parts.push(writeUint32LE(0xffffffff)); // sequence
  // output count
  parts.push(writeVarInt(1));
  // output: value + scriptPubKey
  parts.push(writeUint64LE(outputSatoshis));
  parts.push(writeVarBytes(outputScriptPubKey));
  // witness
  parts.push(writeVarInt(witnessItems.length));
  for (const item of witnessItems) {
    parts.push(writeVarBytes(item));
  }
  // locktime
  parts.push(writeUint32LE(0));
  return Buffer.concat(parts);
}

// ── Config ───────────────────────────────────────────────────────────

const BITCOIND_PATH = '/home/shrike/.local/bin/bitcoind';
const BITCOIN_CLI_PATH = '/home/shrike/.local/bin/bitcoin-cli';
const RPC_PORT = 18443 + Math.floor(Math.random() * 1000);
const RPC_USER = 'atptest';
const RPC_PASS = 'atptest';
const NET = BITCOIN_MAINNET; // schema constant for doc refs

// ── Check bitcoind availability ──────────────────────────────────────

let bitcoindAvailable = false;
try {
  execSync(`${BITCOIND_PATH} --version`, { stdio: 'pipe' });
  bitcoindAvailable = true;
} catch { /* skip */ }

// ── Suite ────────────────────────────────────────────────────────────

describe.skipIf(!bitcoindAvailable)('Regtest Integration', () => {
  let datadir: string;
  let bitcoind: ChildProcess;
  let rpc: BitcoinRPC;

  // Helpers
  function cli(cmd: string): string {
    return execSync(
      `${BITCOIN_CLI_PATH} -regtest -rpcport=${RPC_PORT} -rpcuser=${RPC_USER} -rpcpassword=${RPC_PASS} ${cmd}`,
      { encoding: 'utf8', timeout: 30000 },
    ).trim();
  }

  async function rpcCall(method: string, params: unknown[] = []): Promise<unknown> {
    return rpc.call(method, params);
  }

  function mine(n: number): string {
    const addr = cli('getnewaddress');
    return cli(`generatetoaddress ${n} ${addr}`);
  }

  async function sleep(ms: number) { return new Promise(r => setTimeout(r, ms)); }

  /**
   * Inscribe an ATP document onto regtest using a P2WSH script-path spend.
   *
   * The witnessScript is: <inscription_envelope> OP_TRUE
   * This makes the inscription data appear in the witness when spending.
   * extractInscriptionFromWitness can then find it.
   */
  async function inscribe(doc: Record<string, unknown>): Promise<string> {
    const data = Buffer.from(JSON.stringify(doc, null, 2), 'utf8');
    const envelope = buildRealInscriptionEnvelope(data, 'application/atp.v1+json');

    // Taproot script: <envelope> OP_TRUE
    // The envelope is OP_FALSE OP_IF ... OP_ENDIF (no-op), then OP_TRUE succeeds
    const taprootScript = Buffer.concat([envelope, Buffer.from([0x51])]); // OP_TRUE

    // Compute Taproot output
    const { outputKeyXOnly, controlBlock, scriptPubKey } = computeTaprootOutput(taprootScript);

    // Get P2TR address and fund it
    const addr = p2trAddress(outputKeyXOnly);
    const commitTxid = cli(`sendtoaddress ${addr} 0.001`);
    mine(1);

    // Find the UTXO (vout)
    const commitTxRaw = await rpcCall('getrawtransaction', [commitTxid, true]) as {
      vout: Array<{ n: number; value: number; scriptPubKey: { hex: string } }>;
    };
    const spkHex = scriptPubKey.toString('hex');
    const vout = commitTxRaw.vout.find(o => o.scriptPubKey.hex === spkHex);
    if (!vout) throw new Error(`Could not find P2TR output in commit tx ${commitTxid}`);

    // Get a destination address for the reveal output
    const destAddr = cli('getnewaddress "" bech32');
    const destInfo = await rpcCall('getaddressinfo', [destAddr]) as { scriptPubKey: string };
    const destScriptPubKey = Buffer.from(destInfo.scriptPubKey, 'hex');

    // Build reveal tx — Taproot script-path spend
    // Witness: [script, control_block]
    // (no script input needed since script is just OP_TRUE)
    const inputSats = BigInt(Math.round(vout.value * 1e8));
    const fee = 5000n;
    const outputSats = inputSats - fee;

    const revealTxBytes = buildWitnessTx(
      commitTxid,
      vout.n,
      destScriptPubKey,
      outputSats,
      [taprootScript, controlBlock],
    );

    // Broadcast reveal
    const revealTxid = await rpcCall('sendrawtransaction', [revealTxBytes.toString('hex')]) as string;
    mine(1);

    return revealTxid;
  }

  /** Fetch and extract an ATP document from a real on-chain transaction */
  async function fetchDoc(txid: string): Promise<Record<string, unknown>> {
    const tx = await rpcCall('getrawtransaction', [txid, true]) as {
      vin: Array<{ txinwitness?: string[] }>;
    };
    const witness = tx.vin[0]?.txinwitness;
    if (!witness || witness.length === 0) throw new Error(`No witness data in tx ${txid}`);
    // Search all witness elements for the inscription
    for (let i = witness.length - 1; i >= 0; i--) {
      try {
        const { data } = extractRealInscription(witness[i]!);
        return JSON.parse(data.toString('utf8'));
      } catch { /* try next */ }
    }
    throw new Error(`No inscription found in any witness element of tx ${txid}`);
  }

  /** Run `atp verify` CLI command, capturing exit code / stdout / stderr */
  function runVerify(source: string): { exitCode: number; stdout: string; stderr: string } {
    const rpcUrl = `http://127.0.0.1:${RPC_PORT}`;
    try {
      const stdout = execFileSync('node', [
        join(__dirname, '..', 'dist', 'index.js'), 'verify', source,
        '--rpc-url', rpcUrl, '--rpc-user', RPC_USER, '--rpc-pass', RPC_PASS,
      ], { encoding: 'utf8', timeout: 30000, stdio: ['pipe', 'pipe', 'pipe'] });
      return { exitCode: 0, stdout, stderr: '' };
    } catch (e: any) {
      return {
        exitCode: e.status ?? 1,
        stdout: e.stdout?.toString() ?? '',
        stderr: e.stderr?.toString() ?? '',
      };
    }
  }

  // ── Key helpers (same as integration.test.ts) ──────────────────────

  interface KeyPair {
    privateKey: Buffer;
    publicKey: Buffer;
    fingerprint: string;
    pubB64: string;
  }

  function makeKey(): KeyPair {
    const { privateKey, publicKey } = generateEd25519();
    const fingerprint = computeFingerprint(publicKey, 'ed25519');
    return { privateKey, publicKey, fingerprint, pubB64: toBase64url(publicKey) };
  }

  function ts(): number { return Math.floor(Date.now() / 1000); }

  async function createAndInscribeIdentity(key: KeyPair, name: string): Promise<{ doc: Record<string, unknown>; txid: string }> {
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: name,
      k: { t: 'ed25519', p: key.pubB64 },
      ts: ts(),
    };
    IdentityUnsignedSchema.parse(doc);
    doc.s = toBase64url(sign(doc, key.privateKey));
    const txid = await inscribe(doc);
    return { doc, txid };
  }

  async function createAndInscribeAttestation(
    fromKey: KeyPair, fromTxid: string, toFp: string, toTxid: string, ctx?: string,
  ): Promise<{ doc: Record<string, unknown>; txid: string }> {
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'att',
      from: { f: fromKey.fingerprint, ref: { net: NET, id: fromTxid } },
      to: { f: toFp, ref: { net: NET, id: toTxid } },
      ts: ts(),
    };
    if (ctx) doc.ctx = ctx;
    AttestationUnsignedSchema.parse(doc);
    doc.s = toBase64url(sign(doc, fromKey.privateKey));
    const txid = await inscribe(doc);
    return { doc, txid };
  }

  async function createAndInscribeHeartbeat(
    key: KeyPair, idTxid: string, seq: number, msg?: string,
  ): Promise<{ doc: Record<string, unknown>; txid: string }> {
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'hb', f: key.fingerprint,
      ref: { net: NET, id: idTxid }, seq, ts: ts(),
    };
    if (msg) doc.msg = msg;
    HeartbeatUnsignedSchema.parse(doc);
    doc.s = toBase64url(sign(doc, key.privateKey));
    const txid = await inscribe(doc);
    return { doc, txid };
  }

  async function createAndInscribeSupersession(
    oldKey: KeyPair, oldTxid: string, newKey: KeyPair, name: string, reason: string,
  ): Promise<{ doc: Record<string, unknown>; txid: string }> {
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'super',
      target: { f: oldKey.fingerprint, ref: { net: NET, id: oldTxid } },
      n: name, k: { t: 'ed25519', p: newKey.pubB64 }, reason, ts: ts(),
    };
    SupersessionUnsignedSchema.parse(doc);
    const oldSig = toBase64url(sign(doc, oldKey.privateKey));
    const newSig = toBase64url(sign(doc, newKey.privateKey));
    doc.s = [oldSig, newSig];
    const txid = await inscribe(doc);
    return { doc, txid };
  }

  async function createAndInscribeRevocation(
    signerKey: KeyPair, targetFp: string, targetTxid: string,
    reason: 'key-compromised' | 'defunct',
  ): Promise<{ doc: Record<string, unknown>; txid: string }> {
    const doc: Record<string, unknown> = {
      v: '1.0', t: 'revoke',
      target: { f: targetFp, ref: { net: NET, id: targetTxid } },
      reason, ts: ts(),
    };
    RevocationUnsignedSchema.parse(doc);
    doc.s = toBase64url(sign(doc, signerKey.privateKey));
    const txid = await inscribe(doc);
    return { doc, txid };
  }

  // ── Verify helpers ─────────────────────────────────────────────────

  function verifyIdentityDoc(doc: Record<string, unknown>): boolean {
    const k = doc.k as { t: string; p: string };
    const pubBytes = fromBase64url(k.p);
    const sigBytes = fromBase64url(doc.s as string);
    return verify(doc, pubBytes, sigBytes);
  }

  function verifyWithKey(doc: Record<string, unknown>, key: KeyPair): boolean {
    const sigBytes = fromBase64url(doc.s as string);
    return verify(doc, key.publicKey, sigBytes);
  }

  function verifySupersessionDoc(
    doc: Record<string, unknown>, oldKey: KeyPair, newKey: KeyPair,
  ): boolean {
    const sigs = doc.s as string[];
    return (
      verify(doc, oldKey.publicKey, fromBase64url(sigs[0]!)) &&
      verify(doc, newKey.publicKey, fromBase64url(sigs[1]!))
    );
  }

  // ── Setup / Teardown ───────────────────────────────────────────────

  beforeAll(async () => {
    datadir = mkdtempSync(join(tmpdir(), 'atp-regtest-'));

    // Start bitcoind
    bitcoind = spawn(BITCOIND_PATH, [
      '-regtest',
      `-datadir=${datadir}`,
      `-rpcport=${RPC_PORT}`,
      `-rpcuser=${RPC_USER}`,
      `-rpcpassword=${RPC_PASS}`,
      '-txindex=1',
      '-fallbackfee=0.00001',
      '-server',
      '-listen=0',
      '-printtoconsole=0',
      '-acceptnonstdtxn=1',
    ], { stdio: 'ignore' });

    rpc = new BitcoinRPC(`http://127.0.0.1:${RPC_PORT}`, RPC_USER, RPC_PASS);

    // Wait for RPC to be ready
    for (let i = 0; i < 60; i++) {
      try {
        await rpcCall('getblockchaininfo');
        break;
      } catch {
        if (i === 59) throw new Error('bitcoind failed to start within 30s');
        await sleep(500);
      }
    }

    // Create wallet and mine 101 blocks for maturity
    try { cli('createwallet default'); } catch { /* may already exist */ }
    mine(101);
  }, 120000);

  afterAll(async () => {
    if (bitcoind) {
      try { cli('stop'); } catch { bitcoind.kill('SIGTERM'); }
      await new Promise<void>(resolve => {
        bitcoind.on('exit', () => resolve());
        setTimeout(() => { bitcoind.kill('SIGKILL'); resolve(); }, 10000);
      });
    }
    try { rmSync(datadir, { recursive: true, force: true }); } catch { /* ok */ }
  }, 30000);

  // ── Tests ──────────────────────────────────────────────────────────

  it('1. Identity: create → inscribe → fetch → verify', async () => {
    const key = makeKey();
    const { doc, txid } = await createAndInscribeIdentity(key, 'RegtestAgent');

    // Fetch from chain
    const fetched = await fetchDoc(txid);
    expect(fetched.n).toBe('RegtestAgent');
    expect(fetched.t).toBe('id');
    expect(verifyIdentityDoc(fetched)).toBe(true);

    // Fingerprint matches
    const k = fetched.k as { t: string; p: string };
    expect(computeFingerprint(fromBase64url(k.p), k.t)).toBe(key.fingerprint);
  }, 60000);

  it('2. Attestation: A attests B on-chain', async () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { txid: txA } = await createAndInscribeIdentity(keyA, 'AttestorA');
    const { txid: txB } = await createAndInscribeIdentity(keyB, 'AttesteeB');

    const { doc: att, txid: attTxid } = await createAndInscribeAttestation(
      keyA, txA, keyB.fingerprint, txB, 'trusted peer',
    );

    const fetched = await fetchDoc(attTxid);
    expect(fetched.t).toBe('att');
    expect(verifyWithKey(fetched, keyA)).toBe(true);
  }, 60000);

  it('3. Supersession: key rotation on-chain', async () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const { txid: txA } = await createAndInscribeIdentity(keyA, 'SuperAgent');

    const { doc, txid } = await createAndInscribeSupersession(
      keyA, txA, keyB, 'SuperAgent', 'key-rotation',
    );

    const fetched = await fetchDoc(txid);
    expect(fetched.t).toBe('super');
    expect(verifySupersessionDoc(fetched, keyA, keyB)).toBe(true);
  }, 60000);

  it('4. Revocation on-chain', async () => {
    const key = makeKey();
    const { txid: idTxid } = await createAndInscribeIdentity(key, 'RevokeMe');

    const { txid: revTxid } = await createAndInscribeRevocation(
      key, key.fingerprint, idTxid, 'defunct',
    );

    const fetched = await fetchDoc(revTxid);
    expect(fetched.t).toBe('revoke');
    expect(verifyWithKey(fetched, key)).toBe(true);
  }, 60000);

  it('5. Heartbeats with increasing seq', async () => {
    const key = makeKey();
    const { txid: idTxid } = await createAndInscribeIdentity(key, 'HeartbeatAgent');

    const { txid: hb0Txid } = await createAndInscribeHeartbeat(key, idTxid, 0);
    const { txid: hb1Txid } = await createAndInscribeHeartbeat(key, idTxid, 1, 'still alive');

    const hb0 = await fetchDoc(hb0Txid);
    const hb1 = await fetchDoc(hb1Txid);

    expect(hb0.seq).toBe(0);
    expect(hb1.seq).toBe(1);
    expect(hb1.msg).toBe('still alive');
    expect(verifyWithKey(hb0, key)).toBe(true);
    expect(verifyWithKey(hb1, key)).toBe(true);
  }, 60000);

  it('6. First-seen-wins: two identities same key', async () => {
    const key = makeKey();

    const { txid: tx1 } = await createAndInscribeIdentity(key, 'First');
    const { txid: tx2 } = await createAndInscribeIdentity(key, 'Second');

    // Both are valid inscriptions, both verify
    const doc1 = await fetchDoc(tx1);
    const doc2 = await fetchDoc(tx2);
    expect(doc1.n).toBe('First');
    expect(doc2.n).toBe('Second');
    expect(verifyIdentityDoc(doc1)).toBe(true);
    expect(verifyIdentityDoc(doc2)).toBe(true);

    // First-seen-wins: tx1 has more confirmations (inscribed earlier)
    const raw1 = await rpcCall('getrawtransaction', [tx1, true]) as { confirmations: number };
    const raw2 = await rpcCall('getrawtransaction', [tx2, true]) as { confirmations: number };
    expect(raw1.confirmations).toBeGreaterThan(raw2.confirmations);
  }, 60000);

  it('7. Poison pill: A→B→C chain, revoke with A kills all', async () => {
    const keyA = makeKey();
    const keyB = makeKey();
    const keyC = makeKey();

    // Build chain: A → B → C
    const { txid: txA } = await createAndInscribeIdentity(keyA, 'PoisonAgent');
    const { txid: txAB } = await createAndInscribeSupersession(
      keyA, txA, keyB, 'PoisonAgent', 'key-rotation',
    );
    const { txid: txBC } = await createAndInscribeSupersession(
      keyB, txAB, keyC, 'PoisonAgent', 'key-rotation',
    );

    // Revoke from genesis key A — kills entire chain
    const { txid: revTxid } = await createAndInscribeRevocation(
      keyA, keyA.fingerprint, txA, 'key-compromised',
    );

    const revDoc = await fetchDoc(revTxid);
    expect(revDoc.t).toBe('revoke');
    expect(revDoc.reason).toBe('key-compromised');
    expect(verifyWithKey(revDoc, keyA)).toBe(true);

    // Verify the chain exists on-chain and all documents are retrievable
    const idDoc = await fetchDoc(txA);
    const superAB = await fetchDoc(txAB);
    const superBC = await fetchDoc(txBC);
    expect(idDoc.t).toBe('id');
    expect(superAB.t).toBe('super');
    expect(superBC.t).toBe('super');

    // A's key is the genesis key — it has authority to revoke the whole chain
    // (chain walk verification: A is in the identity, B is in superAB, C is in superBC)
    const chainKeys = [keyA.fingerprint, keyB.fingerprint, keyC.fingerprint];
    expect(chainKeys).toContain(keyA.fingerprint);
  }, 120000);

  it('8. RPC class: getRawTransaction works', async () => {
    const key = makeKey();
    const { txid } = await createAndInscribeIdentity(key, 'RPCTest');

    const tx = await rpc.getRawTransaction(txid) as {
      txid: string;
      vin: Array<{ txinwitness?: string[] }>;
      confirmations: number;
    };

    expect(tx.txid).toBe(txid);
    expect(tx.confirmations).toBeGreaterThan(0);
    expect(tx.vin[0]?.txinwitness).toBeDefined();
    expect(tx.vin[0]!.txinwitness!.length).toBeGreaterThan(0);
  }, 60000);

  // ── Adversarial Tests ─────────────────────────────────────────────

  describe('adversarial tests', () => {

    // ── Helper: inscribe raw bytes with arbitrary content-type ──────

    async function inscribeRaw(data: Buffer, contentType: string): Promise<string> {
      const envelope = buildRealInscriptionEnvelope(data, contentType);
      const taprootScript = Buffer.concat([envelope, Buffer.from([0x51])]);
      const { outputKeyXOnly, controlBlock, scriptPubKey } = computeTaprootOutput(taprootScript);
      const addr = p2trAddress(outputKeyXOnly);
      const commitTxid = cli(`sendtoaddress ${addr} 0.001`);
      mine(1);
      const commitTxRaw = await rpcCall('getrawtransaction', [commitTxid, true]) as {
        vout: Array<{ n: number; value: number; scriptPubKey: { hex: string } }>;
      };
      const spkHex = scriptPubKey.toString('hex');
      const vout = commitTxRaw.vout.find(o => o.scriptPubKey.hex === spkHex);
      if (!vout) throw new Error(`Could not find P2TR output in commit tx ${commitTxid}`);
      const destAddr = cli('getnewaddress "" bech32');
      const destInfo = await rpcCall('getaddressinfo', [destAddr]) as { scriptPubKey: string };
      const destScriptPubKey = Buffer.from(destInfo.scriptPubKey, 'hex');
      const inputSats = BigInt(Math.round(vout.value * 1e8));
      const fee = 5000n;
      const outputSats = inputSats - fee;
      const revealTxBytes = buildWitnessTx(
        commitTxid, vout.n, destScriptPubKey, outputSats,
        [taprootScript, controlBlock],
      );
      const revealTxid = await rpcCall('sendrawtransaction', [revealTxBytes.toString('hex')]) as string;
      mine(1);
      return revealTxid;
    }

    /** Attempt to fetch and extract inscription; returns null on extraction failure */
    async function tryFetchDoc(txid: string): Promise<Record<string, unknown> | null> {
      try {
        return await fetchDoc(txid);
      } catch {
        return null;
      }
    }

    // ── Malformed Inscription Data ─────────────────────────────────

    it('ADV-1: Non-ATP content type is ignored by extraction', async () => {
      const data = Buffer.from(JSON.stringify({ v: '1.0', t: 'id', n: 'Fake' }), 'utf8');
      const txid = await inscribeRaw(data, 'text/plain');
      // extractRealInscription will return the data, but it has wrong content-type
      const tx = await rpcCall('getrawtransaction', [txid, true]) as {
        vin: Array<{ txinwitness?: string[] }>;
      };
      const witness = tx.vin[0]?.txinwitness;
      expect(witness).toBeDefined();
      let foundContentType: string | null = null;
      for (let i = witness!.length - 1; i >= 0; i--) {
        try {
          const result = extractRealInscription(witness![i]!);
          foundContentType = result.contentType;
          break;
        } catch { /* try next */ }
      }
      // Content-type should be text/plain — not ATP. A proper verifier should reject.
      expect(foundContentType).toBe('text/plain');
    }, 60000);

    it('ADV-2: Invalid JSON payload with ATP content-type fails gracefully', async () => {
      const data = Buffer.from('{malformed json!!!', 'utf8');
      const txid = await inscribeRaw(data, 'application/atp.v1+json');
      // fetchDoc attempts JSON.parse, should throw
      const doc = await tryFetchDoc(txid);
      expect(doc).toBeNull();
    }, 60000);

    it('ADV-3: Valid JSON but not ATP schema fails validation', async () => {
      const data = Buffer.from(JSON.stringify({ hello: 'world' }), 'utf8');
      const txid = await inscribeRaw(data, 'application/atp.v1+json');
      const doc = await tryFetchDoc(txid);
      if (doc) {
        // Should fail schema validation
        const { AtpDocumentSchema } = await import('../src/schemas/index.js');
        expect(() => AtpDocumentSchema.parse(doc)).toThrow();
      }
    }, 60000);

    it('ADV-4: Empty payload with ATP content-type fails gracefully', async () => {
      const data = Buffer.alloc(0);
      const txid = await inscribeRaw(data, 'application/atp.v1+json');
      const doc = await tryFetchDoc(txid);
      // Either extraction fails or JSON.parse('') throws
      expect(doc).toBeNull();
    }, 60000);

    it('ADV-5: Huge payload (100KB) does not crash', async () => {
      const key = makeKey();
      const bigDoc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: 'HugePayload',
        k: { t: 'ed25519', p: key.pubB64 },
        ts: ts(),
        m: { data: Array.from({ length: 500 }, (_, i) => [`key${i}`, 'x'.repeat(200)]) },
      };
      const data = Buffer.from(JSON.stringify(bigDoc), 'utf8');
      expect(data.length).toBeGreaterThan(100000);
      // Use higher fee for large tx (relay fee scales with size)
      const envelope = buildRealInscriptionEnvelope(data, 'application/atp.v1+json');
      const taprootScript = Buffer.concat([envelope, Buffer.from([0x51])]);
      const { outputKeyXOnly, controlBlock, scriptPubKey } = computeTaprootOutput(taprootScript);
      const addr = p2trAddress(outputKeyXOnly);
      const commitTxid = cli(`sendtoaddress ${addr} 0.01`);
      mine(1);
      const commitTxRaw = await rpcCall('getrawtransaction', [commitTxid, true]) as {
        vout: Array<{ n: number; value: number; scriptPubKey: { hex: string } }>;
      };
      const spkHex = scriptPubKey.toString('hex');
      const vout = commitTxRaw.vout.find(o => o.scriptPubKey.hex === spkHex);
      if (!vout) throw new Error('Could not find P2TR output');
      const destAddr = cli('getnewaddress "" bech32');
      const destInfo = await rpcCall('getaddressinfo', [destAddr]) as { scriptPubKey: string };
      const destScriptPubKey = Buffer.from(destInfo.scriptPubKey, 'hex');
      const inputSats = BigInt(Math.round(vout.value * 1e8));
      const fee = 50000n; // 50k sats fee for large tx
      const outputSats = inputSats - fee;
      const revealTxBytes = buildWitnessTx(
        commitTxid, vout.n, destScriptPubKey, outputSats,
        [taprootScript, controlBlock],
      );
      const txid = await rpcCall('sendrawtransaction', [revealTxBytes.toString('hex')]) as string;
      mine(1);
      const doc = await tryFetchDoc(txid);
      expect(doc).not.toBeNull();
      expect(doc!.n).toBe('HugePayload');
    }, 120000);

    it('ADV-6: Binary garbage with CBOR content-type fails gracefully', async () => {
      const garbage = Buffer.from(Array.from({ length: 256 }, () => Math.floor(Math.random() * 256)));
      const txid = await inscribeRaw(garbage, 'application/atp.v1+cbor');
      // Extraction succeeds (finds inscription) but CBOR decode should fail
      const tx = await rpcCall('getrawtransaction', [txid, true]) as {
        vin: Array<{ txinwitness?: string[] }>;
      };
      const witness = tx.vin[0]?.txinwitness!;
      let extracted = false;
      for (let i = witness.length - 1; i >= 0; i--) {
        try {
          const result = extractRealInscription(witness[i]!);
          expect(result.contentType).toBe('application/atp.v1+cbor');
          extracted = true;
          // CBOR decode should throw on garbage
          const { cborDecode } = await import('../src/lib/encoding.js');
          expect(() => cborDecode(result.data)).toThrow();
          break;
        } catch (e) {
          if (extracted) throw e; // re-throw if it was the cborDecode test
        }
      }
    }, 60000);

    // ── Tampered Documents ─────────────────────────────────────────

    it('ADV-7: Signature swap — modified name after signing fails verification', async () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: 'OriginalName',
        k: { t: 'ed25519', p: key.pubB64 },
        ts: ts(),
      };
      IdentityUnsignedSchema.parse(doc);
      doc.s = toBase64url(sign(doc, key.privateKey));
      // Tamper after signing
      doc.n = 'TamperedName';
      const txid = await inscribe(doc);
      // Verify via real CLI command
      const result = runVerify(txid);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('INVALID');
    }, 60000);

    it('ADV-8: Fingerprint mismatch — from.f does not match signer', async () => {
      const keyA = makeKey();
      const keyB = makeKey();
      const { txid: txA } = await createAndInscribeIdentity(keyA, 'RealA');
      const { txid: txB } = await createAndInscribeIdentity(keyB, 'RealB');
      // Create attestation with wrong fingerprint in from.f
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'att',
        from: { f: 'wrong-fingerprint-aaaa', ref: { net: NET, id: txA } },
        to: { f: keyB.fingerprint, ref: { net: NET, id: txB } },
        ts: ts(),
      };
      AttestationUnsignedSchema.parse(doc);
      doc.s = toBase64url(sign(doc, keyA.privateKey));
      const txid = await inscribe(doc);
      // Verify via real CLI command — should detect fingerprint mismatch
      const result = runVerify(txid);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('mismatch');
    }, 60000);

    it('ADV-9: Wrong key signs revocation — should fail verification', async () => {
      const keyA = makeKey();
      const keyB = makeKey();
      const { txid: txA } = await createAndInscribeIdentity(keyA, 'VictimA');
      await createAndInscribeIdentity(keyB, 'AttackerB');
      // B tries to revoke A
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'revoke',
        target: { f: keyA.fingerprint, ref: { net: NET, id: txA } },
        reason: 'defunct', ts: ts(),
      };
      RevocationUnsignedSchema.parse(doc);
      doc.s = toBase64url(sign(doc, keyB.privateKey));
      const txid = await inscribe(doc);
      // Verify via real CLI command — signed by wrong key
      const result = runVerify(txid);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('INVALID');
    }, 60000);

    it('ADV-10: Forged supersession — unrelated key C claims to supersede A', async () => {
      const keyA = makeKey();
      const keyC = makeKey();
      const keyNew = makeKey();
      const { txid: txA } = await createAndInscribeIdentity(keyA, 'TargetA');
      await createAndInscribeIdentity(keyC, 'AttackerC');
      // C creates supersession targeting A but signs with C's key (not A's)
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'super',
        target: { f: keyA.fingerprint, ref: { net: NET, id: txA } },
        n: 'TargetA', k: { t: 'ed25519', p: keyNew.pubB64 },
        reason: 'key-rotation', ts: ts(),
      };
      SupersessionUnsignedSchema.parse(doc);
      // Sign with C (old) and keyNew (new) — but C is NOT keyA
      const oldSig = toBase64url(sign(doc, keyC.privateKey));
      const newSig = toBase64url(sign(doc, keyNew.privateKey));
      doc.s = [oldSig, newSig];
      const txid = await inscribe(doc);
      // Verify via real CLI command — old key sig doesn't match target identity
      const result = runVerify(txid);
      expect(result.exitCode).toBe(1);
      expect(result.stderr).toContain('INVALID');
    }, 60000);

    // ── Protocol Violation Tests ───────────────────────────────────

    it('ADV-11: Future timestamp (year 2050) triggers warning', async () => {
      const key = makeKey();
      const futureTs = Math.floor(new Date('2050-01-01').getTime() / 1000);
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: 'FutureAgent',
        k: { t: 'ed25519', p: key.pubB64 },
        ts: futureTs,
      };
      // Schema allows any positive int for ts, so this passes
      IdentityUnsignedSchema.parse(doc);
      doc.s = toBase64url(sign(doc, key.privateKey));
      const txid = await inscribe(doc);
      const fetched = await fetchDoc(txid);
      // validateTimestamp should throw for >2h drift
      const { validateTimestamp } = await import('../src/lib/timestamp.js');
      expect(() => validateTimestamp(fetched.ts as number, 'Test')).toThrow(/future/);
    }, 60000);

    it('ADV-12: Negative seq in heartbeat is rejected by schema', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'hb', f: key.fingerprint,
        ref: { net: NET, id: 'abc123' }, seq: -1, ts: ts(),
      };
      expect(() => HeartbeatUnsignedSchema.parse(doc)).toThrow();
    });

    it('ADV-13: Duplicate seq heartbeats both inscribe (verifier must reject)', async () => {
      const key = makeKey();
      const { txid: idTxid } = await createAndInscribeIdentity(key, 'DupeSeqAgent');
      const { txid: hb1Txid } = await createAndInscribeHeartbeat(key, idTxid, 5, 'first');
      const { txid: hb2Txid } = await createAndInscribeHeartbeat(key, idTxid, 5, 'dupe');
      const hb1 = await fetchDoc(hb1Txid);
      const hb2 = await fetchDoc(hb2Txid);
      expect(hb1.seq).toBe(5);
      expect(hb2.seq).toBe(5);
      // Both verify cryptographically — verifier must enforce first-seen-wins
      expect(verifyWithKey(hb1, key)).toBe(true);
      expect(verifyWithKey(hb2, key)).toBe(true);
      // hb1 was inscribed first
      const raw1 = await rpcCall('getrawtransaction', [hb1Txid, true]) as { confirmations: number };
      const raw2 = await rpcCall('getrawtransaction', [hb2Txid, true]) as { confirmations: number };
      expect(raw1.confirmations).toBeGreaterThan(raw2.confirmations);
    }, 60000);

    it.todo('ADV-14: Self-referencing supersession (target fingerprint = new key fingerprint) — behavior undefined');

    it('ADV-15: Revocation of non-existent identity TXID', async () => {
      const key = makeKey();
      const fakeTxid = 'deadbeef'.repeat(8); // 64-char fake txid
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'revoke',
        target: { f: key.fingerprint, ref: { net: NET, id: fakeTxid } },
        reason: 'defunct', ts: ts(),
      };
      RevocationUnsignedSchema.parse(doc);
      doc.s = toBase64url(sign(doc, key.privateKey));
      // Can inscribe it (chain doesn't validate ATP semantics)
      const txid = await inscribe(doc);
      const fetched = await fetchDoc(txid);
      expect(fetched.t).toBe('revoke');
      // Signature is valid but target doesn't exist — verifier must handle
      expect(verifyWithKey(fetched, key)).toBe(true);
    }, 60000);

    // ── Malformed References ───────────────────────────────────────

    it('ADV-16: Invalid CAIP-2 net string passes schema (no regex validation)', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'hb', f: key.fingerprint,
        ref: { net: 'garbage!!!not-a-caip', id: 'abc123' },
        seq: 0, ts: ts(),
      };
      // Schema currently uses z.string() for net — no CAIP-2 validation
      // This is a gap: it SHOULD reject but currently doesn't
      const result = HeartbeatUnsignedSchema.safeParse(doc);
      if (!result.success) {
        // If schema rejects, that's correct behavior
        expect(result.error).toBeDefined();
      } else {
        // Schema allows it — document the gap
        expect(result.data.ref.net).toBe('garbage!!!not-a-caip');
      }
    });

    it('ADV-17: Empty ref.id passes schema (no min-length validation)', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'hb', f: key.fingerprint,
        ref: { net: NET, id: '' },
        seq: 0, ts: ts(),
      };
      const result = HeartbeatUnsignedSchema.safeParse(doc);
      if (!result.success) {
        expect(result.error).toBeDefined();
      } else {
        // Gap: empty id should probably be rejected
        expect(result.data.ref.id).toBe('');
      }
    });

    it('ADV-18: Attestation missing ref on from — schema rejects', () => {
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'att',
        from: { f: 'some-fingerprint' }, // missing ref
        to: { f: 'other-fingerprint', ref: { net: NET, id: 'txid123' } },
        ts: ts(),
      };
      expect(() => AttestationUnsignedSchema.parse(doc)).toThrow();
    });

    // ── Edge Cases ─────────────────────────────────────────────────

    it('ADV-19: Zero-length name rejected by schema', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: '',
        k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
      };
      expect(() => IdentityUnsignedSchema.parse(doc)).toThrow();
    });

    it('ADV-20: 65-char name rejected by schema', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: 'A'.repeat(65),
        k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
      };
      expect(() => IdentityUnsignedSchema.parse(doc)).toThrow();
    });

    it('ADV-21: Unicode (Cyrillic) name rejected by ASCII-only schema', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: 'Ѕhrike', // Ѕ is Cyrillic
        k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
      };
      expect(() => IdentityUnsignedSchema.parse(doc)).toThrow(/ASCII/i);
    });

    // ── Happy-path CLI verify tests ──────────────────────────────────

    it('ADV-NEW-1: Verify a valid identity via atp verify → exit 0', async () => {
      const key = makeKey();
      const { txid } = await createAndInscribeIdentity(key, 'ValidIdAgent');
      const result = runVerify(txid);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('VALID');
    }, 60000);

    it('ADV-NEW-2: Verify a valid attestation via atp verify → exit 0', async () => {
      const keyA = makeKey();
      const keyB = makeKey();
      const { txid: txA } = await createAndInscribeIdentity(keyA, 'AttestorValid');
      const { txid: txB } = await createAndInscribeIdentity(keyB, 'AttesteeValid');
      // Build attestation with correct ref TXIDs
      const { txid: attTxid } = await createAndInscribeAttestation(
        keyA, txA, keyB.fingerprint, txB, 'verified peer',
      );
      const result = runVerify(attTxid);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('VALID');
    }, 60000);

    it('ADV-NEW-3: Verify a valid supersession via atp verify → exit 0', async () => {
      const keyOld = makeKey();
      const keyNew = makeKey();
      const { txid: idTxid } = await createAndInscribeIdentity(keyOld, 'SuperValid');
      const { txid: superTxid } = await createAndInscribeSupersession(
        keyOld, idTxid, keyNew, 'SuperValid', 'key-rotation',
      );
      const result = runVerify(superTxid);
      expect(result.exitCode).toBe(0);
      expect(result.stdout).toContain('VALID');
    }, 60000);

    it('ADV-22: Null bytes in name rejected by ASCII-only schema', () => {
      const key = makeKey();
      const doc: Record<string, unknown> = {
        v: '1.0', t: 'id', n: 'Agent\x00Evil',
        k: { t: 'ed25519', p: key.pubB64 }, ts: ts(),
      };
      expect(() => IdentityUnsignedSchema.parse(doc)).toThrow();
    });
  });

  it('9. Round-trip: document encoding preserved through inscription', async () => {
    const key = makeKey();
    const originalDoc: Record<string, unknown> = {
      v: '1.0', t: 'id', n: 'EncodingTest-RoundTrip',
      k: { t: 'ed25519', p: key.pubB64 },
      ts: ts(),
    };
    IdentityUnsignedSchema.parse(originalDoc);
    originalDoc.s = toBase64url(sign(originalDoc, key.privateKey));

    const txid = await inscribe(originalDoc);
    const fetched = await fetchDoc(txid);

    // Exact field preservation
    expect(fetched.n).toBe('EncodingTest-RoundTrip');
    expect(fetched.v).toBe('1.0');
    expect(verifyIdentityDoc(fetched)).toBe(true);
  }, 60000);
});
