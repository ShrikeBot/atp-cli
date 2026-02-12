/**
 * Build an Ordinals inscription envelope (witness script).
 */

const OP_FALSE = 0x00;
const OP_IF = 0x63;
const OP_ENDIF = 0x68;
const OP_PUSH_3 = 0x03;

function pushData(buf: Buffer): Buffer {
  const chunks: Buffer[] = [];
  if (buf.length <= 75) {
    chunks.push(Buffer.from([buf.length]));
    chunks.push(buf);
  } else if (buf.length <= 255) {
    chunks.push(Buffer.from([0x4c, buf.length]));
    chunks.push(buf);
  } else if (buf.length <= 520) {
    chunks.push(Buffer.from([0x4d, buf.length & 0xff, (buf.length >> 8) & 0xff]));
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}

export function buildInscriptionEnvelope(data: Buffer, contentType: string): Buffer {
  const parts: Buffer[] = [
    Buffer.from([OP_FALSE, OP_IF]),
    Buffer.from([OP_PUSH_3]),
    Buffer.from('ord', 'ascii'),
    Buffer.from([0x01]),
    pushData(Buffer.from(contentType, 'ascii')),
    Buffer.from([OP_FALSE]),
  ];

  for (let i = 0; i < data.length; i += 520) {
    const chunk = data.subarray(i, Math.min(i + 520, data.length));
    parts.push(pushData(chunk));
  }

  parts.push(Buffer.from([OP_ENDIF]));
  return Buffer.concat(parts);
}

export function extractInscriptionFromWitness(witnessHex: string): {
  contentType: string;
  data: Buffer;
} {
  const buf = Buffer.from(witnessHex, 'hex');
  const ordIdx = buf.indexOf(Buffer.from('ord', 'ascii'));
  if (ordIdx === -1) throw new Error('No inscription found in witness');

  let pos = ordIdx + 3;

  if (buf[pos] !== 0x01) throw new Error('Expected content-type tag');
  pos++;

  // Detect format: real ordinals uses PUSH1 0x01 (tag value) then pushdata for ct,
  // while the simple format uses <ctLen> <ct bytes> directly.
  // Heuristic: if buf[pos] === 0x01 and buf[pos+1] > 0x01, it's real ordinals format
  // (the 0x01 is the tag value, followed by a pushdata for content-type).
  let contentType: string;
  if (buf[pos] === 0x01 && pos + 1 < buf.length && buf[pos + 1]! > 0x01) {
    // Real ordinals format: 01 01 <pushdata content-type>
    pos++; // skip tag value 0x01
    const { value: ctBuf, newPos } = readPush(buf, pos);
    contentType = ctBuf.toString('ascii');
    pos = newPos;
  } else {
    // Simple format: <ctLen> <ct bytes>
    const ctLen = buf[pos]!;
    pos++;
    contentType = buf.subarray(pos, pos + ctLen).toString('ascii');
    pos += ctLen;
  }

  if (buf[pos] !== 0x00) throw new Error('Expected body separator');
  pos++;

  const dataChunks: Buffer[] = [];
  while (pos < buf.length && buf[pos] !== 0x68) {
    if (buf[pos] === 0x00) {
      pos++;
      continue;
    }
    const { value: chunk, newPos } = readPush(buf, pos);
    dataChunks.push(chunk);
    pos = newPos;
  }

  return { contentType, data: Buffer.concat(dataChunks) };
}

function readPush(buf: Buffer, pos: number): { value: Buffer; newPos: number } {
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
