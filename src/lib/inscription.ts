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
    if (i + 520 < data.length) {
      parts.push(Buffer.from([OP_FALSE]));
    }
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

  const ctLen = buf[pos]!;
  pos++;
  const contentType = buf.subarray(pos, pos + ctLen).toString('ascii');
  pos += ctLen;

  if (buf[pos] !== 0x00) throw new Error('Expected body separator');
  pos++;

  const dataChunks: Buffer[] = [];
  while (pos < buf.length && buf[pos] !== 0x68) {
    if (buf[pos] === 0x00) {
      pos++;
      continue;
    }
    const len = buf[pos]!;
    if (len <= 75) {
      pos++;
      dataChunks.push(buf.subarray(pos, pos + len));
      pos += len;
    } else if (len === 0x4c) {
      pos++;
      const dlen = buf[pos]!;
      pos++;
      dataChunks.push(buf.subarray(pos, pos + dlen));
      pos += dlen;
    } else if (len === 0x4d) {
      pos++;
      const dlen = buf[pos]! | (buf[pos + 1]! << 8);
      pos += 2;
      dataChunks.push(buf.subarray(pos, pos + dlen));
      pos += dlen;
    } else {
      break;
    }
  }

  return { contentType, data: Buffer.concat(dataChunks) };
}
