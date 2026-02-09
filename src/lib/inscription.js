/**
 * Build an Ordinals inscription envelope (witness script).
 * This produces the script bytes for the OP_FALSE OP_IF ... OP_ENDIF envelope.
 *
 * For actual commit/reveal tx construction, a full Bitcoin library is needed.
 * This module provides the envelope building and hex output.
 */

const OP_FALSE = 0x00;
const OP_IF = 0x63;
const OP_ENDIF = 0x68;
const OP_PUSH_3 = 0x03; // push 3 bytes

function pushData(buf) {
  const chunks = [];
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

/**
 * Build inscription envelope script bytes.
 * @param {Buffer} data - The document bytes
 * @param {string} contentType - e.g. 'application/json'
 * @returns {Buffer} Script bytes for the inscription envelope
 */
export function buildInscriptionEnvelope(data, contentType) {
  const parts = [
    Buffer.from([OP_FALSE, OP_IF]),
    // Push "ord"
    Buffer.from([OP_PUSH_3]),
    Buffer.from('ord', 'ascii'),
    // Push 0x01 (content-type tag)
    Buffer.from([0x01, 0x01]),
    // Push content-type string
    pushData(Buffer.from(contentType, 'ascii')),
    // Push 0x00 (body separator)
    Buffer.from([OP_FALSE]),
  ];

  // Split data into 520-byte chunks
  for (let i = 0; i < data.length; i += 520) {
    const chunk = data.subarray(i, Math.min(i + 520, data.length));
    parts.push(pushData(chunk));
    if (i + 520 < data.length) {
      parts.push(Buffer.from([OP_FALSE])); // separator between chunks
    }
  }

  parts.push(Buffer.from([OP_ENDIF]));
  return Buffer.concat(parts);
}

/**
 * Extract inscription data from witness hex (simplified parser).
 * Looks for the OP_FALSE OP_IF ... ord ... OP_ENDIF pattern.
 */
export function extractInscriptionFromWitness(witnessHex) {
  const buf = Buffer.from(witnessHex, 'hex');
  // Find "ord" marker
  const ordIdx = buf.indexOf(Buffer.from('ord', 'ascii'));
  if (ordIdx === -1) throw new Error('No inscription found in witness');

  // Simple extraction: find content-type and body
  // This is a simplified parser; production use needs full script parsing
  let pos = ordIdx + 3; // after "ord"

  // Read content-type tag (0x01)
  if (buf[pos] !== 0x01) throw new Error('Expected content-type tag');
  pos++;

  // Read content-type length + string
  const ctLen = buf[pos]; pos++;
  const contentType = buf.subarray(pos, pos + ctLen).toString('ascii');
  pos += ctLen;

  // Read body separator (0x00)
  if (buf[pos] !== 0x00) throw new Error('Expected body separator');
  pos++;

  // Read data chunks until OP_ENDIF (0x68)
  const dataChunks = [];
  while (pos < buf.length && buf[pos] !== 0x68) {
    if (buf[pos] === 0x00) { pos++; continue; } // skip separators
    const len = buf[pos];
    if (len <= 75) {
      pos++;
      dataChunks.push(buf.subarray(pos, pos + len));
      pos += len;
    } else if (len === 0x4c) {
      pos++;
      const dlen = buf[pos]; pos++;
      dataChunks.push(buf.subarray(pos, pos + dlen));
      pos += dlen;
    } else if (len === 0x4d) {
      pos++;
      const dlen = buf[pos] | (buf[pos + 1] << 8); pos += 2;
      dataChunks.push(buf.subarray(pos, pos + dlen));
      pos += dlen;
    } else {
      break;
    }
  }

  return { contentType, data: Buffer.concat(dataChunks) };
}
