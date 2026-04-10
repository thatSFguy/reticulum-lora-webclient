// js/lxmf.js — LXMF message pack/unpack.
//
// LXMF packed format (before encryption):
//   destination_hash(16) + source_hash(16) + signature(64) + msgpack(payload)
//
// For single-packet opportunistic delivery, destination_hash is stripped
// (inferred from the RNS packet header). So on-wire LXMF payload is:
//   source_hash(16) + signature(64) + msgpack(payload)
//
// Payload msgpack array: [timestamp, title_bytes, content_bytes, fields_dict]
// Optional 5th element: stamp (proof-of-work, ignored for now)

'use strict';

import { encode as msgpackEncode, decode as msgpackDecode } from '@msgpack/msgpack';
import { Identity, sha256 } from './identity.js';
import { concatBytes } from './announce.js';
import { TRUNCATED_HASHLENGTH, SIGLENGTH } from './reticulum.js';

const DESTINATION_LENGTH = 16;
const SIGNATURE_LENGTH   = 64;

// ---- Unpack an LXMF message (after decryption) -----------------------

// Unpack from the on-wire format (destination_hash already known from RNS header):
//   source_hash(16) + signature(64) + msgpack(payload)
export async function unpackMessage(data, destHash) {
  if (data.length < TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH + 1) {
    throw new Error('LXMF message too short');
  }

  const sourceHash = data.subarray(0, TRUNCATED_HASHLENGTH);
  const signature  = data.subarray(TRUNCATED_HASHLENGTH, TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH);
  const msgpackData = data.subarray(TRUNCATED_HASHLENGTH + SIGNATURE_LENGTH);

  // Decode msgpack payload
  const payload = msgpackDecode(msgpackData);

  if (!Array.isArray(payload) || payload.length < 4) {
    throw new Error('Invalid LXMF payload structure');
  }

  const timestamp = payload[0];
  const title     = decodeField(payload[1]);
  const content   = decodeField(payload[2]);
  const fields    = payload[3] || {};
  const stamp     = payload.length > 4 ? payload[4] : null;

  // Compute message hash for verification
  // For stamp handling: rebuild msgpack without stamp for hash
  const msgpackForHash = stamp !== null
    ? msgpackEncode([timestamp, payload[1], payload[2], fields])
    : msgpackData;

  const hashedPart = concatBytes([destHash, sourceHash, msgpackForHash]);
  const messageHash = await sha256(hashedPart);

  return {
    sourceHash,
    signature,
    timestamp,
    title,
    content,
    fields,
    stamp,
    messageHash,
    hashedPart,
    msgpackForHash,
  };
}

// Verify LXMF message signature using the sender's public key
export function verifyMessageSignature(message, senderIdentity) {
  const signedData = concatBytes([message.hashedPart, message.messageHash]);
  return senderIdentity.verify(message.signature, signedData);
}

// ---- Pack an outbound LXMF message -----------------------------------

export async function packMessage(sourceIdentity, destHash, sourceHash, title, content, fields = {}) {
  const titleBytes   = new TextEncoder().encode(title || '');
  const contentBytes = new TextEncoder().encode(content || '');
  const timestamp    = Date.now() / 1000;  // float seconds

  // Msgpack encode payload
  const msgpackData = new Uint8Array(msgpackEncode([timestamp, titleBytes, contentBytes, fields]));

  // Compute message hash
  const hashedPart = concatBytes([destHash, sourceHash, msgpackData]);
  const messageHash = await sha256(hashedPart);

  // Sign: signed_data = hashed_part + message_hash
  const signedData = concatBytes([hashedPart, messageHash]);
  const signature = sourceIdentity.sign(signedData);

  // On-wire format (destination stripped for opportunistic single-packet):
  //   source_hash(16) + signature(64) + msgpack(payload)
  return concatBytes([sourceHash, signature, msgpackData]);
}

// ---- Helpers ---------------------------------------------------------

function decodeField(val) {
  if (val instanceof Uint8Array || val instanceof ArrayBuffer) {
    return new TextDecoder().decode(val);
  }
  if (typeof val === 'string') return val;
  if (val === null || val === undefined) return '';
  return String(val);
}
