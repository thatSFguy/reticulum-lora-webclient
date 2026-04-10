// js/link.js — Reticulum Link responder (incoming link establishment only).
//
// Implements enough of the upstream Reticulum Link protocol to accept a
// LINKREQUEST from a peer, derive a session key, emit the LRPROOF, and
// encrypt/decrypt packets that arrive on the established link. Only the
// responder (destination) side is implemented — we never initiate links.
// Supports AES256_CBC mode only (the default in modern Reticulum).
//
// Scope reference: reticulum-lora-repeater/.pio/libdeps/Faketec/
// microReticulum/src/Link.cpp validate_request / handshake / prove and
// the upstream Python source comments in that file.

'use strict';

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { sha256 } from './identity.js';
import { hkdfDerive, tokenEncrypt, tokenDecrypt } from './crypto.js';
import { HEADER_1, TRUNCATED_HASHLENGTH } from './reticulum.js';
import { concatBytes } from './announce.js';

export const ECPUBSIZE      = 64;   // 32 X25519 + 32 Ed25519
export const SIGLENGTH      = 64;   // Ed25519 signature
export const LINK_MTU_SIZE  = 3;
export const LINK_KEYSIZE   = 64;   // AES256_CBC derives 64 bytes (32 HMAC + 32 AES)
export const MODE_AES256_CBC = 0x01;

// Link status values mirroring upstream Link::status.
export const LINK_PENDING   = 0x00;
export const LINK_HANDSHAKE = 0x01;
export const LINK_ACTIVE    = 0x02;
export const LINK_CLOSED    = 0x04;

// Encode a 3-byte signalling field carrying mtu (low 21 bits) and mode
// (top 3 bits). Matches upstream Link.signalling_bytes():
//   val = (mtu & 0x1FFFFF) | ((mode & 0x07) << 21)
//   bytes = big-endian (val >> 16) (val >> 8) (val)
export function encodeSignalling(mtu, mode) {
  const val = (mtu & 0x1FFFFF) | ((mode & 0x07) << 21);
  return new Uint8Array([(val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF]);
}

export function decodeSignalling(bytes) {
  const val = (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
  return { mtu: val & 0x1FFFFF, mode: (val >> 21) & 0x07 };
}

// Compute the link_id from an inbound LINKREQUEST packet.
//
// Upstream Link.link_id_from_lr_packet:
//   hashable_part = (flags & 0x0F) || raw[2:]            (HEADER_1)
//   hashable_part = (flags & 0x0F) || raw[18:]           (HEADER_2)
//   if data.size > ECPUBSIZE:
//       hashable_part = hashable_part[:-(data.size - ECPUBSIZE)]
//   link_id = SHA256(hashable_part)[:16]
export async function computeLinkId(pkt) {
  const flagsLow = pkt.flags & 0x0F;
  const skipBytes = pkt.headerType === HEADER_1 ? 2 : 2 + TRUNCATED_HASHLENGTH;
  const tail = pkt.raw.subarray(skipBytes);

  const hp = new Uint8Array(1 + tail.length);
  hp[0] = flagsLow;
  hp.set(tail, 1);

  let hashable = hp;
  if (pkt.payload.length > ECPUBSIZE) {
    const diff = pkt.payload.length - ECPUBSIZE;
    hashable = hp.subarray(0, hp.length - diff);
  }

  const digest = await sha256(hashable);
  return digest.subarray(0, 16);
}

export class Link {
  constructor() {
    this.linkId           = null;            // Uint8Array(16)
    this.ourX25519Priv    = null;            // ephemeral
    this.ourX25519Pub     = null;            // ephemeral
    this.ourSigPriv       = null;            // long-term identity signing key
    this.ourSigPub        = null;            // long-term identity signing pubkey
    this.peerX25519Pub    = null;
    this.peerEd25519Pub   = null;            // ephemeral on the initiator side
    this.derivedKey       = null;            // Uint8Array(64) — 32 HMAC + 32 AES
    this.mtu              = 500;
    this.mode             = MODE_AES256_CBC;
    this.signallingBytes  = null;            // what we echo back in LRPROOF
    this.status           = LINK_PENDING;
    this.cachedProofData  = null;            // for dedup / retransmit of LRPROOF
    this.ownerDestHash    = null;            // the LXMF destination this link targets
    this.establishedAt    = 0;
  }

  encrypt(plaintext) {
    return tokenEncrypt(this.derivedKey, plaintext);
  }

  decrypt(ciphertext) {
    return tokenDecrypt(this.derivedKey, ciphertext);
  }

  // Accept an inbound LINKREQUEST packet and derive all link state.
  //
  // `pkt` is the parsed packet object from parsePacket().
  // `ourIdentity` is the Identity instance that owns the destination the
  // request was addressed to; its long-term Ed25519 private key signs the
  // LRPROOF so the initiator can verify we are the intended destination.
  //
  // Returns { link, proofData } on success where proofData is the raw
  // payload bytes to put into an LRPROOF packet. Throws on invalid input.
  static async validateRequest(pkt, ourIdentity) {
    const data = pkt.payload;
    if (data.length !== ECPUBSIZE && data.length !== ECPUBSIZE + LINK_MTU_SIZE) {
      throw new Error(`Invalid LINKREQUEST payload size ${data.length}`);
    }

    const peerX25519Pub  = data.subarray(0, 32);
    const peerEd25519Pub = data.subarray(32, 64);

    let mtu  = 500;
    let mode = MODE_AES256_CBC;
    if (data.length === ECPUBSIZE + LINK_MTU_SIZE) {
      const sig = decodeSignalling(data.subarray(ECPUBSIZE, ECPUBSIZE + LINK_MTU_SIZE));
      if (sig.mtu > 0) mtu = sig.mtu;
      mode = sig.mode;
    }
    if (mode !== MODE_AES256_CBC) {
      throw new Error(`Unsupported link mode 0x${mode.toString(16)}`);
    }

    const linkId = await computeLinkId(pkt);

    const link = new Link();
    link.linkId         = linkId;
    link.ourX25519Priv  = x25519.utils.randomPrivateKey();
    link.ourX25519Pub   = x25519.getPublicKey(link.ourX25519Priv);
    link.ourSigPriv     = ourIdentity.sigPrivKey;
    link.ourSigPub      = ourIdentity.sigPubKey;
    link.peerX25519Pub  = new Uint8Array(peerX25519Pub);
    link.peerEd25519Pub = new Uint8Array(peerEd25519Pub);
    link.mtu            = mtu;
    link.mode           = mode;
    link.ownerDestHash  = new Uint8Array(pkt.destHash);

    // ECDH + HKDF. Upstream Link::handshake uses salt=link_id, info=empty.
    const shared = x25519.getSharedSecret(link.ourX25519Priv, link.peerX25519Pub);
    link.derivedKey = await hkdfDerive(shared, link.linkId, new Uint8Array(0), LINK_KEYSIZE);
    link.status = LINK_HANDSHAKE;

    // Build the LRPROOF payload.
    //
    // signed_data = link_id + our_x25519_pub + our_long_term_sig_pub + signalling
    // signature   = Ed25519(our long-term sig priv, signed_data)
    // proof_data  = signature + our_x25519_pub + signalling
    //
    // The initiator already knows our long-term Ed25519 pubkey from our
    // announce and looks it up by destination hash; that is why the sig
    // pub is in the SIGNED data but NOT in the wire proof_data payload.
    link.signallingBytes = encodeSignalling(mtu, mode);
    const signedData = concatBytes([
      link.linkId,
      link.ourX25519Pub,
      link.ourSigPub,
      link.signallingBytes,
    ]);
    const signature = ed25519.sign(signedData, link.ourSigPriv);
    const proofData = concatBytes([signature, link.ourX25519Pub, link.signallingBytes]);
    link.cachedProofData = proofData;

    return { link, proofData };
  }
}
