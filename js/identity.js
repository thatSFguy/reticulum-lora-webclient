// js/identity.js — Reticulum identity: Ed25519 signing + X25519 encryption.

'use strict';

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { TRUNCATED_HASHLENGTH, NAME_HASH_LENGTH } from './reticulum.js';

// SHA-256 helper (returns Uint8Array)
export async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

// Truncated hash (SHA-256 truncated to `length` bytes)
export async function truncatedHash(data, length = TRUNCATED_HASHLENGTH) {
  const full = await sha256(data);
  return full.subarray(0, length);
}

export class Identity {
  constructor() {
    this.encPrivKey = null;   // X25519 private key (32 bytes)
    this.encPubKey = null;    // X25519 public key (32 bytes)
    this.sigPrivKey = null;   // Ed25519 private key (32 bytes)
    this.sigPubKey = null;    // Ed25519 public key (32 bytes)
    this.publicKey = null;    // Combined: encPub(32) + sigPub(32) = 64 bytes
    this.hash = null;         // Identity hash: SHA-256(publicKey)[0:16]
  }

  async generate() {
    this.encPrivKey = x25519.utils.randomPrivateKey();
    this.encPubKey = x25519.getPublicKey(this.encPrivKey);

    this.sigPrivKey = ed25519.utils.randomPrivateKey();
    this.sigPubKey = ed25519.getPublicKey(this.sigPrivKey);

    this.publicKey = new Uint8Array(64);
    this.publicKey.set(this.encPubKey, 0);
    this.publicKey.set(this.sigPubKey, 32);

    this.hash = await truncatedHash(this.publicKey);
  }

  async loadFromPrivateKeys(encPriv, sigPriv) {
    this.encPrivKey = new Uint8Array(encPriv);
    this.sigPrivKey = new Uint8Array(sigPriv);
    this.encPubKey = x25519.getPublicKey(this.encPrivKey);
    this.sigPubKey = ed25519.getPublicKey(this.sigPrivKey);

    this.publicKey = new Uint8Array(64);
    this.publicKey.set(this.encPubKey, 0);
    this.publicKey.set(this.sigPubKey, 32);

    this.hash = await truncatedHash(this.publicKey);
  }

  async loadFromPublicKey(pubKey) {
    this.publicKey = new Uint8Array(pubKey);
    this.encPubKey = this.publicKey.subarray(0, 32);
    this.sigPubKey = this.publicKey.subarray(32, 64);
    this.hash = await truncatedHash(this.publicKey);
  }

  sign(data) {
    return ed25519.sign(data, this.sigPrivKey);
  }

  verify(signature, data) {
    try {
      return ed25519.verify(signature, data, this.sigPubKey);
    } catch {
      return false;
    }
  }

  exportPrivateKeys() {
    return {
      encPrivKey: Array.from(this.encPrivKey),
      sigPrivKey: Array.from(this.sigPrivKey),
    };
  }
}

export async function computeDestinationHash(appName, identityHash) {
  const nameHash = await truncatedHash(
    new TextEncoder().encode(appName),
    NAME_HASH_LENGTH
  );
  const material = new Uint8Array(NAME_HASH_LENGTH + TRUNCATED_HASHLENGTH);
  material.set(nameHash, 0);
  material.set(identityHash, NAME_HASH_LENGTH);
  return truncatedHash(material);
}

export async function computeNameHash(appName) {
  return truncatedHash(
    new TextEncoder().encode(appName),
    NAME_HASH_LENGTH
  );
}
