// js/identity.js — Reticulum identity: Ed25519 signing + X25519 encryption.
//
// Uses @noble/curves for Ed25519/X25519 and Web Crypto for SHA-256.
// Identity = X25519 encryption keypair + Ed25519 signing keypair.
// Public key = encryption_pub(32) + signing_pub(32) = 64 bytes.
// Identity hash = SHA-256(public_key)[0:16] (TRUNCATED_HASHLENGTH).

'use strict';

import { TRUNCATED_HASHLENGTH, NAME_HASH_LENGTH } from './reticulum.js';

// We load @noble/curves from a CDN in index.html and access via window
function getNoble() {
  if (!window.noble_ed25519 || !window.noble_x25519) {
    throw new Error('@noble/curves not loaded — check script tags in index.html');
  }
  return { ed25519: window.noble_ed25519, x25519: window.noble_x25519 };
}

// SHA-256 helper (returns Uint8Array)
async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

// Truncated hash (SHA-256 truncated to `length` bytes)
async function truncatedHash(data, length = TRUNCATED_HASHLENGTH) {
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

  // Generate a new random identity
  async generate() {
    const { ed25519, x25519 } = getNoble();

    // X25519 encryption keypair
    this.encPrivKey = x25519.utils.randomPrivateKey();
    this.encPubKey = x25519.getPublicKey(this.encPrivKey);

    // Ed25519 signing keypair
    this.sigPrivKey = ed25519.utils.randomPrivateKey();
    this.sigPubKey = ed25519.getPublicKey(this.sigPrivKey);

    // Combined public key
    this.publicKey = new Uint8Array(64);
    this.publicKey.set(this.encPubKey, 0);
    this.publicKey.set(this.sigPubKey, 32);

    // Identity hash
    this.hash = await truncatedHash(this.publicKey);
  }

  // Load from stored private keys
  async loadFromPrivateKeys(encPriv, sigPriv) {
    const { ed25519, x25519 } = getNoble();

    this.encPrivKey = new Uint8Array(encPriv);
    this.sigPrivKey = new Uint8Array(sigPriv);
    this.encPubKey = x25519.getPublicKey(this.encPrivKey);
    this.sigPubKey = ed25519.getPublicKey(this.sigPrivKey);

    this.publicKey = new Uint8Array(64);
    this.publicKey.set(this.encPubKey, 0);
    this.publicKey.set(this.sigPubKey, 32);

    this.hash = await truncatedHash(this.publicKey);
  }

  // Load from public key only (for contacts — no private keys)
  async loadFromPublicKey(pubKey) {
    this.publicKey = new Uint8Array(pubKey);
    this.encPubKey = this.publicKey.subarray(0, 32);
    this.sigPubKey = this.publicKey.subarray(32, 64);
    this.hash = await truncatedHash(this.publicKey);
  }

  // Sign data with Ed25519
  sign(data) {
    const { ed25519 } = getNoble();
    return ed25519.sign(data, this.sigPrivKey);
  }

  // Verify Ed25519 signature
  verify(signature, data) {
    const { ed25519 } = getNoble();
    try {
      return ed25519.verify(signature, data, this.sigPubKey);
    } catch {
      return false;
    }
  }

  // Export private keys for storage
  exportPrivateKeys() {
    return {
      encPrivKey: Array.from(this.encPrivKey),
      sigPrivKey: Array.from(this.sigPrivKey),
    };
  }
}

// Compute destination hash for a given app name and identity hash.
// name = "lxmf.delivery" for LXMF messaging.
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

// Compute name hash for an app name
export async function computeNameHash(appName) {
  return truncatedHash(
    new TextEncoder().encode(appName),
    NAME_HASH_LENGTH
  );
}

// Compute full SHA-256 hash
export { sha256, truncatedHash };
