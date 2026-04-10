// js/crypto.js — Reticulum encryption: ECDH + HKDF + Token (Fernet-variant).
//
// Encrypt: ephemeral X25519 ECDH → HKDF → AES-256-CBC + HMAC-SHA256
// Token format: iv(16) + aes_ciphertext + hmac(32)
// Wire format: ephemeral_pubkey(32) + token

'use strict';

import { x25519 } from '@noble/curves/ed25519';
import { concatBytes } from './announce.js';

// ---- HKDF (HMAC-SHA256) using Web Crypto API -------------------------

async function hkdfDerive(ikm, salt, info, length) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', ikm, 'HKDF', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    keyMaterial, length * 8
  );
  return new Uint8Array(bits);
}

// ---- PKCS7 padding ---------------------------------------------------

function pkcs7Pad(data, blockSize = 16) {
  const padLen = blockSize - (data.length % blockSize);
  const padded = new Uint8Array(data.length + padLen);
  padded.set(data);
  padded.fill(padLen, data.length);
  return padded;
}

function pkcs7Unpad(data) {
  if (data.length === 0) throw new Error('PKCS7: empty data');
  const padLen = data[data.length - 1];
  if (padLen === 0 || padLen > 16) throw new Error('PKCS7: invalid padding');
  for (let i = data.length - padLen; i < data.length; i++) {
    if (data[i] !== padLen) throw new Error('PKCS7: invalid padding bytes');
  }
  return data.subarray(0, data.length - padLen);
}

// ---- Token (modified Fernet) -----------------------------------------
// Key split: first 32 bytes = signing key (HMAC), last 32 bytes = encryption key (AES-256)
// Token = iv(16) + aes_ciphertext + hmac(32)

async function tokenEncrypt(derivedKey, plaintext) {
  const signingKey    = derivedKey.subarray(0, 32);
  const encryptionKey = derivedKey.subarray(32, 64);

  const iv = new Uint8Array(16);
  crypto.getRandomValues(iv);

  const padded = pkcs7Pad(plaintext);

  // AES-256-CBC encrypt
  const aesKey = await crypto.subtle.importKey('raw', encryptionKey, 'AES-CBC', false, ['encrypt']);
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, padded);
  const ciphertext = new Uint8Array(cipherBuf);

  // HMAC-SHA256 over iv + ciphertext
  const hmacKey = await crypto.subtle.importKey('raw', signingKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const hmacData = concatBytes([iv, ciphertext]);
  const hmacBuf = await crypto.subtle.sign('HMAC', hmacKey, hmacData);
  const hmac = new Uint8Array(hmacBuf);

  return concatBytes([iv, ciphertext, hmac]);
}

async function tokenDecrypt(derivedKey, token) {
  if (token.length < 48) throw new Error('Token too short');

  const signingKey    = derivedKey.subarray(0, 32);
  const encryptionKey = derivedKey.subarray(32, 64);

  const iv         = token.subarray(0, 16);
  const ciphertext = token.subarray(16, token.length - 32);
  const hmac       = token.subarray(token.length - 32);

  // Verify HMAC-SHA256
  const hmacKey = await crypto.subtle.importKey('raw', signingKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const hmacData = concatBytes([iv, ciphertext]);
  const valid = await crypto.subtle.verify('HMAC', hmacKey, hmac, hmacData);
  if (!valid) throw new Error('HMAC verification failed');

  // AES-256-CBC decrypt
  const aesKey = await crypto.subtle.importKey('raw', encryptionKey, 'AES-CBC', false, ['decrypt']);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, aesKey, ciphertext);
  const padded = new Uint8Array(plainBuf);

  return pkcs7Unpad(padded);
}

// ---- Reticulum encrypt/decrypt (ECDH + HKDF + Token) ----------------

// Encrypt plaintext for a recipient's X25519 public key.
// Returns: ephemeral_pubkey(32) + token
export async function encrypt(plaintext, recipientEncPubKey, recipientIdentityHash) {
  // Generate ephemeral X25519 keypair
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub  = x25519.getPublicKey(ephPriv);

  // ECDH shared secret
  const shared = x25519.getSharedSecret(ephPriv, recipientEncPubKey);

  // HKDF derive 64 bytes (32 signing + 32 encryption)
  const derived = await hkdfDerive(shared, recipientIdentityHash, new Uint8Array(0), 64);

  // Token encrypt
  const token = await tokenEncrypt(derived, plaintext);

  return concatBytes([ephPub, token]);
}

// Decrypt ciphertext using our X25519 private key.
// ciphertext = ephemeral_pubkey(32) + token
export async function decrypt(ciphertext, ourEncPrivKey, ourIdentityHash) {
  if (ciphertext.length < 32 + 48) throw new Error('Ciphertext too short');

  const ephPub = ciphertext.subarray(0, 32);
  const token  = ciphertext.subarray(32);

  // ECDH shared secret
  const shared = x25519.getSharedSecret(ourEncPrivKey, ephPub);

  // HKDF derive 64 bytes
  const derived = await hkdfDerive(shared, ourIdentityHash, new Uint8Array(0), 64);

  // Token decrypt
  return tokenDecrypt(derived, token);
}
