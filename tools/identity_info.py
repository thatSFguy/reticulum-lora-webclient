#!/usr/bin/env python3
"""
Dump derived public material from an exported web-client identity file.

The web client's Export Identity button writes a JSON file that looks
like `{"encPrivKey": [...], "sigPrivKey": [...]}` where each value is
an array of 32 bytes. This tool reads that file, reconstructs the
Identity server-side using RNS's own crypto primitives, and prints
everything that can be derived: the raw byte form of each key, the
combined 64-byte public key, the 16-byte identity hash, and the
16-byte LXMF delivery destination hash for name "lxmf.delivery".

It is read-only. It does not touch the private keys beyond loading
them in-memory to derive the public halves, and it does not transmit
anything.

Usage:
    python tools/identity_info.py path/to/reticulum-identity-XXXX.json
"""
import argparse
import hashlib
import json
import sys

from RNS.Cryptography import Ed25519PrivateKey, X25519PrivateKey

NAME_HASH_LENGTH     = 10    # 80 bits
TRUNCATED_HASHLENGTH = 16    # 128 bits


def bytes_from_array(a):
    b = bytes(a)
    if len(b) != 32:
        sys.exit(f"expected 32 byte private key, got {len(b)}")
    return b


def sha256(data):
    return hashlib.sha256(data).digest()


def destination_hash(full_name, identity_hash):
    name_hash = sha256(full_name.encode("utf-8"))[:NAME_HASH_LENGTH]
    return sha256(name_hash + identity_hash)[:TRUNCATED_HASHLENGTH]


def main():
    ap = argparse.ArgumentParser(description="Print derived pubs and hashes from a web-client exported identity.")
    ap.add_argument("path", help="path to the JSON file produced by the Export Identity button")
    args = ap.parse_args()

    with open(args.path, "r") as f:
        data = json.load(f)

    enc_priv_bytes = bytes_from_array(data["encPrivKey"])
    sig_priv_bytes = bytes_from_array(data["sigPrivKey"])
    ratchet_priv_bytes = bytes_from_array(data["ratchetPrivKey"]) if "ratchetPrivKey" in data else None

    # Load through RNS to match exactly how the client derives its pub halves.
    # RNS's X25519PrivateKey.from_private_bytes / public_key does the clamping
    # and scalar multiplication internally; the resulting pub is identical to
    # noble-curves' getPublicKey on the same seed.
    enc_priv = X25519PrivateKey.from_private_bytes(enc_priv_bytes)
    enc_pub_bytes = enc_priv.public_key().public_bytes()

    sig_priv = Ed25519PrivateKey.from_private_bytes(sig_priv_bytes)
    sig_pub_bytes = sig_priv.public_key().public_bytes()

    ratchet_pub_bytes = None
    if ratchet_priv_bytes:
        ratchet_priv = X25519PrivateKey.from_private_bytes(ratchet_priv_bytes)
        ratchet_pub_bytes = ratchet_priv.public_key().public_bytes()

    public_key = enc_pub_bytes + sig_pub_bytes     # 64 bytes
    identity_hash = sha256(public_key)[:TRUNCATED_HASHLENGTH]

    lxmf_dest_hash = destination_hash("lxmf.delivery", identity_hash)

    print("encPrivKey    (32) =", enc_priv_bytes.hex())
    print("encPubKey     (32) =", enc_pub_bytes.hex())
    print("sigPrivKey    (32) =", sig_priv_bytes.hex())
    print("sigPubKey     (32) =", sig_pub_bytes.hex())
    if ratchet_priv_bytes:
        print("ratchetPrivKey(32) =", ratchet_priv_bytes.hex())
        print("ratchetPubKey (32) =", ratchet_pub_bytes.hex())
    else:
        print("ratchetPrivKey     = (not present; pre-ratchet identity export)")
    print("publicKey     (64) =", public_key.hex())
    print("identityHash  (16) =", identity_hash.hex())
    print("lxmfDestHash  (16) =", lxmf_dest_hash.hex())


if __name__ == "__main__":
    main()
