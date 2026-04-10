#!/usr/bin/env python3
"""
Verify an LRPROOF produced by the web client against RNS's own Ed25519
implementation. Runs in two phases: first a known-good round trip
where this script both signs and verifies using RNS, confirming the
library is functioning and our understanding of the signed-data
layout is correct; then an external-input phase where hex values
lifted from the web client's log are fed in and verified.

Usage:
    python verify_lrproof.py
    python verify_lrproof.py --sigpub HEX --signed HEX --sig HEX
    python verify_lrproof.py --sigpub HEX --linkid HEX --x25519 HEX --signalling HEX --sig HEX
    python verify_lrproof.py --sigpub HEX --lrproof HEX --linkid HEX

The first form runs only the self-test. The second and third forms
also run the external-verification phase with values from a webclient
log line:
    LR sigpub=<hex>
    LR signed(83)=<hex>
    LRPROOF tx(118)=<hex>

The third form accepts the raw LRPROOF packet bytes (as logged) plus
the link id and reconstructs signed_data from the proof payload.
"""
import argparse
import sys

from RNS.Cryptography import Ed25519PrivateKey, Ed25519PublicKey, X25519PrivateKey, HKDF


OK = "\033[32mOK\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36m..\033[0m"

MTU_BYTEMASK = 0x1FFFFF


def encode_signalling(mtu, mode):
    val = (mtu & MTU_BYTEMASK) | ((mode & 0x07) << 21)
    return bytes([(val >> 16) & 0xFF, (val >> 8) & 0xFF, val & 0xFF])


def decode_signalling(b):
    val = (b[0] << 16) | (b[1] << 8) | b[2]
    return val & MTU_BYTEMASK, (val >> 21) & 0x07


def ed25519_verify(sig_pub_bytes, signed_data, signature):
    pub = Ed25519PublicKey.from_public_bytes(sig_pub_bytes)
    try:
        pub.verify(signature, signed_data)
        return True
    except Exception:
        return False


def phase_self_test():
    print(f"{INFO} phase 1: RNS Ed25519 self test")

    responder_sig_priv = Ed25519PrivateKey.generate()
    responder_sig_pub = responder_sig_priv.public_key().public_bytes()

    responder_x_priv = X25519PrivateKey.generate()
    responder_x_pub = responder_x_priv.public_key().public_bytes()

    link_id = b"\x01\x23\x45\x67\x89\xab\xcd\xef" * 2   # 16 bytes
    mtu = 500
    mode = 1                                              # AES256_CBC
    signalling = encode_signalling(mtu, mode)

    signed_data = link_id + responder_x_pub + responder_sig_pub + signalling
    assert len(signed_data) == 16 + 32 + 32 + 3, f"bad signed_data len {len(signed_data)}"

    signature = responder_sig_priv.sign(signed_data)
    assert len(signature) == 64, f"bad signature len {len(signature)}"

    ok = ed25519_verify(responder_sig_pub, signed_data, signature)
    status = OK if ok else FAIL
    print(f"   {status} sign-and-verify self test")

    bad = bytearray(signature); bad[0] ^= 0x01
    ok_bad = ed25519_verify(responder_sig_pub, signed_data, bytes(bad))
    status = OK if not ok_bad else FAIL
    print(f"   {status} tampered signature rejected")

    # HKDF round trip on a fresh X25519 pair, just to confirm that
    # the link key derivation matches what the webclient does.
    ephemeral = X25519PrivateKey.generate()
    shared_a = ephemeral.exchange(responder_x_priv.public_key())
    shared_b = responder_x_priv.exchange(ephemeral.public_key())
    status = OK if shared_a == shared_b else FAIL
    print(f"   {status} X25519 ECDH symmetric ({len(shared_a)} B)")

    derived = HKDF.hkdf(64, shared_a, link_id, b"")
    status = OK if len(derived) == 64 else FAIL
    print(f"   {status} HKDF(64, shared, salt=link_id, info=empty) -> {len(derived)} B")

    print()


def parse_hex(s, name, expected_len=None):
    if s is None:
        return None
    s = s.strip().replace(" ", "").replace(":", "")
    try:
        b = bytes.fromhex(s)
    except ValueError as e:
        sys.exit(f"{name}: invalid hex ({e})")
    if expected_len is not None and len(b) != expected_len:
        sys.exit(f"{name}: expected {expected_len} bytes, got {len(b)}")
    return b


def phase_external(args):
    print(f"{INFO} phase 2: verifying webclient log hex")

    sig_pub = parse_hex(args.sigpub, "sigpub", 32)

    if args.signed and args.sig:
        signed_data = parse_hex(args.signed, "signed")
        signature = parse_hex(args.sig, "sig", 64)
    elif args.lrproof and args.linkid:
        proof = parse_hex(args.lrproof, "lrproof")
        link_id = parse_hex(args.linkid, "linkid", 16)
        if len(proof) < 19 + 64 + 32 + 3:
            sys.exit(f"lrproof: too short ({len(proof)} B)")
        header = proof[:19]
        data = proof[19:]
        if header[0] != 0x0F:
            print(f"   {FAIL} lrproof flags byte 0x{header[0]:02x} is not 0x0f")
        if header[2:18] != link_id:
            print(f"   {FAIL} lrproof header destination slot does not match link id")
        if header[18] != 0xFF:
            print(f"   {FAIL} lrproof context byte 0x{header[18]:02x} is not 0xff (LRPROOF)")
        signature = data[:64]
        x25519_pub = data[64:96]
        signalling = data[96:99]
        mtu, mode = decode_signalling(signalling)
        print(f"   {INFO} proof payload: sig=64 x25519={x25519_pub.hex()[:16]}... sig=... mtu={mtu} mode={mode}")
        signed_data = link_id + x25519_pub + sig_pub + signalling
    elif args.linkid and args.x25519 and args.signalling and args.sig:
        link_id = parse_hex(args.linkid, "linkid", 16)
        x25519_pub = parse_hex(args.x25519, "x25519", 32)
        signalling = parse_hex(args.signalling, "signalling", 3)
        signature = parse_hex(args.sig, "sig", 64)
        signed_data = link_id + x25519_pub + sig_pub + signalling
    else:
        print(f"   (no external hex supplied, skipping)")
        return

    print(f"   {INFO} signed_data({len(signed_data)}) = {signed_data.hex()}")
    print(f"   {INFO} signature    = {signature.hex()}")
    print(f"   {INFO} sig_pub      = {sig_pub.hex()}")

    ok = ed25519_verify(sig_pub, signed_data, signature)
    status = OK if ok else FAIL
    print(f"   {status} LRPROOF signature verification")


def main():
    ap = argparse.ArgumentParser(description="Verify an LRPROOF signature using RNS.")
    ap.add_argument("--sigpub",     help="responder long-term Ed25519 public key (32 B hex)")
    ap.add_argument("--signed",     help="exact signed_data bytes that were signed (hex)")
    ap.add_argument("--sig",        help="Ed25519 signature (64 B hex)")
    ap.add_argument("--lrproof",    help="full LRPROOF packet bytes including 19 B header (hex)")
    ap.add_argument("--linkid",     help="link id (16 B hex)")
    ap.add_argument("--x25519",     help="responder ephemeral X25519 pub (32 B hex)")
    ap.add_argument("--signalling", help="signalling bytes (3 B hex)")
    args = ap.parse_args()

    phase_self_test()
    if args.sigpub is not None:
        phase_external(args)


if __name__ == "__main__":
    main()
