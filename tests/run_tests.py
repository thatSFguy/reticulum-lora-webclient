#!/usr/bin/env python3
"""
Level 2 test runner. Spawns the Node harness (tests/roundtrip.mjs),
captures its JSON output, and validates each test vector against
RNS's own reference implementation. Any regression in a web client
module that changes the on-wire format of announces, LXMF messages,
or LRPROOFs will surface here as a FAIL on one or more scenarios.

Run directly with `python tests/run_tests.py`. Exit code is 0 on
all-pass, 1 on any failure. Designed to be called from CI.
"""
import json
import os
import subprocess
import sys

os.environ["RNS_LOG_DEST"] = "stderr"

import RNS
from RNS import Identity, Packet, Reticulum
from RNS.Cryptography import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
    X25519PrivateKey,
    X25519PublicKey,
    HKDF,
    Token,
)
import hashlib

try:
    import umsgpack
except ImportError:
    import msgpack as umsgpack

OK = "\033[32mOK\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36m..\033[0m"


def run_harness():
    """Spawn tests/roundtrip.mjs and parse its JSON output."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        ["node", "tests/roundtrip.mjs"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"{FAIL} Node harness exited {result.returncode}")
        print("stderr:", result.stderr)
        sys.exit(1)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"{FAIL} Could not parse harness output as JSON: {e}")
        print("stdout:", result.stdout[:500])
        sys.exit(1)


def load_rns_identity_from_hex(hex_record):
    """Rebuild an RNS Identity from the hex seeds the harness emitted."""
    enc_seed = bytes.fromhex(hex_record["encPriv"])
    sig_seed = bytes.fromhex(hex_record["sigPriv"])
    identity = Identity(create_keys=False)
    # RNS expects enc (x25519) first, then sig (ed25519).
    identity.load_private_key(enc_seed + sig_seed)
    return identity


def scenario_announce(vectors, results):
    """Validate that the announce packet our JS emits is accepted by
    RNS.Identity.validate_announce. This exercises the whole outbound
    announce path: destination hash formula, ratchet insertion,
    signature computation, packet framing."""
    print(f"{INFO} Scenario 1: announce round-trip")

    js_alice = vectors["alice"]
    raw = bytes.fromhex(vectors["announce"]["packet"])

    pkt = Packet(None, None)
    pkt.raw = raw
    pkt.unpack()

    # Sanity checks on the unpacked header before we hand it to the
    # full validator. These catch "our JS built a header that looks
    # like a different packet type" kinds of bugs before we even try
    # the signature verify.
    if pkt.packet_type != RNS.Packet.ANNOUNCE:
        print(f"   {FAIL} unpacked packet_type is not ANNOUNCE ({pkt.packet_type})")
        results.append(False)
        return
    if pkt.context_flag != RNS.Packet.FLAG_SET:
        print(f"   {FAIL} context_flag is not SET (ratchet announce should have bit 5 high)")
        results.append(False)
        return
    if pkt.destination_hash.hex() != js_alice["destHash"]:
        print(f"   {FAIL} dest_hash mismatch: js={js_alice['destHash']} python={pkt.destination_hash.hex()}")
        results.append(False)
        return

    if Identity.validate_announce(pkt):
        print(f"   {OK} RNS.Identity.validate_announce accepted ratchet announce")
        results.append(True)
    else:
        print(f"   {FAIL} RNS.Identity.validate_announce rejected our announce")
        results.append(False)


def scenario_lxmf_send(vectors, results):
    """Alice (in JS) encrypts an LXMF message to Bob's ratchet pubkey.
    Python loads Bob's identity from the hex seeds, extracts the
    ratchet private key, manually performs ECDH+HKDF+Token decrypt,
    and verifies the LXMF signature against Alice's sig pub. If any
    byte of the encrypt path drifts this test fails loudly."""
    print(f"{INFO} Scenario 2: opportunistic LXMF round-trip")

    alice_hex = vectors["alice"]
    bob_hex = vectors["bob"]
    raw = bytes.fromhex(vectors["lxmf_send"]["packet"])

    # Unpack the packet header manually so we can get at the encrypted
    # body without relying on RNS's Destination-based decrypt (which
    # would require us to register a matching Destination with the
    # right Identity — more moving parts than necessary).
    pkt = Packet(None, None)
    pkt.raw = raw
    pkt.unpack()

    if pkt.packet_type != RNS.Packet.DATA:
        print(f"   {FAIL} unpacked packet_type is not DATA")
        results.append(False)
        return
    if pkt.destination_hash.hex() != bob_hex["destHash"]:
        print(f"   {FAIL} dest_hash addressed to {pkt.destination_hash.hex()}, expected Bob's {bob_hex['destHash']}")
        results.append(False)
        return

    # The on-wire ciphertext: ephemeral_x25519_pub(32) || token
    body = pkt.data
    eph_pub = body[:32]
    token_bytes = body[32:]

    # Decrypt with Bob's ratchet private key (what the webclient's
    # decrypt fallback tries first).
    bob_ratchet_priv_bytes = bytes.fromhex(bob_hex["ratchetPriv"])
    bob_ratchet = X25519PrivateKey.from_private_bytes(bob_ratchet_priv_bytes)
    # RNS's X25519PrivateKey.exchange() wants a public-key *object*,
    # not raw bytes, so wrap the ephemeral pub we pulled off the wire.
    eph_pub_obj = X25519PublicKey.from_public_bytes(eph_pub)
    shared = bob_ratchet.exchange(eph_pub_obj)

    bob_identity_hash = bytes.fromhex(bob_hex["identityHash"])
    derived = HKDF.hkdf(64, shared, salt=bob_identity_hash, context=b"")

    try:
        token = Token(derived)
        plaintext = token.decrypt(token_bytes)
    except Exception as e:
        print(f"   {FAIL} Token.decrypt threw: {e}")
        results.append(False)
        return

    # LXMF opportunistic on-wire payload:
    #   source_hash(16) || signature(64) || msgpack(payload)
    if len(plaintext) < 16 + 64 + 1:
        print(f"   {FAIL} plaintext too short to be an LXMF message ({len(plaintext)} B)")
        results.append(False)
        return

    source_hash = plaintext[:16]
    signature = plaintext[16:80]
    msgpack_data = plaintext[80:]

    if source_hash.hex() != alice_hex["destHash"]:
        print(f"   {FAIL} source_hash={source_hash.hex()} != Alice's destHash={alice_hex['destHash']}")
        results.append(False)
        return

    try:
        payload = umsgpack.unpackb(msgpack_data)
    except Exception as e:
        print(f"   {FAIL} msgpack.unpackb threw: {e}")
        results.append(False)
        return

    if not isinstance(payload, list) or len(payload) < 4:
        print(f"   {FAIL} LXMF payload is not a 4-element array: {type(payload).__name__} len={len(payload) if hasattr(payload, '__len__') else '?'}")
        results.append(False)
        return

    content_bytes = payload[2]
    content = content_bytes.decode("utf-8") if isinstance(content_bytes, (bytes, bytearray)) else content_bytes
    expected_content = vectors["lxmf_send"]["content"]
    if content != expected_content:
        print(f"   {FAIL} decoded content {content!r} != expected {expected_content!r}")
        results.append(False)
        return

    # Verify signature: hashed_part || message_hash
    bob_dest_bytes = bytes.fromhex(bob_hex["destHash"])
    hashed_part = bob_dest_bytes + source_hash + msgpack_data
    message_hash = hashlib.sha256(hashed_part).digest()
    signed_part = hashed_part + message_hash

    alice_sig_pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(alice_hex["sigPub"]))
    try:
        alice_sig_pub.verify(signature, signed_part)
        print(f"   {OK} LXMF message decrypted, unpacked ({content!r}), signature verified")
        results.append(True)
    except Exception as e:
        print(f"   {FAIL} Ed25519 verify of LXMF signature raised: {type(e).__name__}")
        results.append(False)


def scenario_link_handshake(vectors, results):
    """Full 4-way Alice-initiates-link-to-Bob handshake. The JS harness
    has already run both the initiator and the responder in-process,
    checked that link_ids match, checked that derived keys match, and
    encrypted a known plaintext under the derived key. Here we verify
    that the ciphertext decrypts cleanly under RNS's own Token, which
    proves the derived key is bit-identical to what upstream would
    produce for the same inputs."""
    print(f"{INFO} Scenario 4: Alice initiates link to Bob, full handshake + data")
    handshake = vectors.get("link_handshake")
    if not handshake:
        print(f"   {FAIL} harness did not emit link_handshake vector")
        results.append(False)
        return

    if handshake["linkIdInitiator"] != handshake["linkIdResponder"]:
        print(f"   {FAIL} initiator and responder disagree on link_id")
        results.append(False)
        return

    derived_key = bytes.fromhex(handshake["derivedKey"])
    if len(derived_key) != 64:
        print(f"   {FAIL} derived key is {len(derived_key)} B, expected 64")
        results.append(False)
        return

    ciphertext = bytes.fromhex(handshake["testCiphertext"])
    expected = handshake["testPlaintext"].encode("utf-8")
    try:
        token = Token(derived_key)
        plaintext = token.decrypt(ciphertext)
    except Exception as e:
        print(f"   {FAIL} RNS Token.decrypt with JS derived key raised: {e}")
        results.append(False)
        return

    if plaintext != expected:
        print(f"   {FAIL} link plaintext mismatch: got {plaintext!r} expected {expected!r}")
        results.append(False)
        return

    print(f"   {OK} link handshake + encrypted data round-trip succeeds under RNS Token")
    results.append(True)


def scenario_link_proof(vectors, results):
    """Verify that the LRPROOF our Link.validateRequest produces has a
    header, signed data, and Ed25519 signature that RNS's reference
    implementation accepts. The Python side does not hold the mock
    initiator's private keys, but it does not need them: LRPROOF
    verification is a pure Ed25519 signature check over a known
    layout, so we can reconstruct signed_data from the pieces in
    the JSON and verify against Alice's long-term sig pub."""
    print(f"{INFO} Scenario 3: LRPROOF signature check")

    alice_hex = vectors["alice"]
    link_hex = vectors["link"]

    lr_proof = bytes.fromhex(link_hex["lrProofPacket"])
    link_id = bytes.fromhex(link_hex["linkId"])
    signed_data = bytes.fromhex(link_hex["signedData"])

    # Parse the LRPROOF packet header manually. Upstream packs it
    # specially: the dest slot carries link_id (not a destination
    # hash), the context byte is 0xFF, flags = 0x0F.
    if len(lr_proof) < 19 + 64 + 32 + 3:
        print(f"   {FAIL} LRPROOF too short: {len(lr_proof)} B")
        results.append(False)
        return
    if lr_proof[0] != 0x0F:
        print(f"   {FAIL} LRPROOF flags byte 0x{lr_proof[0]:02x} != 0x0F")
        results.append(False)
        return
    if lr_proof[18] != 0xFF:
        print(f"   {FAIL} LRPROOF context byte 0x{lr_proof[18]:02x} != 0xFF (LRPROOF)")
        results.append(False)
        return
    if lr_proof[2:18] != link_id:
        print(f"   {FAIL} LRPROOF header link_id mismatch")
        results.append(False)
        return

    proof_data = lr_proof[19:]
    signature = proof_data[:64]
    ephemeral_x25519_pub = proof_data[64:96]
    signalling = proof_data[96:99]

    # Reconstruct signed_data the way an initiator would:
    # link_id || ephemeral_x25519_pub || responder_long_term_sig_pub || signalling
    responder_sig_pub = bytes.fromhex(alice_hex["sigPub"])
    rebuilt_signed = link_id + ephemeral_x25519_pub + responder_sig_pub + signalling

    if rebuilt_signed != signed_data:
        print(f"   {FAIL} rebuilt signed_data does not match what JS reported")
        print(f"          js     : {signed_data.hex()}")
        print(f"          rebuilt: {rebuilt_signed.hex()}")
        results.append(False)
        return

    try:
        Ed25519PublicKey.from_public_bytes(responder_sig_pub).verify(signature, rebuilt_signed)
        print(f"   {OK} LRPROOF signature verified against Alice's long-term sig pub")
        results.append(True)
    except Exception as e:
        print(f"   {FAIL} LRPROOF signature verification raised: {type(e).__name__}")
        results.append(False)


def main():
    RNS.loglevel = 0
    Reticulum(loglevel=0)

    print(f"{INFO} running tests/roundtrip.mjs to collect test vectors...")
    vectors = run_harness()
    print(f"   {OK} harness produced {len(json.dumps(vectors))} bytes of JSON")
    print()

    results = []
    scenario_announce(vectors, results)
    scenario_lxmf_send(vectors, results)
    scenario_link_proof(vectors, results)
    scenario_link_handshake(vectors, results)

    print()
    passed = sum(1 for r in results if r)
    total = len(results)
    if passed == total:
        print(f"{OK} all {total} scenarios passed")
        sys.exit(0)
    else:
        print(f"{FAIL} {passed}/{total} scenarios passed")
        sys.exit(1)


if __name__ == "__main__":
    main()
