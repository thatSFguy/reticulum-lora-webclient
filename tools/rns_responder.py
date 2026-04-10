#!/usr/bin/env python3
"""
Run Python RNS as an LXMF link responder against a synthetic
LINKREQUEST input, capture the LRPROOF that RNS emits, and dump it as
hex so it can be diff-checked against the web client's output for the
same logical input.

The point of this tool is to answer one specific question that the
verify_lrproof.py self-test cannot: when given a LINKREQUEST whose
fields we control, does the upstream Reticulum reference produce a
wire packet identical (modulo the random ephemeral X25519 key) to
what js/link.js produces? If yes, the web client's link responder is
byte-for-byte interop-correct and any continued failure on real RF is
not a code defect. If no, the diff tells us exactly which byte to fix.

The script does NOT touch any radio. It instantiates RNS in
no-interface mode, monkey-patches Packet.send to capture rather than
transmit, builds a synthetic LINKREQUEST locally from caller-supplied
ephemeral pubkeys, and walks it through Link.validate_request the
same way Transport.inbound would.

Usage:
    python tools/rns_responder.py <identity.json> [--linkreq HEX]

If --linkreq is given, it must be the 64- or 67-byte LINKREQUEST data
field captured from the web client log line "LR data(67)=...". The
script will reconstruct the packet header around it. If --linkreq is
omitted, the script generates a fresh random LINKREQUEST so you can
at least see what an RNS-emitted LRPROOF looks like for comparison.
"""
import argparse
import json
import os
import sys

# Suppress RNS startup chatter and disable filesystem persistence so
# this script does not create any state on the host.
os.environ["RNS_LOG_DEST"] = "stdout"

import RNS
from RNS import Identity, Destination, Link, Packet, Reticulum, Transport
from RNS.Cryptography import X25519PrivateKey


def setup_quiet_reticulum():
    """Bring RNS up just enough to construct Destinations and Links,
    without any interfaces, persistence, or transport announcement
    side effects."""
    RNS.loglevel = 0  # quiet
    # Reticulum() with no config dir spins up an in-memory instance.
    return Reticulum(loglevel=0)


def load_identity(path):
    with open(path) as f:
        data = json.load(f)
    enc_seed = bytes(data["encPrivKey"])
    sig_seed = bytes(data["sigPrivKey"])
    if len(enc_seed) != 32 or len(sig_seed) != 32:
        sys.exit("identity file: each private key must be 32 bytes")
    identity = Identity(create_keys=False)
    # RNS Identity.load_private_key expects [enc_x25519_seed(32) || sig_ed25519_seed(32)]
    identity.load_private_key(enc_seed + sig_seed)
    return identity


def build_linkreq_packet(dest, lr_data):
    """Construct an inbound LINKREQUEST Packet with the given data
    field, addressed to the supplied Destination, and unpack it the
    way Transport.inbound would. Returns the unpacked Packet ready
    for Link.validate_request to consume."""
    # Build a Packet object as if we were the initiator and it was
    # being sent to `dest`. We don't actually send it; we pack and
    # then re-unpack it so the responder side gets a Packet that
    # looks identical to one received off the wire.
    pkt = Packet(dest, lr_data, packet_type=Packet.LINKREQUEST)
    pkt.pack()

    inbound = Packet(None, None)
    inbound.raw = pkt.raw
    inbound.unpack()
    inbound.destination_hash = pkt.destination_hash
    inbound.destination = dest
    return inbound


def capture_link_prove(link, captured_box):
    """Replace Link.prove with a wrapper that snapshots the LRPROOF
    Packet bytes and skips the network send. This is the cleanest way
    to extract upstream's wire bytes without setting up an interface."""
    original_send = Packet.send

    def fake_send(self, *args, **kwargs):
        # Make sure the packet is packed before we capture.
        if not getattr(self, "packed", False):
            try:
                self.pack()
            except Exception:
                pass
        captured_box["packet"] = self
        return None

    Packet.send = fake_send
    try:
        link.prove()
    finally:
        Packet.send = original_send


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("identity", help="path to identity JSON exported from the web client")
    ap.add_argument("--linkreq", help="hex of inbound LINKREQUEST data field (64 or 67 bytes)")
    args = ap.parse_args()

    setup_quiet_reticulum()
    identity = load_identity(args.identity)
    dest = Destination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery")
    print(f".. responder destination hash : {dest.hash.hex()}")
    print(f".. responder identity hash    : {identity.hash.hex()}")
    print(f".. responder long-term sig pub: {identity.get_public_key()[32:64].hex()}")

    if args.linkreq:
        lr_data = bytes.fromhex(args.linkreq.strip())
        if len(lr_data) not in (64, 67):
            sys.exit(f"--linkreq: expected 64 or 67 bytes, got {len(lr_data)}")
        print(f".. using supplied LINKREQUEST data ({len(lr_data)} B)")
    else:
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes()
        sig_eph_pub = bytes(32)  # ephemeral Ed25519 placeholder
        signalling = bytes([0x20, 0x01, 0xF4])  # mtu=500 mode=1
        lr_data = eph_pub + sig_eph_pub + signalling
        print(f".. generated random LINKREQUEST data ({len(lr_data)} B)")

    pkt = build_linkreq_packet(dest, lr_data)
    print(f".. inbound LINKREQUEST raw    : {pkt.raw.hex()}")
    print(f".. inbound LINKREQUEST length : {len(pkt.raw)} B")

    # Pre-compute the link_id the same way Link.link_id_from_lr_packet does
    link_id = Link.link_id_from_lr_packet(pkt)
    print(f".. expected link_id           : {link_id.hex()}")

    captured = {}
    Packet_send_orig = Packet.send

    def fake_send(self, *a, **kw):
        if not getattr(self, "packed", False):
            try: self.pack()
            except Exception: pass
        captured["packet"] = self
        return None

    Packet.send = fake_send
    try:
        link = Link.validate_request(dest, lr_data, pkt)
    finally:
        Packet.send = Packet_send_orig

    if link is None:
        sys.exit("FAIL: Link.validate_request returned None")

    if "packet" not in captured:
        sys.exit("FAIL: Link.prove did not produce a packet")

    proof_pkt = captured["packet"]
    raw = proof_pkt.raw
    print()
    print(f"== RNS-emitted LRPROOF ==")
    print(f"   total length    : {len(raw)} B")
    print(f"   raw hex         : {raw.hex()}")
    print()
    print(f"   header[0] flags : 0x{raw[0]:02x}")
    print(f"   header[1] hops  : 0x{raw[1]:02x}")
    print(f"   dest slot (16)  : {raw[2:18].hex()}")
    print(f"   context byte    : 0x{raw[18]:02x}")
    print()
    data = raw[19:]
    print(f"   data length     : {len(data)} B")
    print(f"   signature (64)  : {data[:64].hex()}")
    print(f"   x25519 pub (32) : {data[64:96].hex()}")
    if len(data) == 99:
        print(f"   signalling (3)  : {data[96:99].hex()}")
    elif len(data) == 96:
        print(f"   signalling      : (none)")
    else:
        print(f"   trailing bytes  : {data[96:].hex()}")


if __name__ == "__main__":
    main()
