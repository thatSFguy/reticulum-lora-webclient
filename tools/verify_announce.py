#!/usr/bin/env python3
"""
Build an lxmf.delivery announce the same way the web client does,
hand it to RNS's own Identity.validate_announce, and report whether
the upstream reference accepts it. If this passes, the web client's
outgoing announce wire format is cryptographically valid and any
refusal by Sideband or NomadNet to pick the announce up is on their
side (cache, blackhole list, stale identity), not ours.

Loads the identity from the Export Identity JSON that the web
client writes.

Usage:
    python tools/verify_announce.py reticulum-identity-544fef09.json [--name WebClient]
"""
import argparse
import json
import os
import sys

# Quiet RNS startup
os.environ["RNS_LOG_DEST"] = "stdout"

import RNS
import umsgpack
from RNS import Identity, Destination, Packet, Reticulum
from RNS.Cryptography import Ed25519PrivateKey, X25519PrivateKey


OK = "\033[32mOK\033[0m"
FAIL = "\033[31mFAIL\033[0m"
INFO = "\033[36m..\033[0m"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("identity")
    ap.add_argument("--name", default="WebClient")
    args = ap.parse_args()

    RNS.loglevel = 0
    Reticulum(loglevel=0)

    with open(args.identity) as f:
        data = json.load(f)
    enc = bytes(data["encPrivKey"])
    sig = bytes(data["sigPrivKey"])
    if len(enc) != 32 or len(sig) != 32:
        sys.exit("identity: each private key must be 32 bytes")

    identity = Identity(create_keys=False)
    identity.load_private_key(enc + sig)

    dest = Destination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery")
    print(f"{INFO} destination hash: {dest.hash.hex()}")
    print(f"{INFO} identity hash   : {identity.hash.hex()}")
    print(f"{INFO} sig pub         : {identity.get_public_key()[32:64].hex()}")

    # Build the exact app_data the web client emits.
    # sendAnnounce in js/app.js does msgpack([display_name_bytes, 0])
    # which encodes as: fixarray(2) | bin8(len)(name) | int0
    app_data = umsgpack.packb([args.name.encode("utf-8"), 0])
    print(f"{INFO} app_data        : {app_data.hex()} ({len(app_data)} B)")

    # Ask RNS to build an announce packet the same way it would over the wire.
    pkt = dest.announce(app_data=app_data, send=False)
    if pkt is None:
        sys.exit("FAIL: Destination.announce(send=False) returned None")

    # announce(send=False) returns the Packet object; pack it to see raw bytes.
    if not pkt.packed:
        pkt.pack()
    print(f"{INFO} announce bytes  : {len(pkt.raw)} B total")
    print(f"{INFO} raw hex         : {pkt.raw.hex()}")

    # Feed the packed Packet through validate_announce (simulate inbound).
    inbound = Packet(None, None)
    inbound.raw = pkt.raw
    inbound.unpack()
    print(f"{INFO} unpacked dest   : {inbound.destination_hash.hex()}")
    print(f"{INFO} unpacked type   : packet_type={inbound.packet_type} context_flag={inbound.context_flag}")
    print(f"{INFO} unpacked data   : {len(inbound.data)} B")

    ok = Identity.validate_announce(inbound)
    status = OK if ok else FAIL
    print()
    print(f"   {status} RNS Identity.validate_announce on our announce bytes")

    if not ok:
        print()
        print("   If validation failed above, the web client is producing")
        print("   an announce the reference implementation rejects. Dump")
        print("   the raw hex and compare to a known-good Sideband announce.")
    else:
        print()
        print("   Web client announce format is byte-compatible with RNS.")
        print("   If Sideband still refuses to pick it up, the cause is on")
        print("   Sideband's side (blackhole list, stale known_destinations")
        print("   cache entry, or UI-level dedup). Restarting Sideband or")
        print("   clearing its app data is the easiest thing to try first.")


if __name__ == "__main__":
    main()
