# reticulum-lora-webclient

A browser-based Reticulum messaging client that talks to an [RNode](https://unsigned.io/rnode) LoRa modem over Web Bluetooth or Web Serial and exchanges encrypted LXMF messages with Sideband, NomadNet, MeshChat, and other Reticulum nodes on a LoRa mesh.

**Live app:** <https://thatsfguy.github.io/reticulum-lora-webclient/>

No build step, no server, no framework. Plain ES modules, loaded directly in the browser. Designed to be served as static files from GitHub Pages or any file host.

## What it does

- Connects to an RNode over Web Bluetooth (primary) or Web Serial (dev fallback).
- Configures the radio (frequency, bandwidth, spreading factor, coding rate, TX power) and turns it on.
- Generates and persists an Ed25519 / X25519 Reticulum identity in IndexedDB.
- Sends and receives Reticulum announces, auto-announces once at connect and every five minutes thereafter so relay identity caches stay warm.
- Encrypts and decrypts LXMF messages for **opportunistic single-packet delivery** using the standard Reticulum ECDH + HKDF + AES-256-CBC + HMAC-SHA256 scheme.
- Accepts incoming **Reticulum Link** handshakes and receives link-delivered LXMF messages. We act as link responder only — we validate LINKREQUESTs, emit LRPROOFs signed with our long-term Ed25519 key, receive LRRTT acknowledgements, decrypt inbound link traffic, and send per-packet PROOF receipts back so the sender does not retry forever. Sideband and MeshChat both round-trip cleanly this way.
- Filters the contact list by LXMF `name_hash` so announces from telemetry beacons, heartbeats, or other non-LXMF destinations do not pollute it. Contacts get an unread-count badge and a small delete button in the sidebar.
- Stores identity, contacts, and message history locally in IndexedDB. Messages are sorted in the conversation view by their IndexedDB insertion order, which keeps the timeline correct even when a clockless LoRa sender reports a nonsense timestamp. Nothing leaves your browser except over the radio link.

## What it does not do (yet)

- **Link initiation** — we are responder only. Messages we originate are always delivered opportunistically, which caps them at roughly 250–300 bytes of content.
- **Resources** — multi-packet transfers over an established link (needed for messages larger than a single packet). So no file or image attachments.
- **Ratchet emission on outbound announces** — we parse ratchet fields on inbound announces so the signature still validates, but we do not yet emit our own ratchet.
- **Outbound retry queue** — a send that fails has no "pending" or "failed" state in the UI yet.
- No propagation node / store-and-forward support. Both parties must be on the air at the same time.
- No multi-hop transport routing tables. Single-hop LoRa only.
- No IFAC, no LXMF stamps (we handle them on inbound, but do not emit them), no GROUP destinations.

See `CLAUDE.md` for the scope rules and implementation plan, and `docs/PROTOCOL_NOTES.md` for the detailed Reticulum / LXMF interop findings accumulated while building this client.

## Platform support

| Platform            | Web Bluetooth | Web Serial | Works? |
|---------------------|---------------|------------|--------|
| Chrome Android      | Yes           | No         | Primary target |
| Chrome/Edge desktop | Yes           | Yes        | Dev and daily use |
| Brave desktop       | Yes           | Yes        | Works |
| Safari (iOS/macOS)  | No            | No         | Blocked by Apple |
| Firefox             | No            | No         | Blocked by Mozilla |

Web Bluetooth requires HTTPS (or `http://localhost`). GitHub Pages and any other HTTPS host are fine.

## Running it

Because it is all static files with ES module imports, any HTTPS static host works. Locally:

```bash
# from the project root
python -m http.server 8000
```

Then open `http://localhost:8000/` in Chrome, Edge, or Brave. `localhost` is treated as a secure origin, so Web Bluetooth and Web Serial are both available without a certificate.

For a public deploy, push to `gh-pages` (or any static bucket) and visit the HTTPS URL directly. No build step.

## Using it

1. **Connect.** Click `Connect (BLE)` and pick your RNode from the Bluetooth chooser, or click `Connect (Serial)` and select the USB serial port. The webapp will detect the modem, read firmware version and battery, and auto-start the radio with the values in the collapsible Radio Configuration panel.
2. **Set your display name** and click `Send Announce`. This broadcasts your identity and destination to the mesh so other Reticulum nodes can learn how to reach you. Your LXMF address is shown under `Your Identity`.
3. **Wait for announces.** When another node announces on the same radio parameters, it shows up in the contact list on the left.
4. **Open a conversation.** Click a contact to open the conversation view, type a message, and hit Enter. Incoming messages from that contact land in the same view.

Identity persists across reloads. `Export Identity` writes a JSON file containing your private keys; `New Identity` generates a fresh keypair (and will change your LXMF address).

## Architecture

The RNode is a dumb LoRa modem over KISS. All Reticulum protocol logic runs in the browser.

```
Browser (Web Bluetooth / Web Serial) --> KISS --> RNode firmware --> SX126x --> LoRa RF
                                                                                   |
                                                         Sideband / NomadNet / MeshChat / other RNodes
```

## Module layout

```
reticulum-lora-webclient/
  index.html              Single-page app shell
  css/style.css           Dark theme

  js/
    ble-transport.js      Web Bluetooth NUS byte stream
    serial-transport.js   Web Serial byte stream
    kiss.js               KISS frame encode/decode + parser that reassembles
                          frames split across BLE notifications
    rnode.js              RNode command layer (detect, configure, send/recv)
    reticulum.js          Reticulum packet header encode/decode + constants
    identity.js           Ed25519 + X25519 keypair, identity hash, destination hash
    crypto.js             ECDH + HKDF + Token (AES-256-CBC + HMAC-SHA256)
    announce.js           Build, parse, and validate Reticulum announces
    link.js               Reticulum Link responder: LINKREQUEST validation,
                          LRPROOF build, link_id derivation, signalling encoding,
                          Token encrypt/decrypt over the derived link key
    lxmf.js               LXMF message pack/unpack + signature
    store.js              IndexedDB for identity, contacts, messages
    app.js                UI controller and state management

  tools/                  Python RNS-based offline verifiers (see below)
  docs/PROTOCOL_NOTES.md  Reticulum / LXMF interop findings reference
```

Libraries (`@noble/curves` for Ed25519/X25519 and `@msgpack/msgpack` for LXMF payload serialization) are loaded from a CDN via an import map in `index.html`. Web Crypto handles AES-CBC, HMAC, HKDF, and SHA-256 natively.

## Diagnostic tools

The `tools/` directory contains Python scripts that validate the web client's wire output against the Python RNS reference without needing any radio or browser in the loop. Each takes the JSON file produced by the `Export Identity` button as its input.

- `tools/identity_info.py` — dumps every derivable public piece of an exported identity (enc/sig private and public bytes, identity hash, LXMF destination hash). Read-only, never touches network.
- `tools/verify_lrproof.py` — runs a self-test of RNS's Ed25519, X25519, and HKDF primitives, then verifies a real LRPROOF hex string (lifted from the web client log) against `Identity.validate` to prove our link-proof signatures are byte-compatible with upstream.
- `tools/verify_announce.py` — builds an `lxmf.delivery` announce with RNS using the web client's identity and runs it through `Identity.validate_announce`, proving our announce format is acceptable to the upstream reference.
- `tools/rns_responder.py` — runs Python RNS as a link responder against a supplied LINKREQUEST data field, captures the LRPROOF bytes RNS would emit, and prints them field by field for a byte-for-byte diff against the web client's own output.

All four depend only on `rns` and `umsgpack` from pip and are safe to run against a real exported identity on the local machine.

## Development notes

- Open the browser DevTools console to see stack traces. The in-page log shows a terse one-line error, but the full trace only lives in the console.
- The webapp listens for `error` and `unhandledrejection` on `window` and mirrors the message into the log, so uncaught errors from async handlers still show up.
- `store.js` uses a single IndexedDB database named `reticulum-webclient` with object stores for `identity`, `contacts`, and `messages`. To wipe local state, open DevTools then Application then Storage then Clear site data.
- The KISS parser accumulates bytes across BLE notifications and emits complete frames on FEND boundaries. BLE splits frames at arbitrary points, so any per-notification framing assumption will break.
- Reticulum destination hashes are computed with the identity hexhash **outside** the name hash input, matching upstream `Destination.hash(identity, app_name, *aspects)`. The hexhash appears only in the human-readable `Destination.name`, never in on-wire hashes.
- LRPROOF packets have a special framing exception in upstream `Packet::pack`: the 16-byte destination slot of the header carries the link_id instead of the SINGLE destination's hash, and the flag byte's destination-type bits are hardcoded to `LINK` regardless of the destination the packet was constructed with. Our `buildPacket` matches this by accepting `destType` and `destHash` as explicit parameters rather than deriving them from a destination object.
- Every accepted CONTEXT_NONE data packet on an established link gets an immediate PROOF packet sent back, carrying the 32-byte SHA-256 of the received packet's hashable part plus an Ed25519 signature of that hash. Without this packet receipt, the sender's delivery-receipt timeout fires and it retries on a fresh link, producing a "same message keeps arriving" loop.
- Periodic re-announcement is mandatory for inbound link delivery, not cosmetic. Relays validate inbound LRPROOFs by looking up the responder's identity in their own `Identity.known_destinations` cache, and that cache gets GC'd — without a periodic refresh the LRPROOF is dropped at the relay before ever reaching the initiator. See `docs/PROTOCOL_NOTES.md` §14 for detail.
- See `docs/PROTOCOL_NOTES.md` for the full set of protocol-layer findings, including the destination hash formula, Web Crypto AES-CBC auto-padding gotcha, LXMF wire format differences between opportunistic and link delivery, stamp handling for signature verification, and the clockless-sender timestamp workaround.

## Related projects

- [reticulum-rnode](https://github.com/thatSFguy/reticulum-rnode) — the RNode firmware this client talks to.
- [reticulum-lora-repeater](https://github.com/thatSFguy/reticulum-lora-repeater) — a repeater node built on the same LoRa stack. Its `docs/RATCHET_PROTOCOL.md` is the canonical reference for how Reticulum 0.7+ announces are laid out on the wire.
- [markqvist/Reticulum](https://github.com/markqvist/Reticulum) — upstream Python Reticulum.
- [markqvist/LXMF](https://github.com/markqvist/LXMF) — upstream LXMF message format.
