# reticulum-lora-webclient

A browser-based Reticulum messaging client that talks to an [RNode](https://unsigned.io/rnode) LoRa modem over Web Bluetooth or Web Serial and exchanges encrypted LXMF messages with Sideband, NomadNet, MeshChat, and other Reticulum nodes on a LoRa mesh.

No build step, no server, no framework. Plain ES modules, loaded directly in the browser. Designed to be served as static files from GitHub Pages or any file host.

## What it does

- Connects to an RNode over Web Bluetooth (primary) or Web Serial (dev fallback).
- Configures the radio (frequency, bandwidth, spreading factor, coding rate, TX power) and turns it on.
- Generates and persists an Ed25519 / X25519 Reticulum identity in IndexedDB.
- Sends and receives Reticulum announces, so the web client shows up in other Reticulum nodes' contact lists and learns about their destinations from theirs.
- Encrypts and decrypts LXMF messages for opportunistic single-packet delivery using the standard Reticulum ECDH + HKDF + AES-256-CBC + HMAC-SHA256 scheme.
- Stores identity, contacts, and message history locally in IndexedDB. Nothing leaves your browser except over the radio link.

## What it does not do (yet)

- No Reticulum Links, so no multi-packet messages and no file transfers. Messages are capped at roughly 250–300 bytes of payload.
- No ratchet key rotation. Inbound announces that carry ratchet pubkeys are parsed so the signature still validates, but we do not rotate our own ratchet or emit one in our announces.
- No propagation node / store-and-forward support. Both parties must be on the air at the same time.
- No multi-hop transport routing tables. Single-hop LoRa only.
- No IFAC, no LXMF stamps, no GROUP destinations.

See `CLAUDE.md` for the full scope rules and implementation plan.

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
    lxmf.js               LXMF message pack/unpack + signature
    store.js              IndexedDB for identity, contacts, messages
    app.js                UI controller and state management
```

Libraries (`@noble/curves` for Ed25519/X25519 and `@msgpack/msgpack` for LXMF payload serialization) are loaded from a CDN via an import map in `index.html`. Web Crypto handles AES-CBC, HMAC, HKDF, and SHA-256 natively.

## Development notes

- Open the browser DevTools console to see stack traces. The in-page log shows a terse one-line error, but the full trace only lives in the console.
- The webapp listens for `error` and `unhandledrejection` on `window` and mirrors the message into the log, so uncaught errors from async handlers still show up.
- `store.js` uses a single IndexedDB database named `reticulum-webclient` with object stores for `identity`, `contacts`, and `messages`. To wipe local state, open DevTools then Application then Storage then Clear site data.
- The KISS parser accumulates bytes across BLE notifications and emits complete frames on FEND boundaries. BLE splits frames at arbitrary points, so any per-notification framing assumption will break.
- Reticulum destination hashes are computed with the identity hexhash **outside** the name hash input, matching upstream `Destination.hash(identity, app_name, *aspects)`. The hexhash appears only in the human-readable `Destination.name`, never in on-wire hashes. See the comments in `js/identity.js`.

## Related projects

- [reticulum-rnode](https://github.com/thatSFguy/reticulum-rnode) — the RNode firmware this client talks to.
- [reticulum-lora-repeater](https://github.com/thatSFguy/reticulum-lora-repeater) — a repeater node built on the same LoRa stack. Its `docs/RATCHET_PROTOCOL.md` is the canonical reference for how Reticulum 0.7+ announces are laid out on the wire.
- [markqvist/Reticulum](https://github.com/markqvist/Reticulum) — upstream Python Reticulum.
- [markqvist/LXMF](https://github.com/markqvist/LXMF) — upstream LXMF message format.
