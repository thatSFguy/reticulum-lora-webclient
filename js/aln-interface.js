// js/aln-interface.js — Reticulum-over-agnostic-LoRa-Net tunnel interface.
//
// Tunnels raw Reticulum packets across an agnostic-LoRa-Net ("ALN") mesh by
// talking to an ALN node over Web Bluetooth. The node runs the mesh (routing,
// per-hop ARQ, SAR fragmentation); we hand it opaque RNS packets and it carries
// them to a destination node, exactly like the project's Python
// AgnosticLoraInterface — NOT RNode emulation (which would bypass ALN routing).
//
// Same shape as rnsd-interface.js so app.js drives it without branching:
//   {connect, disconnect, sendPacket, _onPacket, _onLog, _onDisconnect,
//    connected, capabilities, + RNode command stubs}.
//
// Wire contract (see ../platformIO/agnostic-lora-net/docs/tcp-bridge.md and
// src/main.cpp tunnel_rx_frame/tunnel_emit). Each HDLC frame carries a typed,
// length-prefixed address envelope, then the opaque RNS packet:
//
//   TX (host → node):  [0x01][16][dst-locator(16)][rns_packet]  → node routes to dst
//   RX (node → host):  [0x01][16][src-locator(16)][rns_packet]  ← arrived from src
//
// Notes:
//   * BLE auto-enters tunnel mode on connect — no "tunnel\n" (that's USB only).
//   * The firmware requires addr_len == 16 (v2 self-certifying node ids); a
//     4-byte v1 id is rejected. We always send a 16-byte locator.
//   * No radio to configure and no RSSI in tunnel frames — capabilities report
//     no RNode control, and we pass rssi=0/snr=0 into _onPacket like rnsd.
//   * The BLE link is PIN-paired on ALN nodes; the OS handles the pairing
//     prompt when we subscribe to the encrypted characteristic.

'use strict';

import { BleTransport } from './ble-transport.js';
import { HdlcParser, encodeFrame } from './hdlc.js';

const ADDR_LOCATOR = 0x01;          // typed-envelope address type (the only live one)
const NODE_ID_LEN  = 16;            // v2 self-certifying node id width (bytes)
const BROADCAST    = new Uint8Array(NODE_ID_LEN).fill(0xFF);  // NODE_ID_BROADCAST → flood

// Parse a peer node id from user config. Accepts 32 hex chars (16-byte v2 id),
// with optional whitespace/0x. Blank / "broadcast" → flood to all mesh nodes.
// Returns { locator: Uint8Array(16), broadcast: bool } or throws on bad input.
function parsePeer(peerHex) {
  const s = (peerHex || '').trim().replace(/^0x/i, '').replace(/\s+/g, '');
  if (s === '' || /^broadcast$/i.test(s)) return { locator: BROADCAST, broadcast: true };
  if (!/^[0-9a-fA-F]+$/.test(s) || s.length !== NODE_ID_LEN * 2) {
    throw new Error(`ALN peer id must be ${NODE_ID_LEN * 2} hex chars (a v2 node id), or blank for broadcast`);
  }
  const locator = new Uint8Array(NODE_ID_LEN);
  for (let i = 0; i < NODE_ID_LEN; i++) locator[i] = parseInt(s.substr(i * 2, 2), 16);
  return { locator, broadcast: false };
}

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

export class AlnInterface {
  // peerHex: optional 32-hex node id; blank/"broadcast" floods to the whole mesh.
  constructor(peerHex) {
    const { locator, broadcast } = parsePeer(peerHex);
    this.peer = locator;
    this.broadcast = broadcast;

    this.transport = new BleTransport();
    this._onPacket = null;
    this._onDisconnect = null;
    this._onLog = null;

    // Each HDLC frame is one typed-envelope tunnel frame. The firmware
    // deframes byte-by-byte across BLE notifications, so chunked writes are
    // fine; the HdlcParser does the same on our side for inbound chunks.
    this._parser = new HdlcParser((frame) => this._handleFrame(frame));
    this.transport._onReceive = (bytes) => this._parser.feed(bytes);
  }

  get connected() { return this.transport.connected; }

  // No radio and no RNode command set on the far side — app.js uses these to
  // skip the detect/firmware/battery/radio-config sequence (same as rnsd).
  get capabilities() {
    return { rnodeControl: false, radioConfig: false };
  }

  _log(msg) { if (this._onLog) this._onLog(msg); }

  async connect() {
    this.transport._onLog = (msg) => this._log(msg);
    this.transport._onDisconnect = () => {
      this._parser.reset();
      if (this._onDisconnect) this._onDisconnect();
    };
    await this.transport.connect();
    this._log(this.broadcast
      ? 'ALN tunnel ready — broadcasting to neighbor (1-hop) nodes; set a peer node id in Settings for multi-hop routed delivery'
      : `ALN tunnel ready — directed to node ${hex(this.peer)} (multi-hop routed)`);
  }

  async disconnect() {
    await this.transport.disconnect();
  }

  // RNode command stubs so any un-gated app.js caller still works without
  // branching. All benign; app.js gates the real RNode sequence on
  // capabilities.rnodeControl === false (see rnsd-interface.js).
  async detect()             { return true; }
  async getFirmwareVersion() { return { major: 0, minor: 0 }; }
  async getPlatform()        { return 0; }
  async getBoard()           { return 0; }
  async getBattery()         { return 0; }
  async setFrequency()       { return 0; }
  async setBandwidth()       { return 0; }
  async setSpreadingFactor() { return 0; }
  async setCodingRate()      { return 0; }
  async setTxPower()         { return 0; }
  async setRadioState()      { return true; }
  async configureAndStart()  { return true; }
  async blink()              { }

  // Send a raw Reticulum packet. Wrap it in the typed-address envelope
  // [0x01][16][dst-locator][packet], HDLC-frame it, and write it to the node.
  // The node routes (and SAR-fragments if needed) to the locator. The broadcast
  // locator is DELIVER-only at each receiver (the forwarder doesn't reflood it),
  // so it reaches 1-hop neighbors; a real node id gets multi-hop routing.
  async sendPacket(data) {
    if (!this.transport.connected) throw new Error('ALN not connected');
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const frame = new Uint8Array(2 + NODE_ID_LEN + bytes.length);
    frame[0] = ADDR_LOCATOR;
    frame[1] = NODE_ID_LEN;
    frame.set(this.peer, 2);
    frame.set(bytes, 2 + NODE_ID_LEN);
    await this.transport.write(encodeFrame(frame));
  }

  // One decoded HDLC frame from the node: [addr_type][addr_len][src][payload].
  // Strip the envelope and hand the raw RNS packet up. RSSI/SNR aren't carried
  // in tunnel frames, so pass zeros (existing log lines still render).
  _handleFrame(buf) {
    if (buf.length < 2) return;
    const addrType = buf[0];
    const addrLen  = buf[1];
    if (addrType !== ADDR_LOCATOR || buf.length < 2 + addrLen) return;
    const payload = buf.subarray(2 + addrLen);
    if (payload.length === 0) return;
    if (this._onPacket) this._onPacket(payload, 0, 0);
  }
}
