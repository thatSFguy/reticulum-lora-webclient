// js/rnsd-interface.js — Reticulum-direct interface over a byte stream.
//
// Wraps a WebSocketTransport + HdlcParser into the same
// {connect, disconnect, sendPacket, _onPacket, _onLog} shape
// js/rnode.js exposes, so app.js can drive either without
// branching. Unlike rnode.js this module does not speak KISS and
// does not issue any RNode command — there is no radio on the
// other end, just an rnsd that will inject our packets into a
// Reticulum network.
//
// Packet flow:
//   TX: app.js builds a raw Reticulum packet, calls sendPacket(),
//       we HDLC-frame it and write it to the transport (which hands
//       it to the WebSocket-to-TCP bridge, which forwards to rnsd).
//   RX: the bridge delivers bytes from rnsd via the transport, the
//       HdlcParser emits one complete frame per boundary, each
//       frame IS a raw Reticulum packet which we hand to _onPacket.
//
// Since there is no physical radio, RSSI and SNR are not available.
// We pass zeros into _onPacket so existing log lines still render.

'use strict';

import { WebSocketTransport } from './websocket-transport.js';
import { HdlcParser, encodeFrame } from './hdlc.js';

export class RnsdInterface {
  constructor(url) {
    this.transport = new WebSocketTransport(url);
    this._onPacket = null;
    this._onLog = null;

    // Stream HDLC frames out of whatever byte chunks the transport
    // delivers. Each complete frame is a raw Reticulum packet; we
    // forward it to _onPacket with rssi=0 and snr=0.
    this._parser = new HdlcParser((packet) => {
      if (this._onPacket) this._onPacket(packet, 0, 0);
    });
    this.transport._onReceive = (bytes) => this._parser.feed(bytes);
  }

  get connected() {
    return this.transport.connected;
  }

  // Capability flag consumed by app.js to decide whether to show the
  // radio config panel and whether to issue RNode-specific commands
  // (detect, getFirmwareVersion, getBattery, configureAndStart).
  // None of those apply over a WebSocket-to-rnsd path.
  get capabilities() {
    return {
      rnodeControl: false,
      radioConfig:  false,
    };
  }

  _log(msg) {
    if (this._onLog) this._onLog(msg);
  }

  async connect() {
    this.transport._onLog = (msg) => this._log(msg);
    this.transport._onDisconnect = () => {
      this._parser.reset();
    };
    await this.transport.connect();
  }

  async disconnect() {
    await this.transport.disconnect();
  }

  // Stubs for the RNode command API so any forgotten caller in
  // app.js still works without branching. All return benign values;
  // a future refactor can replace app.js's `await rnode.detect()`
  // style calls with capability-gated conditionals and delete these.
  async detect()               { return true; }
  async getFirmwareVersion()   { return { major: 0, minor: 0 }; }
  async getPlatform()          { return 0; }
  async getBoard()             { return 0; }
  async getBattery()           { return 0; }
  async setFrequency()         { return 0; }
  async setBandwidth()         { return 0; }
  async setSpreadingFactor()   { return 0; }
  async setCodingRate()        { return 0; }
  async setTxPower()           { return 0; }
  async setRadioState()        { return true; }
  async configureAndStart()    { return true; }
  async blink()                { }

  // Send a raw Reticulum packet. HDLC-frame it and push it through
  // the transport in one write. rnsd's TCPClientInterface on the
  // other side will strip the framing and hand the packet to its
  // Transport for onward routing.
  async sendPacket(data) {
    if (!this.transport.connected) throw new Error('WebSocket not connected');
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const frame = encodeFrame(bytes);
    await this.transport.write(frame);
  }
}
