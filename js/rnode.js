// js/rnode.js — RNode command layer over BLE transport.
//
// Wraps BleTransport + KissParser to provide async RNode commands
// (detect, configure, send/receive packets) over Web Bluetooth.

'use strict';

import { BleTransport } from './ble-transport.js';
import { SerialTransport } from './serial-transport.js';
import {
  KissParser, buildFrame, uint32ToBytes, bytesToUint32,
  CMD_DATA, CMD_FREQUENCY, CMD_BANDWIDTH, CMD_TXPOWER, CMD_SF, CMD_CR,
  CMD_RADIO_STATE, CMD_DETECT, CMD_STAT_RSSI, CMD_STAT_SNR, CMD_STAT_BAT,
  CMD_BLINK, CMD_BOARD, CMD_PLATFORM, CMD_MCU, CMD_FW_VERSION,
  CMD_RESET, CMD_ERROR, DETECT_REQ, DETECT_RESP,
} from './kiss.js';

export class RNode {
  constructor(transportType = 'ble') {
    if (transportType === 'serial') {
      this.transport = new SerialTransport();
    } else {
      this.transport = new BleTransport();
    }
    this._callbacks = new Map();  // cmd → resolve
    this._onPacket = null;        // callback for CMD_DATA (received radio packets)
    this._onDisconnect = null;    // callback when the transport drops unexpectedly
    this._onRssi = null;
    this._onSnr = null;
    this._lastRssi = 0;
    this._lastSnr = 0;
    this._onLog = null;

    // KISS parser wired to BLE receive
    this._parser = new KissParser((cmd, payload) => this._onFrame(cmd, payload));
    this.transport._onReceive = (bytes) => this._parser.feed(bytes);
  }

  get connected() { return this.transport.connected; }

  _log(msg) {
    if (this._onLog) this._onLog(msg);
  }

  // Handle a decoded KISS frame
  _onFrame(cmd, payload) {
    // RSSI and SNR come before each DATA frame
    if (cmd === CMD_STAT_RSSI && payload.length >= 1) {
      this._lastRssi = payload[0] - 157;  // RSSI_OFFSET
      return;
    }
    if (cmd === CMD_STAT_SNR && payload.length >= 1) {
      this._lastSnr = (payload[0] > 127 ? payload[0] - 256 : payload[0]) / 4.0;
      return;
    }

    // Received radio packet
    if (cmd === CMD_DATA) {
      if (this._onPacket) {
        this._onPacket(payload, this._lastRssi, this._lastSnr);
      }
      return;
    }

    // Command response — resolve pending promise
    const cb = this._callbacks.get(cmd);
    if (cb) {
      this._callbacks.delete(cmd);
      cb(payload);
    }
  }

  // Send a KISS command and optionally wait for response
  async _send(cmd, data = new Uint8Array(0)) {
    const frame = buildFrame(cmd, data);
    await this.transport.write(frame);
  }

  async _sendAndWait(cmd, data = new Uint8Array(0), responseCmd, timeoutMs = 10000) {
    if (responseCmd === undefined) responseCmd = cmd;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._callbacks.delete(responseCmd);
        reject(new Error(`Timeout waiting for cmd 0x${responseCmd.toString(16)}`));
      }, timeoutMs);

      this._callbacks.set(responseCmd, (payload) => {
        clearTimeout(timer);
        resolve(payload);
      });

      this._send(cmd, data).catch(reject);
    });
  }

  // ---- Connection ---------------------------------------------------

  async connect() {
    this.transport._onLog = (msg) => this._log(msg);
    this.transport._onDisconnect = () => {
      this._parser.reset();
      this._callbacks.clear();
      if (this._onDisconnect) this._onDisconnect();
    };
    await this.transport.connect();
  }

  async disconnect() {
    await this.transport.disconnect();
  }

  // ---- RNode commands -----------------------------------------------

  async detect() {
    const resp = await this._sendAndWait(CMD_DETECT, new Uint8Array([DETECT_REQ]));
    return resp.length >= 1 && resp[0] === DETECT_RESP;
  }

  async getFirmwareVersion() {
    const resp = await this._sendAndWait(CMD_FW_VERSION, new Uint8Array([0x00]));
    return resp.length >= 2 ? { major: resp[0], minor: resp[1] } : null;
  }

  async getPlatform() {
    const resp = await this._sendAndWait(CMD_PLATFORM, new Uint8Array([0x00]));
    return resp.length >= 1 ? resp[0] : null;
  }

  async getBoard() {
    const resp = await this._sendAndWait(CMD_BOARD, new Uint8Array([0x00]));
    return resp.length >= 1 ? resp[0] : null;
  }

  async getBattery() {
    const resp = await this._sendAndWait(CMD_STAT_BAT);
    return resp.length >= 1 ? resp[0] : null;
  }

  async blink(count = 3) {
    await this._send(CMD_BLINK, new Uint8Array([count]));
  }

  // ---- Radio config -------------------------------------------------

  async setFrequency(hz) {
    const resp = await this._sendAndWait(CMD_FREQUENCY, uint32ToBytes(hz));
    return resp.length >= 4 ? bytesToUint32(resp) : null;
  }

  async setBandwidth(hz) {
    const resp = await this._sendAndWait(CMD_BANDWIDTH, uint32ToBytes(hz));
    return resp.length >= 4 ? bytesToUint32(resp) : null;
  }

  async setSpreadingFactor(sf) {
    const resp = await this._sendAndWait(CMD_SF, new Uint8Array([sf]));
    return resp.length >= 1 ? resp[0] : null;
  }

  async setCodingRate(cr) {
    const resp = await this._sendAndWait(CMD_CR, new Uint8Array([cr]));
    return resp.length >= 1 ? resp[0] : null;
  }

  async setTxPower(dbm) {
    const resp = await this._sendAndWait(CMD_TXPOWER, new Uint8Array([dbm & 0xFF]));
    return resp.length >= 1 ? resp[0] : null;
  }

  async setRadioState(on) {
    const resp = await this._sendAndWait(CMD_RADIO_STATE, new Uint8Array([on ? 0x01 : 0x00]));
    return resp.length >= 1 ? resp[0] === 0x01 : false;
  }

  // Configure radio with standard params and turn on
  async configureAndStart({ freq, bw, sf, cr, txp }) {
    await this.setFrequency(freq);
    await this.setBandwidth(bw);
    await this.setSpreadingFactor(sf);
    await this.setCodingRate(cr);
    await this.setTxPower(txp);
    return await this.setRadioState(true);
  }

  // ---- Packet TX/RX -------------------------------------------------

  async sendPacket(data) {
    await this._send(CMD_DATA, data instanceof Uint8Array ? data : new Uint8Array(data));
  }
}
