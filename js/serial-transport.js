// js/serial-transport.js — Web Serial transport (USB CDC).
//
// Drop-in replacement for BleTransport with the same interface.
// Used for debugging on desktop where Web Bluetooth may not be
// available or where serial console access is needed.

'use strict';

export class SerialTransport {
  constructor() {
    this.port = null;
    this.reader = null;
    this.writer = null;
    this._readLoopRunning = false;
    this._onReceive = null;
    this._onDisconnect = null;
    this._onLog = null;
    this.mtu = 256;  // serial has no real MTU
  }

  get connected() {
    return this.port !== null;
  }

  _log(msg) {
    if (this._onLog) this._onLog(msg);
  }

  async connect() {
    if (!navigator.serial) {
      throw new Error('Web Serial not supported in this browser');
    }

    this._log('Requesting serial port...');
    this.port = await navigator.serial.requestPort();
    if (!this.port) throw new Error('No port selected');

    await this.port.open({ baudRate: 115200, dataBits: 8, stopBits: 1, parity: 'none' });
    this.writer = this.port.writable.getWriter();
    this._startReadLoop();
    this._log('Serial port opened at 115200');
  }

  async disconnect() {
    this._readLoopRunning = false;
    if (this.reader) {
      try { await this.reader.cancel(); } catch {}
      try { this.reader.releaseLock(); } catch {}
      this.reader = null;
    }
    if (this.writer) {
      try { this.writer.releaseLock(); } catch {}
      this.writer = null;
    }
    if (this.port) {
      try { await this.port.close(); } catch {}
      this.port = null;
    }
  }

  _startReadLoop() {
    this._readLoopRunning = true;
    const self = this;
    (async function loop() {
      self.reader = self.port.readable.getReader();
      try {
        while (self._readLoopRunning) {
          const { value, done } = await self.reader.read();
          if (done) break;
          if (value && self._onReceive) self._onReceive(new Uint8Array(value));
        }
      } catch (e) {
        if (self._readLoopRunning) self._log('Serial read error: ' + e.message);
      } finally {
        try { self.reader.releaseLock(); } catch {}
        self.reader = null;
        if (self._onDisconnect) self._onDisconnect();
      }
    })();
  }

  async write(data) {
    if (!this.writer) throw new Error('Not connected');
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    await this.writer.write(bytes);
  }
}
