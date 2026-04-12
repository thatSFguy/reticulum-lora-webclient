// js/ble-native-transport.js — Capacitor-native BLE NUS transport.
//
// The Android System WebView does NOT expose navigator.bluetooth —
// Web Bluetooth in Chromium is gated behind an experimental flag
// that's off in WebView builds. So when the app is running inside
// the Capacitor APK we need a separate transport that routes BLE
// through the native @capacitor-community/bluetooth-le plugin.
// Same public shape as BleTransport so rnode.js can swap them in
// without touching anything above the transport layer.
//
// The plugin's JavaScript shim is dynamically imported from a local
// on first use. That means the browser/web builds never download
// it, and the APK builds get it once it's pulled into the WebView
// context on the first Connect (BLE) click.

'use strict';

const NUS_SERVICE_UUID = '6e400001-b5a3-f393-e0a9-e50e24dcca9e';
const NUS_TX_UUID      = '6e400002-b5a3-f393-e0a9-e50e24dcca9e'; // write (phone → device)
const NUS_RX_UUID      = '6e400003-b5a3-f393-e0a9-e50e24dcca9e'; // notify (device → phone)

let _BleClient = null;

async function getBleClient() {
  if (_BleClient) return _BleClient;
  // Self-hosted bundle with @capacitor/core inlined. At runtime
  // inside the Capacitor WebView, the inlined core discovers the
  // native bridge via window.Capacitor (injected by the native
  // shell on APK startup). In a plain browser where window.
  // Capacitor does not exist, the plugin falls back to its Web
  // Bluetooth implementation (which is equivalent to our regular
  // BleTransport and never actually gets called because app.js
  // only routes to BleNativeTransport when isCapacitorNative()
  // is true).
  const mod = await import('../lib/capacitor-bluetooth-le.js');
  _BleClient = mod.BleClient;
  if (!_BleClient) throw new Error('BleClient not found in plugin module');
  return _BleClient;
}

export class BleNativeTransport {
  constructor() {
    this.deviceId = null;
    this.mtu = 20;           // conservative default; plugin negotiates higher internally
    this._connected = false;
    this._onReceive = null;
    this._onDisconnect = null;
    this._onLog = null;
    this._writeLock = Promise.resolve();  // serializes concurrent writes
  }

  get connected() {
    return this._connected;
  }

  _log(msg) {
    if (this._onLog) this._onLog(msg);
  }

  async connect() {
    const BleClient = await getBleClient();

    // Initialise plugin — prompts the user to enable Bluetooth if
    // off, requests the BLUETOOTH_SCAN / BLUETOOTH_CONNECT runtime
    // permissions on Android 12+, and falls back to fine-location
    // permission on older Android. androidNeverForLocation: true
    // matches the BLUETOOTH_SCAN flag we set in the manifest.
    this._log('Initialising native BLE plugin...');
    await BleClient.initialize({ androidNeverForLocation: true });

    // Scan + show the native device picker. The picker filters by
    // the NUS service UUID so only RNode-class modems appear.
    this._log('Requesting BLE device (NUS service)...');
    const device = await BleClient.requestDevice({
      services: [NUS_SERVICE_UUID],
    });
    if (!device) throw new Error('No device selected');
    this.deviceId = device.deviceId;
    this._log(`Selected: ${device.name || 'unnamed'} (${device.deviceId})`);

    // Connect. The second arg is an onDisconnect callback the
    // plugin fires if the link drops after connection.
    this._log('Connecting GATT...');
    await BleClient.connect(device.deviceId, () => {
      this._log('BLE disconnected');
      this._connected = false;
      if (this._onDisconnect) this._onDisconnect();
    });

    // Negotiate a higher MTU. The default ATT MTU is 23 (20 payload).
    // Chrome's Web Bluetooth auto-negotiates 244-512 during connect;
    // the Capacitor plugin does not. Without this, a ~200-byte
    // announce KISS frame needs ~11 rapid writeWithoutResponse calls
    // that can overflow Android's local BLE write buffer and kill the
    // connection. With a 517-byte MTU the same frame fits in 1 write.
    try {
      const negotiated = await BleClient.requestMtu(device.deviceId, 517);
      this.mtu = negotiated - 3;  // ATT header overhead
      this._log(`MTU negotiated: ${negotiated} (payload ${this.mtu})`);
    } catch (e) {
      this._log(`MTU negotiation failed (${e.message}), keeping default ${this.mtu}`);
    }

    // Subscribe to RX notifications. The callback receives a
    // DataView; convert to Uint8Array for consistency with
    // BleTransport.
    await BleClient.startNotifications(
      device.deviceId,
      NUS_SERVICE_UUID,
      NUS_RX_UUID,
      (value) => {
        const bytes = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        if (this._onReceive) this._onReceive(bytes);
      },
    );

    this._connected = true;
    this._log(`Connected to ${device.name || 'RNode'} via native BLE`);
  }

  async disconnect() {
    if (!this.deviceId) return;
    try {
      const BleClient = await getBleClient();
      await BleClient.disconnect(this.deviceId);
    } catch (e) {
      this._log(`Disconnect error (ignored): ${e.message || e}`);
    }
    this._connected = false;
    this.deviceId = null;
  }

  // Write bytes to the device, chunked at the MTU. Serialized so
  // concurrent callers (e.g., the retry tick and a manual send)
  // can't interleave their chunks and corrupt the KISS framing.
  //
  // Uses writeWithoutResponse (GATT Write Command) because the
  // RNode's NUS TX characteristic does not support Write Request.
  // A 35ms pause between chunks prevents Android's BLE write
  // buffer from overflowing — covers the worst-case BLE connection
  // interval (30ms) with margin. An 11-chunk announce takes ~385ms.
  async write(data) {
    // Wait for any in-flight write to finish before starting ours.
    // This prevents chunk interleaving from concurrent callers.
    await this._writeLock;
    let unlock;
    this._writeLock = new Promise(r => { unlock = r; });
    try {
      if (!this.deviceId) throw new Error('Not connected');
      const BleClient = await getBleClient();
      const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
      const chunkSize = this.mtu;
      for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        const end = Math.min(offset + chunkSize, bytes.length);
        const chunk = bytes.slice(offset, end);
        const view = new DataView(chunk.buffer);
        await BleClient.writeWithoutResponse(
          this.deviceId,
          NUS_SERVICE_UUID,
          NUS_TX_UUID,
          view,
        );
        if (end < bytes.length) {
          await new Promise(r => setTimeout(r, 35));
        }
      }
    } finally {
      unlock();
    }
  }
}
