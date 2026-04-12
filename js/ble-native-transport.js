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
  // Load from esm.sh CDN. Self-hosting this plugin was attempted
  // (lib/capacitor-bluetooth-le.js, bundled with esbuild) but the
  // bundle inlines its own copy of @capacitor/core, which creates
  // a second Capacitor plugin registry that doesn't connect to
  // the native bridge the Capacitor shell set up. The result is
  // an unstable BLE connection that drops within seconds.
  //
  // The esm.sh path works because esm.sh resolves @capacitor/core
  // as an external that hooks into the existing window.Capacitor
  // bridge. This import only runs inside the Capacitor APK on the
  // first BLE connect — the web build never reaches this code
  // because app.js gates BleNativeTransport behind
  // isCapacitorNative(). Network access is available inside the
  // APK (map tiles, etc.), and the plugin JS is cached by the
  // WebView after the first load.
  const mod = await import('https://esm.sh/@capacitor-community/bluetooth-le@6.1.0');
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
      this._stopHeartbeat();
      this._connected = false;
      if (this._onDisconnect) this._onDisconnect();
    });

    // Request HIGH connection priority — matches what Chrome does
    // internally on every Web Bluetooth connection. HIGH gives
    // 11-15ms connection intervals vs BALANCED's 30-50ms, making
    // the link much more resilient under load. The RNode firmware
    // (nRF52/Bluefruit) already requests 7.5-15ms from the
    // peripheral side, but Android ignores that unless the app
    // explicitly asks for HIGH priority from the central side.
    try {
      await BleClient.requestConnectionPriority(device.deviceId, 1); // 1 = HIGH
      this._log('Connection priority: HIGH');
    } catch (e) {
      this._log(`Connection priority request failed: ${e.message || e}`);
    }

    // MTU negotiation is intentionally skipped. requestMtu() causes
    // delayed GATT disconnects on Samsung — the nRF52 SoftDevice
    // already initiates MTU exchange from the peripheral side, and
    // a second exchange from Android violates the BLE spec's one-
    // exchange-per-connection rule. Samsung's stack doesn't handle
    // that gracefully. The 20-byte default with pacing is slower
    // but universally reliable.

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

    // Start a BLE keep-alive heartbeat. The default BLE supervision
    // timeout on many Android stacks is ~5 seconds. Chrome's Web
    // Bluetooth sends internal GATT housekeeping that prevents the
    // timeout; the Capacitor plugin does not. Without a heartbeat,
    // the connection drops ~5s after the last write if no mesh
    // traffic arrives to trigger an inbound BLE notification.
    //
    // A single FEND byte (0xC0) is a valid KISS no-op — the RNode's
    // parser sees it as an empty frame boundary and discards it.
    this._startHeartbeat(BleClient);
  }

  _startHeartbeat(BleClient) {
    this._stopHeartbeat();
    const HEARTBEAT_MS = 3000;
    const fend = new DataView(new Uint8Array([0xC0]).buffer);
    this._heartbeatTimer = setInterval(async () => {
      if (!this._connected || !this.deviceId) {
        this._stopHeartbeat();
        return;
      }
      try {
        await BleClient.writeWithoutResponse(
          this.deviceId,
          NUS_SERVICE_UUID,
          NUS_TX_UUID,
          fend,
        );
      } catch (_) {
        // Write failed — connection is probably already dead,
        // the onDisconnect callback will handle cleanup.
      }
    }, HEARTBEAT_MS);
  }

  _stopHeartbeat() {
    if (this._heartbeatTimer) {
      clearInterval(this._heartbeatTimer);
      this._heartbeatTimer = null;
    }
  }

  async disconnect() {
    this._stopHeartbeat();
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
