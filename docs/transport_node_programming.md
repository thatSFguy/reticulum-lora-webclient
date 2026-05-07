# Transport node programming

> **Move this file to** `reticulum-lora-webclient/docs/transport_node_programming.md`. It was authored in the transport-node repo because the sandbox blocked direct writes to the sibling repo; the content is intended for the webclient.
>
> **Live flasher** — drag-and-drop UF2 binaries to nRF52840 boards from the browser: <https://thatsfguy.github.io/reticulum-lora-webclient/flasher.html>

This document describes the protocol the webclient uses to configure a `reticulum-lora-transport` node. The transport node's firmware exposes a config surface over **two transports** — both speaking the same payload protocol (msgpack over a thin framing layer). The webclient should target whichever the user's connection mode supports (Web Bluetooth or Web Serial); the application logic above the transport is identical.

The firmware repo is at `reticulum-lora-transport`. The exact wire layout is implemented in `src/Ble.cpp`, `src/SerialConsole.cpp`, and `src/ConfigProtocol.cpp`. When the firmware-side schema changes, this document should be updated in the same PR.

---

## 1. Transports

### 1.1 Web Bluetooth (BLE GATT)

Use Web Bluetooth (`navigator.bluetooth.requestDevice`). The device advertises a custom service; filter for the service UUID below.

| | UUID |
|---|---|
| Service | `00000000-a5a5-524c-7272-00000100726c` |
| `request` characteristic | `00000000-a5a5-524c-7272-00000200726c` — properties: write / write-without-response, max 244 bytes per write |
| `response` characteristic | `00000000-a5a5-524c-7272-00000300726c` — properties: notify, max 244 bytes per notification |

The advertised device name is `Config.display_name`. On first boot the firmware stamps a unique default of the form **`Rptr-XXXXXXXX`** (the first 4 bytes of the node's `identity_hash` in hex), so every fresh node is uniquely identifiable on a BLE scan without any setup. Operators can override via `set_config` + `commit`; the override persists across reboots.

**Connection flow:**
1. `navigator.bluetooth.requestDevice({ filters: [{ services: [SERVICE_UUID] }] })`
2. `device.gatt.connect()`
3. Get the `request` and `response` characteristics from the service.
4. Start notifications on the `response` characteristic.
5. Each `requestChar.writeValueWithoutResponse(msgpackBytes)` triggers a `characteristicvaluechanged` event on the response characteristic carrying the response.

**Framing:** none. One characteristic write = one msgpack message. One notification = one msgpack response. The ATT MTU caps a single message at 244 bytes; current commands are well under this.

**Pairing / security:** none required. The characteristics are `SECMODE_OPEN` — operators control physical access to the device, and the LoRa mesh isn't reachable through the BLE surface.

**Disconnects:** the firmware re-advertises automatically (`restartOnDisconnect`). The webclient should treat disconnect as a recoverable state, not an error — reconnect transparently.

### 1.2 Web Serial (USB cable)

Use the Web Serial API. The user picks a port; we don't filter by VID/PID.

| | Value |
|---|---|
| Baud rate | `115200` |
| Data bits | `8` |
| Parity | `none` |
| Stop bits | `1` |
| Flow control | none |

**Framing:** length-prefixed binary frames.

```
┌─────────────────┬───────────────────────────────────────┐
│ u16 BE length   │ msgpack-encoded payload (length bytes)│
└─────────────────┴───────────────────────────────────────┘
```

The length is the byte count of the payload, big-endian, 16-bit unsigned. Hard cap on the firmware side is 1024 bytes; current commands stay under 200.

JS encoder example:

```js
function frame(msgpackBytes) {
  const n = msgpackBytes.length;
  const out = new Uint8Array(2 + n);
  out[0] = (n >>> 8) & 0xff;
  out[1] = n & 0xff;
  out.set(msgpackBytes, 2);
  return out;
}
```

JS streaming decoder (state machine — accumulate over multiple `read()` calls):

```js
class Deframer {
  state = 'LEN_HI';
  expected = 0;
  received = 0;
  buf = null;
  push(byte, onFrame) {
    switch (this.state) {
      case 'LEN_HI':
        this.expected = byte << 8;
        this.state = 'LEN_LO';
        break;
      case 'LEN_LO':
        this.expected |= byte;
        if (this.expected === 0 || this.expected > 1024) {
          this.state = 'LEN_HI';   // bogus — wait for next start
          break;
        }
        this.buf = new Uint8Array(this.expected);
        this.received = 0;
        this.state = 'PAYLOAD';
        break;
      case 'PAYLOAD':
        this.buf[this.received++] = byte;
        if (this.received >= this.expected) {
          onFrame(this.buf);
          this.state = 'LEN_HI';
        }
        break;
    }
  }
}
```

---

## 2. Payload format — msgpack

All messages (requests and responses, on both transports) are [msgpack](https://github.com/msgpack/msgpack/blob/master/spec.md) maps. Recommend `@msgpack/msgpack` (npm) for encoding/decoding:

```js
import { encode, decode } from "@msgpack/msgpack";

const reqBytes = encode({ cmd: "ping" });    // Uint8Array
const respObj  = decode(respBytes);          // plain JS object
```

**Required:** `cmd` MUST be the **first** key in every request map. The firmware dispatches before scanning the rest of the map; if `cmd` isn't first, you get an error response.

**Forward compat:** `set_config` silently skips unknown keys, so a newer webclient with extra fields won't break older firmware. Likewise, when adding new commands, older firmware returns `{"ok": false, "err": "unknown command"}` rather than misbehaving.

---

## 3. Commands

### 3.1 `ping`

Health check. Confirms the device responds and exposes its identity hash for UI labelling.

**Request:**
```json
{ "cmd": "ping" }
```

**Response:**
```json
{
  "ok": true,
  "identity_hash": <bin 16 bytes>,
  "version": "v0.1.6"
}
```

`identity_hash` is the device's stable 16-byte identity hash (`SHA256(public_key)[:16]` per Reticulum spec §1.1). It persists across reboots — use it as a stable device key in the webapp's UI.

`version` is the firmware version string, injected at build time. Tagged release builds report the tag exactly (`v0.1.6`). Dev / master builds report `git describe --tags --always --dirty` (e.g. `v0.1.5-3-gabcdef0`). Builds that bypass the inject script report `dev`. Use to gate features the webapp depends on.

### 3.2 `get_config`

Read all Config fields.

**Request:**
```json
{ "cmd": "get_config" }
```

**Response:**
```json
{
  "ok": true,
  "freq_hz": 904375000,
  "bw_hz": 250000,
  "sf": 10,
  "cr": 5,
  "txp_dbm": 22,
  "lat_udeg": 0,
  "lon_udeg": 0,
  "alt_m": 0,
  "batt_mult": 1.284,
  "display_name": "Rptr-9baae22f"
}
```

See §4 for field semantics + valid ranges.

### 3.3 `set_config`

Update one or more Config fields **in memory only** — no flash write. Call `commit` afterwards to persist.

**Request:** `cmd` first, then any subset of the field names from `get_config`.
```json
{
  "cmd": "set_config",
  "freq_hz": 904375000,
  "sf": 10,
  "lat_udeg": 37774900,
  "lon_udeg": -122419400,
  "display_name": "rlr-rooftop-1"
}
```

**Response:**
```json
{ "ok": true, "set": 5 }
```

`set` is the count of recognised fields applied. Unknown fields are silently skipped (forward-compat).

**Type rules:**
- Integer fields accept **either** signed or unsigned msgpack encodings. Just pass JS numbers directly — `@msgpack/msgpack`'s native encoding works for both positive and negative values:
  ```js
  encode({ cmd: "set_config", lat_udeg: 37774900,  lon_udeg: -122419400 });
  ```
  The webclient does NOT need the uint32 bit-pattern hack documented in earlier versions of this doc. The firmware's `read_int` accepts negative-fixint, int8/16/32/64, positive-fixint, and uint8/16/32/64 transparently.
- **Response decoding** of negative fields: `get_config` still emits all integers as msgpack uints (since the firmware uses fixed-width writers for wire stability). Decode signed fields by re-casting:
  ```js
  const lat_udeg = (rawUint << 0);   // back to signed int32
  ```
- `batt_mult` is decoded as either msgpack float32 or float64 — pass JS numbers directly (which encode as float64 by default in `@msgpack/msgpack`).
- `display_name` is a UTF-8 string (max 31 chars; longer values are silently truncated). Defaults to `Rptr-XXXXXXXX` per §1.1; pass any UTF-8 string to override.

### 3.4 `commit`

Persist the current in-memory Config to flash. Diff-before-write inside the firmware: a no-op write costs no flash cycles.

**Request:**
```json
{ "cmd": "commit" }
```

**Response (success):**
```json
{ "ok": true }
```

**Response (failure):**
```json
{ "ok": false, "err": "commit failed" }
```

The most likely failure modes are flash full or filesystem corruption — both rare. Webapp should surface a generic "save failed, please retry" UX.

---

## 4. Config field reference

Single source of truth: `src/Config.h` in the firmware repo. When that file changes, this section needs to follow.

| Field | Type | Default | Range | Notes |
|---|---|---|---|---|
| `freq_hz` | uint32 | 904375000 | LoRa-legal in your region | Carrier frequency in Hz. US ISM 902-928 MHz. |
| `bw_hz` | uint32 | 250000 | 7800..500000 | LoRa bandwidth. SX1262-supported steps: 7.81, 10.42, 15.63, 20.83, 31.25, 41.67, 62.5, 125, 250, 500 kHz. |
| `sf` | uint8 | 10 | 5..12 | LoRa spreading factor. Higher SF = longer range, less throughput. SF10 = our deployment default. |
| `cr` | uint8 | 5 | 5..8 | LoRa coding-rate denominator. 5 = 4/5, 6 = 4/6, 7 = 4/7, 8 = 4/8. |
| `txp_dbm` | int8 | 22 | -9..+22 | TX power at the SX1262 core pin. Modules with external PA add gain on top (ProMicroDIY's E22 → ~30 dBm radiated at +22 core). |
| `lat_udeg` | int32 | 0 | ±90,000,000 | Latitude in microdegrees (deg × 1e6). 0 = unset (telemetry beacon emits nil lat). |
| `lon_udeg` | int32 | 0 | ±180,000,000 | Longitude in microdegrees. 0 = unset. |
| `alt_m` | int32 | 0 | n/a | Altitude in meters above sea level. 0 = unset. |
| `batt_mult` | float32 | 1.0 (board default in header) | 0.1..10.0 | ADC scale factor for battery voltage divider. Each board's header has a default; webapp can override after a CALIBRATE BATTERY flow. |
| `display_name` | str ≤31 chars | `Rptr-XXXXXXXX` (auto, first 4 bytes of `identity_hash` hex) | UTF-8 | Human-readable device name. Drives the BLE advert name and the `name` field in the telemetry beacon. |

---

## 5. Error responses

Any failure on the firmware side returns:

```json
{ "ok": false, "err": "<short message>" }
```

Possible `err` strings (current firmware):

| `err` | Meaning |
|---|---|
| `expected msgpack map at top level` | Request wasn't a map. |
| `empty request map` | Map was 0-pair. |
| `expected string key at position 0` | First key wasn't a string. |
| `first map key must be 'cmd'` | `cmd` must be the first key in the request. |
| `'cmd' value must be a string` | `cmd` was non-string (e.g. an int). |
| `unknown command` | The `cmd` value isn't one of the four supported. |
| `malformed set_config payload` | A field's value type didn't match the expected type. |
| `commit not configured` | Firmware doesn't have a save callback wired (shouldn't happen in production builds). |
| `commit failed` | Flash write returned an error. |

Webapp should always be able to decode an `ok` field — even on parse-rejects, the firmware emits a valid msgpack map with `ok: false`. If decoding fails entirely, that's a transport-layer issue (BLE disconnect, serial cable unplug); surface as such.

---

## 6. Operational notes

### 6.1 Identity is stable

Each device generates its 64-byte private key on first boot (using SX1262 RNG) and persists it to flash. **Don't store identity_hash in localStorage as a "trusted device" flag** — if the user reflashes with a wiped filesystem, the device will rotate identity. Treat identity_hash as the stable per-device handle within a single firmware lifetime.

### 6.2 BLE link blips

BLE connections drop transiently on busy 2.4 GHz channels (microwave ovens, Wi-Fi traffic, etc.). The firmware re-advertises automatically. The webapp should:
- Auto-reconnect on `gattserverdisconnected`.
- Retry the last user-visible operation on reconnect (e.g., re-fetch `get_config`).
- Don't surface every blip as an error — only flag if reconnect fails for >30 seconds.

### 6.3 Long radio TX may starve BLE timing

The firmware shares the nRF52840's CPU between the SoftDevice (BLE) and the SX1262 LoRa driver via SPI. At high spreading factors (SF11, SF12) a single LoRa TX takes >500 ms; BLE may drop the link during one. SF10 default is tolerable. If a webapp `set_config` selects SF11/SF12 and immediately `commit`s, the next outbound radio event may briefly disconnect BLE — auto-reconnect covers it.

### 6.4 Flash-wear discipline

The firmware applies diff-before-write — issuing `commit` repeatedly with the same Config burns no flash cycles. Webapp doesn't need to debounce.

### 6.5 No unsolicited pushes

The firmware never sends a notification or serial frame except in direct response to a request. The webapp's read pump only fires after a write. Future telemetry / log streaming may add an unsolicited channel; this document will be updated when that lands.

---

## 7. Reference: minimal end-to-end JS

```js
import { encode, decode } from "@msgpack/msgpack";

const SVC = "00000000-a5a5-524c-7272-00000100726c";
const REQ = "00000000-a5a5-524c-7272-00000200726c";
const RSP = "00000000-a5a5-524c-7272-00000300726c";

async function connect() {
  const dev = await navigator.bluetooth.requestDevice({
    filters: [{ services: [SVC] }],
  });
  const server = await dev.gatt.connect();
  const svc    = await server.getPrimaryService(SVC);
  const req    = await svc.getCharacteristic(REQ);
  const rsp    = await svc.getCharacteristic(RSP);
  await rsp.startNotifications();
  return { req, rsp };
}

async function call(req, rsp, request) {
  return new Promise((resolve) => {
    const onResp = (ev) => {
      rsp.removeEventListener("characteristicvaluechanged", onResp);
      const buf = new Uint8Array(ev.target.value.buffer);
      resolve(decode(buf));
    };
    rsp.addEventListener("characteristicvaluechanged", onResp);
    req.writeValueWithoutResponse(encode(request));
  });
}

// Usage:
const { req, rsp } = await connect();
const pong = await call(req, rsp, { cmd: "ping" });
console.log("connected to", pong.identity_hash);

const cfg = await call(req, rsp, { cmd: "get_config" });

await call(req, rsp, {
  cmd: "set_config",
  lat_udeg: 37774900,
  lon_udeg: -122419400,
  display_name: "rlr-rooftop-1",
});

await call(req, rsp, { cmd: "commit" });
```
