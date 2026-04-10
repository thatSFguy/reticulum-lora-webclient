// js/app.js — UI controller for the Reticulum web client.

'use strict';

import { RNode } from './rnode.js';
import { toHex } from './kiss.js';

const $ = id => document.getElementById(id);
const rnode = new RNode();

// ---- Logging --------------------------------------------------------

function log(cls, msg) {
  const el = $('log');
  const div = document.createElement('div');
  if (cls) div.className = cls;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  div.textContent = `[${ts}] ${msg}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  // Trim log to 500 entries
  while (el.childNodes.length > 500) el.removeChild(el.firstChild);
}

rnode._onLog = (msg) => log('info', msg);

// ---- Packet display -------------------------------------------------

// Parse Reticulum header for display
function parseReticulumHeader(data) {
  if (data.length < 19) return null;
  const flags = data[0];
  const hops = data[1];
  const destHash = data.subarray(2, 18);
  const context = data[18];
  const payload = data.subarray(19);

  const headerType = (flags >> 6) & 0x03;
  const contextFlag = (flags >> 5) & 0x01;
  const transportType = (flags >> 4) & 0x01;
  const destType = (flags >> 2) & 0x03;
  const packetType = flags & 0x03;

  const packetTypeNames = ['DATA', 'ANNOUNCE', 'LINKREQ', 'PROOF'];
  const destTypeNames = ['SINGLE', 'GROUP', 'PLAIN', 'LINK'];

  return {
    flags, hops, destHash, context, payload,
    headerType, contextFlag, transportType, destType, packetType,
    typeName: packetTypeNames[packetType] || '?',
    destTypeName: destTypeNames[destType] || '?',
  };
}

function onPacket(data, rssi, snr) {
  const pkt = parseReticulumHeader(data);
  if (pkt) {
    const hash = toHex(pkt.destHash).substring(0, 12) + '...';
    log('rx',
      `RX ${data.length}B  RSSI=${rssi} dBm  SNR=${snr} dB  ` +
      `${pkt.typeName} → ${pkt.destTypeName}  dest=${hash}  hops=${pkt.hops}`
    );

    // For ANNOUNCE packets, show more detail
    if (pkt.packetType === 1 && pkt.payload.length >= 84) {
      const pubkey = toHex(pkt.payload.subarray(0, 64));
      const nameHash = toHex(pkt.payload.subarray(64, 74));
      log('info', `  pubkey=${pubkey.substring(0, 32)}...`);
      log('info', `  name_hash=${nameHash}`);
    }
  } else {
    log('rx', `RX ${data.length}B  RSSI=${rssi} dBm  SNR=${snr} dB  (too short for Reticulum header)`);
  }

  // Hex dump (first 64 bytes)
  const hexPart = toHex(data.subarray(0, Math.min(64, data.length)));
  const truncated = data.length > 64 ? '...' : '';
  log('hex', `  ${hexPart}${truncated}`);
}

rnode._onPacket = onPacket;

// ---- Connect --------------------------------------------------------

$('btn-connect').addEventListener('click', async () => {
  try {
    $('btn-connect').disabled = true;
    await rnode.connect();

    $('conn-dot').classList.add('on');
    $('conn-text').textContent = 'Connected';
    $('btn-disconnect').classList.remove('hidden');

    // Detect RNode
    log('info', 'Detecting RNode...');
    const detected = await rnode.detect();
    if (!detected) { log('err', 'RNode detect failed'); return; }
    log('ok', 'RNode detected');

    const fw = await rnode.getFirmwareVersion();
    const platform = await rnode.getPlatform();
    const board = await rnode.getBoard();
    const battery = await rnode.getBattery();

    log('ok', `FW ${fw?.major}.${fw?.minor}  Platform=0x${(platform||0).toString(16)}  Board=0x${(board||0).toString(16)}  Bat=${battery}%`);

    // Show config panel
    $('config-panel').classList.remove('hidden');
    $('packet-panel').classList.remove('hidden');
  } catch (e) {
    log('err', 'Connect failed: ' + e.message);
  } finally {
    $('btn-connect').disabled = false;
  }
});

$('btn-disconnect').addEventListener('click', async () => {
  await rnode.disconnect();
  $('conn-dot').classList.remove('on');
  $('conn-text').textContent = 'Disconnected';
  $('btn-disconnect').classList.add('hidden');
  $('config-panel').classList.add('hidden');
  $('packet-panel').classList.add('hidden');
  log('info', 'Disconnected');
});

// ---- Radio config ---------------------------------------------------

$('btn-start-radio').addEventListener('click', async () => {
  try {
    const freq = parseInt($('cfg-freq').value);
    const bw = parseInt($('cfg-bw').value);
    const sf = parseInt($('cfg-sf').value);
    const cr = parseInt($('cfg-cr').value);
    const txp = parseInt($('cfg-txp').value);

    log('info', `Configuring: freq=${freq} bw=${bw} sf=${sf} cr=${cr} txp=${txp}`);
    const on = await rnode.configureAndStart({ freq, bw, sf, cr, txp });
    if (on) {
      log('ok', 'Radio on — listening for packets');
      $('radio-status').textContent = 'Radio: ON';
      $('radio-status').className = 'status-on';
    } else {
      log('err', 'Failed to start radio');
    }
  } catch (e) {
    log('err', 'Config failed: ' + e.message);
  }
});

$('btn-stop-radio').addEventListener('click', async () => {
  try {
    await rnode.setRadioState(false);
    log('info', 'Radio off');
    $('radio-status').textContent = 'Radio: OFF';
    $('radio-status').className = 'status-off';
  } catch (e) {
    log('err', e.message);
  }
});

$('btn-clear-log').addEventListener('click', () => {
  $('log').innerHTML = '';
});

// ---- Browser check --------------------------------------------------
if (!navigator.bluetooth) {
  $('unsupported').classList.remove('hidden');
}
