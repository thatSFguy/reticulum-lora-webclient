// js/app.js — Main controller for the Reticulum web client.

'use strict';

import { RNode } from './rnode.js';
import { toHex } from './kiss.js';
import { Identity, computeDestinationHash, computeNameHash } from './identity.js';
import { parsePacket, buildPacket, PACKET_ANNOUNCE, PACKET_DATA, DEST_SINGLE, HEADER_1, PACKET_TYPE_NAMES } from './reticulum.js';
import { parseAnnounce, validateAnnounce, buildAnnounce, extractDisplayName, concatBytes, arraysEqual } from './announce.js';
import { encrypt, decrypt } from './crypto.js';
import { unpackMessage, verifyMessageSignature, packMessage } from './lxmf.js';
import { openDatabase, saveIdentity, loadIdentity, saveContact, getContact, getAllContacts, saveMessage, getMessages } from './store.js';

const $ = id => document.getElementById(id);
const rnode = new RNode();

// ---- State -----------------------------------------------------------

let myIdentity = null;     // Identity instance
let myDestHash = null;     // Our LXMF destination hash (16 bytes)
let contacts = new Map();  // hash_hex → { hash, publicKey, displayName, destHash, identity }
let activeContactHash = null;
let radioOn = false;

// ---- Logging ---------------------------------------------------------

function log(cls, msg) {
  const el = $('log');
  if (!el) return;
  const div = document.createElement('div');
  if (cls) div.className = cls;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  div.textContent = `[${ts}] ${msg}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  while (el.childNodes.length > 500) el.removeChild(el.firstChild);
}

rnode._onLog = (msg) => log('info', msg);

// ---- Identity --------------------------------------------------------

async function initIdentity() {
  await openDatabase();

  const stored = await loadIdentity();
  myIdentity = new Identity();

  if (stored && stored.encPrivKey && stored.sigPrivKey) {
    await myIdentity.loadFromPrivateKeys(
      new Uint8Array(stored.encPrivKey),
      new Uint8Array(stored.sigPrivKey)
    );
    log('ok', 'Identity loaded from storage');
  } else {
    await myIdentity.generate();
    await saveIdentity(myIdentity.exportPrivateKeys());
    log('ok', 'New identity generated and saved');
  }

  myDestHash = await computeDestinationHash('lxmf.delivery', myIdentity.hash);
  $('my-address').textContent = toHex(myDestHash);
  log('info', `LXMF address: ${toHex(myDestHash)}`);

  // Load saved contacts
  const savedContacts = await getAllContacts();
  for (const c of savedContacts) {
    const identity = new Identity();
    await identity.loadFromPublicKey(new Uint8Array(c.publicKey));
    contacts.set(c.hash, { ...c, identity });
  }
  renderContactList();
}

// ---- Packet handling -------------------------------------------------

rnode._onPacket = async (data, rssi, snr) => {
  const pkt = parsePacket(data);
  if (!pkt) {
    log('rx', `RX ${data.length}B RSSI=${rssi} SNR=${snr} (invalid header)`);
    return;
  }

  const hashHex = toHex(pkt.destHash).substring(0, 12);
  log('rx', `RX ${data.length}B RSSI=${rssi} SNR=${snr} ${PACKET_TYPE_NAMES[pkt.packetType]} dest=${hashHex}...`);

  if (pkt.packetType === PACKET_ANNOUNCE) {
    await handleAnnounce(pkt, rssi);
  } else if (pkt.packetType === PACKET_DATA) {
    await handleData(pkt, rssi);
  }
};

// ---- Announce handling -----------------------------------------------

async function handleAnnounce(pkt, rssi) {
  const announce = await parseAnnounce(pkt.payload, pkt.contextFlag, pkt.destHash);
  if (!announce) {
    log('info', '  (announce parse failed)');
    return;
  }

  const idHash = toHex(announce.identityHash);
  const displayName = extractDisplayName(announce.appData) || idHash.substring(0, 8);

  // Validate signature
  const valid = validateAnnounce(announce, pkt.destHash);
  log(valid ? 'ok' : 'err', `  Announce from "${displayName}" [${idHash.substring(0,12)}...] sig=${valid ? 'valid' : 'INVALID'}`);

  if (!valid) return;

  // Store contact
  const destHashHex = announce.destHash ? toHex(announce.destHash) : toHex(pkt.destHash);
  const contact = {
    hash: destHashHex,
    identityHash: idHash,
    publicKey: Array.from(announce.publicKey),
    displayName,
    lastSeen: Date.now(),
    rssi,
  };

  const identity = new Identity();
  await identity.loadFromPublicKey(announce.publicKey);
  contacts.set(destHashHex, { ...contact, identity, destHash: announce.destHash || pkt.destHash });

  await saveContact(contact);
  renderContactList();
}

// ---- Data packet handling (incoming messages) -------------------------

async function handleData(pkt, rssi) {
  // Check if this packet is addressed to us
  if (!myDestHash || !arraysEqual(pkt.destHash, myDestHash)) {
    return;  // Not for us
  }

  log('info', '  Packet addressed to us — attempting decrypt...');

  try {
    // The packet data (after RNS header) is the encrypted LXMF payload
    const plaintext = await decrypt(pkt.payload, myIdentity.encPrivKey, myIdentity.hash);

    // Unpack LXMF message
    const msg = await unpackMessage(plaintext, myDestHash);

    // Look up sender
    const sourceHashHex = toHex(msg.sourceHash);
    let senderName = sourceHashHex.substring(0, 8);

    // Try to find contact by identity hash matching
    for (const [hash, c] of contacts) {
      if (c.identityHash === sourceHashHex || hash === sourceHashHex) {
        senderName = c.displayName;

        // Verify signature
        const valid = verifyMessageSignature(msg, c.identity);
        log(valid ? 'ok' : 'err', `  Signature: ${valid ? 'valid' : 'INVALID'}`);
        break;
      }
    }

    log('ok', `  Message from "${senderName}": ${msg.content}`);

    // Find the contact hash for this sender
    let contactHash = null;
    for (const [hash, c] of contacts) {
      if (c.identityHash === sourceHashHex) {
        contactHash = hash;
        break;
      }
    }

    // Save message
    const savedMsg = {
      contactHash: contactHash || sourceHashHex,
      direction: 'incoming',
      content: msg.content,
      title: msg.title,
      timestamp: msg.timestamp * 1000,
      rssi,
    };
    await saveMessage(savedMsg);

    // Update UI if viewing this conversation
    if (activeContactHash === savedMsg.contactHash) {
      await renderMessages(activeContactHash);
    }
  } catch (e) {
    log('err', `  Decrypt/parse failed: ${e.message}`);
  }
}

// ---- Send message ----------------------------------------------------

async function sendMessage() {
  if (!activeContactHash || !radioOn) return;

  const content = $('msg-content').value.trim();
  if (!content) return;

  const contact = contacts.get(activeContactHash);
  if (!contact) { log('err', 'Contact not found'); return; }

  try {
    log('info', `Sending to "${contact.displayName}"...`);

    // Pack LXMF message
    const lxmfPayload = await packMessage(
      myIdentity, contact.destHash, myIdentity.hash,
      '', content, {}
    );

    // Encrypt for recipient
    const encrypted = await encrypt(lxmfPayload, contact.identity.encPubKey, contact.identity.hash);

    // Build Reticulum packet
    const packet = buildPacket({
      headerType: HEADER_1,
      destType: DEST_SINGLE,
      packetType: PACKET_DATA,
      destHash: contact.destHash,
      context: 0x00,
      payload: encrypted,
    });

    // Check size
    if (packet.length > 500) {
      log('err', `Packet too large (${packet.length} bytes, max 500). Shorten your message.`);
      return;
    }

    // Send via RNode
    await rnode.sendPacket(packet);
    log('ok', `Sent ${packet.length}B to "${contact.displayName}"`);

    // Save message
    await saveMessage({
      contactHash: activeContactHash,
      direction: 'outgoing',
      content,
      title: '',
      timestamp: Date.now(),
    });

    $('msg-content').value = '';
    await renderMessages(activeContactHash);
  } catch (e) {
    log('err', `Send failed: ${e.message}`);
  }
}

// ---- Send announce ---------------------------------------------------

async function sendAnnounce() {
  if (!radioOn || !myIdentity) { log('err', 'Radio not on or identity not ready'); return; }

  const displayName = $('my-name').value.trim() || 'WebClient';
  const appData = new TextEncoder().encode(displayName);

  const { destHash, payload } = await buildAnnounce(myIdentity, 'lxmf.delivery', appData);

  const packet = buildPacket({
    headerType: HEADER_1,
    destType: DEST_SINGLE,
    packetType: PACKET_ANNOUNCE,
    destHash: destHash,
    context: 0x00,
    payload: payload,
  });

  await rnode.sendPacket(packet);
  log('ok', `Announce sent as "${displayName}" [${toHex(destHash).substring(0,12)}...]`);
}

// ---- UI rendering ----------------------------------------------------

function renderContactList() {
  const list = $('contact-list');
  if (contacts.size === 0) {
    list.innerHTML = '<li style="color: var(--muted); font-size: 13px; cursor: default;">Listening for announces...</li>';
    return;
  }

  list.innerHTML = '';
  for (const [hash, c] of contacts) {
    const li = document.createElement('li');
    li.className = hash === activeContactHash ? 'active' : '';
    li.innerHTML = `<div><div class="contact-name">${escapeHtml(c.displayName)}</div><div class="contact-hash">${hash.substring(0, 16)}...</div></div>`;
    li.addEventListener('click', () => selectContact(hash));
    list.appendChild(li);
  }
}

async function selectContact(hash) {
  activeContactHash = hash;
  const c = contacts.get(hash);
  $('conv-title').textContent = c ? c.displayName : hash.substring(0, 16);
  $('compose-area').classList.remove('hidden');
  renderContactList();
  await renderMessages(hash);
}

async function renderMessages(contactHash) {
  const list = $('message-list');
  const msgs = await getMessages(contactHash);

  if (msgs.length === 0) {
    list.innerHTML = '<div style="color: var(--muted); font-size: 13px; text-align: center; padding: 40px 0;">No messages yet</div>';
    return;
  }

  list.innerHTML = '';
  for (const msg of msgs.sort((a, b) => a.timestamp - b.timestamp)) {
    const div = document.createElement('div');
    div.className = `message ${msg.direction}`;
    const time = new Date(msg.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
    div.innerHTML = `<div>${escapeHtml(msg.content)}</div><div class="meta">${time}</div>`;
    list.appendChild(div);
  }
  list.scrollTop = list.scrollHeight;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- Event wiring ----------------------------------------------------

// Connect
$('btn-connect').addEventListener('click', async () => {
  try {
    $('btn-connect').disabled = true;
    await rnode.connect();

    $('conn-dot').classList.add('on');
    $('conn-text').textContent = 'Connected';
    $('btn-disconnect').classList.remove('hidden');

    const detected = await rnode.detect();
    if (!detected) { log('err', 'RNode detect failed'); return; }

    const fw = await rnode.getFirmwareVersion();
    const battery = await rnode.getBattery();
    log('ok', `RNode FW ${fw?.major}.${fw?.minor}, Bat ${battery}%`);

    // Show panels
    $('identity-panel').classList.remove('hidden');
    $('config-panel').classList.remove('hidden');
    $('messaging-panel').classList.remove('hidden');

    // Auto-start radio with form values
    await startRadio();
  } catch (e) {
    log('err', 'Connect: ' + e.message);
  } finally {
    $('btn-connect').disabled = false;
  }
});

$('btn-disconnect').addEventListener('click', async () => {
  await rnode.disconnect();
  $('conn-dot').classList.remove('on');
  $('conn-text').textContent = 'Disconnected';
  $('btn-disconnect').classList.add('hidden');
  $('identity-panel').classList.add('hidden');
  $('config-panel').classList.add('hidden');
  $('messaging-panel').classList.add('hidden');
  radioOn = false;
  $('radio-status').textContent = '';
  log('info', 'Disconnected');
});

// Radio
async function startRadio() {
  try {
    const freq = parseInt($('cfg-freq').value);
    const bw = parseInt($('cfg-bw').value);
    const sf = parseInt($('cfg-sf').value);
    const cr = parseInt($('cfg-cr').value);
    const txp = parseInt($('cfg-txp').value);
    const on = await rnode.configureAndStart({ freq, bw, sf, cr, txp });
    radioOn = on;
    $('radio-status').textContent = on ? 'Radio: ON' : '';
    $('radio-status').className = on ? 'status-on' : 'status-off';
    if (on) log('ok', 'Radio on');
  } catch (e) { log('err', 'Radio: ' + e.message); }
}

$('btn-start-radio').addEventListener('click', startRadio);
$('btn-stop-radio').addEventListener('click', async () => {
  await rnode.setRadioState(false);
  radioOn = false;
  $('radio-status').textContent = 'Radio: OFF';
  $('radio-status').className = 'status-off';
});

// Identity
$('btn-announce').addEventListener('click', sendAnnounce);
$('btn-new-id').addEventListener('click', async () => {
  if (!confirm('Generate new identity? Your current address will change.')) return;
  myIdentity = new Identity();
  await myIdentity.generate();
  await saveIdentity(myIdentity.exportPrivateKeys());
  myDestHash = await computeDestinationHash('lxmf.delivery', myIdentity.hash);
  $('my-address').textContent = toHex(myDestHash);
  log('ok', `New identity: ${toHex(myDestHash)}`);
});
$('btn-export-id').addEventListener('click', () => {
  const data = JSON.stringify(myIdentity.exportPrivateKeys());
  const blob = new Blob([data], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `reticulum-identity-${toHex(myDestHash).substring(0,8)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  log('ok', 'Identity exported');
});

// Messaging
$('btn-send').addEventListener('click', sendMessage);
$('msg-content').addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
});

// Log
$('btn-clear-log').addEventListener('click', () => { $('log').innerHTML = ''; });

// Browser check
if (!navigator.bluetooth) {
  $('unsupported').classList.remove('hidden');
}

// ---- Init ------------------------------------------------------------
initIdentity().catch(e => log('err', 'Identity init: ' + e.message));
