// js/app.js — Main controller for the Reticulum web client.

'use strict';

import { encode as msgpackEncode } from '@msgpack/msgpack';
import { RNode } from './rnode.js';
import { toHex } from './kiss.js';
import { Identity, computeDestinationHash, computeNameHash } from './identity.js';
import { parsePacket, buildPacket, PACKET_ANNOUNCE, PACKET_DATA, PACKET_LINKREQ, PACKET_PROOF, DEST_SINGLE, DEST_LINK, HEADER_1, PACKET_TYPE_NAMES } from './reticulum.js';
import { parseAnnounce, validateAnnounce, buildAnnounce, extractDisplayName, concatBytes, arraysEqual } from './announce.js';
import { encrypt, decrypt } from './crypto.js';
import { unpackMessage, unpackLinkMessage, verifyMessageSignature, packMessage } from './lxmf.js';
import { Link, LINK_ACTIVE, LINK_CLOSED } from './link.js';

// Reticulum packet context values relevant to link traffic
const CTX_NONE      = 0x00;
const CTX_KEEPALIVE = 0xFA;
const CTX_LINKCLOSE = 0xFC;
const CTX_LRRTT     = 0xFE;
const CTX_LRPROOF   = 0xFF;
import { openDatabase, saveIdentity, loadIdentity, saveContact, getContact, getAllContacts, deleteContact, deleteMessagesForContact, saveMessage, getMessages } from './store.js';

const $ = id => document.getElementById(id);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// Normalize an LXMF timestamp field to Unix ms. Upstream LXMF writes
// time.time() which is float seconds since epoch, but some encoders
// produce msgpack Timestamp extensions (which @msgpack/msgpack decodes
// to a JS Date) and some write integer milliseconds directly. Handle
// all three, and fall back to the local clock if the value is absent
// or nonsensical.
function normalizeLxmfTimestamp(ts) {
  if (ts == null) return Date.now();
  if (ts instanceof Date) return ts.getTime();
  if (typeof ts === 'bigint') ts = Number(ts);
  if (typeof ts !== 'number' || !isFinite(ts)) return Date.now();
  // Values above ~1e12 are already in milliseconds; below that they
  // are in seconds. Any plausible recent timestamp in seconds is in
  // the 1.5e9–3e9 range; any plausible timestamp in ms is in the
  // 1.5e12–3e12 range. The gap is wide enough for this heuristic to
  // be unambiguous.
  return ts > 1e12 ? ts : ts * 1000;
}

// Logging — declared early so error handlers can use it
function log(cls, msg) {
  const el = $('log');
  if (!el) { console.log(`[${cls}]`, msg); return; }
  const div = document.createElement('div');
  if (cls) div.className = cls;
  const ts = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  div.textContent = `[${ts}] ${msg}`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
  while (el.childNodes.length > 500) el.removeChild(el.firstChild);
}

// Global error handler — show errors in the visible log
window.addEventListener('error', (e) => {
  log('err', `JS error: ${e.message} (${e.filename}:${e.lineno})`);
});
window.addEventListener('unhandledrejection', (e) => {
  log('err', `Unhandled promise: ${e.reason?.message || e.reason}`);
});

let rnode = new RNode('ble');  // default; can be reassigned

// ---- State -----------------------------------------------------------

let myIdentity = null;     // Identity instance
let myDestHash = null;     // Our LXMF destination hash (16 bytes)
let contacts = new Map();  // hash_hex → { hash, publicKey, displayName, destHash, identity }
let activeContactHash = null;
let radioOn = false;
let links = new Map();     // hex link_id → Link instance (incoming links only)

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
    // destHash may be stored as array; fall back to decoding the hex hash field
    // for legacy records saved before destHash was persisted.
    const destHash = c.destHash ? new Uint8Array(c.destHash) : hexToBytes(c.hash);
    contacts.set(c.hash, { ...c, identity, destHash });
  }
  renderContactList();
}

// ---- Packet handling -------------------------------------------------

async function onPacket(data, rssi, snr) {
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
    if (pkt.destType === DEST_LINK) {
      await handleLinkData(pkt, rssi);
    } else {
      await handleData(pkt, rssi);
    }
  } else if (pkt.packetType === PACKET_LINKREQ) {
    if (myDestHash && arraysEqual(pkt.destHash, myDestHash)) {
      await handleLinkRequest(pkt);
    } else {
      log('info', `  LINKREQUEST dest=${toHex(pkt.destHash).substring(0,16)}... (not for us)`);
    }
  } else if (pkt.packetType === PACKET_PROOF) {
    // PROOF packets we might see: LRPROOF from a responder to some
    // initiator on the mesh (we never initiate links), and packet
    // proofs for opportunistic messages we've sent. Both are fine to
    // ignore at this layer.
  }
}

rnode._onPacket = onPacket;

// ---- Announce handling -----------------------------------------------

async function handleAnnounce(pkt, rssi) {
  const announce = await parseAnnounce(pkt.payload, pkt.contextFlag, pkt.destHash);
  if (!announce) {
    log('info', '  (announce parse failed)');
    return;
  }

  const idHash = toHex(announce.identityHash);
  const displayName = extractDisplayName(announce.appData) || idHash.substring(0, 8);

  // Skip our own announce (rebroadcast by relay/repeater)
  if (myIdentity && idHash === toHex(myIdentity.hash)) {
    log('info', '  (own announce, ignoring)');
    return;
  }

  // Validate signature
  const valid = validateAnnounce(announce, pkt.destHash);
  log(valid ? 'ok' : 'err', `  Announce from "${displayName}" [${idHash.substring(0,12)}...] sig=${valid ? 'valid' : 'INVALID'}`);

  if (!valid) return;

  // Store contact
  const destHashBytes = announce.destHash || pkt.destHash;
  const destHashHex = toHex(destHashBytes);
  const contact = {
    hash: destHashHex,
    identityHash: idHash,
    publicKey: Array.from(announce.publicKey),
    destHash: Array.from(destHashBytes),
    displayName,
    lastSeen: Date.now(),
    rssi,
  };

  const identity = new Identity();
  await identity.loadFromPublicKey(announce.publicKey);
  contacts.set(destHashHex, { ...contact, identity, destHash: destHashBytes });

  await saveContact(contact);
  renderContactList();
}

// ---- Data packet handling (incoming messages) -------------------------

async function handleData(pkt, rssi) {
  // Always log incoming DATA dest hash so we can see what's arriving
  const incomingHex = toHex(pkt.destHash);
  const ourHex = myDestHash ? toHex(myDestHash) : '(none)';
  const matches = myDestHash && arraysEqual(pkt.destHash, myDestHash);

  log(matches ? 'ok' : 'info',
    `  DATA dest=${incomingHex.substring(0,16)}...  (ours=${ourHex.substring(0,16)}...)  ${matches ? 'MATCH' : 'no match'}`
  );

  if (!matches) return;

  log('info', '  Packet addressed to us — attempting decrypt...');

  try {
    // The packet data (after RNS header) is the encrypted LXMF payload
    const plaintext = await decrypt(pkt.payload, myIdentity.encPrivKey, myIdentity.hash);

    // Unpack LXMF message (opportunistic form: dest hash stripped)
    const msg = await unpackMessage(plaintext, myDestHash);
    await dispatchIncomingMessage(msg, rssi);
  } catch (e) {
    log('err', `  Decrypt/parse failed: ${e.message}`);
  }
}

// Common post-decrypt handling shared between opportunistic (handleData)
// and link-delivered (handleLinkData) inbound LXMF messages. Takes an
// already-unpacked LXMF message object and the RSSI of the carrying packet.
async function dispatchIncomingMessage(msg, rssi) {
  const sourceHashHex = toHex(msg.sourceHash);
  let senderName = sourceHashHex.substring(0, 8);
  let contactHash = null;

  for (const [hash, c] of contacts) {
    if (c.identityHash === sourceHashHex || hash === sourceHashHex) {
      senderName = c.displayName;
      contactHash = hash;
      const valid = verifyMessageSignature(msg, c.identity);
      log(valid ? 'ok' : 'err', `  Signature: ${valid ? 'valid' : 'INVALID'}`);
      break;
    }
  }

  log('ok', `  Message from "${senderName}": ${msg.content}`);

  const savedMsg = {
    contactHash: contactHash || sourceHashHex,
    direction: 'incoming',
    content: msg.content,
    title: msg.title,
    timestamp: normalizeLxmfTimestamp(msg.timestamp),
    rssi,
  };
  await saveMessage(savedMsg);

  if (activeContactHash === savedMsg.contactHash) {
    await renderMessages(activeContactHash);
  }
}

// ---- Link handling ---------------------------------------------------

async function handleLinkRequest(pkt) {
  const sizeOk = pkt.payload.length === 64 || pkt.payload.length === 67;
  if (!sizeOk) {
    log('err', `  LINKREQUEST addressed to us but payload size ${pkt.payload.length} is not 64 or 67, dropping`);
    return;
  }

  try {
    // Trace the inbound request for byte-level debugging of the link_id
    // derivation. First line shows flags/hops and the packet header;
    // second line shows the 64 or 67 bytes of LINKREQUEST data.
    log('info', `  LR header type=${pkt.headerType === HEADER_1 ? 'H1' : 'H2'} flags=0x${pkt.flags.toString(16).padStart(2,'0')} hops=${pkt.hops}`);
    log('info', `  LR data(${pkt.payload.length})=${toHex(pkt.payload)}`);

    const { link, proofData } = await Link.validateRequest(pkt, myIdentity);
    const linkIdHex = toHex(link.linkId);

    // If we've already accepted this exact request, just resend the
    // cached LRPROOF. Regenerating the ephemeral key would orphan the
    // initiator's existing session state.
    const existing = links.get(linkIdHex);
    const linkToStore = existing || link;
    if (!existing) links.set(linkIdHex, link);

    const proofPacket = buildPacket({
      headerType: HEADER_1,
      destType:   DEST_LINK,
      packetType: PACKET_PROOF,
      destHash:   linkToStore.linkId,
      context:    CTX_LRPROOF,
      payload:    linkToStore.cachedProofData,
    });

    log('info', `  LRPROOF tx(${proofPacket.length})=${toHex(proofPacket)}`);
    await rnode.sendPacket(proofPacket);

    log('ok', `  LINKREQUEST accepted, LRPROOF sent (link ${linkIdHex.substring(0,12)}...)`);
  } catch (e) {
    log('err', `  LINKREQUEST validation failed: ${e.message}`);
  }
}

async function handleLinkData(pkt, rssi) {
  const linkIdHex = toHex(pkt.destHash);
  const link = links.get(linkIdHex);
  if (!link) {
    log('info', `  DATA for unknown link ${linkIdHex.substring(0,16)}..., ignoring`);
    return;
  }

  try {
    switch (pkt.context) {
      case CTX_NONE: {
        // Full LXMF container encrypted with the link session key.
        const plaintext = await link.decrypt(pkt.payload);
        const msg = await unpackLinkMessage(plaintext);
        log('ok', `  Link ${linkIdHex.substring(0,12)}... delivered LXMF message`);
        await dispatchIncomingMessage(msg, rssi);
        break;
      }
      case CTX_LRRTT: {
        // Decrypting it is how we confirm the initiator successfully
        // verified our LRPROOF; the RTT value itself is not useful here.
        await link.decrypt(pkt.payload);
        link.status = LINK_ACTIVE;
        link.establishedAt = Date.now();
        log('ok', `  Link ${linkIdHex.substring(0,12)}... ACTIVE (RTT ack received)`);
        break;
      }
      case CTX_LINKCLOSE: {
        const plaintext = await link.decrypt(pkt.payload);
        if (plaintext.length === link.linkId.length &&
            arraysEqual(plaintext, link.linkId)) {
          link.status = LINK_CLOSED;
          links.delete(linkIdHex);
          log('info', `  Link ${linkIdHex.substring(0,12)}... closed by peer`);
        } else {
          log('err', `  LINKCLOSE payload did not match link_id, ignoring`);
        }
        break;
      }
      case CTX_KEEPALIVE: {
        // Responder has no action to take on keepalives from the
        // initiator during a short delivery session.
        break;
      }
      default: {
        log('info', `  Link packet context 0x${pkt.context.toString(16)} not handled`);
      }
    }
  } catch (e) {
    log('err', `  Link packet handling failed (ctx=0x${pkt.context.toString(16)}): ${e.message}`);
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

    // Pack LXMF message. LXMF's source_hash field is the sender's
    // LXMF delivery *destination* hash, not the identity hash —
    // receivers key their contact table on destination hashes.
    const lxmfPayload = await packMessage(
      myIdentity, contact.destHash, myDestHash,
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
  // LXMF/Sideband format: msgpack([display_name_bytes, stamp_cost])
  const nameBytes = new TextEncoder().encode(displayName);
  const appData = new Uint8Array(msgpackEncode([nameBytes, 0]));

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

    const info = document.createElement('div');
    info.innerHTML = `<div class="contact-name">${escapeHtml(c.displayName)}</div><div class="contact-hash">${hash.substring(0, 16)}...</div>`;
    info.addEventListener('click', () => selectContact(hash));

    const del = document.createElement('button');
    del.className = 'contact-delete';
    del.title = 'Delete contact';
    del.textContent = '\u00d7';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      removeContact(hash);
    });

    li.appendChild(info);
    li.appendChild(del);
    list.appendChild(li);
  }
}

async function removeContact(hash) {
  const c = contacts.get(hash);
  const label = c ? `"${c.displayName}"` : hash.substring(0, 16);
  if (!confirm(`Delete ${label} and all messages with them?`)) return;

  contacts.delete(hash);
  await deleteMessagesForContact(hash);
  await deleteContact(hash);

  if (activeContactHash === hash) {
    activeContactHash = null;
    $('conv-title').textContent = 'Select a contact';
    $('compose-area').classList.add('hidden');
    $('message-list').innerHTML = '';
  }

  renderContactList();
  log('info', `Deleted contact ${label}`);
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

  // Normalize timestamps on read so historical rows that were saved
  // before the normalizer was in place still render as valid dates.
  const normalized = msgs.map(m => ({ ...m, timestamp: normalizeLxmfTimestamp(m.timestamp) }));

  list.innerHTML = '';
  for (const msg of normalized.sort((a, b) => a.timestamp - b.timestamp)) {
    const div = document.createElement('div');
    div.className = `message ${msg.direction}`;
    const time = formatMessageTime(msg.timestamp);
    div.innerHTML = `<div>${escapeHtml(msg.content)}</div><div class="meta">${time}</div>`;
    list.appendChild(div);
  }
  list.scrollTop = list.scrollHeight;
}

// Format a message timestamp. Shows "HH:MM" for messages from today,
// "MMM D, HH:MM" for older messages in the current year, and the full
// date for anything older than that. 24-hour time throughout so the
// earlier AM/PM confusion can't recur.
function formatMessageTime(ms) {
  const d = new Date(ms);
  const now = new Date();
  const sameDay = d.getFullYear() === now.getFullYear() &&
                  d.getMonth() === now.getMonth() &&
                  d.getDate() === now.getDate();
  const hhmm = d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit' });
  if (sameDay) return hhmm;
  if (d.getFullYear() === now.getFullYear()) {
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' + hhmm;
  }
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' }) + ' ' + hhmm;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ---- Event wiring ----------------------------------------------------

// Connect
async function connect(transportType) {
  const btnBle = $('btn-connect-ble');
  const btnSerial = $('btn-connect-serial');
  try {
    btnBle.disabled = true;
    btnSerial.disabled = true;

    // Re-instantiate RNode with chosen transport
    rnode = new RNode(transportType);
    rnode._onLog = (msg) => log('info', msg);
    rnode._onPacket = onPacket;

    await rnode.connect();

    $('conn-dot').classList.add('on');
    $('conn-text').textContent = `Connected (${transportType.toUpperCase()})`;
    $('btn-disconnect').classList.remove('hidden');
    btnBle.classList.add('hidden');
    btnSerial.classList.add('hidden');

    const detected = await rnode.detect();
    if (!detected) { log('err', 'RNode detect failed'); return; }

    const fw = await rnode.getFirmwareVersion();
    const battery = await rnode.getBattery();
    log('ok', `RNode FW ${fw?.major}.${fw?.minor}, Bat ${battery}%`);

    // Show panels
    $('config-panel').classList.remove('hidden');
    $('messaging-panel').classList.remove('hidden');

    // Auto-start radio with form values
    await startRadio();
  } catch (e) {
    log('err', 'Connect: ' + e.message);
  } finally {
    btnBle.disabled = false;
    btnSerial.disabled = false;
  }
}

$('btn-connect-ble').addEventListener('click', () => connect('ble'));
$('btn-connect-serial').addEventListener('click', () => connect('serial'));

$('btn-disconnect').addEventListener('click', async () => {
  await rnode.disconnect();
  $('conn-dot').classList.remove('on');
  $('conn-text').textContent = 'Disconnected';
  $('btn-disconnect').classList.add('hidden');
  $('btn-connect-ble').classList.remove('hidden');
  $('btn-connect-serial').classList.remove('hidden');
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

// Browser check — disable buttons for unsupported transports
if (!navigator.bluetooth) {
  $('btn-connect-ble').disabled = true;
  $('btn-connect-ble').textContent = 'Connect (BLE — not supported)';
}
if (!navigator.serial) {
  $('btn-connect-serial').disabled = true;
  $('btn-connect-serial').textContent = 'Connect (Serial — not supported)';
}
if (!navigator.bluetooth && !navigator.serial) {
  $('unsupported').classList.remove('hidden');
}

// ---- Init ------------------------------------------------------------
initIdentity().catch(e => log('err', 'Identity init: ' + e.message));
