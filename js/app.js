// js/app.js — Main controller for the Reticulum web client.

'use strict';

import { encode as msgpackEncode } from '@msgpack/msgpack';
import { RNode } from './rnode.js';
import { RnsdInterface } from './rnsd-interface.js';
import { toHex } from './kiss.js';
import { Identity, computeDestinationHash, computeNameHash } from './identity.js';
import { parsePacket, buildPacket, PACKET_ANNOUNCE, PACKET_DATA, PACKET_LINKREQ, PACKET_PROOF, DEST_SINGLE, DEST_LINK, HEADER_1, PACKET_TYPE_NAMES } from './reticulum.js';
import { parseAnnounce, validateAnnounce, buildAnnounce, extractDisplayName, concatBytes, arraysEqual } from './announce.js';
import { encrypt, decrypt } from './crypto.js';
import { unpackMessage, unpackLinkMessage, verifyMessageSignature, packMessage } from './lxmf.js';
import { Link, LINK_ACTIVE, LINK_CLOSED, computePacketFullHash } from './link.js';
import { ed25519 } from '@noble/curves/ed25519';

// Reticulum packet context values relevant to link traffic
const CTX_NONE      = 0x00;
const CTX_KEEPALIVE = 0xFA;
const CTX_LINKCLOSE = 0xFC;
const CTX_LRRTT     = 0xFE;
const CTX_LRPROOF   = 0xFF;

// Outbound message state machine. A row in IndexedDB with
// direction='outgoing' transitions through these states as the
// retry tick drives it forward.
const MSG_STATE_PENDING   = 'pending';    // queued, radio off or prior send failed
const MSG_STATE_SENDING   = 'sending';    // TX in flight right now
const MSG_STATE_SENT      = 'sent';       // TX completed, awaiting delivery receipt
const MSG_STATE_DELIVERED = 'delivered';  // inbound PROOF matched this packet hash
const MSG_STATE_FAILED    = 'failed';     // all retries exhausted

const MSG_MAX_ATTEMPTS = 3;
// Wait-for-ack schedule. Index is (attempts - 1): first entry is
// the wait after the 1st send, second is after the 2nd retransmit,
// etc. After MSG_MAX_ATTEMPTS attempts the row transitions to failed.
const MSG_BACKOFF_MS = [5000, 15000, 60000];
const MSG_RETRY_TICK_MS = 5000;
import { openDatabase, saveIdentity, loadIdentity, saveContact, getContact, getAllContacts, deleteContact, deleteMessagesForContact, saveMessage, getMessages, getAllMessages, getMessageById, updateMessage, saveNode, getAllNodes, deleteNode, deleteAllNodes } from './store.js';

const $ = id => document.getElementById(id);

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// Sanity floor for "this is a real wall-clock timestamp": 2020-01-01
// UTC. Anything older almost certainly comes from a sender whose
// time.time() is seconds-since-boot because the device has no RTC.
const SANITY_TS_MIN_MS = Date.UTC(2020, 0, 1);

// Normalize an LXMF timestamp field to Unix ms. Upstream LXMF writes
// time.time() which is float seconds since epoch, but some encoders
// produce msgpack Timestamp extensions (which @msgpack/msgpack decodes
// to a JS Date) and some write integer milliseconds directly. Handle
// all three. Returns null if the value is absent or resolves to a
// pre-2020 wall-clock date, so callers can substitute receive time
// or hide the label.
function normalizeLxmfTimestamp(ts) {
  if (ts == null) return null;
  if (ts instanceof Date) {
    const ms = ts.getTime();
    return ms >= SANITY_TS_MIN_MS ? ms : null;
  }
  if (typeof ts === 'bigint') ts = Number(ts);
  if (typeof ts !== 'number' || !isFinite(ts)) return null;
  // Values above ~1e12 are already in milliseconds; below that they
  // are in seconds. The gap between plausible seconds (1.5e9–3e9)
  // and plausible ms (1.5e12–3e12) is wide enough to be unambiguous.
  const ms = ts > 1e12 ? ts : ts * 1000;
  return ms >= SANITY_TS_MIN_MS ? ms : null;
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
let links = new Map();     // hex link_id → Link instance (responder / incoming)
let initiatorLinks = new Map();  // hex link_id → { link, contact, resolve, reject, timer }
let lxmfNameHash = null;   // SHA256("lxmf.delivery")[:10], cached
let announceTimer = null;  // setInterval handle for the periodic announce
let outboundRetryTimer = null;  // setInterval handle for the outbound retry tick

rnode._onLog = (msg) => log('info', msg);

// ---- Identity --------------------------------------------------------

async function initIdentity() {
  await openDatabase();

  const stored = await loadIdentity();
  myIdentity = new Identity();

  if (stored && stored.encPrivKey && stored.sigPrivKey) {
    await myIdentity.loadFromPrivateKeys(
      new Uint8Array(stored.encPrivKey),
      new Uint8Array(stored.sigPrivKey),
      stored.ratchetPrivKey ? new Uint8Array(stored.ratchetPrivKey) : null
    );
    log('ok', 'Identity loaded from storage');
    // One-time migration for identities saved before the ratchet
    // landed. Generating a ratchet is cheap and only touches the
    // identity row — it does NOT change encPrivKey, sigPrivKey,
    // publicKey, identity hash, or destination hash. The ratchet
    // is an additional keypair that coexists with the identity
    // X25519 key and is advertised in future announces.
    if (!myIdentity.ratchetPrivKey) {
      myIdentity.generateRatchet();
      await saveIdentity(myIdentity.exportPrivateKeys());
      log('info', 'Generated ratchet keypair for existing identity');
    }
  } else {
    await myIdentity.generate();
    await saveIdentity(myIdentity.exportPrivateKeys());
    log('ok', 'New identity generated and saved');
  }

  myDestHash = await computeDestinationHash('lxmf.delivery', myIdentity.hash);
  lxmfNameHash = await computeNameHash('lxmf.delivery');
  setMyAddress(toHex(myDestHash));
  log('info', `LXMF address: ${toHex(myDestHash)}`);

  // Load saved contacts. Drop every legacy record that does not have
  // a stored name_hash, because before the announce parser learned
  // to filter by name_hash we accepted announces from any destination
  // (telemetry beacons, heartbeats, auxiliary destinations on the
  // same identity as a real LXMF presence) and there is no reliable
  // way to tell which legacy rows were legitimate after the fact.
  // Anything genuine will get re-added on the next announce we hear
  // from its owner, this time with name_hash present and verified.
  // Records that DO carry a name_hash and don't match lxmf.delivery
  // are also dropped — same reason, just a different code path.
  const savedContacts = await getAllContacts();
  const expectedNameHashHex = toHex(lxmfNameHash);
  let purged = 0;
  for (const c of savedContacts) {
    const noNameHash = !c.nameHash;
    const wrongNameHash = c.nameHash && toHex(new Uint8Array(c.nameHash)) !== expectedNameHashHex;
    if (noNameHash || wrongNameHash) {
      await deleteMessagesForContact(c.hash);
      await deleteContact(c.hash);
      purged++;
      continue;
    }
    const identity = new Identity();
    await identity.loadFromPublicKey(new Uint8Array(c.publicKey));
    // destHash may be stored as array; fall back to decoding the hex hash field
    // for legacy records saved before destHash was persisted.
    const destHash = c.destHash ? new Uint8Array(c.destHash) : hexToBytes(c.hash);
    // Rehydrate ratchet pub if this contact was learned from a
    // ratchet-bearing announce. Missing on legacy rows; sendMessage
    // falls back to the identity X25519 key in that case.
    const ratchetPub = c.ratchetPub ? new Uint8Array(c.ratchetPub) : null;
    contacts.set(c.hash, { ...c, identity, destHash, ratchetPub });
  }
  if (purged > 0) {
    log('info', `Removed ${purged} legacy contact${purged === 1 ? '' : 's'} (no verifiable name_hash); valid LXMF peers will return on their next announce`);
  }
  renderContactList();
  renderNodesList();
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
    // PROOF types we care about, in order of specificity:
    //   1. LRPROOF (context=0xFF) addressed to one of our pending
    //      initiator links — route to that link's validateProof().
    //   2. PROOF with dest_type=LINK and context=CTX_NONE addressed
    //      to an active initiator link — this is a per-packet
    //      delivery receipt for a message we sent on that link.
    //      The packet hash sits in data[0:32], not the dest slot.
    //   3. Opportunistic delivery PROOF: dest_type=SINGLE (or PLAIN),
    //      dest_hash is the truncated packet hash of the sent packet.
    //      Matched by handleDeliveryProof against saved outgoing rows.
    if (pkt.context === CTX_LRPROOF) {
      await handleInitiatorLinkProof(pkt);
    } else if (pkt.destType === DEST_LINK) {
      await handleLinkDeliveryProof(pkt);
    } else {
      await handleDeliveryProof(pkt);
    }
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

  // Filter by name_hash. The 10-byte name_hash field in the announce
  // identifies which application destination this announce belongs to;
  // we only want lxmf.delivery announces in our contact list. Repeater
  // telemetry beacons (rlr.telemetry), heartbeat destinations, and any
  // other non-LXMF destination produce signed-and-valid announces with
  // a different name_hash and previously polluted the contact list.
  // We still save them to the nodes store so the Nodes panel can show
  // what else is active on the mesh.
  if (!arraysEqual(announce.nameHash, lxmfNameHash)) {
    await handleNonLxmfAnnounce(announce, pkt, rssi);
    return;
  }

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
    nameHash: Array.from(announce.nameHash),
    // If the announce carried a ratchet (context_flag=1), keep it
    // on the contact row so sendMessage can encrypt to it instead
    // of the long-term identity X25519 key. Falls back to the
    // identity key in sendMessage when this is null.
    ratchetPub: announce.ratchet ? Array.from(announce.ratchet) : null,
    displayName,
    lastSeen: Date.now(),
    rssi,
  };

  const identity = new Identity();
  await identity.loadFromPublicKey(announce.publicKey);
  const ratchetPubBytes = announce.ratchet ? new Uint8Array(announce.ratchet) : null;
  contacts.set(destHashHex, { ...contact, identity, destHash: destHashBytes, ratchetPub: ratchetPubBytes });

  await saveContact(contact);
  renderContactList();
}

// ---- Non-LXMF announce handling (Nodes panel) ------------------------

// Repeater telemetry beacons, heartbeats, auxiliary destinations, and
// anything else on the mesh that is NOT lxmf.delivery. We keep these
// out of the Messages contact list but track them in a separate store
// so the Nodes panel can show what else is active.
async function handleNonLxmfAnnounce(announce, pkt, rssi) {
  const idHash = toHex(announce.identityHash);

  // Skip our own echoed announces — noisy and never useful.
  if (myIdentity && idHash === toHex(myIdentity.hash)) return;

  const destHashBytes = announce.destHash || pkt.destHash;
  const destHashHex = toHex(destHashBytes);
  const nameHashHex = toHex(announce.nameHash);

  // Try to decode the app_data for display. For rlr.telemetry these
  // are semicolon-delimited key=value strings like
  //   bat=3952;up=30;hpf=90720;...;lat=43.16;lon=-85.65;msl=280
  // For heartbeats or other destinations we may just get a name.
  // extractDisplayName already returns a usable string for both.
  const displayName = extractDisplayName(announce.appData) || `${nameHashHex.substring(0, 8)} / ${idHash.substring(0, 8)}`;

  const node = {
    hash: destHashHex,
    identityHash: idHash,
    nameHash: Array.from(announce.nameHash),
    displayName,
    appDataHex: toHex(announce.appData),
    lastSeen: Date.now(),
    rssi,
  };
  await saveNode(node);

  log('info', `  Non-LXMF announce from ${idHash.substring(0, 12)}... → Nodes panel`);
  renderNodesList();
}

function renderNodesList() {
  const list = $('nodes-list');
  if (!list) return;
  getAllNodes().then((rows) => {
    if (!rows.length) {
      list.innerHTML = '<div class="nodes-empty">No non-LXMF announces yet. This view fills up with repeater telemetry, heartbeats, and anything else on the mesh that is not an LXMF delivery destination.</div>';
      return;
    }
    // Newest first.
    rows.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
    list.innerHTML = '';
    for (const n of rows) {
      const li = document.createElement('div');
      li.className = 'node-row';
      const ts = n.lastSeen ? new Date(n.lastSeen).toLocaleString() : '(unknown)';
      const rssi = (typeof n.rssi === 'number') ? `${n.rssi} dBm` : 'n/a';
      li.innerHTML =
        `<div class="node-row-top">
           <div class="node-name">${escapeHtml(n.displayName || '')}</div>
           <button class="node-delete" title="Forget this node">\u00d7</button>
         </div>
         <div class="node-meta">
           <span>dest <code>${n.hash.substring(0, 16)}...</code></span>
           <span>name_hash <code>${toHex(new Uint8Array(n.nameHash)).substring(0, 12)}...</code></span>
           <span>RSSI ${rssi}</span>
           <span>${ts}</span>
         </div>`;
      li.querySelector('.node-delete').addEventListener('click', async () => {
        await deleteNode(n.hash);
        renderNodesList();
      });
      list.appendChild(li);
    }
  }).catch((e) => {
    list.innerHTML = `<div class="err">Could not load nodes: ${escapeHtml(e.message)}</div>`;
  });
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
    // The packet data (after RNS header) is the encrypted LXMF payload.
    // Try the ratchet private key first (most traffic will be encrypted
    // to it once we advertise one) and fall back to the long-term
    // identity X25519 key for senders that haven't seen our ratchet yet.
    const candidatePrivs = [myIdentity.ratchetPrivKey, myIdentity.encPrivKey].filter(Boolean);
    const plaintext = await decrypt(pkt.payload, candidatePrivs, myIdentity.hash);

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

  // Diagnostic view of the payload the verifier is about to check.
  log('info', `  LXMF payload: elements=${msg.payloadElementCount} raw_msgpack=${msg.msgpackData.length}B stripped=${msg.msgpackForHash.length}B destHashInBody=${toHex(msg.destHash).substring(0, 16)}...`);

  for (const [hash, c] of contacts) {
    if (c.identityHash === sourceHashHex || hash === sourceHashHex) {
      senderName = c.displayName;
      contactHash = hash;
      const result = verifyMessageSignature(msg, c.identity);
      if (result.ok) {
        log('ok', `  Signature: valid (${result.variant})`);
      } else {
        log('err', `  Signature: INVALID (both stripped and original failed)`);
      }
      break;
    }
  }

  log('ok', `  Message from "${senderName}": ${msg.content}`);

  // Fall back to receive time when the sender's clock is bogus so
  // newly-saved rows render in a meaningful place in the timeline
  // instead of showing up as "Jan 1, 1970". Clockless Reticulum
  // nodes (no RTC) send seconds-since-boot as their LXMF timestamp.
  const senderTs = normalizeLxmfTimestamp(msg.timestamp);
  const savedMsg = {
    contactHash: contactHash || sourceHashHex,
    direction: 'incoming',
    content: msg.content,
    title: msg.title,
    timestamp: senderTs != null ? senderTs : Date.now(),
    senderTimeMissing: senderTs == null,
    rssi,
  };
  await saveMessage(savedMsg);
  log('info', `  Saved under contactHash=${savedMsg.contactHash.substring(0, 16)}... activeContact=${activeContactHash ? activeContactHash.substring(0, 16) + '...' : '(none)'}`);

  if (activeContactHash === savedMsg.contactHash) {
    await renderMessages(activeContactHash);
  }
  // Flag the contact as having unread traffic so the sidebar shows
  // something even when the user isn't currently in that conversation.
  const c = contacts.get(savedMsg.contactHash);
  if (c) {
    c.unreadCount = (c.unreadCount || 0) + 1;
    renderContactList();
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
    // derivation. First line shows the full header state (type, flags,
    // hops, and the context byte). Second line shows the 64 or 67 bytes
    // of LINKREQUEST data.
    log('info', `  LR header type=${pkt.headerType === HEADER_1 ? 'H1' : 'H2'} flags=0x${pkt.flags.toString(16).padStart(2,'0')} hops=${pkt.hops} ctx=0x${pkt.context.toString(16).padStart(2,'0')}`);
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

    // Dump everything needed to independently recompute the signature
    // and confirm the math is self-consistent without having to repro
    // on a second device.
    log('info', `  LR sigpub=${toHex(linkToStore.ourSigPub)}`);
    log('info', `  LR signed(${linkToStore.signedData.length})=${toHex(linkToStore.signedData)}`);
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
        // Send a link packet proof back so the sender's delivery
        // receipt timeout fires with success and it does not retry
        // the same message on a fresh link. Upstream's Link.receive
        // does this automatically via Packet.prove() whenever an
        // application-level data packet arrives on an established
        // link. The proof carries the full 32-byte SHA-256 of the
        // received packet's hashable_part plus an Ed25519 signature
        // over that hash, signed with our long-term identity key so
        // the initiator verifies it against the sig_pub it already
        // knows from our announce and LRPROOF.
        try {
          const packetHash = await computePacketFullHash(pkt);
          const signature  = ed25519.sign(packetHash, myIdentity.sigPrivKey);
          const proofData  = new Uint8Array(packetHash.length + signature.length);
          proofData.set(packetHash, 0);
          proofData.set(signature, packetHash.length);
          const proofPacket = buildPacket({
            headerType: HEADER_1,
            destType:   DEST_LINK,
            packetType: PACKET_PROOF,
            destHash:   link.linkId,
            context:    CTX_NONE,
            payload:    proofData,
          });
          await rnode.sendPacket(proofPacket);
        } catch (e) {
          log('info', `  Packet receipt send failed: ${e.message}`);
        }
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

// ---- Initiator-side link establishment ------------------------------

// Open an outbound Link to the given contact. Returns a Promise that
// resolves to the active Link once the LRPROOF has verified and the
// LRRTT has been emitted, or rejects with an Error on timeout or
// signature failure. The caller then uses link.encrypt to wrap
// payloads and routes them through sendViaLink.
async function openLinkToContact(contact, timeoutMs = 15000) {
  if (!radioOn) throw new Error('Radio not on');
  if (!contact || !contact.identity || !contact.identity.sigPubKey) {
    throw new Error('Contact has no known sig pub; need an announce first');
  }

  const { link, requestData } = Link.createInitiator(
    contact.identity.sigPubKey,
    contact.destHash,
  );

  const lrPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_SINGLE,
    packetType: PACKET_LINKREQ,
    destHash:   contact.destHash,
    context:    CTX_NONE,
    payload:    requestData,
  });

  // link_id is derived from the packed LINKREQUEST packet, so it
  // must be computed AFTER buildPacket. Feed the parsed version back
  // through computeLinkId so the bytes match exactly what the
  // responder will compute on its end.
  const parsedLR = parsePacket(lrPacket);
  await link.setLinkIdFromPacket(parsedLR);
  const linkIdHex = toHex(link.linkId);

  let resolve, reject;
  const promise = new Promise((res, rej) => { resolve = res; reject = rej; });

  const entry = {
    link,
    contact,
    resolve,
    reject,
    timer: setTimeout(() => {
      if (initiatorLinks.has(linkIdHex)) {
        initiatorLinks.delete(linkIdHex);
        log('err', `Link to "${contact.displayName}" timed out after ${timeoutMs}ms`);
        reject(new Error('Link establishment timeout'));
      }
    }, timeoutMs),
  };
  initiatorLinks.set(linkIdHex, entry);

  log('info', `Opening link to "${contact.displayName}" (link_id=${linkIdHex.substring(0,12)}...)`);
  try {
    await rnode.sendPacket(lrPacket);
  } catch (e) {
    clearTimeout(entry.timer);
    initiatorLinks.delete(linkIdHex);
    reject(e);
  }

  return promise;
}

// Handle an inbound LRPROOF that might belong to one of our pending
// initiator links. If the dest_hash matches an entry in our map,
// verify the proof and on success emit the LRRTT packet to transition
// the responder to ACTIVE on its side, then resolve the caller's
// promise with the active link.
async function handleInitiatorLinkProof(pkt) {
  const linkIdHex = toHex(pkt.destHash);
  const entry = initiatorLinks.get(linkIdHex);
  if (!entry) {
    // Not one of ours (responder-side LRPROOF addressed to someone
    // else's link, or an LRPROOF for a link we already torn down).
    return;
  }

  const result = await entry.link.validateProof(pkt);
  if (!result.ok) {
    log('err', `  LRPROOF rejected on link ${linkIdHex.substring(0,12)}...: ${result.reason}`);
    clearTimeout(entry.timer);
    initiatorLinks.delete(linkIdHex);
    entry.reject(new Error(result.reason));
    return;
  }

  log('ok', `  Link ${linkIdHex.substring(0,12)}... ACTIVE (rtt=${result.rtt.toFixed(3)}s)`);

  // Send the LRRTT packet back so the responder transitions its side
  // to ACTIVE. This is a DATA packet with context=LRRTT addressed to
  // the link_id, carrying the Token-encrypted msgpack of the rtt.
  const rttPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_LINK,
    packetType: PACKET_DATA,
    destHash:   entry.link.linkId,
    context:    CTX_LRRTT,
    payload:    result.rttData,
  });
  try {
    await rnode.sendPacket(rttPacket);
  } catch (e) {
    log('err', `  LRRTT send failed: ${e.message}`);
  }

  clearTimeout(entry.timer);
  initiatorLinks.delete(linkIdHex);
  // Keep the link itself reachable so sendViaLink can find it by id.
  links.set(linkIdHex, entry.link);

  entry.resolve(entry.link);
}

// Send a pre-packed LXMF container over an already-ACTIVE link.
// Returns the truncated packet hash suitable for matching a later
// delivery PROOF so the caller can update the outgoing message row.
async function sendViaLink(link, packedLxmf) {
  const encrypted = await link.encrypt(packedLxmf);
  const dataPacket = buildPacket({
    headerType: HEADER_1,
    destType:   DEST_LINK,
    packetType: PACKET_DATA,
    destHash:   link.linkId,
    context:    CTX_NONE,
    payload:    encrypted,
  });
  await rnode.sendPacket(dataPacket);

  // Compute the full 32-byte packet hash of what we just sent so a
  // subsequent link-delivery PROOF (which carries the packet hash
  // in its data, not in its dest slot) can be matched back to this
  // send. Truncated to 16 bytes because that's what our existing
  // outbound row stores for opportunistic matching.
  const parsed = parsePacket(dataPacket);
  const fullHash = await computePacketFullHash(parsed);
  return { packet: dataPacket, packetHash: fullHash };
}

// Match a link-delivered delivery PROOF back to an outbound row. The
// proof's dest_hash is the link_id, and data[0:32] is the original
// packet's full 32-byte hash. We store only the first 16 bytes on
// the row, so match on the prefix.
async function handleLinkDeliveryProof(pkt) {
  if (pkt.payload.length < 32) return;
  const packetHashPrefixHex = toHex(pkt.payload.subarray(0, 16));
  const rows = await getAllMessages();
  for (const row of rows) {
    if (row.direction !== 'outgoing') continue;
    if (row.packetHash !== packetHashPrefixHex) continue;
    if (row.state === MSG_STATE_DELIVERED) return;
    await updateMessage(row.id, { state: MSG_STATE_DELIVERED });
    const preview = (row.content || '').substring(0, 24);
    log('ok', `  Link delivery proof matched outbound "${preview}"`);
    if (activeContactHash === row.contactHash) {
      await renderMessages(activeContactHash);
    }
    return;
  }
}

// ---- Send message ----------------------------------------------------

async function sendMessage() {
  if (!activeContactHash) return;

  const content = $('msg-content').value.trim();
  if (!content) return;

  const contact = contacts.get(activeContactHash);
  if (!contact) { log('err', 'Contact not found'); return; }

  try {
    // Pack LXMF message. LXMF's source_hash field is the sender's
    // LXMF delivery *destination* hash, not the identity hash —
    // receivers key their contact table on destination hashes.
    const lxmfPayload = await packMessage(
      myIdentity, contact.destHash, myDestHash,
      '', content, {}
    );

    // Encrypt for recipient. Prefer their current ratchet pubkey
    // (learned from a ratchet-bearing announce) so the recipient's
    // forward-secrecy story benefits from our side too. Fall back
    // to the identity X25519 key if no ratchet is known.
    const recipientPub = contact.ratchetPub || contact.identity.encPubKey;
    const encrypted = await encrypt(lxmfPayload, recipientPub, contact.identity.hash);

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

    // Compute the truncated (16 B) packet hash so we can match any
    // delivery PROOF that comes back later. The dest_hash slot of a
    // non-link PROOF packet carries this truncated hash, so this is
    // the key we look up on.
    const packetHashHex = toHex(await computeOutboundPacketHashTruncated(packet));

    // Save a pending row before touching the radio so the message
    // is durable even if the send call throws or the user
    // reloads mid-transmission.
    const row = {
      contactHash: activeContactHash,
      direction: 'outgoing',
      content,
      title: '',
      timestamp: Date.now(),
      state: radioOn ? MSG_STATE_SENDING : MSG_STATE_PENDING,
      packetHash: packetHashHex,
      rawPacket: Array.from(packet),
      attempts: 0,
      nextRetryAt: 0,
    };
    const id = await saveMessage(row);

    $('msg-content').value = '';
    await renderMessages(activeContactHash);

    if (radioOn) {
      await doOutboundSend(id);
    } else {
      log('info', `Queued message to "${contact.displayName}" (radio off)`);
    }
  } catch (e) {
    log('err', `Send failed: ${e.message}`);
  }
}

// Compute the 16-byte truncated SHA-256 of the hashable part of a
// newly-built outbound packet. The dest_hash field of any inbound
// delivery PROOF for this packet will equal this value, so it is
// the key we store on the outgoing row and match on.
async function computeOutboundPacketHashTruncated(packet) {
  const flagsLow = packet[0] & 0x0F;
  // HEADER_1: skip flags + hops (2 bytes). HEADER_2 skips 18, but
  // every packet we originate is HEADER_1.
  const tail = packet.subarray(2);
  const hp = new Uint8Array(1 + tail.length);
  hp[0] = flagsLow;
  hp.set(tail, 1);
  const fullBuf = await crypto.subtle.digest('SHA-256', hp);
  return new Uint8Array(fullBuf).subarray(0, 16);
}

// Core outbound send/retry path. Reads the row from IndexedDB,
// transmits the stored rawPacket, and writes back the new state
// (sent + nextRetryAt on success, pending or failed on error).
// Invoked from sendMessage for a fresh row and from the retry tick
// for a row whose nextRetryAt has passed.
async function doOutboundSend(id) {
  const row = await getMessageById(id);
  if (!row) return;
  if (row.state === MSG_STATE_DELIVERED || row.state === MSG_STATE_FAILED) return;
  if (!row.rawPacket) return;   // legacy row without a packet — nothing to retransmit

  const contact = contacts.get(row.contactHash);
  const label = contact ? contact.displayName : row.contactHash.substring(0, 12);
  const attemptNumber = (row.attempts || 0) + 1;

  await updateMessage(id, { state: MSG_STATE_SENDING, attempts: attemptNumber });
  if (activeContactHash === row.contactHash) {
    await renderMessages(activeContactHash);
  }

  const packet = new Uint8Array(row.rawPacket);
  try {
    log('info', `Sending to "${label}"${attemptNumber > 1 ? ` (attempt ${attemptNumber})` : ''}...`);
    await rnode.sendPacket(packet);
    log('ok', `Sent ${packet.length}B to "${label}"`);

    const backoffIndex = Math.min(attemptNumber - 1, MSG_BACKOFF_MS.length - 1);
    await updateMessage(id, {
      state: MSG_STATE_SENT,
      nextRetryAt: Date.now() + MSG_BACKOFF_MS[backoffIndex],
      lastError: null,
    });
  } catch (e) {
    log('err', `Send failed: ${e.message}`);
    const isFinal = attemptNumber >= MSG_MAX_ATTEMPTS;
    const backoffIndex = Math.min(attemptNumber - 1, MSG_BACKOFF_MS.length - 1);
    await updateMessage(id, {
      state: isFinal ? MSG_STATE_FAILED : MSG_STATE_PENDING,
      nextRetryAt: isFinal ? 0 : Date.now() + MSG_BACKOFF_MS[backoffIndex],
      lastError: e.message,
    });
  }

  if (activeContactHash === row.contactHash) {
    await renderMessages(activeContactHash);
  }
}

// Walk every outgoing row and drive the state machine forward for
// anything that is overdue. Pending rows get a fresh send attempt
// now that the radio is up. Sent rows whose ack timeout has fired
// either retry or transition to failed. Terminal states are
// skipped. Runs on a setInterval that only lives while the radio
// is on.
async function outboundRetryTick() {
  if (!radioOn) return;
  const rows = await getAllMessages();
  const now = Date.now();

  for (const row of rows) {
    if (row.direction !== 'outgoing') continue;
    if (row.state === MSG_STATE_DELIVERED || row.state === MSG_STATE_FAILED) continue;

    if (row.state === MSG_STATE_PENDING && (row.attempts || 0) < MSG_MAX_ATTEMPTS) {
      await doOutboundSend(row.id);
      continue;
    }

    if (row.state === MSG_STATE_SENT && row.nextRetryAt && now >= row.nextRetryAt) {
      if ((row.attempts || 0) >= MSG_MAX_ATTEMPTS) {
        await updateMessage(row.id, { state: MSG_STATE_FAILED });
        if (activeContactHash === row.contactHash) {
          await renderMessages(activeContactHash);
        }
      } else {
        await doOutboundSend(row.id);
      }
    }
  }
}

// Match an inbound PROOF packet against outstanding outgoing rows.
// The packet's destination_hash is the 16-byte truncated hash of the
// original packet being acknowledged, so it lines up directly with
// the packetHash we stored on the row at send time. If a match is
// found, mark the row as delivered.
async function handleDeliveryProof(pkt) {
  const hashHex = toHex(pkt.destHash);
  const rows = await getAllMessages();
  for (const row of rows) {
    if (row.direction !== 'outgoing') continue;
    if (row.packetHash !== hashHex) continue;
    if (row.state === MSG_STATE_DELIVERED) return;
    await updateMessage(row.id, { state: MSG_STATE_DELIVERED });
    const preview = (row.content || '').substring(0, 24);
    log('ok', `  Delivery proof matched outbound "${preview}"`);
    if (activeContactHash === row.contactHash) {
      await renderMessages(activeContactHash);
    }
    return;
  }
}

// ---- Send announce ---------------------------------------------------

async function sendAnnounce() {
  if (!radioOn || !myIdentity) { log('err', 'Radio not on or identity not ready'); return; }

  const displayName = $('my-name').value.trim() || 'WebClient';
  // LXMF/Sideband format: msgpack([display_name_bytes, stamp_cost])
  const nameBytes = new TextEncoder().encode(displayName);
  const appData = new Uint8Array(msgpackEncode([nameBytes, 0]));

  const { destHash, payload, hasRatchet } = await buildAnnounce(
    myIdentity, 'lxmf.delivery', appData, myIdentity.ratchetPubKey
  );

  const packet = buildPacket({
    headerType: HEADER_1,
    // The context_flag bit of the header signals to receivers that
    // the payload contains a 32-byte ratchet pubkey between the
    // random hash and the signature. Must be 1 iff buildAnnounce
    // actually inserted a ratchet.
    contextFlag: hasRatchet ? 1 : 0,
    destType: DEST_SINGLE,
    packetType: PACKET_ANNOUNCE,
    destHash: destHash,
    context: 0x00,
    payload: payload,
  });

  await rnode.sendPacket(packet);
  log('ok', `Announce sent as "${displayName}" [${toHex(destHash).substring(0,12)}...]${hasRatchet ? ' (ratchet)' : ''}`);
}

// ---- UI rendering ----------------------------------------------------

function renderContactList() {
  const list = $('contact-list');
  if (contacts.size === 0) {
    list.innerHTML = '<li class="contact-empty">Listening for announces…</li>';
    return;
  }

  list.innerHTML = '';
  for (const [hash, c] of contacts) {
    const li = document.createElement('li');
    li.className = hash === activeContactHash ? 'active' : '';

    const unread = c.unreadCount ? ` <span class="contact-unread">${c.unreadCount}</span>` : '';
    const initials = initialsFor(c.displayName || hash);
    const shortHash = `${hash.substring(0, 8)}…${hash.substring(hash.length - 4)}`;
    const info = document.createElement('div');
    info.innerHTML = `
      <div class="contact-avatar">${escapeHtml(initials)}</div>
      <div style="flex:1; min-width:0">
        <div class="contact-name">${escapeHtml(c.displayName || hash.substring(0, 8))}${unread}</div>
        <div class="contact-hash">${shortHash}</div>
      </div>`;
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
  if (c) c.unreadCount = 0;
  $('conv-title').textContent = c ? c.displayName : hash.substring(0, 16);
  $('compose-area').classList.remove('hidden');
  renderContactList();
  await renderMessages(hash);
}

async function renderMessages(contactHash) {
  const list = $('message-list');
  const msgs = await getMessages(contactHash);

  if (msgs.length === 0) {
    list.innerHTML = '<div class="message-empty">No messages yet</div>';
    return;
  }

  // Sort by the IndexedDB auto-increment id, which is strictly the
  // order the rows were saved. Using the stored timestamp would put
  // any historical messages that were saved before the bogus-sender-
  // clock fix at the top of the list, because those rows hold
  // seconds-since-boot values from clockless LoRa senders that
  // resolve to Jan 1, 1970.
  const ordered = msgs.slice().sort((a, b) => (a.id || 0) - (b.id || 0));

  list.innerHTML = '';
  for (const msg of ordered) {
    const div = document.createElement('div');
    div.className = `message ${msg.direction}`;
    const ts = normalizeLxmfTimestamp(msg.timestamp);
    const time = ts != null ? formatMessageTime(ts) : '(no time)';
    const stateIcon = renderOutgoingStateIcon(msg);
    div.innerHTML = `<div>${escapeHtml(msg.content)}</div><div class="meta">${time}${stateIcon}</div>`;
    list.appendChild(div);
  }
  list.scrollTop = list.scrollHeight;
}

// Small state indicator for outgoing rows. Returns HTML that lives
// inline next to the timestamp in the message meta line. Incoming
// rows and legacy outgoing rows (saved before the retry queue
// landed, no `state` field) return an empty string.
function renderOutgoingStateIcon(msg) {
  if (msg.direction !== 'outgoing' || !msg.state) return '';
  const labels = {
    [MSG_STATE_PENDING]:   ['\u23F3', 'pending'],    // hourglass
    [MSG_STATE_SENDING]:   ['\u2191', 'sending'],    // up arrow
    [MSG_STATE_SENT]:      ['\u2713', 'sent'],        // single check
    [MSG_STATE_DELIVERED]: ['\u2713\u2713', 'delivered'],   // double check
    [MSG_STATE_FAILED]:    ['\u2717', 'failed'],      // cross
  };
  const entry = labels[msg.state];
  if (!entry) return '';
  const [glyph, cls] = entry;
  const title = msg.state === MSG_STATE_FAILED && msg.lastError
    ? ` title="${escapeHtml(msg.lastError)}"`
    : '';
  return ` <span class="message-state ${cls}"${title}>${glyph}</span>`;
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

// ---- DOM mirror helpers ---------------------------------------------
// Several pieces of state are shown in more than one place (sidebar,
// right panel, settings). Each helper here writes the canonical element
// by id and then fans out to any `.js-*` mirror elements in the DOM.

function initialsFor(name) {
  if (!name) return '??';
  const clean = String(name).trim();
  if (!clean) return '??';
  const parts = clean.split(/\s+/);
  if (parts.length >= 2 && parts[0][0] && parts[1][0]) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return clean.substring(0, 2).toUpperCase();
}

function setConnectionState(on, label) {
  const dot = $('conn-dot');
  if (dot) dot.classList.toggle('on', on);
  const text = $('conn-text');
  if (text) text.textContent = label;
  document.querySelectorAll('.js-conn-dot').forEach(el => el.classList.toggle('on', on));
  document.querySelectorAll('.js-conn-text').forEach(el => el.textContent = label);
}

function setRadioStatus(text, on) {
  const main = $('radio-status');
  if (main) {
    main.textContent = text;
    main.className = `js-radio-status ${on ? 'status-on' : 'status-muted'}`;
  }
  document.querySelectorAll('.js-radio-status').forEach(el => {
    if (el === main) return;
    el.textContent = text || '—';
    el.classList.toggle('status-on', !!on);
  });
}

function setMyAddress(hex) {
  const el = $('my-address');
  if (el) el.textContent = hex;
  const short = hex && hex.length > 12
    ? `${hex.substring(0, 6)}…${hex.substring(hex.length - 4)}`
    : (hex || '—');
  document.querySelectorAll('.js-address-short').forEach(el => { el.textContent = short; });
  updateAvatars();
}

function updateAvatars() {
  const name = ($('my-name')?.value || 'WebClient');
  const initials = initialsFor(name);
  ['my-avatar', 'my-avatar-rp'].forEach(id => {
    const el = $(id);
    if (el) el.textContent = initials;
  });
  ['my-name-display', 'my-name-display-rp'].forEach(id => {
    const el = $(id);
    if (el) el.textContent = name;
  });
}

// ---- View switching --------------------------------------------------

function switchView(name) {
  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  const target = document.querySelector(`.view-${name}`);
  if (target) target.classList.add('active');
  document.querySelectorAll('[data-view]').forEach(n => {
    n.classList.toggle('active', n.dataset.view === name);
  });
}

// ---- Theme -----------------------------------------------------------

const THEME_KEY = 'reticulum-theme';

function applyTheme(choice) {
  const effective = choice === 'system'
    ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
    : choice;
  document.documentElement.dataset.theme = effective;
  document.querySelectorAll('#theme-seg .seg-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.theme === choice);
  });
}

function setTheme(choice) {
  localStorage.setItem(THEME_KEY, choice);
  applyTheme(choice);
}

// ---- Event wiring ----------------------------------------------------

// Helpers: connect buttons live in three places (sidebar quick-connect,
// mobile hero, settings). Toggle them all at once by class so they
// stay in sync regardless of which one the user clicked.
function setConnectButtonsDisabled(disabled) {
  document.querySelectorAll('.js-connect-btn').forEach(b => { b.disabled = disabled; });
}
function setConnectButtonsHidden(hidden) {
  document.querySelectorAll('.js-connect-btn').forEach(b => {
    b.classList.toggle('hidden', hidden);
  });
}

// Connect
async function connect(transportType) {
  try {
    setConnectButtonsDisabled(true);

    // Pick the right interface based on transport type.
    //   'ble' / 'serial' → RNode-over-KISS (owns a radio)
    //   'ws'             → rnsd-over-HDLC (no radio, direct to a Reticulum daemon)
    if (transportType === 'ws') {
      const url = ($('ws-url').value || '').trim();
      if (!url) { log('err', 'WebSocket URL is empty'); return; }
      rnode = new RnsdInterface(url);
    } else {
      rnode = new RNode(transportType);
    }
    rnode._onLog = (msg) => log('info', msg);
    rnode._onPacket = onPacket;

    await rnode.connect();

    setConnectionState(true, `Connected (${transportType.toUpperCase()})`);
    $('btn-disconnect').classList.remove('hidden');
    setConnectButtonsHidden(true);
    $('ws-url-row').classList.add('hidden');

    // Interfaces with an RNode on the other side (BLE/Serial) need
    // the full detect/fw/battery/radio-config sequence. Interfaces
    // that talk directly to a Reticulum daemon via WebSocket skip
    // all of that — there is no radio to configure.
    const usesRnode = rnode.capabilities?.rnodeControl !== false;

    if (usesRnode) {
      const detected = await rnode.detect();
      if (!detected) { log('err', 'RNode detect failed'); return; }
      const fw = await rnode.getFirmwareVersion();
      const battery = await rnode.getBattery();
      log('ok', `RNode FW ${fw?.major}.${fw?.minor}, Bat ${battery}%`);
      await startRadio();
    } else {
      // WebSocket path: no radio config, no detect, no battery.
      // Go straight to the "ready for messaging" state that
      // startRadio would have reached for the RNode path.
      log('ok', `Connected to Reticulum network via WebSocket`);
      markInterfaceReady();
    }
  } catch (e) {
    log('err', 'Connect: ' + e.message);
  } finally {
    setConnectButtonsDisabled(false);
  }
}

// Flip the "we are ready to send and receive" bit, fire the startup
// auto-announce, start the periodic announce timer, and start the
// outbound retry tick. Called from both the RNode path (after
// startRadio reports the radio is on) and the WebSocket path (after
// the socket is up — there is no radio to wait for).
function markInterfaceReady() {
  radioOn = true;
  setRadioStatus('Ready', true);
  sendAnnounce().catch(e => log('info', `Startup announce skipped: ${e.message}`));
  if (announceTimer) clearInterval(announceTimer);
  announceTimer = setInterval(() => {
    if (radioOn) {
      sendAnnounce().catch(e => log('info', `Periodic announce skipped: ${e.message}`));
    }
  }, 5 * 60 * 1000);
  if (outboundRetryTimer) clearInterval(outboundRetryTimer);
  outboundRetryTimer = setInterval(() => {
    outboundRetryTick().catch(e => log('info', `Retry tick error: ${e.message}`));
  }, MSG_RETRY_TICK_MS);
  outboundRetryTick().catch(e => log('info', `Retry tick error: ${e.message}`));
}

// Wire every connect button (sidebar quick-connect, mobile hero,
// settings) through a single listener keyed on data-transport.
document.querySelectorAll('.js-connect-btn').forEach(b => {
  b.addEventListener('click', () => connect(b.dataset.transport));
});

$('btn-disconnect').addEventListener('click', async () => {
  if (announceTimer) { clearInterval(announceTimer); announceTimer = null; }
  if (outboundRetryTimer) { clearInterval(outboundRetryTimer); outboundRetryTimer = null; }
  await rnode.disconnect();
  setConnectionState(false, 'Disconnected');
  $('btn-disconnect').classList.add('hidden');
  setConnectButtonsHidden(false);
  $('ws-url-row').classList.remove('hidden');
  radioOn = false;
  setRadioStatus('', false);
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
    setRadioStatus(on ? 'Radio: ON' : '', on);
    if (on) {
      log('ok', 'Radio on');
      markInterfaceReady();
    } else {
      radioOn = false;
    }
  } catch (e) { log('err', 'Radio: ' + e.message); }
}

$('btn-start-radio').addEventListener('click', startRadio);
$('btn-stop-radio').addEventListener('click', async () => {
  await rnode.setRadioState(false);
  radioOn = false;
  setRadioStatus('Radio: OFF', false);
});

// Identity
$('btn-announce').addEventListener('click', sendAnnounce);
$('btn-new-id').addEventListener('click', async () => {
  if (!confirm('Generate new identity? Your current address will change.')) return;
  myIdentity = new Identity();
  await myIdentity.generate();
  await saveIdentity(myIdentity.exportPrivateKeys());
  myDestHash = await computeDestinationHash('lxmf.delivery', myIdentity.hash);
  setMyAddress(toHex(myDestHash));
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

// Nodes panel — clear all forgets every stored non-LXMF announce.
// Fresh announces repopulate the list automatically.
$('btn-clear-nodes').addEventListener('click', async () => {
  if (!confirm('Forget all stored non-LXMF node announces?')) return;
  await deleteAllNodes();
  renderNodesList();
  log('info', 'Cleared all nodes');
});

// Browser check — disable buttons for unsupported transports. Every
// connect surface (sidebar, mobile hero, settings) is selected by
// data-transport, so all of them get disabled together.
function disableTransport(name, label) {
  document.querySelectorAll(`[data-transport="${name}"]`).forEach(b => {
    b.disabled = true;
    if (b.id) b.textContent = label;  // only the settings button has the long label
  });
}
if (!navigator.bluetooth) disableTransport('ble', 'Connect (BLE — not supported)');
if (!navigator.serial) disableTransport('serial', 'Connect (Serial — not supported)');
if (typeof WebSocket === 'undefined') disableTransport('ws', 'Connect (WebSocket — not supported)');
if (!navigator.bluetooth && !navigator.serial && typeof WebSocket === 'undefined') {
  $('unsupported').classList.remove('hidden');
}

// ---- View / theme / misc UI wiring ----------------------------------

// Sidebar nav + mobile bottom-nav: both carry data-view="messages|nodes|settings"
document.querySelectorAll('[data-view]').forEach(n => {
  n.addEventListener('click', () => switchView(n.dataset.view));
});

// Mobile back button clears the active contact so the list re-appears.
$('btn-back')?.addEventListener('click', () => {
  activeContactHash = null;
  $('conv-title').textContent = 'Select a contact';
  $('compose-area').classList.add('hidden');
  $('message-list').innerHTML = '';
  renderContactList();
});

// Reflect display-name edits into avatars and sidebar/right panel labels.
$('my-name')?.addEventListener('input', updateAvatars);

// Theme: stored choice in localStorage, 'system' follows OS preference.
const storedTheme = localStorage.getItem(THEME_KEY) || 'system';
applyTheme(storedTheme);
document.querySelectorAll('#theme-seg .seg-btn').forEach(b => {
  b.addEventListener('click', () => setTheme(b.dataset.theme));
});
$('theme-toggle')?.addEventListener('click', () => {
  const current = document.documentElement.dataset.theme;
  setTheme(current === 'dark' ? 'light' : 'dark');
});
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if ((localStorage.getItem(THEME_KEY) || 'system') === 'system') applyTheme('system');
});

// ---- Init ------------------------------------------------------------
updateAvatars();
initIdentity().catch(e => log('err', 'Identity init: ' + e.message));
