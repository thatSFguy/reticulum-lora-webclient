// js/store.js — IndexedDB storage for identity, contacts, and messages.

'use strict';

const DB_NAME = 'reticulum-webclient';
const DB_VERSION = 1;

let db = null;

export async function openDatabase() {
  if (db) return db;

  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);

    req.onupgradeneeded = (event) => {
      const db = event.target.result;

      // Identity store (single row — our keypair)
      if (!db.objectStoreNames.contains('identity')) {
        db.createObjectStore('identity', { keyPath: 'id' });
      }

      // Contacts (discovered identities from announces)
      if (!db.objectStoreNames.contains('contacts')) {
        const store = db.createObjectStore('contacts', { keyPath: 'hash' });
        store.createIndex('name', 'displayName', { unique: false });
      }

      // Messages (LXMF messages)
      if (!db.objectStoreNames.contains('messages')) {
        const store = db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
        store.createIndex('contact', 'contactHash', { unique: false });
        store.createIndex('timestamp', 'timestamp', { unique: false });
      }
    };

    req.onsuccess = (event) => {
      db = event.target.result;
      resolve(db);
    };

    req.onerror = () => reject(req.error);
  });
}

// ---- Identity --------------------------------------------------------

export async function saveIdentity(identityData) {
  const d = await openDatabase();
  const tx = d.transaction('identity', 'readwrite');
  tx.objectStore('identity').put({ id: 'self', ...identityData });
  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

export async function loadIdentity() {
  const d = await openDatabase();
  const tx = d.transaction('identity', 'readonly');
  const req = tx.objectStore('identity').get('self');
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

// ---- Contacts --------------------------------------------------------

export async function saveContact(contact) {
  const d = await openDatabase();
  const tx = d.transaction('contacts', 'readwrite');
  tx.objectStore('contacts').put(contact);
  return new Promise((resolve, reject) => {
    tx.oncomplete = resolve;
    tx.onerror = () => reject(tx.error);
  });
}

export async function getContact(hash) {
  const d = await openDatabase();
  const tx = d.transaction('contacts', 'readonly');
  const req = tx.objectStore('contacts').get(hash);
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}

export async function getAllContacts() {
  const d = await openDatabase();
  const tx = d.transaction('contacts', 'readonly');
  const req = tx.objectStore('contacts').getAll();
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// ---- Messages --------------------------------------------------------

export async function saveMessage(message) {
  const d = await openDatabase();
  const tx = d.transaction('messages', 'readwrite');
  const req = tx.objectStore('messages').add(message);
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);  // returns auto-generated id
    req.onerror = () => reject(tx.error);
  });
}

export async function getMessages(contactHash) {
  const d = await openDatabase();
  const tx = d.transaction('messages', 'readonly');
  const index = tx.objectStore('messages').index('contact');
  const req = index.getAll(contactHash);
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function getAllMessages() {
  const d = await openDatabase();
  const tx = d.transaction('messages', 'readonly');
  const req = tx.objectStore('messages').getAll();
  return new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
