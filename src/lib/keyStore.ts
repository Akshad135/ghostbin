/**
 * Local persistence for the non-extractable vault key.
 *
 * The vault key is stored as a `CryptoKey` handle in IndexedDB. Browsers
 * structured-clone CryptoKey handles, so it survives reloads without the raw
 * bytes leaving the WebCrypto boundary. The key is imported with
 * `extractable = false`, which means JavaScript can use it to derive paste
 * keys but cannot export the raw vault key.
 *
 * This is an opt-in convenience cache. Alongside the handle the store keeps:
 * - a canary: an HMAC (keyed by a key derived from the handle itself) over a
 *   fixed label. On load the canary is recomputed; a mismatch means the
 *   record is corrupt or tampered with, and it is discarded.
 * - a stamp: a hash of the server's current wrapped vault key envelope. The
 *   envelope changes whenever the vault is re-wrapped (passphrase change,
 *   reset, new setup), so a stale cached key from an older vault is rejected
 *   and the user must derive the key from the passphrase again.
 *
 * If IndexedDB is unavailable, the user must enter the passphrase again after
 * a reload.
 */

import { vaultCanary } from "./e2ee/index.ts";

const DB_NAME = "ghostbin-vault-keys";
const DB_VERSION = 1;
const STORE_NAME = "keys";
const KEY_ID = "vault";

interface StoredVaultKey {
  key: CryptoKey;
  canary: string;
  stamp: string;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () =>
      reject(request.error ?? new Error("Failed to open key store"));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () =>
      reject(transaction.error ?? new Error("Key store transaction failed"));
    transaction.onabort = () =>
      reject(transaction.error ?? new Error("Key store transaction aborted"));
  });
}

function isUsableVaultKey(value: unknown): value is CryptoKey {
  return (
    value instanceof CryptoKey &&
    value.type === "secret" &&
    !value.extractable &&
    value.algorithm.name === "HKDF"
  );
}

function isStoredVaultKey(value: unknown): value is StoredVaultKey {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const record = value as Record<string, unknown>;
  return (
    isUsableVaultKey(record.key) &&
    typeof record.canary === "string" &&
    record.canary.length > 0 &&
    typeof record.stamp === "string" &&
    record.stamp.length > 0
  );
}

export async function saveVaultKey(
  key: CryptoKey,
  stamp: string,
): Promise<void> {
  if (key.extractable) {
    throw new Error("Refusing to persist an extractable vault key");
  }
  const record: StoredVaultKey = {
    key,
    canary: await vaultCanary(key),
    stamp,
  };
  const db = await openDB();
  try {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(record, KEY_ID);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}

export async function loadVaultKey(
  expectedStamp: string,
): Promise<CryptoKey | null> {
  const db = await openDB();
  let record: unknown;
  try {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(KEY_ID);
    record = await new Promise<unknown>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("Failed to read key store"));
    });
    await transactionDone(transaction);
  } finally {
    db.close();
  }

  const discard = async (): Promise<null> => {
    await clearVaultKey();
    return null;
  };

  if (!isStoredVaultKey(record)) {
    // An unusable record is worthless; drop it so it cannot linger.
    return record === undefined ? null : discard();
  }

  // The canary must match the handle it was stored with. A mismatch means
  // the record is corrupt or was modified.
  const canary = await vaultCanary(record.key);
  if (canary !== record.canary) {
    return discard();
  }

  // The stamp must match the vault the server currently holds. A mismatch
  // means the vault was re-wrapped or reset after this key was cached.
  if (record.stamp !== expectedStamp) {
    return discard();
  }

  return record.key;
}

/**
 * Refresh the stamp of an existing cached record. Does nothing when no
 * record is cached, so a device that never opted in stays that way.
 */
export async function refreshVaultKeyStamp(
  key: CryptoKey,
  stamp: string,
): Promise<boolean> {
  const db = await openDB();
  let existing: unknown;
  try {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const request = transaction.objectStore(STORE_NAME).get(KEY_ID);
    existing = await new Promise<unknown>((resolve, reject) => {
      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(request.error ?? new Error("Failed to read key store"));
    });
    await transactionDone(transaction);
  } finally {
    db.close();
  }

  if (existing === undefined) {
    return false;
  }

  const record: StoredVaultKey = {
    key,
    canary: await vaultCanary(key),
    stamp,
  };
  const writeDb = await openDB();
  try {
    const transaction = writeDb.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).put(record, KEY_ID);
    await transactionDone(transaction);
  } finally {
    writeDb.close();
  }
  return true;
}

export async function clearVaultKey(): Promise<void> {
  const db = await openDB();
  try {
    const transaction = db.transaction(STORE_NAME, "readwrite");
    transaction.objectStore(STORE_NAME).delete(KEY_ID);
    await transactionDone(transaction);
  } finally {
    db.close();
  }
}
