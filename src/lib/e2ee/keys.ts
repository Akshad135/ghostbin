import { openRaw, packEnvelope, sealRaw, unpackEnvelope } from "./aead.ts";
import { VAULT_AAD } from "./aad.ts";
import {
  bytesToBase64Url,
  randomBytes,
  toArrayBuffer,
  utf8,
} from "./bytes.ts";
import { PASTE_ID_BYTES } from "./aad.ts";

const HKDF_HASH = "SHA-256";
const AES_KEY_BITS = 256;
const KEY_BYTES = 32;
const KEY_SALT_BYTES = 16;
const FILE_ID_BYTES = 16;

const AUTH_INFO = "ghostbin/auth/v1";
const MASTER_INFO = "ghostbin/enc/v1";
const PASTE_INFO = "ghostbin/paste/v1|";

async function importHkdfKey(
  bytes: Uint8Array,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(bytes),
    "HKDF",
    false,
    usages,
  );
}

export async function deriveAuthKey(root: Uint8Array): Promise<Uint8Array> {
  if (root.byteLength !== KEY_BYTES) {
    throw new Error("deriveAuthKey: root must be 32 bytes");
  }
  const hkdfKey = await importHkdfKey(root, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: HKDF_HASH,
      salt: toArrayBuffer(new Uint8Array(0)),
      info: toArrayBuffer(utf8(AUTH_INFO)),
    },
    hkdfKey,
    AES_KEY_BITS,
  );
  return new Uint8Array(bits);
}

export async function deriveMasterKey(root: Uint8Array): Promise<CryptoKey> {
  if (root.byteLength !== KEY_BYTES) {
    throw new Error("deriveMasterKey: root must be 32 bytes");
  }
  const hkdfKey = await importHkdfKey(root, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: HKDF_HASH,
      salt: toArrayBuffer(new Uint8Array(0)),
      info: toArrayBuffer(utf8(MASTER_INFO)),
    },
    hkdfKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

export function generateVaultKey(): Uint8Array {
  return randomBytes(KEY_BYTES);
}

export async function wrapVaultKey(
  masterKey: CryptoKey,
  vaultKey: Uint8Array,
): Promise<string> {
  if (vaultKey.byteLength !== KEY_BYTES) {
    throw new Error("wrapVaultKey: vault key must be 32 bytes");
  }
  return packEnvelope(await sealRaw(masterKey, vaultKey, VAULT_AAD));
}

export async function unwrapVaultKey(
  masterKey: CryptoKey,
  envelope: string,
): Promise<Uint8Array> {
  const vaultKey = await openRaw(masterKey, unpackEnvelope(envelope), VAULT_AAD);
  if (vaultKey.byteLength !== KEY_BYTES) {
    throw new Error("unwrapVaultKey: invalid vault key length");
  }
  return vaultKey;
}

export async function importVaultKey(
  vaultKey: Uint8Array,
): Promise<CryptoKey> {
  if (vaultKey.byteLength !== KEY_BYTES) {
    throw new Error("importVaultKey: vault key must be 32 bytes");
  }
  return importHkdfKey(vaultKey, ["deriveBits"]);
}

export async function derivePasteKeyBytes(
  vaultKey: CryptoKey,
  keySalt: Uint8Array,
  pasteId: string,
): Promise<Uint8Array> {
  if (keySalt.byteLength !== KEY_SALT_BYTES) {
    throw new Error("derivePasteKeyBytes: key salt must be 16 bytes");
  }
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: HKDF_HASH,
      salt: toArrayBuffer(keySalt),
      info: toArrayBuffer(utf8(PASTE_INFO + pasteId)),
    },
    vaultKey,
    AES_KEY_BITS,
  );
  return new Uint8Array(bits);
}

export async function importPasteKey(
  pasteKey: Uint8Array,
): Promise<CryptoKey> {
  if (pasteKey.byteLength !== KEY_BYTES) {
    throw new Error("importPasteKey: paste key must be 32 bytes");
  }
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(pasteKey),
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function derivePasteKey(
  vaultKey: CryptoKey,
  keySalt: Uint8Array,
  pasteId: string,
): Promise<CryptoKey> {
  return importPasteKey(await derivePasteKeyBytes(vaultKey, keySalt, pasteId));
}

export function generatePasteId(): string {
  return bytesToBase64Url(randomBytes(PASTE_ID_BYTES));
}

export function generateFileId(): string {
  return bytesToBase64Url(randomBytes(FILE_ID_BYTES));
}

export function generateKeySalt(): Uint8Array {
  return randomBytes(KEY_SALT_BYTES);
}
