import { openRaw, packEnvelope, sealRaw, unpackEnvelope } from "./aead.ts";
import { SHARE_SALT_BYTES, shareAad } from "./aad.ts";
import {
  argon2idBytes,
  type Argon2Params,
} from "./argon2.ts";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  randomBytes,
  toArrayBuffer,
  utf8,
} from "./bytes.ts";

export const SHARE_CODE_LENGTH = 14;
export const SHARE_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
export const FRAGMENT_SECRET_BYTES = 32;

const SHARE_AUTH_INFO = "ghostbin/share-auth/v1|";
const SHARE_WRAP_INFO = "ghostbin/share-wrap/v1|";
const KEY_BYTES = 32;
const AES_KEY_BITS = 256;

export class ShareCodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ShareCodeError";
  }
}

export function generateShareCode(): string {
  const bytes = randomBytes(SHARE_CODE_LENGTH);
  let code = "";
  for (let i = 0; i < bytes.length; i++) {
    code += SHARE_CODE_ALPHABET[bytes[i] % SHARE_CODE_ALPHABET.length];
  }
  return code;
}

export function normalizeShareCode(input: string): string {
  const normalized = input.toUpperCase().replace(/[\s-]+/g, "");
  if (normalized.length !== SHARE_CODE_LENGTH) {
    throw new ShareCodeError("Share code must be 14 characters");
  }
  for (const char of normalized) {
    if (!SHARE_CODE_ALPHABET.includes(char)) {
      throw new ShareCodeError("Share code contains an invalid character");
    }
  }
  return normalized;
}

export function isShareCode(input: string): boolean {
  try {
    normalizeShareCode(input);
    return true;
  } catch {
    return false;
  }
}

export function generateShareSalt(): Uint8Array {
  return randomBytes(SHARE_SALT_BYTES);
}

export function generateFragmentSecret(): Uint8Array {
  return randomBytes(FRAGMENT_SECRET_BYTES);
}

export function encodeFragmentSecret(secret: Uint8Array): string {
  if (secret.byteLength !== FRAGMENT_SECRET_BYTES) {
    throw new Error("Fragment secret must be 32 bytes");
  }
  return bytesToBase64Url(secret);
}

export function decodeFragmentSecret(encoded: string): Uint8Array {
  const secret = base64UrlToBytes(encoded);
  if (secret.byteLength !== FRAGMENT_SECRET_BYTES) {
    throw new Error("Fragment secret must be 32 bytes");
  }
  return secret;
}

function assertShareSalt(shareSalt: Uint8Array): void {
  if (shareSalt.byteLength !== SHARE_SALT_BYTES) {
    throw new Error("Share salt must be 16 bytes");
  }
}

function assertFragmentSecret(fragmentSecret: Uint8Array): void {
  if (fragmentSecret.byteLength !== FRAGMENT_SECRET_BYTES) {
    throw new Error("Fragment secret must be 32 bytes");
  }
}

async function deriveHkdfBits(
  ikm: Uint8Array,
  shareSalt: Uint8Array,
  info: string,
): Promise<Uint8Array> {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(ikm),
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(shareSalt),
      info: toArrayBuffer(utf8(info)),
    },
    hkdfKey,
    AES_KEY_BITS,
  );
  return new Uint8Array(bits);
}

async function deriveHkdfAesKey(
  ikm: Uint8Array,
  shareSalt: Uint8Array,
  info: string,
): Promise<CryptoKey> {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(ikm),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: toArrayBuffer(shareSalt),
      info: toArrayBuffer(utf8(info)),
    },
    hkdfKey,
    { name: "AES-GCM", length: AES_KEY_BITS },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function deriveShareCodeKey(
  code: string,
  shareSalt: Uint8Array,
  params: Partial<Argon2Params> = {},
): Promise<Uint8Array> {
  assertShareSalt(shareSalt);
  return argon2idBytes(utf8(normalizeShareCode(code)), shareSalt, params);
}

export async function deriveShareAuthKey(
  codeKey: Uint8Array,
  shareSalt: Uint8Array,
  fragmentSecret: Uint8Array,
): Promise<Uint8Array> {
  if (codeKey.byteLength !== KEY_BYTES) {
    throw new Error("Share code key must be 32 bytes");
  }
  assertShareSalt(shareSalt);
  assertFragmentSecret(fragmentSecret);
  return deriveHkdfBits(
    codeKey,
    shareSalt,
    SHARE_AUTH_INFO + encodeFragmentSecret(fragmentSecret),
  );
}

export async function deriveShareWrapKey(
  codeKey: Uint8Array,
  shareSalt: Uint8Array,
  fragmentSecret: Uint8Array,
): Promise<CryptoKey> {
  if (codeKey.byteLength !== KEY_BYTES) {
    throw new Error("Share code key must be 32 bytes");
  }
  assertShareSalt(shareSalt);
  assertFragmentSecret(fragmentSecret);
  return deriveHkdfAesKey(
    codeKey,
    shareSalt,
    SHARE_WRAP_INFO + encodeFragmentSecret(fragmentSecret),
  );
}

export async function deriveShareKeys(
  code: string,
  shareSalt: Uint8Array,
  fragmentSecret: Uint8Array,
  params: Partial<Argon2Params> = {},
): Promise<{
  codeKey: Uint8Array;
  authKey: Uint8Array;
  wrapKey: CryptoKey;
}> {
  const codeKey = await deriveShareCodeKey(code, shareSalt, params);
  return {
    codeKey,
    authKey: await deriveShareAuthKey(codeKey, shareSalt, fragmentSecret),
    wrapKey: await deriveShareWrapKey(codeKey, shareSalt, fragmentSecret),
  };
}

export async function wrapPasteKeyForShare(
  wrapKey: CryptoKey,
  pasteKey: Uint8Array,
  pasteId: string,
  shareSalt: Uint8Array,
): Promise<string> {
  if (pasteKey.byteLength !== KEY_BYTES) {
    throw new Error("Paste key must be 32 bytes");
  }
  return packEnvelope(
    await sealRaw(wrapKey, pasteKey, shareAad(pasteId, shareSalt)),
  );
}

export async function unwrapPasteKeyFromShare(
  wrapKey: CryptoKey,
  envelope: string,
  pasteId: string,
  shareSalt: Uint8Array,
): Promise<Uint8Array> {
  const pasteKey = await openRaw(
    wrapKey,
    unpackEnvelope(envelope),
    shareAad(pasteId, shareSalt),
  );
  if (pasteKey.byteLength !== KEY_BYTES) {
    throw new Error("Unwrapped paste key must be 32 bytes");
  }
  return pasteKey;
}

export async function deriveShareProof(
  authKey: Uint8Array,
  nonce: string,
  pasteId: string,
): Promise<Uint8Array> {
  if (authKey.byteLength !== KEY_BYTES) {
    throw new Error("Share auth key must be 32 bytes");
  }
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(authKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const proof = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    toArrayBuffer(utf8(`${nonce}|${pasteId}`)),
  );
  return new Uint8Array(proof);
}
