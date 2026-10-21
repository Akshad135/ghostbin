import {
  bytesToBase64Url,
  base64UrlToBytes,
  concatBytes,
  fromUtf8,
  randomBytes,
  toArrayBuffer,
  utf8,
} from "./bytes.ts";

export const ENVELOPE_VERSION = "v1";
export const IV_LENGTH = 12;
export const TAG_LENGTH = 16;

export type Aad = string | Uint8Array;

function aadToBytes(aad?: Aad): Uint8Array | undefined {
  if (aad === undefined) return undefined;
  return typeof aad === "string" ? utf8(aad) : aad;
}

export async function sealRaw(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad?: Aad,
): Promise<Uint8Array> {
  const iv = randomBytes(IV_LENGTH);
  const additionalData = aadToBytes(aad);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: additionalData
        ? toArrayBuffer(additionalData)
        : undefined,
      tagLength: TAG_LENGTH * 8,
    },
    key,
    toArrayBuffer(plaintext),
  );
  return concatBytes(iv, new Uint8Array(ciphertext));
}

export async function openRaw(
  key: CryptoKey,
  sealed: Uint8Array,
  aad?: Aad,
): Promise<Uint8Array> {
  if (sealed.byteLength < IV_LENGTH + TAG_LENGTH) {
    throw new Error("AEAD: ciphertext is too short");
  }

  const iv = sealed.slice(0, IV_LENGTH);
  const ciphertext = sealed.slice(IV_LENGTH);
  const additionalData = aadToBytes(aad);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: toArrayBuffer(iv),
      additionalData: additionalData
        ? toArrayBuffer(additionalData)
        : undefined,
      tagLength: TAG_LENGTH * 8,
    },
    key,
    toArrayBuffer(ciphertext),
  );
  return new Uint8Array(plaintext);
}

export function packEnvelope(sealed: Uint8Array): string {
  return `${ENVELOPE_VERSION}:${bytesToBase64Url(sealed)}`;
}

export function unpackEnvelope(envelope: string): Uint8Array {
  const prefix = `${ENVELOPE_VERSION}:`;
  if (!envelope.startsWith(prefix)) {
    throw new Error("AEAD: unsupported envelope version");
  }
  return base64UrlToBytes(envelope.slice(prefix.length));
}

export async function sealText(
  key: CryptoKey,
  plaintext: string,
  aad?: Aad,
): Promise<string> {
  return packEnvelope(await sealRaw(key, utf8(plaintext), aad));
}

export async function openText(
  key: CryptoKey,
  envelope: string,
  aad?: Aad,
): Promise<string> {
  return fromUtf8(await openRaw(key, unpackEnvelope(envelope), aad));
}
