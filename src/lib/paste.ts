import {
  base64UrlToBytes,
  bytesToBase64Url,
  derivePasteKey,
  derivePasteKeyBytes,
  fileChunkAad,
  fileMetaAad,
  generateFileId,
  importPasteKey,
  openRaw,
  openText,
  pasteFieldAad,
  sealRaw,
  sealText,
} from "./e2ee/index.ts";
import type { FileMeta, GuestPaste, PasteDetail, PasteSummary } from "./api";

export interface PasteFields {
  title: string;
  content: string;
  language: string;
}

export interface AttachmentSource {
  name: string;
  mime: string;
  bytes: Uint8Array;
}

export interface AttachmentMeta {
  name: string;
  mime: string;
  /** Plaintext byte length. */
  size: number;
}

export interface EncryptedAttachment {
  fileId: string;
  encrypted: Uint8Array;
  encMeta: string;
  meta: AttachmentMeta;
}

const MAX_FILE_NAME_LENGTH = 255;
const MAX_MIME_LENGTH = 255;

function decodeKeySalt(keySalt: string): Uint8Array {
  const salt = base64UrlToBytes(keySalt);
  if (salt.byteLength !== 16) {
    throw new Error("Invalid paste key salt");
  }
  return salt;
}

export function pasteKeyForSummary(
  vaultKey: CryptoKey,
  paste: Pick<PasteSummary, "id" | "keySalt">,
): Promise<CryptoKey> {
  return derivePasteKey(vaultKey, decodeKeySalt(paste.keySalt), paste.id);
}

export function pasteKeyBytesForSummary(
  vaultKey: CryptoKey,
  paste: Pick<PasteSummary, "id" | "keySalt">,
): Promise<Uint8Array> {
  return derivePasteKeyBytes(
    vaultKey,
    decodeKeySalt(paste.keySalt),
    paste.id,
  );
}

export async function encryptPasteFields(
  pasteKey: CryptoKey,
  pasteId: string,
  fields: PasteFields,
): Promise<{ titleCt: string; contentCt: string; languageCt: string }> {
  const [titleCt, contentCt, languageCt] = await Promise.all([
    sealText(pasteKey, fields.title, pasteFieldAad(pasteId, "title")),
    sealText(pasteKey, fields.content, pasteFieldAad(pasteId, "content")),
    sealText(pasteKey, fields.language, pasteFieldAad(pasteId, "language")),
  ]);
  return { titleCt, contentCt, languageCt };
}

export async function decryptPasteWithKey(
  pasteKey: CryptoKey,
  paste: Pick<PasteSummary, "id" | "titleCt" | "languageCt"> & {
    contentCt: string;
  },
): Promise<PasteFields> {
  const [title, content, language] = await Promise.all([
    openText(pasteKey, paste.titleCt, pasteFieldAad(paste.id, "title")),
    openText(pasteKey, paste.contentCt, pasteFieldAad(paste.id, "content")),
    paste.languageCt
      ? openText(
          pasteKey,
          paste.languageCt,
          pasteFieldAad(paste.id, "language"),
        )
      : Promise.resolve("plaintext"),
  ]);
  return { title, content, language };
}

export function decryptPasteDetail(
  vaultKey: CryptoKey,
  paste: PasteDetail,
): Promise<PasteFields> {
  return pasteKeyForSummary(vaultKey, paste).then((key) =>
    decryptPasteWithKey(key, paste),
  );
}

export async function decryptPasteTitleAndLanguage(
  vaultKey: CryptoKey,
  paste: Pick<PasteSummary, "id" | "keySalt" | "titleCt" | "languageCt">,
): Promise<{ title: string; language: string }> {
  const key = await pasteKeyForSummary(vaultKey, paste);
  const [title, language] = await Promise.all([
    openText(key, paste.titleCt, pasteFieldAad(paste.id, "title")),
    paste.languageCt
      ? openText(
          key,
          paste.languageCt,
          pasteFieldAad(paste.id, "language"),
        )
      : Promise.resolve("plaintext"),
  ]);
  return { title, language };
}

export function decryptGuestPaste(
  pasteKey: CryptoKey,
  paste: GuestPaste,
): Promise<PasteFields> {
  return decryptPasteWithKey(pasteKey, paste);
}

function encodeFileMeta(meta: AttachmentMeta): string {
  return JSON.stringify(meta);
}

function parseFileMeta(raw: string): AttachmentMeta {
  const parsed: unknown = JSON.parse(raw);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("Invalid attachment metadata");
  }
  const value = parsed as Record<string, unknown>;
  if (
    typeof value.name !== "string" ||
    typeof value.mime !== "string" ||
    !Number.isInteger(value.size) ||
    (value.size as number) < 0
  ) {
    throw new Error("Invalid attachment metadata");
  }
  return {
    name: value.name,
    mime: value.mime,
    size: value.size as number,
  };
}

function validateAttachmentMeta(meta: AttachmentMeta): void {
  if (!meta.name || meta.name.length > MAX_FILE_NAME_LENGTH) {
    throw new Error("Attachment name is too long");
  }
  if (meta.mime.length > MAX_MIME_LENGTH) {
    throw new Error("Attachment type is too long");
  }
  if (
    !Number.isInteger(meta.size) ||
    meta.size < 0 ||
    !Number.isSafeInteger(meta.size)
  ) {
    throw new Error("Invalid attachment size");
  }
}

function fileContentAad(pasteId: string, fileId: string): string {
  return fileChunkAad(pasteId, fileId, 0, 1, true);
}

export async function encryptAttachment(
  pasteKey: CryptoKey,
  pasteId: string,
  fileId: string,
  source: AttachmentSource,
): Promise<EncryptedAttachment> {
  const meta: AttachmentMeta = {
    name: source.name,
    mime: source.mime || "application/octet-stream",
    size: source.bytes.byteLength,
  };
  validateAttachmentMeta(meta);

  const [encMeta, encrypted] = await Promise.all([
    sealText(
      pasteKey,
      encodeFileMeta(meta),
      fileMetaAad(pasteId, fileId),
    ),
    sealRaw(
      pasteKey,
      source.bytes,
      fileContentAad(pasteId, fileId),
    ),
  ]);

  return { fileId, encrypted, encMeta, meta };
}

export async function encryptNewAttachment(
  pasteKey: CryptoKey,
  pasteId: string,
  source: AttachmentSource,
): Promise<EncryptedAttachment> {
  return encryptAttachment(pasteKey, pasteId, generateFileId(), source);
}

export async function decryptAttachmentMeta(
  pasteKey: CryptoKey,
  pasteId: string,
  file: Pick<FileMeta, "id" | "encMeta">,
): Promise<AttachmentMeta> {
  const raw = await openText(
    pasteKey,
    file.encMeta,
    fileMetaAad(pasteId, file.id),
  );
  const meta = parseFileMeta(raw);
  validateAttachmentMeta(meta);
  return meta;
}

export async function decryptAttachmentBytes(
  pasteKey: CryptoKey,
  pasteId: string,
  fileId: string,
  encrypted: Uint8Array,
  expectedSize?: number,
): Promise<Uint8Array> {
  const plaintext = await openRaw(
    pasteKey,
    encrypted,
    fileContentAad(pasteId, fileId),
  );
  if (expectedSize != null && plaintext.byteLength !== expectedSize) {
    throw new Error("Attachment size mismatch");
  }
  return plaintext;
}

export async function importPasteKeyFromShare(
  shareKey: Uint8Array,
): Promise<CryptoKey> {
  return importPasteKey(shareKey);
}

export function encodeKeySalt(salt: Uint8Array): string {
  return bytesToBase64Url(salt);
}
