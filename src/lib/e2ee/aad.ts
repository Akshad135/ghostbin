import {
  bytesToBase64Url,
  isBase64UrlOfByteLength,
} from "./bytes.ts";

export const PASTE_ID_BYTES = 16;
export const FILE_ID_BYTES = 16;
export const SHARE_SALT_BYTES = 16;

export const VAULT_AAD = "ghostbin/vault/v1";

const PASTE_FIELDS = new Set(["title", "content", "language"]);
export type PasteField = "title" | "content" | "language";

export function isPasteId(value: string): boolean {
  return isBase64UrlOfByteLength(value, PASTE_ID_BYTES);
}

export function isFileId(value: string): boolean {
  return isBase64UrlOfByteLength(value, FILE_ID_BYTES);
}

export function pasteFieldAad(pasteId: string, field: PasteField): string {
  if (!isPasteId(pasteId)) {
    throw new Error("pasteFieldAad: invalid paste ID");
  }
  if (!PASTE_FIELDS.has(field)) {
    throw new Error("pasteFieldAad: invalid field");
  }
  return `ghostbin/paste/v1|${pasteId}|${field}`;
}

export function fileChunkAad(
  pasteId: string,
  fileId: string,
  chunkIndex: number,
  totalChunks: number,
  final: boolean,
): string {
  if (!isPasteId(pasteId)) {
    throw new Error("fileChunkAad: invalid paste ID");
  }
  if (!isFileId(fileId)) {
    throw new Error("fileChunkAad: invalid file ID");
  }
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0) {
    throw new Error("fileChunkAad: invalid chunk index");
  }
  if (!Number.isInteger(totalChunks) || totalChunks < 1) {
    throw new Error("fileChunkAad: invalid total chunks");
  }
  if (chunkIndex >= totalChunks) {
    throw new Error("fileChunkAad: chunk index out of range");
  }
  if (final !== (chunkIndex === totalChunks - 1)) {
    throw new Error("fileChunkAad: final flag does not match chunk index");
  }
  return [
    "ghostbin/file/v1",
    pasteId,
    fileId,
    String(chunkIndex),
    String(totalChunks),
    final ? "1" : "0",
  ].join("|");
}

export function shareAad(pasteId: string, shareSalt: Uint8Array): string {
  if (!isPasteId(pasteId)) {
    throw new Error("shareAad: invalid paste ID");
  }
  if (shareSalt.byteLength !== SHARE_SALT_BYTES) {
    throw new Error("shareAad: invalid share salt");
  }
  return `ghostbin/share/v1|${pasteId}|${bytesToBase64Url(shareSalt)}`;
}
