import assert from "node:assert/strict";
import { test } from "node:test";
import {
  bytesToBase64Url,
  fileMetaAad,
  generateFileId,
  generateKeySalt,
  generatePasteId,
  generateVaultKey,
  importVaultKey,
} from "../../src/lib/e2ee/index.ts";
import {
  decryptAttachmentBytes,
  decryptAttachmentMeta,
  decryptPasteTitleAndLanguage,
  decryptPasteWithKey,
  encryptAttachment,
  encryptPasteFields,
  pasteKeyForSummary,
} from "../../src/lib/paste.ts";

async function testPaste() {
  const vaultKey = await importVaultKey(generateVaultKey());
  const salt = generateKeySalt();
  const pasteId = generatePasteId();
  const pasteKey = await pasteKeyForSummary(vaultKey, {
    id: pasteId,
    keySalt: bytesToBase64Url(salt),
  });
  return { vaultKey, pasteId, pasteKey, keySalt: bytesToBase64Url(salt) };
}

test("file metadata AAD binds paste and file IDs", () => {
  const pasteId = generatePasteId();
  const fileId = generateFileId();
  assert.equal(
    fileMetaAad(pasteId, fileId),
    `ghostbin/file-meta/v1|${pasteId}|${fileId}`,
  );
  assert.throws(() => fileMetaAad("bad", fileId));
  assert.throws(() => fileMetaAad(pasteId, "bad"));
});

test("paste fields round-trip and reject a different paste ID", async () => {
  const { pasteId, pasteKey } = await testPaste();
  const fields = {
    title: "Quarterly plan",
    content: "line one\nline two\n",
    language: "rust",
  };
  const ciphertext = await encryptPasteFields(pasteKey, pasteId, fields);

  const opened = await decryptPasteWithKey(pasteKey, {
    id: pasteId,
    ...ciphertext,
  });
  assert.deepEqual(opened, fields);

  await assert.rejects(
    decryptPasteWithKey(pasteKey, {
      id: generatePasteId(),
      ...ciphertext,
    }),
  );
});

test("legacy pastes without a language ciphertext open as plaintext", async () => {
  const { vaultKey, pasteId, pasteKey, keySalt } = await testPaste();
  const ciphertext = await encryptPasteFields(pasteKey, pasteId, {
    title: "No language",
    content: "body",
    language: "plaintext",
  });
  const opened = await decryptPasteWithKey(pasteKey, {
    id: pasteId,
    titleCt: ciphertext.titleCt,
    contentCt: ciphertext.contentCt,
    languageCt: null,
  });
  assert.deepEqual(opened, {
    title: "No language",
    content: "body",
    language: "plaintext",
  });

  const summary = await decryptPasteTitleAndLanguage(vaultKey, {
    id: pasteId,
    keySalt,
    titleCt: ciphertext.titleCt,
    languageCt: null,
  });
  assert.deepEqual(summary, {
    title: "No language",
    language: "plaintext",
  });
});

test("attachment metadata and bytes round-trip", async () => {
  const { pasteId, pasteKey } = await testPaste();
  const fileId = generateFileId();
  const bytes = new Uint8Array([0, 1, 2, 3, 254, 255]);

  const encrypted = await encryptAttachment(pasteKey, pasteId, fileId, {
    name: "report \"final\".txt",
    mime: "text/plain",
    bytes,
  });

  assert.equal(encrypted.encrypted.byteLength, bytes.byteLength + 28);
  assert.equal(encrypted.encMeta.includes("report"), false);

  const meta = await decryptAttachmentMeta(pasteKey, pasteId, {
    id: fileId,
    encMeta: encrypted.encMeta,
  });
  assert.equal(meta.name, "report \"final\".txt");
  assert.equal(meta.mime, "text/plain");
  assert.equal(meta.size, bytes.byteLength);

  const opened = await decryptAttachmentBytes(
    pasteKey,
    pasteId,
    fileId,
    encrypted.encrypted,
    bytes.byteLength,
  );
  assert.deepEqual(opened, bytes);
});

test("attachment decryption rejects wrong IDs and sizes", async () => {
  const { pasteId, pasteKey } = await testPaste();
  const fileId = generateFileId();
  const encrypted = await encryptAttachment(pasteKey, pasteId, fileId, {
    name: "a.bin",
    mime: "application/octet-stream",
    bytes: new Uint8Array([7, 8, 9]),
  });

  await assert.rejects(
    decryptAttachmentBytes(
      pasteKey,
      pasteId,
      generateFileId(),
      encrypted.encrypted,
      3,
    ),
  );
  await assert.rejects(
    decryptAttachmentBytes(
      pasteKey,
      generatePasteId(),
      fileId,
      encrypted.encrypted,
      3,
    ),
  );
  await assert.rejects(
    decryptAttachmentBytes(
      pasteKey,
      pasteId,
      fileId,
      encrypted.encrypted,
      2,
    ),
  );
});

test("encryptAttachment rejects malformed metadata", async () => {
  const { pasteId, pasteKey } = await testPaste();
  await assert.rejects(
    encryptAttachment(pasteKey, pasteId, generateFileId(), {
      name: "x".repeat(256),
      mime: "text/plain",
      bytes: new Uint8Array([1]),
    }),
  );
});
