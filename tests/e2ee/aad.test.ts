import assert from "node:assert/strict";
import { test } from "node:test";
import {
  fileChunkAad,
  generateFileId,
  generatePasteId,
  generateShareSalt,
  isPasteId,
  pasteFieldAad,
  shareAad,
  type PasteField,
} from "../../src/lib/e2ee/index.ts";

test("paste AAD binds the paste ID and field", () => {
  const pasteId = generatePasteId();
  assert.equal(isPasteId(pasteId), true);
  assert.equal(
    pasteFieldAad(pasteId, "content"),
    `ghostbin/paste/v1|${pasteId}|content`,
  );
  assert.notEqual(
    pasteFieldAad(pasteId, "title"),
    pasteFieldAad(pasteId, "content"),
  );
  assert.throws(() =>
    pasteFieldAad(pasteId, "not-a-field" as PasteField),
  );
});

test("file AAD binds chunk order and the final flag", () => {
  const pasteId = generatePasteId();
  const fileId = generateFileId();
  assert.equal(
    fileChunkAad(pasteId, fileId, 0, 2, false),
    `ghostbin/file/v1|${pasteId}|${fileId}|0|2|0`,
  );
  assert.equal(
    fileChunkAad(pasteId, fileId, 1, 2, true),
    `ghostbin/file/v1|${pasteId}|${fileId}|1|2|1`,
  );
  assert.throws(() => fileChunkAad(pasteId, fileId, 1, 2, false));
  assert.throws(() => fileChunkAad(pasteId, fileId, 2, 2, false));
  assert.throws(() => fileChunkAad("bad", fileId, 0, 1, true));
});

test("share AAD binds the paste ID and share salt", () => {
  const pasteId = generatePasteId();
  const shareSalt = generateShareSalt();
  assert.match(shareAad(pasteId, shareSalt), /^ghostbin\/share\/v1\|/);
  assert.throws(() => shareAad(pasteId, new Uint8Array(15)));
});
