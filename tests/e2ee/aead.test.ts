import assert from "node:assert/strict";
import { test } from "node:test";
import {
  IV_LENGTH,
  generatePasteId,
  importPasteKey,
  openRaw,
  openText,
  packEnvelope,
  pasteFieldAad,
  randomBytes,
  sealRaw,
  sealText,
  unpackEnvelope,
  utf8,
} from "../../src/lib/e2ee/index.ts";

async function freshKey(): Promise<CryptoKey> {
  return importPasteKey(randomBytes(32));
}

test("text round-trips with AAD", async () => {
  const key = await freshKey();
  const envelope = await sealText(key, "hello secret", "v1|paste|content");
  assert.equal(envelope.startsWith("v1:"), true);
  assert.equal(
    await openText(key, envelope, "v1|paste|content"),
    "hello secret",
  );
});

test("wrong AAD fails", async () => {
  const key = await freshKey();
  const envelope = await sealText(key, "hello secret", "v1|paste|content");
  await assert.rejects(() =>
    openText(key, envelope, "v1|paste|title"),
  );
});

test("tampered ciphertext fails", async () => {
  const key = await freshKey();
  const envelope = await sealText(key, "hello secret", "v1|paste|content");
  const sealed = unpackEnvelope(envelope);
  sealed[sealed.length - 1] ^= 1;
  await assert.rejects(() =>
    openText(key, packEnvelope(sealed), "v1|paste|content"),
  );
});

test("raw bytes round-trip and include IV plus tag", async () => {
  const key = await freshKey();
  const plaintext = randomBytes(1024);
  const sealed = await sealRaw(key, plaintext, "v1|file|chunk");
  assert.equal(sealed.byteLength, 12 + plaintext.byteLength + 16);
  assert.deepEqual(
    await openRaw(key, sealed, "v1|file|chunk"),
    plaintext,
  );
});

test("sealRaw uses a fresh 12-byte IV on every call", async () => {
  const key = await freshKey();
  const plaintext = utf8("same plaintext");
  const a = await sealRaw(key, plaintext, "v1|paste|content");
  const b = await sealRaw(key, plaintext, "v1|paste|content");

  const ivA = a.slice(0, IV_LENGTH);
  const ivB = b.slice(0, IV_LENGTH);
  assert.equal(ivA.byteLength, 12);
  assert.equal(ivB.byteLength, 12);
  assert.notDeepEqual(ivA, ivB);
  assert.notDeepEqual(a, b);
  assert.deepEqual(await openRaw(key, a, "v1|paste|content"), plaintext);
  assert.deepEqual(await openRaw(key, b, "v1|paste|content"), plaintext);
});

test("title ciphertext fails with content AAD", async () => {
  const key = await freshKey();
  const pasteId = generatePasteId();
  const envelope = await sealText(
    key,
    "secret title",
    pasteFieldAad(pasteId, "title"),
  );
  await assert.rejects(() =>
    openText(key, envelope, pasteFieldAad(pasteId, "content")),
  );
});

test("wrong key fails", async () => {
  const key = await freshKey();
  const otherKey = await freshKey();
  const sealed = await sealRaw(key, randomBytes(32));
  await assert.rejects(() => openRaw(otherKey, sealed));
});

test("bad envelope versions and short ciphertexts are rejected", async () => {
  const key = await freshKey();
  assert.throws(() => unpackEnvelope("v2:AAAA"));
  await assert.rejects(() => openRaw(key, new Uint8Array(16)));
});
