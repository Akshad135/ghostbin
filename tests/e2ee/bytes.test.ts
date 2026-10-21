import assert from "node:assert/strict";
import { test } from "node:test";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  fromUtf8,
  randomBytes,
  sha256,
  toArrayBuffer,
  utf8,
} from "../../src/lib/e2ee/index.ts";

test("base64url round-trips arbitrary bytes", () => {
  for (const length of [0, 1, 16, 32, 100]) {
    const bytes = randomBytes(length);
    const encoded = bytesToBase64Url(bytes);
    assert.equal(encoded.includes("="), false);
    assert.equal(encoded.includes("+"), false);
    assert.equal(encoded.includes("/"), false);
    assert.deepEqual(base64UrlToBytes(encoded), bytes);
  }
});

test("UTF-8 round-trips", () => {
  const value = "passwords, spaces, and unicode: \u00e9\u00e8\u00ea";
  assert.equal(fromUtf8(utf8(value)), value);
});

test("SHA-256 matches a known vector", async () => {
  const digest = await sha256(utf8("abc"));
  const hex = Array.from(digest)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  assert.equal(
    hex,
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
});

test("toArrayBuffer copies exactly the visible bytes", () => {
  const backing = new Uint8Array([1, 2, 3, 4, 5]);
  const view = backing.subarray(1, 4);
  const buffer = toArrayBuffer(view);
  assert.equal(buffer.byteLength, 3);
  assert.deepEqual(new Uint8Array(buffer), new Uint8Array([2, 3, 4]));
});
