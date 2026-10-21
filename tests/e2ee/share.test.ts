import assert from "node:assert/strict";
import { test } from "node:test";
import {
  SHARE_CODE_ALPHABET,
  SHARE_CODE_LENGTH,
  ShareCodeError,
  decodeFragmentSecret,
  deriveShareAuthKey,
  deriveShareCodeKey,
  deriveShareKeys,
  deriveShareProof,
  encodeFragmentSecret,
  generateFragmentSecret,
  generatePasteId,
  generateShareCode,
  generateShareSalt,
  isShareCode,
  normalizeShareCode,
  randomBytes,
  unwrapPasteKeyFromShare,
  wrapPasteKeyForShare,
} from "../../src/lib/e2ee/index.ts";

const FAST_ARGON2 = {
  memorySize: 1024,
  iterations: 1,
  parallelism: 1,
  hashLength: 32,
};

test("generated codes use the 14-char unambiguous alphabet", () => {
  for (let i = 0; i < 50; i++) {
    const code = generateShareCode();
    assert.equal(code.length, SHARE_CODE_LENGTH);
    assert.equal(isShareCode(code), true);
    for (const char of code) {
      assert.equal(SHARE_CODE_ALPHABET.includes(char), true);
    }
  }
});

test("code normalization accepts lowercase, spaces, and hyphens", () => {
  const code = generateShareCode();
  const messy = ` ${code.slice(0, 4).toLowerCase()}-${code.slice(4, 8)} ${code
    .slice(8)
    .toLowerCase()} `;
  assert.equal(normalizeShareCode(messy), code);
  assert.equal(isShareCode(messy), true);
});

test("invalid codes are rejected", () => {
  assert.throws(() => normalizeShareCode("ABC"), ShareCodeError);
  assert.throws(() => normalizeShareCode("O".repeat(14)), ShareCodeError);
  assert.throws(() => normalizeShareCode("A".repeat(13)), ShareCodeError);
  assert.equal(isShareCode("not a code"), false);
});

test("fragment secrets encode and decode as 32 bytes", () => {
  const secret = generateFragmentSecret();
  const encoded = encodeFragmentSecret(secret);
  assert.equal(encoded.length, 43);
  assert.deepEqual(decodeFragmentSecret(encoded), secret);
  assert.throws(() => decodeFragmentSecret("AAAA"));
});

test("share keys are deterministic for the same code and fragment", async () => {
  const code = generateShareCode();
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();

  const a = await deriveShareKeys(code, shareSalt, fragmentSecret, FAST_ARGON2);
  const b = await deriveShareKeys(code.toLowerCase(), shareSalt, fragmentSecret, FAST_ARGON2);
  const otherFragment = await deriveShareKeys(
    code,
    shareSalt,
    generateFragmentSecret(),
    FAST_ARGON2,
  );

  assert.deepEqual(a.codeKey, b.codeKey);
  assert.deepEqual(a.authKey, b.authKey);
  assert.notDeepEqual(a.authKey, a.codeKey);
  assert.notDeepEqual(a.authKey, otherFragment.authKey);
});

test("share keys change when the code changes", async () => {
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const a = await deriveShareCodeKey(generateShareCode(), shareSalt, FAST_ARGON2);
  const b = await deriveShareCodeKey(generateShareCode(), shareSalt, FAST_ARGON2);
  assert.notDeepEqual(a, b);

  const authA = await deriveShareAuthKey(a, shareSalt, fragmentSecret);
  const authB = await deriveShareAuthKey(b, shareSalt, fragmentSecret);
  assert.notDeepEqual(authA, authB);
});

test("paste key wraps and unwraps with the share wrap key", async () => {
  const code = generateShareCode();
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const pasteId = generatePasteId();
  const pasteKey = randomBytes(32);

  const { wrapKey } = await deriveShareKeys(
    code,
    shareSalt,
    fragmentSecret,
    FAST_ARGON2,
  );
  const envelope = await wrapPasteKeyForShare(
    wrapKey,
    pasteKey,
    pasteId,
    shareSalt,
  );
  assert.equal(envelope.startsWith("v1:"), true);
  assert.deepEqual(
    await unwrapPasteKeyFromShare(wrapKey, envelope, pasteId, shareSalt),
    pasteKey,
  );

  await assert.rejects(() =>
    unwrapPasteKeyFromShare(wrapKey, envelope, generatePasteId(), shareSalt),
  );
});

test("share auth key cannot decrypt the share envelope", async () => {
  const code = generateShareCode();
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const pasteId = generatePasteId();

  const { authKey, wrapKey } = await deriveShareKeys(
    code,
    shareSalt,
    fragmentSecret,
    FAST_ARGON2,
  );
  const envelope = await wrapPasteKeyForShare(
    wrapKey,
    randomBytes(32),
    pasteId,
    shareSalt,
  );
  const authAsAes = await crypto.subtle.importKey(
    "raw",
    authKey,
    "AES-GCM",
    false,
    ["decrypt"],
  );

  await assert.rejects(() =>
    unwrapPasteKeyFromShare(authAsAes, envelope, pasteId, shareSalt),
  );
});

test("wrong code or wrong fragment cannot unwrap the paste key", async () => {
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const pasteId = generatePasteId();
  const pasteKey = randomBytes(32);
  const code = generateShareCode();

  const correct = await deriveShareKeys(
    code,
    shareSalt,
    fragmentSecret,
    FAST_ARGON2,
  );
  const envelope = await wrapPasteKeyForShare(
    correct.wrapKey,
    pasteKey,
    pasteId,
    shareSalt,
  );

  const wrongCode = await deriveShareKeys(
    generateShareCode(),
    shareSalt,
    fragmentSecret,
    FAST_ARGON2,
  );
  const wrongFragment = await deriveShareKeys(
    code,
    shareSalt,
    generateFragmentSecret(),
    FAST_ARGON2,
  );

  await assert.rejects(() =>
    unwrapPasteKeyFromShare(wrongCode.wrapKey, envelope, pasteId, shareSalt),
  );
  await assert.rejects(() =>
    unwrapPasteKeyFromShare(
      wrongFragment.wrapKey,
      envelope,
      pasteId,
      shareSalt,
    ),
  );
});

test("share proofs are deterministic and nonce-bound", async () => {
  const code = generateShareCode();
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const pasteId = generatePasteId();
  const { authKey } = await deriveShareKeys(
    code,
    shareSalt,
    fragmentSecret,
    FAST_ARGON2,
  );

  const a = await deriveShareProof(authKey, "nonce-a", pasteId);
  const b = await deriveShareProof(authKey, "nonce-a", pasteId);
  const c = await deriveShareProof(authKey, "nonce-b", pasteId);

  assert.equal(a.byteLength, 32);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, c);
});
