import assert from "node:assert/strict";
import { test } from "node:test";
import {
  deriveAuthKey,
  deriveMasterKey,
  derivePasteKey,
  derivePasteKeyBytes,
  deriveRootKey,
  generateFileId,
  generateKeySalt,
  generatePasteId,
  generateVaultKey,
  importVaultKey,
  isFileId,
  isPasteId,
  randomBytes,
  unwrapVaultKey,
  vaultCanary,
  vaultStamp,
  wrapVaultKey,
} from "../../src/lib/e2ee/index.ts";

const FAST_ARGON2 = {
  memorySize: 1024,
  iterations: 1,
  parallelism: 1,
  hashLength: 32,
};

test("root derivation is deterministic and salt-dependent", async () => {
  const salt = randomBytes(16);
  const rootA = await deriveRootKey("correct horse battery staple", salt, FAST_ARGON2);
  const rootB = await deriveRootKey("correct horse battery staple", salt, FAST_ARGON2);
  const rootC = await deriveRootKey(
    "correct horse battery staple",
    randomBytes(16),
    FAST_ARGON2,
  );

  assert.equal(rootA.byteLength, 32);
  assert.deepEqual(rootA, rootB);
  assert.notDeepEqual(rootA, rootC);
});

test("auth and master keys are separated and non-extractable", async () => {
  const salt = randomBytes(16);
  const rootA = await deriveRootKey("passphrase-a", salt, FAST_ARGON2);
  const rootB = await deriveRootKey("passphrase-b", salt, FAST_ARGON2);

  const authA = await deriveAuthKey(rootA);
  const authB = await deriveAuthKey(rootB);
  const masterA = await deriveMasterKey(rootA);

  assert.equal(authA.byteLength, 32);
  assert.notDeepEqual(authA, authB);
  assert.notDeepEqual(authA, rootA);
  assert.equal(masterA.extractable, false);
  assert.equal(masterA.algorithm.name, "AES-GCM");
});

test("vault key wraps and unwraps", async () => {
  const root = await deriveRootKey("passphrase", randomBytes(16), FAST_ARGON2);
  const masterKey = await deriveMasterKey(root);
  const vaultKey = generateVaultKey();

  const envelope = await wrapVaultKey(masterKey, vaultKey);
  assert.equal(envelope.startsWith("v1:"), true);
  assert.deepEqual(await unwrapVaultKey(masterKey, envelope), vaultKey);
});

test("auth key cannot decrypt a vault envelope", async () => {
  const root = await deriveRootKey("passphrase", randomBytes(16), FAST_ARGON2);
  const authKey = await deriveAuthKey(root);
  const masterKey = await deriveMasterKey(root);
  const envelope = await wrapVaultKey(masterKey, generateVaultKey());
  const authAsAes = await crypto.subtle.importKey(
    "raw",
    authKey,
    "AES-GCM",
    false,
    ["decrypt"],
  );

  await assert.rejects(() => unwrapVaultKey(authAsAes, envelope));
});

test("vault key fails with the wrong master key", async () => {
  const salt = randomBytes(16);
  const masterA = await deriveMasterKey(
    await deriveRootKey("passphrase-a", salt, FAST_ARGON2),
  );
  const masterB = await deriveMasterKey(
    await deriveRootKey("passphrase-b", salt, FAST_ARGON2),
  );
  const envelope = await wrapVaultKey(masterA, generateVaultKey());

  await assert.rejects(() => unwrapVaultKey(masterB, envelope));
});

test("paste keys are deterministic and bound to paste ID and salt", async () => {
  const vaultKey = await importVaultKey(generateVaultKey());
  const pasteId = generatePasteId();
  const keySalt = generateKeySalt();

  const a = await derivePasteKeyBytes(vaultKey, keySalt, pasteId);
  const b = await derivePasteKeyBytes(vaultKey, keySalt, pasteId);
  const otherId = await derivePasteKeyBytes(vaultKey, keySalt, generatePasteId());
  const otherSalt = await derivePasteKeyBytes(vaultKey, generateKeySalt(), pasteId);

  assert.equal(a.byteLength, 32);
  assert.deepEqual(a, b);
  assert.notDeepEqual(a, otherId);
  assert.notDeepEqual(a, otherSalt);

  const key = await derivePasteKey(vaultKey, keySalt, pasteId);
  assert.equal(key.extractable, false);
  assert.equal(key.algorithm.name, "AES-GCM");
});

test("generated IDs have the expected format", () => {
  const pasteId = generatePasteId();
  const fileId = generateFileId();
  assert.equal(isPasteId(pasteId), true);
  assert.equal(isFileId(fileId), true);
  assert.equal(pasteId.length, 22);
  assert.equal(fileId.length, 22);
});

test("vault canary is deterministic per key and differs across keys", async () => {
  const vaultKeyA = await importVaultKey(generateVaultKey());
  const vaultKeyB = await importVaultKey(generateVaultKey());

  const canaryA1 = await vaultCanary(vaultKeyA);
  const canaryA2 = await vaultCanary(vaultKeyA);
  const canaryB = await vaultCanary(vaultKeyB);

  assert.equal(canaryA1, canaryA2);
  assert.notEqual(canaryA1, canaryB);
  assert.match(canaryA1, /^[A-Za-z0-9_-]+$/);
});

test("vault stamp tracks the wrapped vault key envelope", async () => {
  const salt = randomBytes(16);
  const masterKey = await deriveMasterKey(
    await deriveRootKey("passphrase", salt, FAST_ARGON2),
  );
  const envelopeA = await wrapVaultKey(masterKey, generateVaultKey());
  const envelopeB = await wrapVaultKey(masterKey, generateVaultKey());

  assert.equal(await vaultStamp(envelopeA), await vaultStamp(envelopeA));
  assert.notEqual(await vaultStamp(envelopeA), await vaultStamp(envelopeB));
});
