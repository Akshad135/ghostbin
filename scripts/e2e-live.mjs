#!/usr/bin/env node
/**
 * Live end-to-end exercise of the E2EE API against a running GhostBin
 * server, using the exact crypto modules the browser client uses.
 *
 * Start a throwaway server first, e.g.:
 *
 *   DATABASE_PATH=/tmp/gb-e2e/test.sqlite UPLOADS_DIR=/tmp/gb-e2e/uploads \
 *   RESET_DB=force PORT=8791 cargo run
 *
 * Then:
 *
 *   node --experimental-strip-types scripts/e2e-live.mjs [base-url]
 *
 * Covers: setup, login, vault, paste create/read/update/delete, file
 * upload/download, share create/unlock/view/revoke, wrong-code rejection,
 * passphrase change (session kept, old passphrase dead), unlock-count burn,
 * and logout.
 */

import assert from "node:assert/strict";
import {
  DEFAULT_ARGON2_PARAMS,
  base64UrlToBytes,
  bytesToBase64Url,
  deriveAuthKey,
  deriveMasterKey,
  deriveRootKey,
  deriveShareKeys,
  deriveShareProof,
  encodeFragmentSecret,
  generateFragmentSecret,
  generateKeySalt,
  generatePasteId,
  generateShareCode,
  generateShareSalt,
  generateVaultKey,
  importPasteKey,
  importVaultKey,
  unwrapPasteKeyFromShare,
  unwrapVaultKey,
  wrapPasteKeyForShare,
  wrapVaultKey,
} from "../src/lib/e2ee/index.ts";
import {
  decryptAttachmentBytes,
  decryptAttachmentMeta,
  decryptGuestPaste,
  decryptPasteWithKey,
  encryptAttachment,
  encryptPasteFields,
  pasteKeyBytesForSummary,
  pasteKeyForSummary,
} from "../src/lib/paste.ts";

const BASE = process.argv[2] ?? "http://127.0.0.1:8791";
const PASSPHRASE = "correct horse battery staple e2e";
const NEW_PASSPHRASE = "staple battery horse correct e2e 2";

let stepCount = 0;
function step(name) {
  stepCount += 1;
  process.stdout.write(`[${String(stepCount).padStart(2, "0")}] ${name} ... `);
}
function ok(extra = "") {
  process.stdout.write(`ok${extra ? ` — ${extra}` : ""}\n`);
}

class Http {
  constructor() {
    this.cookies = new Map();
  }

  storeCookies(response) {
    for (const raw of response.headers.getSetCookie?.() ?? []) {
      const [pair] = raw.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) this.cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1));
    }
  }

  cookieHeader() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  async request(method, path, { json, body, headers = {} } = {}) {
    const h = { ...headers };
    if (this.cookies.size > 0) h.Cookie = this.cookieHeader();
    if (json !== undefined) h["Content-Type"] = "application/json";
    const response = await fetch(`${BASE}${path}`, {
      method,
      headers: h,
      body: json !== undefined ? JSON.stringify(json) : body,
    });
    this.storeCookies(response);
    const text = await response.text();
    let data;
    try {
      data = text ? JSON.parse(text) : undefined;
    } catch {
      data = text;
    }
    return { status: response.status, data };
  }

  get(path, options) {
    return this.request("GET", path, options);
  }
  post(path, json, headers) {
    return this.request("POST", path, { json, headers });
  }
  put(path, json, headers) {
    return this.request("PUT", path, { json, headers });
  }
  del(path, headers) {
    return this.request("DELETE", path, { headers });
  }
}

async function deriveLoginMaterial(passphrase, salt, kdfParams) {
  const root = await deriveRootKey(passphrase, salt, kdfParams);
  return {
    root,
    authKey: await deriveAuthKey(root),
    masterKey: await deriveMasterKey(root),
  };
}

async function createSharedPaste(owner, vaultHandle, { burnMode, burnAfter } = {}) {
  const pasteId = generatePasteId();
  const keySalt = generateKeySalt();
  const pasteKey = await pasteKeyForSummary(vaultHandle, {
    id: pasteId,
    keySalt: bytesToBase64Url(keySalt),
  });
  const fields = {
    title: "Live E2E paste",
    content: "the quick brown fox\njumps over the lazy dog\n",
    language: "rust",
  };
  const ct = await encryptPasteFields(pasteKey, pasteId, fields);

  const createBody = {
    id: pasteId,
    keySalt: bytesToBase64Url(keySalt),
    titleCt: ct.titleCt,
    contentCt: ct.contentCt,
    languageCt: ct.languageCt,
  };
  if (burnMode) {
    createBody.burnMode = burnMode;
    createBody.burnAfter = burnAfter;
  }
  return { pasteId, keySalt, pasteKey, fields, ct, createBody };
}

async function main() {
  const owner = new Http();
  const guest = new Http();

  // ── Setup ──────────────────────────────────────────────────────────
  step("fresh server reports unconfigured");
  let r = await owner.get("/api/auth/params");
  assert.equal(r.status, 200);
  assert.equal(r.data.configured, false);
  ok();

  step("setup creates the vault and a session");
  const setupSalt = generateKeySalt();
  const setup = await deriveLoginMaterial(PASSPHRASE, setupSalt, DEFAULT_ARGON2_PARAMS);
  const vaultBytes = generateVaultKey();
  const wrappedVaultKey = await wrapVaultKey(setup.masterKey, vaultBytes);
  r = await owner.post("/api/auth/setup", {
    authKey: bytesToBase64Url(setup.authKey),
    kdfSalt: bytesToBase64Url(setupSalt),
    kdfParams: { ...DEFAULT_ARGON2_PARAMS },
    wrappedVaultKey,
  });
  assert.equal(r.status, 201);
  assert.equal(r.data.success, true);
  const csrf = r.data.csrfToken;
  assert.equal(typeof csrf, "string");
  const csrfHeaders = () => ({ "X-CSRF-Token": csrf });
  ok();

  step("setup is one-time");
  r = await owner.post("/api/auth/setup", {
    authKey: bytesToBase64Url(setup.authKey),
    kdfSalt: bytesToBase64Url(setupSalt),
    kdfParams: { ...DEFAULT_ARGON2_PARAMS },
    wrappedVaultKey,
  }, csrfHeaders());
  assert.equal(r.status, 409);
  ok();

  step("vault returns our wrapped key");
  r = await owner.get("/api/vault");
  assert.equal(r.status, 200);
  assert.equal(r.data.wrappedVaultKey, wrappedVaultKey);
  ok();

  step("wrong passphrase login is rejected");
  const wrong = await deriveLoginMaterial("not the passphrase", setupSalt, DEFAULT_ARGON2_PARAMS);
  r = await owner.post("/api/auth/login", {
    authKey: bytesToBase64Url(wrong.authKey),
  });
  assert.equal(r.status, 401);
  ok();

  step("login with the right passphrase rotates the session");
  r = await owner.post("/api/auth/login", {
    authKey: bytesToBase64Url(setup.authKey),
  });
  assert.equal(r.status, 200);
  const csrf2 = r.data.csrfToken;
  const csrfHeadersNow = () => ({ "X-CSRF-Token": csrf2 });
  ok();

  const vaultHandle = await importVaultKey(vaultBytes);

  // ── Paste + attachment ─────────────────────────────────────────────
  step("create an encrypted paste");
  const paste = await createSharedPaste(owner, vaultHandle);
  r = await owner.post("/api/pastes", paste.createBody, csrfHeadersNow());
  assert.equal(r.status, 201);
  assert.equal(r.data.paste.id, paste.pasteId);
  ok();

  step("upload an encrypted attachment");
  const fileBytes = new Uint8Array(64 * 1024 + 7);
  for (let i = 0; i < fileBytes.length; i++) fileBytes[i] = i % 251;
  const realFileId = generatePasteId();
  const attachment = await encryptAttachment(paste.pasteKey, paste.pasteId, realFileId, {
    name: "e2e-report.bin",
    mime: "application/octet-stream",
    bytes: fileBytes,
  });
  const query = new URLSearchParams({
    pasteId: paste.pasteId,
    fileId: realFileId,
    size: String(attachment.encrypted.byteLength),
  });
  r = await owner.request("POST", `/api/files?${query.toString()}`, {
    body: attachment.encrypted,
    headers: {
      "Content-Type": "application/octet-stream",
      "X-File-Meta": attachment.encMeta,
      ...csrfHeadersNow(),
    },
  });
  assert.equal(r.status, 201);
  ok();

  step("owner can read, decrypt paste and attachment");
  r = await owner.get(`/api/pastes/${paste.pasteId}`);
  assert.equal(r.status, 200);
  const detail = r.data.paste;
  assert.equal(detail.id, paste.pasteId);
  const opened = await decryptPasteWithKey(paste.pasteKey, {
    id: paste.pasteId,
    titleCt: detail.titleCt,
    contentCt: detail.contentCt,
    languageCt: detail.languageCt,
  });
  assert.deepEqual(opened, paste.fields);
  assert.equal(detail.files.length, 1);
  const fileMeta = await decryptAttachmentMeta(paste.pasteKey, paste.pasteId, detail.files[0]);
  assert.equal(fileMeta.name, "e2e-report.bin");
  assert.equal(fileMeta.size, fileBytes.byteLength);
  ok("(meta checked; binary check below)");

  // Binary-safe download check.
  step("binary attachment download round-trips");
  const binaryResponse = await fetch(`${BASE}/api/files/${realFileId}`, {
    headers: { Cookie: owner.cookieHeader() },
  });
  assert.equal(binaryResponse.status, 200);
  const encryptedOnWire = new Uint8Array(await binaryResponse.arrayBuffer());
  assert.equal(encryptedOnWire.byteLength, attachment.encrypted.byteLength);
  const plainBack = await decryptAttachmentBytes(
    paste.pasteKey,
    paste.pasteId,
    realFileId,
    encryptedOnWire,
    fileBytes.byteLength,
  );
  assert.deepEqual(plainBack, fileBytes);
  ok(`${fileBytes.byteLength} bytes`);

  step("paste list includes the paste");
  r = await owner.get("/api/pastes?page=1&limit=20");
  assert.equal(r.status, 200);
  assert.ok(r.data.pastes.some((p) => p.id === paste.pasteId));
  ok();

  step("update paste (pin)");
  r = await owner.put(`/api/pastes/${paste.pasteId}`, { pinned: true }, csrfHeadersNow());
  assert.equal(r.status, 200);
  assert.equal(r.data.paste.pinned, true);
  ok();

  // ── Sharing ────────────────────────────────────────────────────────
  step("create a share (client-side code + fragment)");
  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const code = generateShareCode();
  const shareKeys = await deriveShareKeys(code, shareSalt, fragmentSecret, DEFAULT_ARGON2_PARAMS);
  const pasteKeyBytes = await pasteKeyBytesForSummary(vaultHandle, {
    id: paste.pasteId,
    keySalt: bytesToBase64Url(paste.keySalt),
  });
  const wrappedPasteKey = await wrapPasteKeyForShare(
    shareKeys.wrapKey,
    pasteKeyBytes,
    paste.pasteId,
    shareSalt,
  );
  r = await owner.post(
    `/api/pastes/${paste.pasteId}/share`,
    {
      shareSalt: bytesToBase64Url(shareSalt),
      shareAuthKey: bytesToBase64Url(shareKeys.authKey),
      kdfParams: { ...DEFAULT_ARGON2_PARAMS },
      wrappedPasteKey,
    },
    csrfHeadersNow(),
  );
  assert.equal(r.status, 201);
  assert.equal(r.data.share.maxUnlocks, null);
  ok(`link /p/${paste.pasteId}#${encodeFragmentSecret(fragmentSecret).slice(0, 8)}…`);

  step("share status is visible to the owner without secrets");
  r = await owner.get(`/api/pastes/${paste.pasteId}/share`);
  assert.equal(r.status, 200);
  assert.equal(r.data.exists, true);
  assert.equal(r.data.share.maxUnlocks, null);
  assert.equal("shareAuthKey" in r.data, false);
  ok();

  step("guest params reveal only public share data");
  r = await guest.get(`/api/shares/${paste.pasteId}/params`);
  assert.equal(r.status, 200);
  assert.equal(r.data.shareSalt, bytesToBase64Url(shareSalt));
  assert.equal(r.data.kdfParams.memorySize, DEFAULT_ARGON2_PARAMS.memorySize);
  ok();

  step("guest unlock with wrong code is rejected");
  const wrongKeys = await deriveShareKeys(
    "XXXXXXXXXXXXXX",
    shareSalt,
    fragmentSecret,
    DEFAULT_ARGON2_PARAMS,
  );
  r = await guest.post(`/api/shares/${paste.pasteId}/challenge`, {});
  assert.equal(r.status, 200);
  const wrongProof = await deriveShareProof(wrongKeys.authKey, r.data.nonce, paste.pasteId);
  r = await guest.post(`/api/shares/${paste.pasteId}/unlock`, {
    nonce: r.data.nonce,
    proof: bytesToBase64Url(wrongProof),
  });
  assert.equal(r.status, 401);
  ok();

  step("guest unlock + view with the right code decrypts everything");
  r = await guest.post(`/api/shares/${paste.pasteId}/challenge`, {});
  assert.equal(r.status, 200);
  const nonce = r.data.nonce;
  const proof = await deriveShareProof(shareKeys.authKey, nonce, paste.pasteId);
  r = await guest.post(`/api/shares/${paste.pasteId}/unlock`, {
    nonce,
    proof: bytesToBase64Url(proof),
  });
  assert.equal(r.status, 200);
  const shareToken = r.data.shareToken;
  assert.equal(typeof shareToken, "string");
  assert.equal(r.data.files.length, 1);

  const guestFile = await fetch(`${BASE}/api/files/${realFileId}`, {
    headers: { "X-Share-Token": shareToken },
  });
  assert.equal(guestFile.status, 200);
  const guestEncrypted = new Uint8Array(await guestFile.arrayBuffer());

  r = await guest.post(`/api/shares/${paste.pasteId}/view`, { shareToken });
  assert.equal(r.status, 200);
  assert.equal(r.data.burned, false);
  assert.equal(r.data.share.shareSalt, bytesToBase64Url(shareSalt));
  const guestPasteKeyBytes = await unwrapPasteKeyFromShare(
    shareKeys.wrapKey,
    r.data.share.wrappedPasteKey,
    paste.pasteId,
    shareSalt,
  );
  assert.deepEqual(guestPasteKeyBytes, pasteKeyBytes);
  const guestKey = await importPasteKey(guestPasteKeyBytes);
  const guestFields = await decryptGuestPaste(guestKey, r.data.paste);
  assert.deepEqual(guestFields, paste.fields);
  const guestMeta = await decryptAttachmentMeta(guestKey, paste.pasteId, r.data.files[0]);
  assert.equal(guestMeta.name, "e2e-report.bin");
  const guestPlain = await decryptAttachmentBytes(
    guestKey,
    paste.pasteId,
    realFileId,
    guestEncrypted,
    fileBytes.byteLength,
  );
  assert.deepEqual(guestPlain, fileBytes);
  ok();

  step("replaying a consumed share token is rejected");
  r = await guest.post(`/api/shares/${paste.pasteId}/view`, { shareToken });
  assert.equal(r.status, 401, "a share token must be single-use for /view");
  ok();

  step("a fresh unlock counts the second view");
  r = await guest.post(`/api/shares/${paste.pasteId}/challenge`, {});
  assert.equal(r.status, 200);
  const proof2 = await deriveShareProof(shareKeys.authKey, r.data.nonce, paste.pasteId);
  r = await guest.post(`/api/shares/${paste.pasteId}/unlock`, {
    nonce: r.data.nonce,
    proof: bytesToBase64Url(proof2),
  });
  assert.equal(r.status, 200);
  r = await guest.post(`/api/shares/${paste.pasteId}/view`, {
    shareToken: r.data.shareToken,
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.unlocksUsed, 2);
  ok("unlocksUsed=2");

  step("owner revokes the share");
  r = await owner.del(`/api/pastes/${paste.pasteId}/share`, csrfHeadersNow());
  assert.equal(r.status, 200);
  r = await guest.get(`/api/shares/${paste.pasteId}/params`);
  assert.equal(r.status, 404);
  ok();

  // ── Passphrase change ──────────────────────────────────────────────
  step("change passphrase keeps this session, kills the old passphrase");
  const newSalt = generateKeySalt();
  const next = await deriveLoginMaterial(NEW_PASSPHRASE, newSalt, DEFAULT_ARGON2_PARAMS);
  const newWrapped = await wrapVaultKey(next.masterKey, vaultBytes);
  r = await owner.post(
    "/api/auth/change-passphrase",
    {
      oldAuthKey: bytesToBase64Url(setup.authKey),
      newAuthKey: bytesToBase64Url(next.authKey),
      newKdfSalt: bytesToBase64Url(newSalt),
      newKdfParams: { ...DEFAULT_ARGON2_PARAMS },
      newWrappedVaultKey: newWrapped,
    },
    csrfHeadersNow(),
  );
  assert.equal(r.status, 200);
  assert.equal(r.data.success, true);

  r = await owner.get("/api/vault");
  assert.equal(r.status, 200, "current session must survive the change");
  assert.equal(r.data.wrappedVaultKey, newWrapped);

  const oldLogin = await deriveLoginMaterial(PASSPHRASE, newSalt, DEFAULT_ARGON2_PARAMS);
  r = await owner.post("/api/auth/login", {
    authKey: bytesToBase64Url(oldLogin.authKey),
  });
  assert.equal(r.status, 401, "old passphrase must be dead");

  r = await owner.post("/api/auth/login", {
    authKey: bytesToBase64Url(next.authKey),
  });
  assert.equal(r.status, 200);
  const csrf3 = r.data.csrfToken;
  const csrfFinal = () => ({ "X-CSRF-Token": csrf3 });

  r = await owner.get("/api/vault");
  assert.equal(r.status, 200);
  const reopened = await unwrapVaultKey(next.masterKey, r.data.wrappedVaultKey);
  assert.deepEqual(reopened, vaultBytes, "same vault key must unwrap under the new passphrase");
  ok();

  // ── Burn on unlock count ───────────────────────────────────────────
  step("unlock-count burn destroys the paste after the final view");
  const burnPaste = await createSharedPaste(owner, vaultHandle, {
    burnMode: "unlock_count",
    burnAfter: 1,
  });
  r = await owner.post("/api/pastes", burnPaste.createBody, csrfFinal());
  assert.equal(r.status, 201);

  const burnShareSalt = generateShareSalt();
  const burnFragment = generateFragmentSecret();
  const burnCode = generateShareCode();
  const burnKeys = await deriveShareKeys(burnCode, burnShareSalt, burnFragment, DEFAULT_ARGON2_PARAMS);
  const burnKeyBytes = await pasteKeyBytesForSummary(vaultHandle, {
    id: burnPaste.pasteId,
    keySalt: bytesToBase64Url(burnPaste.keySalt),
  });
  r = await owner.post(
    `/api/pastes/${burnPaste.pasteId}/share`,
    {
      shareSalt: bytesToBase64Url(burnShareSalt),
      shareAuthKey: bytesToBase64Url(burnKeys.authKey),
      kdfParams: { ...DEFAULT_ARGON2_PARAMS },
      wrappedPasteKey: await wrapPasteKeyForShare(
        burnKeys.wrapKey,
        burnKeyBytes,
        burnPaste.pasteId,
        burnShareSalt,
      ),
    },
    csrfFinal(),
  );
  assert.equal(r.status, 201);

  r = await guest.post(`/api/shares/${burnPaste.pasteId}/challenge`, {});
  const burnProof = await deriveShareProof(burnKeys.authKey, r.data.nonce, burnPaste.pasteId);
  r = await guest.post(`/api/shares/${burnPaste.pasteId}/unlock`, {
    nonce: r.data.nonce,
    proof: bytesToBase64Url(burnProof),
  });
  assert.equal(r.status, 200);
  r = await guest.post(`/api/shares/${burnPaste.pasteId}/view`, {
    shareToken: r.data.shareToken,
  });
  assert.equal(r.status, 200);
  assert.equal(r.data.burned, true);

  r = await owner.get(`/api/pastes/${burnPaste.pasteId}`);
  assert.ok(r.status === 404 || r.status === 410, "burned paste must be gone");
  r = await guest.get(`/api/shares/${burnPaste.pasteId}/params`);
  assert.ok(r.status === 404 || r.status === 410, "burned share must be gone");
  ok();

  // ── Delete + logout ────────────────────────────────────────────────
  step("delete paste removes it");
  r = await owner.del(`/api/pastes/${paste.pasteId}`, csrfFinal());
  assert.equal(r.status, 200);
  r = await owner.get(`/api/pastes/${paste.pasteId}`);
  assert.equal(r.status, 404);
  ok();

  step("logout kills the session");
  r = await owner.post("/api/auth/logout", undefined, csrfFinal());
  assert.equal(r.status, 200);
  r = await owner.get("/api/vault");
  assert.equal(r.status, 401);
  ok();

  process.stdout.write(`\nAll ${stepCount} live e2e steps passed.\n`);
}

main().catch((error) => {
  console.error(`\nLive e2e failed at step ${stepCount}:`);
  console.error(error);
  process.exit(1);
});
