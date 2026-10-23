#!/usr/bin/env node
/**
 * Phase-5 live checks: security headers, HSTS opt-in, X-Forwarded-For
 * handling, exponential share-unlock lockout, and no-store caching.
 *
 * Start two FRESH throwaway servers (RESET_DB=1 wipes them):
 *
 *   # plain server (no trusted proxies, no HSTS)
 *   DATABASE_PATH=/tmp/gb-e2e/plain.sqlite UPLOADS_DIR=/tmp/gb-e2e/plain-uploads \
 *   RESET_DB=1 PORT=8799 BIND_ADDR=127.0.0.1 cargo run
 *
 *   # proxied server (trusts the local proxy, HSTS on)
 *   DATABASE_PATH=/tmp/gb-e2e/proxied.sqlite UPLOADS_DIR=/tmp/gb-e2e/proxied-uploads \
 *   RESET_DB=1 PORT=8798 BIND_ADDR=127.0.0.1 TRUSTED_PROXIES=127.0.0.1 \
 *   HSTS_ENABLED=1 cargo run
 *
 * Then:
 *
 *   node --experimental-strip-types scripts/e2e-phase5.mjs \
 *     http://127.0.0.1:8799 http://127.0.0.1:8798
 *
 * The second URL is required — the XFF-honored and HSTS checks run against
 * the proxied server.
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
  importVaultKey,
  wrapPasteKeyForShare,
  wrapVaultKey,
} from "../src/lib/e2ee/index.ts";
import {
  encryptPasteFields,
  pasteKeyBytesForSummary,
  pasteKeyForSummary,
} from "../src/lib/paste.ts";

const BASE = process.argv[2] ?? "http://127.0.0.1:8799";
const PROXIED_BASE = process.argv[3];
const PASSPHRASE = "correct horse battery staple phase5";

let stepCount = 0;
function step(name) {
  stepCount += 1;
  process.stdout.write(`[${String(stepCount).padStart(2, "0")}] ${name} ... `);
}
function ok(extra = "") {
  process.stdout.write(`ok${extra ? ` — ${extra}` : ""}\n`);
}

async function rawFetch(base, path, options = {}) {
  const response = await fetch(`${base}${path}`, options);
  const text = await response.text();
  let data;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = text;
  }
  return { status: response.status, headers: response.headers, data };
}

function assertCommonSecurityHeaders(headers, { hsts }) {
  const csp = headers.get("content-security-policy") ?? "";
  for (const directive of [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' blob: data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
  ]) {
    assert.ok(csp.includes(directive), `CSP missing: ${directive}`);
  }
  assert.equal(headers.get("referrer-policy"), "no-referrer");
  assert.equal(headers.get("x-content-type-options"), "nosniff");
  assert.ok((headers.get("permissions-policy") ?? "").includes("camera=()"));
  assert.equal(headers.get("x-frame-options"), "DENY");
  if (hsts) {
    assert.equal(
      headers.get("strict-transport-security"),
      "max-age=31536000; includeSubDomains",
    );
  } else {
    assert.equal(headers.get("strict-transport-security"), null);
  }
}

async function setupServer(base) {
  const kdfSalt = generateKeySalt();
  const root = await deriveRootKey(PASSPHRASE, kdfSalt, DEFAULT_ARGON2_PARAMS);
  const authKey = await deriveAuthKey(root);
  const masterKey = await deriveMasterKey(root);
  const vaultBytes = generateVaultKey();
  const wrappedVaultKey = await wrapVaultKey(masterKey, vaultBytes);
  const response = await rawFetch(base, "/api/auth/setup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      authKey: bytesToBase64Url(authKey),
      kdfSalt: bytesToBase64Url(kdfSalt),
      kdfParams: { ...DEFAULT_ARGON2_PARAMS },
      wrappedVaultKey,
    }),
  });
  assert.equal(response.status, 201, `setup failed: ${JSON.stringify(response.data)}`);
  const cookies = new Map();
  for (const raw of response.headers.getSetCookie?.() ?? []) {
    const [pair] = raw.split(";");
    const eq = pair.indexOf("=");
    cookies.set(pair.slice(0, eq).trim(), pair.slice(eq + 1));
  }
  return {
    authKey,
    cookieHeader: [...cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; "),
    csrf: response.data.csrfToken,
    vaultHandle: await importVaultKey(vaultBytes),
  };
}

async function createPasteWithShare(base, session) {
  const pasteId = generatePasteId();
  const keySalt = generateKeySalt();
  const pasteKey = await pasteKeyForSummary(session.vaultHandle, {
    id: pasteId,
    keySalt: bytesToBase64Url(keySalt),
  });
  const ct = await encryptPasteFields(pasteKey, pasteId, {
    title: "phase5",
    content: "lockout probe\n",
    language: "plaintext",
  });
  let response = await rawFetch(base, "/api/pastes", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: session.cookieHeader,
      "X-CSRF-Token": session.csrf,
    },
    body: JSON.stringify({
      id: pasteId,
      keySalt: bytesToBase64Url(keySalt),
      titleCt: ct.titleCt,
      contentCt: ct.contentCt,
      languageCt: ct.languageCt,
    }),
  });
  assert.equal(response.status, 201, `paste create failed: ${JSON.stringify(response.data)}`);

  const shareSalt = generateShareSalt();
  const fragmentSecret = generateFragmentSecret();
  const code = generateShareCode();
  const shareKeys = await deriveShareKeys(code, shareSalt, fragmentSecret, DEFAULT_ARGON2_PARAMS);
  const pasteKeyBytes = await pasteKeyBytesForSummary(session.vaultHandle, {
    id: pasteId,
    keySalt: bytesToBase64Url(keySalt),
  });
  const wrappedPasteKey = await wrapPasteKeyForShare(
    shareKeys.wrapKey,
    pasteKeyBytes,
    pasteId,
    shareSalt,
  );
  response = await rawFetch(base, `/api/pastes/${pasteId}/share`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: session.cookieHeader,
      "X-CSRF-Token": session.csrf,
    },
    body: JSON.stringify({
      shareSalt: bytesToBase64Url(shareSalt),
      shareAuthKey: bytesToBase64Url(shareKeys.authKey),
      kdfParams: { ...DEFAULT_ARGON2_PARAMS },
      wrappedPasteKey,
    }),
  });
  assert.equal(response.status, 201, `share create failed: ${JSON.stringify(response.data)}`);
  return { pasteId, shareKeys, fragmentSecret, shareSalt };
}

async function postJson(base, path, body, headers = {}) {
  return rawFetch(base, path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body ?? {}),
  });
}

async function main() {
  if (!PROXIED_BASE) {
    console.error("usage: e2e-phase5.mjs <plain-base> <proxied-base>");
    console.error("the proxied server must run with TRUSTED_PROXIES and HSTS_ENABLED=1");
    process.exit(2);
  }

  // ── Security headers ───────────────────────────────────────────────
  step("plain server sends security headers without HSTS (static)");
  let response = await rawFetch(BASE, "/");
  assert.equal(response.status, 200);
  assertCommonSecurityHeaders(response.headers, { hsts: false });
  ok();

  step("plain server sends security headers without HSTS (API) + no-store");
  response = await rawFetch(BASE, "/api/auth/params");
  assert.equal(response.status, 200);
  assertCommonSecurityHeaders(response.headers, { hsts: false });
  assert.equal(response.headers.get("cache-control"), "no-store");
  ok();

  step("proxied server sends HSTS when HSTS_ENABLED=1");
  response = await rawFetch(PROXIED_BASE, "/api/ping");
  assert.equal(response.status, 200);
  assertCommonSecurityHeaders(response.headers, { hsts: true });
  ok();

  // ── Exponential share-unlock lockout (plan §7.4) ───────────────────
  step("share unlock lockout trips at 5 attempts/minute");
  const session = await setupServer(BASE);
  const share = await createPasteWithShare(BASE, session);
  const wrongKeys = await deriveShareKeys(
    "XXXXXXXXXXXXXX",
    share.shareSalt,
    share.fragmentSecret,
    DEFAULT_ARGON2_PARAMS,
  );

  // Each challenge issue and each failed proof records an attempt; after
  // five recorded attempts the next request is locked out.
  const wrongProofFor = async (nonce) =>
    bytesToBase64Url(await deriveShareProof(wrongKeys.authKey, nonce, share.pasteId));

  response = await postJson(BASE, `/api/shares/${share.pasteId}/challenge`, {});
  assert.equal(response.status, 200);
  response = await postJson(BASE, `/api/shares/${share.pasteId}/unlock`, {
    nonce: response.data.nonce,
    proof: await wrongProofFor(response.data.nonce),
  });
  assert.equal(response.status, 401);
  response = await postJson(BASE, `/api/shares/${share.pasteId}/challenge`, {});
  assert.equal(response.status, 200);
  response = await postJson(BASE, `/api/shares/${share.pasteId}/unlock`, {
    nonce: response.data.nonce,
    proof: await wrongProofFor(response.data.nonce),
  });
  assert.equal(response.status, 401);
  // Count is now 4; this challenge is the 5th allowed request…
  response = await postJson(BASE, `/api/shares/${share.pasteId}/challenge`, {});
  assert.equal(response.status, 200);
  // …so the next unlock attempt trips the base 60s lockout.
  response = await postJson(BASE, `/api/shares/${share.pasteId}/unlock`, {
    nonce: response.data.nonce,
    proof: await wrongProofFor(response.data.nonce),
  });
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), "60");
  ok("429 with Retry-After 60");

  step("locked-out share attempts extend the lockout exponentially");
  response = await postJson(BASE, `/api/shares/${share.pasteId}/challenge`, {});
  assert.equal(response.status, 429);
  const doubled = Number(response.headers.get("retry-after"));
  assert.ok(doubled >= 118 && doubled <= 120, `expected ~120, got ${doubled}`);
  response = await postJson(BASE, `/api/shares/${share.pasteId}/challenge`, {});
  assert.equal(response.status, 429);
  const quadrupled = Number(response.headers.get("retry-after"));
  assert.ok(
    quadrupled >= 236 && quadrupled <= 240,
    `expected ~240, got ${quadrupled}`,
  );
  ok(`Retry-After ${doubled} → ${quadrupled}`);
  // Enough — no need to burn minutes walking to the 15-minute cap; the
  // cap itself is covered by unit tests.

  // ── X-Forwarded-For handling (plan §9) ─────────────────────────────
  step("XFF is ignored without TRUSTED_PROXIES (plain server)");
  const badAuthKey = bytesToBase64Url(new Uint8Array(32).fill(9));
  for (let i = 0; i < 5; i += 1) {
    response = await postJson(
      BASE,
      "/api/auth/login",
      { authKey: badAuthKey },
      { "X-Forwarded-For": "198.51.100.10" },
    );
    assert.equal(response.status, 401);
  }
  // A different spoofed XFF must not grant a fresh bucket.
  response = await postJson(
    BASE,
    "/api/auth/login",
    { authKey: badAuthKey },
    { "X-Forwarded-For": "198.51.100.99" },
  );
  assert.equal(response.status, 429);
  ok("peer-based bucket, spoofed XFF does not rotate it");

  step("XFF resolves the client IP with TRUSTED_PROXIES (proxied server)");
  const proxiedSession = await setupServer(PROXIED_BASE);
  for (let i = 0; i < 5; i += 1) {
    response = await postJson(
      PROXIED_BASE,
      "/api/auth/login",
      { authKey: badAuthKey },
      { "X-Forwarded-For": "203.0.113.10" },
    );
    assert.equal(response.status, 401);
  }
  response = await postJson(
    PROXIED_BASE,
    "/api/auth/login",
    { authKey: badAuthKey },
    { "X-Forwarded-For": "203.0.113.10" },
  );
  assert.equal(response.status, 429, "same XFF client must hit its own bucket");
  response = await postJson(
    PROXIED_BASE,
    "/api/auth/login",
    { authKey: badAuthKey },
    { "X-Forwarded-For": "203.0.113.99, 127.0.0.5" },
  );
  assert.equal(response.status, 401, "new XFF client gets a fresh bucket");
  ok("per-client buckets keyed by XFF, right-to-left walk accepted");

  step("share unlock limiter keys on the XFF client behind the proxy");
  const proxiedShare = await createPasteWithShare(PROXIED_BASE, proxiedSession);
  const proxiedWrong = await deriveShareKeys(
    "YYYYYYYYYYYYYY",
    proxiedShare.shareSalt,
    proxiedShare.fragmentSecret,
    DEFAULT_ARGON2_PARAMS,
  );
  const xff = (client) => ({ "X-Forwarded-For": client });
  const lockedClient = "203.0.113.77";

  // A successful unlock through the proxy must clear the client's bucket.
  response = await postJson(
    PROXIED_BASE,
    `/api/shares/${proxiedShare.pasteId}/challenge`,
    {},
    xff(lockedClient),
  );
  assert.equal(response.status, 200);
  const rightProof = bytesToBase64Url(
    await deriveShareProof(proxiedShare.shareKeys.authKey, response.data.nonce, proxiedShare.pasteId),
  );
  response = await postJson(
    PROXIED_BASE,
    `/api/shares/${proxiedShare.pasteId}/unlock`,
    { nonce: response.data.nonce, proof: rightProof },
    xff(lockedClient),
  );
  assert.equal(response.status, 200, "right code must unlock through the proxy");

  // Wrong-code cycle until the bucket for that XFF client trips.
  let saw429 = false;
  for (let i = 0; i < 6 && !saw429; i += 1) {
    response = await postJson(
      PROXIED_BASE,
      `/api/shares/${proxiedShare.pasteId}/challenge`,
      {},
      xff(lockedClient),
    );
    if (response.status === 429) {
      saw429 = true;
      break;
    }
    const wrongProof = bytesToBase64Url(
      await deriveShareProof(proxiedWrong.authKey, response.data.nonce, proxiedShare.pasteId),
    );
    response = await postJson(
      PROXIED_BASE,
      `/api/shares/${proxiedShare.pasteId}/unlock`,
      { nonce: response.data.nonce, proof: wrongProof },
      xff(lockedClient),
    );
    if (response.status === 429) saw429 = true;
  }
  assert.ok(saw429, "locked XFF client must eventually hit 429");

  // A different XFF client must get a fresh bucket — proves the limiter
  // keys consistently on the resolved client IP, not the proxy peer.
  response = await postJson(
    PROXIED_BASE,
    `/api/shares/${proxiedShare.pasteId}/challenge`,
    {},
    xff("203.0.113.88"),
  );
  assert.equal(response.status, 200, "new XFF client must not inherit the lockout");
  ok("gate, record, and clear paths all key on the resolved client IP");

  console.log(`\nAll ${stepCount} phase-5 live checks passed.`);
}

main().catch((error) => {
  console.error(`\nFAILED at step ${stepCount}:`, error.message);
  process.exit(1);
});
