// Account connection: scoped token handling and pairing helpers.
import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { ApiError, RECONNECT_MESSAGE, createApi, newPairingSecret, parseStoredAuth, sha256Hex } from "../src/lib.js";

const BASE = "http://127.0.0.1:8000";
const TOKEN = "t".repeat(43);

function fakeFetch(status, body) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return new Response(body === undefined ? null : JSON.stringify(body), { status });
  };
  impl.calls = calls;
  return impl;
}

test("token is sent as a Bearer header only when connected, never with cookies", async () => {
  const withToken = fakeFetch(200, { site_domain: "shop.example.com", items: [] });
  await createApi(BASE, withToken, TOKEN).lookupSignups("shop.example.com");
  assert.equal(withToken.calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(withToken.calls[0].init.credentials, "omit");
  const without = fakeFetch(200, { site_domain: "shop.example.com", items: [] });
  await createApi(BASE, without).lookupSignups("shop.example.com");
  assert.ok(!("authorization" in without.calls[0].init.headers));
});

test("401 means reconnect, for every account call", async () => {
  const api = createApi(BASE, fakeFetch(401, { detail: "Sign in required." }), TOKEN);
  for (const call of [() => api.createSignup({}), () => api.lookupSignups("shop.example.com"), () => api.createReceipt({}), () => api.whoami()]) {
    await assert.rejects(call(), (e) => e instanceof ApiError && e.status === 401 && e.message === RECONNECT_MESSAGE);
  }
});

test("pairing start sends only the secret's hash and validates the reply", async () => {
  const secret = newPairingSecret(webcrypto);
  const hash = await sha256Hex(secret, webcrypto.subtle);
  const ok = fakeFetch(201, { pairing_id: 7, code: "K7QF-M2XR", expires_at: "2026-10-23T12:10:00Z", approve_path: "/dashboard#pair=K7QF-M2XR" });
  const started = await createApi(BASE, ok).startPairing(hash);
  assert.deepEqual(JSON.parse(ok.calls[0].init.body), { secret_hash: createHash("sha256").update(secret).digest("hex") });
  assert.ok(!ok.calls[0].init.body.includes(secret));
  assert.deepEqual(started, { pairingId: 7, code: "K7QF-M2XR", expiresAt: Date.parse("2026-10-23T12:10:00Z"), approvePath: "/dashboard#pair=K7QF-M2XR" });
  for (const bad of [{ pairing_id: "7", code: "K7QF-M2XR", approve_path: "/dashboard#pair=x" },
                     { pairing_id: 7, code: "<b>", approve_path: "/dashboard#pair=x" },
                     { pairing_id: 7, code: "K7QF-M2XR", approve_path: "https://evil.example/" }]) {
    await assert.rejects(createApi(BASE, fakeFetch(201, bad)).startPairing(hash), /unexpected pairing/);
  }
});

test("exchange: pending, success, expiry and malformed replies", async () => {
  assert.deepEqual(await createApi(BASE, fakeFetch(202, { detail: "Waiting" })).exchangePairing(7, "s".repeat(43)), { pending: true });
  const expires = new Date(Date.now() + 3600_000).toISOString();
  const auth = await createApi(BASE, fakeFetch(200, { token: TOKEN, expires_at: expires, email: "alice@example.com", scopes: [] }))
    .exchangePairing(7, "s".repeat(43));
  assert.deepEqual(auth, { token: TOKEN, expiresAt: Date.parse(expires), email: "alice@example.com" });
  await assert.rejects(createApi(BASE, fakeFetch(410, { detail: "This pairing expired or was already used. Start again." }))
    .exchangePairing(7, "s"), /expired/);
  await assert.rejects(createApi(BASE, fakeFetch(200, { token: "short", expires_at: expires, email: "a@b.c" })).exchangePairing(7, "s"), /unexpected token/);
});

test("stored connection is rejected when expired or malformed", () => {
  const now = 1_000_000;
  const good = { token: TOKEN, expiresAt: now + 1, email: "alice@example.com" };
  assert.deepEqual(parseStoredAuth(good, now), good);
  for (const bad of [null, "x", { ...good, expiresAt: now }, { ...good, token: "short" }, { ...good, token: `${TOKEN} x` },
                     { ...good, email: "nobody" }, { ...good, expiresAt: "soon" }]) {
    assert.equal(parseStoredAuth(bad, now), null, JSON.stringify(bad));
  }
});

test("pairing secrets are random and URL-safe", () => {
  const secrets = new Set(Array.from({ length: 50 }, () => newPairingSecret(webcrypto)));
  assert.equal(secrets.size, 50);
  for (const s of secrets) assert.match(s, /^[A-Za-z0-9_-]{43}$/);
});

test("the token is kept only in session storage and never logged or shown", () => {
  const files = ["../popup.js", "../options.js", "../src/lib.js"].map((f) => readFileSync(new URL(f, import.meta.url), "utf8"));
  const all = files.join("\n");
  assert.match(all, /chrome\.storage\.session\.set\(\{ auth: result \}\)/);
  assert.ok(!/chrome\.storage\.local\.set\(\{\s*auth/.test(all), "token must never go to local storage");
  assert.ok(!/chrome\.storage\.sync/.test(all));
  assert.ok(!/console\.\w+\([^)]*token/i.test(all), "token must never be logged");
  assert.ok(!/textContent\s*=\s*[^;]*\.token/.test(all), "token must never be displayed");
});

// ---------- wrong or outdated backend ----------

import { DEFAULT_BASE_URL, OUTDATED_BACKEND_MESSAGE } from "../src/lib.js";

test("the default backend is local-only and passes validation", async () => {
  const { validateBaseUrl } = await import("../src/lib.js");
  assert.equal(DEFAULT_BASE_URL, "http://127.0.0.1:8000");
  assert.equal(validateBaseUrl(DEFAULT_BASE_URL), DEFAULT_BASE_URL);
});

test("checkBackend: current API, outdated server, unreachable, other errors", async () => {
  const at = (status) => createApi("http://127.0.0.1:8003", fakeFetch(status, { detail: "x" }));
  assert.equal((await at(401).checkBackend()).ok, true);
  assert.equal((await at(200).checkBackend()).ok, true);
  const outdated = await at(404).checkBackend();
  assert.deepEqual([outdated.ok, outdated.reason, outdated.message], [false, "outdated", OUTDATED_BACKEND_MESSAGE]);
  assert.equal((await at(500).checkBackend()).reason, "error");
  const down = await createApi("http://127.0.0.1:8003", async () => { throw new TypeError("Failed to fetch"); }).checkBackend();
  assert.equal(down.reason, "unreachable");
  const sent = fakeFetch(401, {});
  await createApi(DEFAULT_BASE_URL, sent, TOKEN).checkBackend();
  assert.equal(sent.calls[0].url, "http://127.0.0.1:8000/auth/me");
  assert.equal(sent.calls[0].init.credentials, "omit");
  assert.ok(!("authorization" in sent.calls[0].init.headers), "no token sent to an unverified backend");
});

test("a missing route (FastAPI 'Not Found') is reported as an outdated backend", async () => {
  await assert.rejects(createApi("http://127.0.0.1:8003", fakeFetch(404, { detail: "Not Found" })).startPairing("a".repeat(64)),
    (e) => e.message === OUTDATED_BACKEND_MESSAGE);
  // The app's own 404s keep their meaning.
  await assert.rejects(createApi(DEFAULT_BASE_URL, fakeFetch(404, { detail: "Signup not found" }), TOKEN).createReceipt({}),
    /Signup not found/);
});
