import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import { test } from "node:test";

import {
  ApiError, RECEIPT_ACTIONS, buildReceiptPayload, buildSignupPayload, copyText, createApi,
  describePayload, hostnameFromTabUrl, normalizeDomain, policyUrlFromPage, sha256Hex, validateBaseUrl,
} from "../src/lib.js";

const BASE = "http://127.0.0.1:8000";
const subtle = webcrypto.subtle;

function fakeFetch(status, body, { raw = false } = {}) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    if (status instanceof Error) throw status;
    return new Response(raw ? body : JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  };
  impl.calls = calls;
  return impl;
}

// ---------- hostnames ----------

for (const [url, expected] of [
  ["https://www.Example.com/path?q=1#x", "example.com"],
  ["http://shop.example.co.uk/", "shop.example.co.uk"],
  ["https://bücher.de/", "xn--bcher-kva.de"],
  ["https://example.com:8443/", "example.com"],
  ["chrome://extensions/", null], ["chrome-extension://abc/popup.html", null], ["file:///etc/passwd", null],
  ["about:blank", null], ["https://localhost/", null], ["http://127.0.0.1:8000/dashboard", null],
  ["https://[::1]/", null], ["not a url", null], [undefined, null], [null, null],
]) {
  test(`hostnameFromTabUrl(${url})`, () => assert.equal(hostnameFromTabUrl(url), expected));
}

test("normalizeDomain accepts bare domains and rejects the rest", () => {
  assert.equal(normalizeDomain("  WWW.Shop.Example.COM. "), "shop.example.com");
  for (const bad of ["", "example", "https://example.com", "example.com/x", "a@example.com", "-x.com", "a..b.com", "1.2.3.4", "ex ample.com"]) {
    assert.throws(() => normalizeDomain(bad), Error, bad);
  }
});

test("validateBaseUrl only allows http://127.0.0.1:<port>", () => {
  assert.equal(validateBaseUrl("http://127.0.0.1:8000"), BASE);
  assert.equal(validateBaseUrl(" http://127.0.0.1:8000/ "), BASE);
  for (const bad of ["", "127.0.0.1:8000", "https://127.0.0.1:8000", "http://localhost:8000", "http://0.0.0.0:8000",
    "http://api.example.com", "http://127.0.0.1:8000/api", "http://user:pw@127.0.0.1:8000", "http://127.0.0.1:8000?x=1"]) {
    assert.throws(() => validateBaseUrl(bad), Error, bad);
  }
});

test("policyUrlFromPage strips query strings and fragments", () => {
  assert.equal(policyUrlFromPage("https://shop.example.com/privacy?session=SECRET#top"), "https://shop.example.com/privacy");
  assert.equal(policyUrlFromPage("chrome://settings"), null);
  assert.equal(policyUrlFromPage(null), null);
});

// ---------- signup payload ----------

test("signup payload matches the backend schema and never includes user_id", () => {
  const payload = buildSignupPayload({ siteName: "  Example   Shop ", siteDomain: "www.shop.example.com" });
  assert.deepEqual(payload, {
    site_name: "Example Shop", site_domain: "shop.example.com", real_name_required: false,
    generate_alias: true, generate_nickname: true,
  });
  assert.ok(!("user_id" in payload));
});

test("signup payload validation", () => {
  assert.throws(() => buildSignupPayload({ siteName: "!!!", siteDomain: "example.com" }), /letter or digit/);
  assert.throws(() => buildSignupPayload({ siteName: "x".repeat(256), siteDomain: "example.com" }), /at most/);
  assert.throws(() => buildSignupPayload({ siteName: "Shop", siteDomain: "https://x.com" }), /only the domain/);
  const real = buildSignupPayload({ siteName: "Bank", siteDomain: "bank.example", realNameRequired: true, generateNickname: false });
  assert.equal(real.real_name_required, true);
  assert.equal(real.generate_nickname, false);
});

// ---------- API: signups ----------

test("createSignup sends the payload once and returns only backend values", async () => {
  const fetchImpl = fakeFetch(201, { id: 7, site_name: "Shop", site_domain: "shop.example.com", alias: "ab12@leaktrap.xyz",
    nickname: "Ocelot", real_name_required: false, user_id: null, created_at: "x", updated_at: "x" });
  const api = createApi(BASE, fetchImpl);
  const payload = buildSignupPayload({ siteName: "Shop", siteDomain: "shop.example.com" });
  const result = await api.createSignup(payload);
  assert.deepEqual(result, { id: 7, siteName: "Shop", siteDomain: "shop.example.com", alias: "ab12@leaktrap.xyz",
    nickname: "Ocelot", realNameRequired: false });
  assert.equal(fetchImpl.calls.length, 1);
  const [{ url, init }] = fetchImpl.calls;
  assert.equal(url, `${BASE}/signups`);
  assert.equal(init.method, "POST");
  assert.equal(init.credentials, "omit");
  assert.deepEqual(JSON.parse(init.body), payload);
  assert.ok(!("authorization" in init.headers));
});

test("missing alias in a successful response stays missing (never invented)", async () => {
  const api = createApi(BASE, fakeFetch(201, { id: 8, site_name: "Shop", site_domain: null, alias: null, nickname: null }));
  const result = await api.createSignup({});
  assert.equal(result.alias, null);
  assert.equal(result.nickname, null);
});

for (const [name, fetchImpl, pattern] of [
  ["422 with field errors", fakeFetch(422, { detail: [{ loc: ["body", "site_domain"], msg: "Value error, domain must be a full domain name", input: "x" }] }), /site_domain: domain must be a full domain name/],
  ["503 string detail", fakeFetch(503, { detail: "Alias generation needs LEAKTRACE_ALIAS_DOMAIN to be configured." }), /LEAKTRACE_ALIAS_DOMAIN/],
  ["409 nickname exhaustion", fakeFetch(409, { detail: "All 99 curated nicknames are already used" }), /nicknames/],
  ["500 non-JSON", fakeFetch(500, "Internal Server Error", { raw: true }), /HTTP 500/],
  ["403 not local", fakeFetch(403, {}), /only accepts requests from this computer/],
  ["network failure", fakeFetch(new TypeError("Failed to fetch")), /Could not reach the LeakTrace backend/],
  ["200 but malformed body", fakeFetch(200, { unexpected: true }), /unexpected signup response/],
  ["200 but not JSON", fakeFetch(200, "<html>", { raw: true }), /unexpected response/],
]) {
  test(`createSignup failure: ${name} raises ApiError and returns no alias`, async () => {
    const api = createApi(BASE, fetchImpl);
    let result;
    await assert.rejects(async () => { result = await api.createSignup({ site_name: "Shop" }); }, (error) => {
      assert.ok(error instanceof ApiError);
      assert.match(error.message, pattern);
      assert.ok(!error.message.includes("ab12"));
      return true;
    });
    assert.equal(result, undefined);
  });
}

test("createApi refuses a non-local base URL before any request", () => {
  const fetchImpl = fakeFetch(201, {});
  assert.throws(() => createApi("https://api.example.com", fetchImpl));
  assert.equal(fetchImpl.calls.length, 0);
});

// ---------- receipts ----------

const NOTICE = "We may share your data with partners.\n";

test("receipt actions match the backend vocabulary", () => {
  assert.deepEqual(RECEIPT_ACTIONS, ["accepted", "declined", "notice_only"]);
});

test("notice text is hashed locally and not sent by default", async () => {
  const payload = await buildReceiptPayload({ signupId: "5", action: "notice_only", noticeText: NOTICE }, subtle);
  assert.deepEqual(payload, { signup_id: 5, action: "notice_only",
    content_hash: createHash("sha256").update(NOTICE).digest("hex") });
});

test("notice text is sent only when the user opts in", async () => {
  const payload = await buildReceiptPayload({ signupId: 5, action: "accepted", noticeText: NOTICE, storeNoticeText: true }, subtle);
  assert.equal(payload.notice_text, NOTICE);
  assert.ok(!("content_hash" in payload));  // the backend computes it from the text
});

test("full receipt payload", async () => {
  const payload = await buildReceiptPayload({
    signupId: "3", action: "declined", sourceUrl: " https://shop.example.com/privacy ", noticeVersion: "  2026-01-15 ",
    consentText: "I agree", occurredAt: "2026-10-01T09:30:00Z",
  }, subtle);
  assert.deepEqual(payload, { signup_id: 3, action: "declined", source_url: "https://shop.example.com/privacy",
    notice_version: "2026-01-15", consent_text: "I agree", reported_occurred_at: "2026-10-01T09:30:00.000Z" });
});

for (const [name, form, pattern] of [
  ["no signup", { action: "accepted", sourceUrl: "https://x.example" }, /Choose a signup/],
  ["signup 0", { signupId: 0, action: "accepted", sourceUrl: "https://x.example" }, /Choose a signup/],
  ["no action chosen", { signupId: 1, action: "", sourceUrl: "https://x.example" }, /Choose what you did/],
  ["unsupported action", { signupId: 1, action: "verified", sourceUrl: "https://x.example" }, /Choose what you did/],
  ["javascript URL", { signupId: 1, action: "accepted", sourceUrl: "javascript:alert(1)" }, /http or https/],
  ["credentials in URL", { signupId: 1, action: "accepted", sourceUrl: "https://u:p@x.example" }, /without credentials/],
  ["bad URL", { signupId: 1, action: "accepted", sourceUrl: "not a url" }, /not a valid URL/],
  ["no evidence", { signupId: 1, action: "accepted" }, /at least/],
  ["notice too long", { signupId: 1, action: "accepted", noticeText: "x".repeat(20_001) }, /at most 20000/],
  ["consent too long", { signupId: 1, action: "accepted", consentText: "x".repeat(2_001) }, /at most 2000/],
  ["bad date", { signupId: 1, action: "accepted", sourceUrl: "https://x.example", occurredAt: "yesterday" }, /not a valid date/],
  ["future date", { signupId: 1, action: "accepted", sourceUrl: "https://x.example", occurredAt: new Date(Date.now() + 86_400_000).toISOString() }, /future/],
]) {
  test(`receipt validation: ${name}`, async () => {
    await assert.rejects(buildReceiptPayload(form, subtle), pattern);
  });
}

test("createReceipt posts once and surfaces backend scope errors", async () => {
  const ok = fakeFetch(201, { id: 11, site_name: "Shop", evidence_basis: "user_reported" });
  const receipt = await createApi(BASE, ok).createReceipt({ signup_id: 1, action: "accepted", source_url: "https://x.example" });
  assert.equal(receipt.id, 11);
  assert.equal(ok.calls[0].url, `${BASE}/consent-receipts`);
  assert.ok(!("user_id" in JSON.parse(ok.calls[0].init.body)));
  assert.ok(!ok.calls[0].url.includes("user_id"));

  await assert.rejects(createApi(BASE, fakeFetch(404, { detail: "Signup not found in this scope" })).createReceipt({}),
    /Signup not found in this scope/);
});

test("describePayload lists exactly the fields being sent, without echoing long text", () => {
  const rows = describePayload({ signup_id: 2, action: "accepted", notice_text: "x".repeat(50), content_hash: "ab" });
  assert.deepEqual(rows, [["Signup ID", "2"], ["Reported action", "accepted"], ["Notice text (stored)", "50 characters"],
    ["Notice text SHA-256 (text not sent)", "ab"]]);
});

test("sha256Hex matches Node's implementation", async () => {
  assert.equal(await sha256Hex("abc", subtle), createHash("sha256").update("abc").digest("hex"));
  await assert.rejects(sha256Hex("abc", null), /cannot compute/);
});

// ---------- clipboard ----------

test("copyText reports success and failure honestly", async () => {
  const written = [];
  assert.equal(await copyText("ab12@leaktrap.xyz", { writeText: async (t) => written.push(t) }), true);
  assert.deepEqual(written, ["ab12@leaktrap.xyz"]);
  assert.equal(await copyText("x", { writeText: async () => { throw new Error("denied"); } }), false);
  assert.equal(await copyText("x", undefined), false);
  assert.equal(await copyText("", { writeText: async () => {} }), false);
});
