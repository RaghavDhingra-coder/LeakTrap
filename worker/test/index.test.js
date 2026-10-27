// Run with: cd worker && npm test   (Node's built-in test runner, no dependencies)
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import worker, { PAYLOAD_FIELDS, buildPayload, handleEmail, ingestSecretProblem, parseFallbackAddress } from "../src/index.js";

const SECRET = "s".repeat(40);
const ENV = {
  ALIAS_DOMAIN: "leaktrap.xyz",
  INGEST_URL: "https://api.example.test/ingest/email",
  INGEST_SECRET: SECRET,
};

function fakeMessage(overrides = {}) {
  const message = {
    from: "bounce@mailer.example",
    to: "Ab12@LeakTrap.xyz",
    headers: new Headers({
      from: "Deals <deals@broker.example>",
      subject: "Hi Ocelot",
      "message-id": "<abc@mailer.example>",
      "arc-authentication-results": "i=1; mx.cloudflare.net; spf=pass smtp.mailfrom=bounce@mailer.example",
    }),
    rejected: null,
    forwardedTo: [],
    setReject(reason) { this.rejected = reason; },
    async forward(address) { this.forwardedTo.push(address); },
    get raw() { throw new Error("raw message must not be read"); },
    ...overrides,
  };
  return message;
}

function fakeFetch(result) {
  const calls = [];
  const statusCalls = [];
  const impl = async (url, init) => {
    if (new URL(url).pathname.endsWith("/alias-status")) {
      statusCalls.push({ url, init });
      return new Response(JSON.stringify({ status: "active", block_promotional_emails: false }), { status: 200 });
    }
    calls.push({ url, init });
    if (result instanceof Error) throw result;
    return new Response(null, { status: result });
  };
  impl.calls = calls;
  impl.statusCalls = statusCalls;
  return impl;
}

let logged;
const originalError = console.error;
const originalLog = console.log;
beforeEach(() => {
  logged = [];
  console.error = (...args) => logged.push(args.join(" "));
  console.log = (...args) => logged.push(args.join(" "));
});
afterEach(() => { console.error = originalError; console.log = originalLog; });

const FALLBACK = "me.inbox@example.com";
const WITH_FALLBACK = { ...ENV, FALLBACK_ADDRESS: FALLBACK };
const FAST = { timeouts: [20, 40] };  // short per-attempt timeouts for tests

function assertNothingSensitiveLogged(extra = []) {
  const text = logged.join("\n").toLowerCase();
  for (const secret of [SECRET, `bearer ${SECRET}`, "ab12@leaktrap.xyz", "broker.example", "ocelot", "mailer.example",
    "me.inbox", "@example.com", ...extra]) {
    assert.ok(!text.includes(secret.toLowerCase()), `log contains ${secret}`);
  }
}

/** Fetch stub: each call takes the next step (a status, an Error, or "hang" until aborted). */
function scriptedFetch(...steps) {
  const calls = [];
  const statusCalls = [];
  const impl = (url, init) => {
    if (new URL(url).pathname.endsWith("/alias-status")) {
      statusCalls.push({ url, init });
      return Promise.resolve(new Response(JSON.stringify({ status: "active", block_promotional_emails: false }), { status: 200 }));
    }
    const step = steps[Math.min(calls.length, steps.length - 1)];
    calls.push({ url, init, at: Date.now() });
    if (step === "hang") {
      return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
    }
    if (step instanceof Error) return Promise.reject(step);
    return Promise.resolve(new Response(null, { status: step }));
  };
  impl.calls = calls;
  impl.statusCalls = statusCalls;
  return impl;
}

function failingForward(error) {
  return { async forward() { this.forwardAttempts = (this.forwardAttempts ?? 0) + 1; throw error; } };
}

test("payload contains only the agreed minimal fields", () => {
  const payload = buildPayload(fakeMessage(), new Date("2026-10-22T10:00:00Z"));
  assert.deepEqual(Object.keys(payload), PAYLOAD_FIELDS);
  assert.deepEqual(payload, {
    recipient: "ab12@leaktrap.xyz",
    envelope_from: "bounce@mailer.example",
    from_header: "Deals <deals@broker.example>",
    subject: "Hi Ocelot",
    message_id: "<abc@mailer.example>",
    received_at: "2026-10-22T10:00:00.000Z",
    auth_results: "i=1; mx.cloudflare.net; spf=pass smtp.mailfrom=bounce@mailer.example",
  });
});

test("the envelope recipient is sent, not the To or Cc headers", () => {
  const payload = buildPayload(fakeMessage({
    to: " Cd34@LeakTrap.xyz ",
    headers: new Headers({ to: "ab12@leaktrap.xyz, ef56@leaktrap.xyz", cc: "gh78@leaktrap.xyz" }),
  }));
  assert.equal(payload.recipient, "cd34@leaktrap.xyz");
  assert.ok(!JSON.stringify(payload).includes("ab12") && !JSON.stringify(payload).includes("gh78"));
});

test("missing headers become null and long headers are truncated", () => {
  const payload = buildPayload(fakeMessage({
    from: "",
    headers: new Headers({ subject: "x".repeat(5000) }),
  }));
  assert.equal(payload.envelope_from, null);
  assert.equal(payload.from_header, null);
  assert.equal(payload.message_id, null);
  assert.equal(payload.subject.length, 998);
  assert.equal(payload.auth_results, null);
  const long = buildPayload(fakeMessage({ headers: new Headers({ "arc-authentication-results": "a".repeat(5000) }) }));
  assert.equal(long.auth_results.length, 2000);
});

// ---------- delivery: forward the original, then record metadata ----------

test("active alias is verified before forwarding using the authenticated backend route", async () => {
  const message = fakeMessage();
  const fetchImpl = scriptedFetch(201);
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "forwarded_and_recorded");
  assert.equal(fetchImpl.statusCalls.length, 1);
  const [check] = fetchImpl.statusCalls;
  assert.equal(check.url, "https://api.example.test/ingest/alias-status");
  assert.equal(check.init.method, "POST");
  assert.deepEqual(JSON.parse(check.init.body), { recipient: "ab12@leaktrap.xyz" });
  assert.equal(check.init.headers.authorization, `Bearer ${SECRET}`);
  assert.deepEqual(message.forwardedTo, [FALLBACK]);
});

for (const [label, status, expected] of [
  ["revoked", { status: "revoked" }, "alias_revoked"],
  ["unknown", { status: "unverifiable" }, "alias_unverified"],
  ["malformed", { status: "active-ish" }, "alias_unverified"],
]) {
  test(`revoked or ${label} alias is never forwarded or recorded`, async () => {
    const message = fakeMessage();
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url, init });
      return new Response(JSON.stringify(status), { status: 200 });
    };
    const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
    assert.equal(result.outcome, expected);
    assert.deepEqual(message.forwardedTo, []);
    assert.ok(message.rejected);
    assert.equal(calls.length, 1);
    assert.ok(calls[0].url.endsWith("/alias-status"));
    assertNothingSensitiveLogged();
  });
}

test("alias-status outage fails closed and never tries FALLBACK_ADDRESS", async () => {
  const message = fakeMessage();
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return new Response("unavailable", { status: 503 });
  };
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "alias_unverified");
  assert.deepEqual(message.forwardedTo, []);
  assert.equal(calls.length, 2); // bounded retry
  assert.ok(calls.every((url) => url.endsWith("/alias-status")));
});

test("alias-status timeout retries only the status lookup and never forwards", async () => {
  const message = fakeMessage();
  const calls = [];
  const fetchImpl = (url, init) => {
    calls.push(url);
    return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason)));
  };
  assert.equal((await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST)).outcome, "alias_unverified");
  assert.equal(calls.length, 2);
  assert.ok(calls.every((url) => url.endsWith("/alias-status")));
  assert.deepEqual(message.forwardedTo, []);
});

test("alias-status authentication failure fails closed without trying fallback", async () => {
  const message = fakeMessage();
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return new Response("unauthorized", { status: 401 });
  };
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "alias_unverified");
  assert.deepEqual(message.forwardedTo, []);
  assert.deepEqual(calls, ["https://api.example.test/ingest/alias-status"]);
});

test("alias-status network error fails closed", async () => {
  const message = fakeMessage();
  const fetchImpl = async () => { throw new TypeError("network unavailable"); };
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "alias_unverified");
  assert.deepEqual(message.forwardedTo, []);
  assert.match(logged.join(), /network error \(TypeError: network unavailable\)/);
});

test("missing deployed status route fails closed even when the ingest route still works", async () => {
  const message = fakeMessage();
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return new Response("Not Found", { status: 404 });
  };
  assert.equal((await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST)).outcome, "alias_unverified");
  assert.deepEqual(message.forwardedTo, []);
  assert.ok(message.rejected);
  assert.deepEqual(calls, ["https://api.example.test/ingest/alias-status"]);
});

test("revocation before a new delivery blocks it; restoration permits a later delivery", async () => {
  let status = "active";
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    return url.endsWith("/alias-status")
      ? new Response(JSON.stringify({ status, ...(status === "active" ? { block_promotional_emails: false } : {}) }), { status: 200 })
      : new Response(null, { status: 201 });
  };
  const first = fakeMessage();
  assert.equal((await handleEmail(first, WITH_FALLBACK, fetchImpl, FAST)).outcome, "forwarded_and_recorded");
  status = "revoked";
  const blocked = fakeMessage();
  assert.equal((await handleEmail(blocked, WITH_FALLBACK, fetchImpl, FAST)).outcome, "alias_revoked");
  assert.deepEqual(blocked.forwardedTo, []);
  status = "active";
  const restored = fakeMessage();
  assert.equal((await handleEmail(restored, WITH_FALLBACK, fetchImpl, FAST)).outcome, "forwarded_and_recorded");
  assert.deepEqual(restored.forwardedTo, [FALLBACK]);
  assert.equal(calls.filter(({ url }) => url.endsWith("/alias-status")).length, 3);
  assert.equal(calls.filter(({ url }) => url.endsWith("/email")).length, 2);
});

test("failed status retry cannot bypass the check or reach fallback", async () => {
  const message = fakeMessage();
  let attempts = 0;
  const fetchImpl = async (url) => {
    assert.ok(url.endsWith("/alias-status"));
    attempts += 1;
    return new Response(attempts === 1 ? "unavailable" : JSON.stringify({ status: "revoked" }),
      { status: attempts === 1 ? 503 : 200 });
  };
  assert.equal((await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST)).outcome, "alias_revoked");
  assert.equal(attempts, 2);
  assert.deepEqual(message.forwardedTo, []);
});

for (const response of [
  new Response(JSON.stringify({ status: "active", block_promotional_emails: false }), { status: 201 }),
  new Response(JSON.stringify({ status: "active", block_promotional_emails: false }), { status: 302, headers: { location: "https://other.example/" } }),
  new Response("{invalid", { status: 200 }),
]) {
  test(`unexpected status response HTTP ${response.status} blocks forwarding`, async () => {
    const message = fakeMessage();
    const fetchImpl = async (url, init) => {
      assert.ok(url.endsWith("/alias-status"));
      assert.equal(init.redirect, "manual");
      return response.clone();
    };
    assert.equal((await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST)).outcome, "alias_unverified");
    assert.deepEqual(message.forwardedTo, []);
  });
}

test("valid ingestion and successful forwarding", async () => {
  const order = [];
  const message = fakeMessage({ async forward(address) { order.push("forward"); this.forwardedTo.push(address); } });
  const fetchImpl = async (url, init) => {
    if (new URL(url).pathname.endsWith("/alias-status")) {
      order.push("status");
      return new Response(JSON.stringify({ status: "active", block_promotional_emails: false }), { status: 200 });
    }
    order.push("record"); fetchImpl.calls.push({ url, init }); return new Response(null, { status: 201 });
  };
  fetchImpl.calls = [];
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl);
  assert.deepEqual(result, { outcome: "forwarded_and_recorded", status: 201, attempts: 1 });
  assert.deepEqual(order, ["status", "forward", "record"]);
  assert.deepEqual(message.forwardedTo, [FALLBACK]);
  const [{ url, init }] = fetchImpl.calls;
  assert.equal(url, ENV.INGEST_URL);
  assert.equal(init.method, "POST");
  assert.equal(init.headers.authorization, `Bearer ${SECRET}`);
  assert.equal(init.headers["content-type"], "application/json");
  assert.deepEqual(Object.keys(JSON.parse(init.body)), PAYLOAD_FIELDS);
  assert.equal(message.rejected, null);
  assert.match(logged.join(), /forwarded and recorded \(HTTP 201, attempt 1\)/);
  assertNothingSensitiveLogged();
});

test("duplicate ingestion (HTTP 200) counts as recorded and is not retried", async () => {
  const message = fakeMessage();
  const fetchImpl = scriptedFetch(200);
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.deepEqual(result, { outcome: "forwarded_and_recorded", status: 200, attempts: 1 });
  assert.equal(fetchImpl.calls.length, 1);
  assert.deepEqual(message.forwardedTo, [FALLBACK]);
});

test("forwarding failure is not reported as delivered; metadata is still recorded", async () => {
  // Cloudflare's own wording, including an address, must not reach the logs.
  const message = fakeMessage(failingForward(new Error(`destination address is invalid: ${FALLBACK} Missing domain or user`)));
  const fetchImpl = scriptedFetch(201);
  await assert.rejects(handleEmail(message, WITH_FALLBACK, fetchImpl, FAST), /could not forward the message/);
  assert.equal(message.forwardAttempts, 1);  // never retried within the run
  assert.equal(fetchImpl.calls.length, 1);
  const text = logged.join("\n");
  assert.match(text, /\[forward\] forwarding failed \(Error: destination address is invalid: <(address|redacted)> Missing domain or user\)/);
  assert.match(text, /metadata recorded \(HTTP 201\)/);
  assertNothingSensitiveLogged();
});

test("forwarding failure and recording failure: thrown, nothing claimed", async () => {
  const message = fakeMessage(failingForward(new Error("destination address not verified")));
  await assert.rejects(handleEmail(message, WITH_FALLBACK, scriptedFetch(503), FAST), /could not forward/);
  assert.match(logged.join(), /metadata not recorded \(attempt 1: backend returned HTTP 503; attempt 2: backend returned HTTP 503\)/);
});

test("backend timeout, then the retry succeeds (cold start); forwarded exactly once", async () => {
  const message = fakeMessage();
  const fetchImpl = scriptedFetch("hang", 201);
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.deepEqual(result, { outcome: "forwarded_and_recorded", status: 201, attempts: 2 });
  assert.deepEqual(message.forwardedTo, [FALLBACK]);
  assert.equal(fetchImpl.calls[0].init.body, fetchImpl.calls[1].init.body);  // identical retry: deduplicated
});

test("backend times out on every attempt: delivered, not recorded, not thrown", async () => {
  const message = fakeMessage();
  const fetchImpl = scriptedFetch("hang");
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "forwarded_not_recorded");
  assert.match(result.reason, /network error \(TimeoutError: /);
  assert.equal(result.attempts, 2);
  assert.deepEqual(message.forwardedTo, [FALLBACK]);  // a throw here would make the sender retry: a second copy
  assert.match(logged.join(), /\[record\] forwarded, but metadata was not recorded \(attempt 1: network error \(TimeoutError: .*; attempt 2: network error \(TimeoutError: /);
  assertNothingSensitiveLogged();
});

const REASONS = {
  401: "backend rejected INGEST_SECRET (HTTP 401): it does not match LEAKTRACE_INGEST_SECRET on Render",
  422: "backend rejected the payload (HTTP 422)",
};
for (const [status, attempts] of [[502, 2], [503, 2], [504, 2], [401, 1], [413, 1], [422, 1], [500, 1]]) {
  test(`backend HTTP ${status}: original still delivered, ${attempts === 2 ? "retried once" : "not retried"}`, async () => {
    const message = fakeMessage();
    const fetchImpl = scriptedFetch(status);
    const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
    const reason = REASONS[status] ?? `backend returned HTTP ${status}`;
    assert.deepEqual(result, { outcome: "forwarded_not_recorded", reason, attempts });
    assert.equal(fetchImpl.calls.length, attempts);
    assert.deepEqual(message.forwardedTo, [FALLBACK]);
    assertNothingSensitiveLogged();
  });
}

test("network error then success", async () => {
  const result = await handleEmail(fakeMessage(), WITH_FALLBACK, scriptedFetch(new TypeError("fetch failed"), 201), FAST);
  assert.deepEqual(result, { outcome: "forwarded_and_recorded", status: 201, attempts: 2 });
});

// ---------- FALLBACK_ADDRESS configuration ----------

test("no FALLBACK_ADDRESS: recorded, and the missing forward is logged", async () => {
  const message = fakeMessage();
  const result = await handleEmail(message, ENV, scriptedFetch(201), FAST);
  assert.deepEqual(result, { outcome: "recorded_not_forwarded", status: 201, attempts: 1 });
  assert.deepEqual(message.forwardedTo, []);
  assert.match(logged.join(), /not forwarded: no FALLBACK_ADDRESS configured/);
});

test("no FALLBACK_ADDRESS and recording fails: thrown so it is visible", async () => {
  const message = fakeMessage();
  await assert.rejects(handleEmail(message, ENV, scriptedFetch(500), FAST), /ingest failed \(backend returned HTTP 500\)/);
  assertNothingSensitiveLogged();
});

for (const [name, value, problem] of [
  ["no domain", "me.inbox@example", /domain after @ is missing or invalid/],
  ["no user", "@example.com", /user part before @ is missing/],
  ["no @", "me.inbox.example.com", /exactly one @ \(found 0\)/],
  ["two addresses", "me.inbox@example.com, other@example.com", /contains 2 email addresses/],
  ["only quotes", '""', /empty after removing quotes/],
  ["space inside", "me inbox@example.com", /address plus other text/],
  ["text without @", "me inbox example", /spaces, commas or semicolons/],
]) {
  test(`malformed FALLBACK_ADDRESS (${name}): never passed to forward, recorded, thrown, value not logged`, async () => {
    const message = fakeMessage();
    const fetchImpl = scriptedFetch(201);
    await assert.rejects(handleEmail(message, { ...ENV, FALLBACK_ADDRESS: value }, fetchImpl, FAST),
      /FALLBACK_ADDRESS is invalid/);
    assert.deepEqual(message.forwardedTo, []);
    assert.equal(fetchImpl.calls.length, 1);
    assert.match(logged.join(), problem);
    assert.match(logged.join(), /metadata recorded \(HTTP 201\)/);
    assertNothingSensitiveLogged([value, "me.inbox", "me inbox"]);
  });
}

for (const [name, value, removed] of [
  ["quotes", `"${FALLBACK}"`, "surrounding quotes"],
  ["display name", `Me <${FALLBACK}>`, "display name or angle brackets"],
  ["whitespace and newline", `  ${FALLBACK}\n`, "surrounding whitespace"],
  ["mailto", `mailto:${FALLBACK}`, "mailto: prefix"],
  ["zero-width space", `${FALLBACK}​`, "invisible characters"],
  ["uppercase domain", "me.inbox@EXAMPLE.COM", null],
]) {
  test(`repairable FALLBACK_ADDRESS (${name}) is normalized before forwarding`, async () => {
    const message = fakeMessage();
    const result = await handleEmail(message, { ...ENV, FALLBACK_ADDRESS: value }, scriptedFetch(201), FAST);
    assert.equal(result.outcome, "forwarded_and_recorded");
    assert.deepEqual(message.forwardedTo, [FALLBACK]);
    if (removed) assert.match(logged.join(), new RegExp(`normalized \\(removed ${removed}`));
    assertNothingSensitiveLogged();
  });
}

test("parseFallbackAddress never returns the value in its problem or repairs", () => {
  for (const value of ["x y@z.com", "a@b", "<>", "Name <a@b.example>", "a@@b.com", "a@b.c0m"]) {
    const { problem, repaired } = parseFallbackAddress(value);
    assert.ok(!`${problem} ${repaired}`.includes(value.trim()), value);
  }
  assert.deepEqual(parseFallbackAddress(undefined), { address: null, problem: null, repaired: [] });
  assert.deepEqual(parseFallbackAddress("  "), { address: null, problem: null, repaired: [] });
});

// ---------- recipient domain and ingest configuration ----------

for (const to of ["a@example.com", "a@sub.leaktrap.xyz", "a@leaktrap.xyz.evil.com", "",
  "a..b@leaktrap.xyz", "a@b@leaktrap.xyz", "bad space@leaktrap.xyz"]) {
  test(`other recipient domain is rejected without forwarding or calling the backend: ${to || "(empty)"}`, async () => {
    const message = fakeMessage({ to });
    const fetchImpl = scriptedFetch(201);
    const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
    assert.equal(result.outcome, "rejected");
    assert.ok(message.rejected);
    assert.equal(fetchImpl.calls.length, 0);
    assert.deepEqual(message.forwardedTo, []);
  });
}

for (const [name, env] of [
  ["missing secret", { ...ENV, INGEST_SECRET: "" }],
  ["short secret", { ...ENV, INGEST_SECRET: "short" }],
  ["missing URL", { ...ENV, INGEST_URL: "" }],
  ["plain http URL", { ...ENV, INGEST_URL: "http://api.example.test/ingest/email" }],
  ["localhost http URL", { ...ENV, INGEST_URL: "http://localhost:8000/ingest/email" }],
]) {
  test(`ingest misconfiguration (${name}) never calls the backend and is not silent`, async () => {
    const fetchImpl = scriptedFetch(201);
    const rejected = fakeMessage();
    assert.equal((await handleEmail(rejected, env, fetchImpl, FAST)).outcome, "alias_unverified");
    assert.ok(rejected.rejected);
    assert.equal(fetchImpl.calls.length, 0);
    const message = fakeMessage();
    const delivered = await handleEmail(message, { ...env, FALLBACK_ADDRESS: FALLBACK }, fetchImpl, FAST);
    assert.equal(delivered.outcome, "alias_unverified");
    assert.deepEqual(message.forwardedTo, []);
    assert.equal(fetchImpl.calls.length, 0);
    assertNothingSensitiveLogged();
  });
}

test("the subject and message headers never reach the logs on any path", async () => {
  await handleEmail(fakeMessage(), WITH_FALLBACK, scriptedFetch(201), FAST);
  await handleEmail(fakeMessage(), WITH_FALLBACK, scriptedFetch("hang"), FAST);
  await handleEmail(fakeMessage(failingForward(new Error("boom"))), WITH_FALLBACK, scriptedFetch(201), FAST).catch(() => {});
  await handleEmail(fakeMessage(), { ...ENV, FALLBACK_ADDRESS: "bad" }, scriptedFetch(201), FAST).catch(() => {});
  assertNothingSensitiveLogged(["hi ocelot", "abc@mailer", "authorization", "deals"]);
});

// ---------- regressions for the demonstrated production failures ----------

// The token format used for INGEST_SECRET: python secrets.token_urlsafe(48).
const TOKEN = "Zq3vN8x_L2mP-7rT9wYb4cKd6fHj1sAe5uGi0oQnXlVyRzWtBpCaDeFgHkJmNo2";

/** Fetch stub that behaves like the Workers runtime for header values. */
function runtimeLikeFetch(status = 201) {
  const impl = scriptedFetch(status);
  return (url, init) => {
    if (/[\r\n]/.test(String(init.headers.authorization).trim())) {
      return Promise.reject(new TypeError("Invalid header value."));
    }
    return impl(url, init);
  };
}

test("REGRESSION: generated token entered as FALLBACK_ADDRESS (found 0 @) is named, never forwarded", async () => {
  const message = fakeMessage();
  const fetchImpl = scriptedFetch(201);
  await assert.rejects(handleEmail(message, { ...ENV, FALLBACK_ADDRESS: TOKEN }, fetchImpl, FAST), /looks like a generated token/);
  assert.deepEqual(message.forwardedTo, []);
  assert.equal(fetchImpl.calls.length, 1);
  assert.match(logged.join(), /\[config\] FALLBACK_ADDRESS is invalid: it looks like a generated token/);
  assertNothingSensitiveLogged([TOKEN]);
});

test("REGRESSION: FALLBACK_ADDRESS holding the same value as INGEST_SECRET is reported as such", async () => {
  const message = fakeMessage();
  await assert.rejects(handleEmail(message, { ...ENV, FALLBACK_ADDRESS: ` ${SECRET}\n` }, scriptedFetch(201), FAST),
    /same value as INGEST_SECRET/);
  assert.deepEqual(message.forwardedTo, []);
  assertNothingSensitiveLogged();
});

for (const [name, value, problem] of [
  ["a copied dashboard row", "me.inbox@example.com\tVerified", /address plus other text/],
  ["two dashboard rows", "me.inbox@example.com Verified\nother@example.com Verified", /contains 2 email addresses/],
  ["two addresses on two lines", "me.inbox@example.com\nother@example.com", /contains 2 email addresses/],
]) {
  test(`REGRESSION: clipboard with ${name} is refused as FALLBACK_ADDRESS`, async () => {
    const message = fakeMessage();
    await assert.rejects(handleEmail(message, { ...ENV, FALLBACK_ADDRESS: value }, scriptedFetch(201), FAST), /FALLBACK_ADDRESS is invalid/);
    assert.deepEqual(message.forwardedTo, []);
    assert.match(logged.join(), problem);
    assertNothingSensitiveLogged(["other@example.com", "Verified\n"]);
  });
}

test("REGRESSION: INGEST_SECRET with a line break caused 'network error: TypeError'; now a named config error", async () => {
  const multiLine = "me.inbox Verified 2026\nother Verified 2026 more text";
  // What the deployed Worker did: the runtime rejects the header with a TypeError.
  await assert.rejects(runtimeLikeFetch()("https://x.example/", { headers: { authorization: `Bearer ${multiLine}` } }),
    { name: "TypeError", message: "Invalid header value." });
  // Now: refused before fetch, the message is rejected, and the stage is named.
  const message = fakeMessage();
  const fetchImpl = scriptedFetch(201);
  const result = await handleEmail(message, { ...WITH_FALLBACK, INGEST_SECRET: multiLine }, fetchImpl, FAST);
  assert.equal(result.outcome, "alias_unverified");
  assert.equal(fetchImpl.calls.length, 0);
  assert.deepEqual(message.forwardedTo, []);
  assert.match(logged.join(), /\[config\] INGEST_SECRET contains a line break/);
  assertNothingSensitiveLogged(["Verified 2026"]);
});

test("a TypeError from fetch is logged with its message, not just its name", async () => {
  const fetchImpl = async () => { throw new TypeError("Invalid header value."); };
  const result = await handleEmail(fakeMessage(), WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "alias_unverified");
  assert.match(logged.join(), /\[alias_status\] network error \(TypeError: Invalid header value\.\)/);
});

for (const [name, value, problem] of [
  ["a line break", `${TOKEN}\n${TOKEN}`, /line break/],
  ["an email address", "me.inbox@example.com and padding text 1234567890", /contains @/],
  ["spaces", "abcdefghij klmnopqrst uvwxyz 0123456789", /spaces or tabs/],
  ["non-ASCII", `${TOKEN}…`, /non-ASCII/],
  ["too few characters", "short-token", /shorter than 32/],
  ["nothing", "  ", /not set/],
]) {
  test(`INGEST_SECRET with ${name} is refused before any request`, () => {
    assert.match(ingestSecretProblem(value), problem);
    assert.ok(!ingestSecretProblem(value).includes(value.trim()) || value.trim() === "");
  });
}

test("a generated token is a valid INGEST_SECRET; surrounding whitespace is ignored as fetch ignores it", async () => {
  assert.equal(ingestSecretProblem(TOKEN), null);
  assert.equal(ingestSecretProblem(`${TOKEN}\n`), null);
  const fetchImpl = scriptedFetch(201);
  await handleEmail(fakeMessage(), { ...WITH_FALLBACK, INGEST_SECRET: `${TOKEN}\n` }, fetchImpl, FAST);
  assert.equal(fetchImpl.calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
});

test("valid single fallback address is forwarded to exactly", async () => {
  assert.deepEqual(parseFallbackAddress("first.last+tag@example.com"),
    { address: "first.last+tag@example.com", problem: null, repaired: [] });
});

test("authentication failure after secret rotation: named, not retried, original delivered", async () => {
  const message = fakeMessage();
  const fetchImpl = scriptedFetch(401);
  const result = await handleEmail(message, WITH_FALLBACK, fetchImpl, FAST);
  assert.equal(result.outcome, "forwarded_not_recorded");
  assert.equal(fetchImpl.calls.length, 1);
  assert.deepEqual(message.forwardedTo, [FALLBACK]);
  assert.match(logged.join(), /\[record\].*does not match LEAKTRACE_INGEST_SECRET on Render/);
  assertNothingSensitiveLogged();
});

test("duplicate Message-ID: a retried delivery sends the identical payload and HTTP 200 counts as recorded", async () => {
  const first = scriptedFetch(201);
  const second = scriptedFetch(200);
  await handleEmail(fakeMessage(), WITH_FALLBACK, first, FAST);
  const again = await handleEmail(fakeMessage(), WITH_FALLBACK, second, FAST);
  assert.equal(again.outcome, "forwarded_and_recorded");
  const a = JSON.parse(first.calls[0].init.body);
  const b = JSON.parse(second.calls[0].init.body);
  assert.equal(a.message_id, b.message_id);
  assert.equal(a.recipient, b.recipient);
});

test("redaction: secret values never reach the logs, even inside runtime error messages", async () => {
  const fetchImpl = async (url) => {
    if (new URL(url).pathname.endsWith("/alias-status")) {
      return new Response(JSON.stringify({ status: "active", block_promotional_emails: false }), { status: 200 });
    }
    throw new Error(`upstream said Bearer ${SECRET} was bad for ${FALLBACK}`);
  };
  const message = fakeMessage(failingForward(new Error(`cannot deliver to ${FALLBACK} using ${SECRET}`)));
  await assert.rejects(handleEmail(message, WITH_FALLBACK, fetchImpl, FAST), (error) => {
    assert.ok(!error.message.includes(SECRET) && !error.message.includes(FALLBACK));
    return true;
  });
  assertNothingSensitiveLogged();
});

test("default export exposes an email handler", () => {
  assert.equal(typeof worker.email, "function");
});
