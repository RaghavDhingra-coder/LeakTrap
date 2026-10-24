// Run with: cd worker && npm test   (Node's built-in test runner, no dependencies)
import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import worker, { PAYLOAD_FIELDS, buildPayload, handleEmail } from "../src/index.js";

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
  const impl = async (url, init) => {
    calls.push({ url, init });
    if (result instanceof Error) throw result;
    return new Response(null, { status: result });
  };
  impl.calls = calls;
  return impl;
}

let logged;
const originalError = console.error;
beforeEach(() => {
  logged = [];
  console.error = (...args) => logged.push(args.join(" "));
});
afterEach(() => { console.error = originalError; });

function assertNothingSensitiveLogged() {
  const text = logged.join("\n").toLowerCase();
  for (const secret of [SECRET, "ab12@leaktrap.xyz", "broker.example", "ocelot", "mailer.example"]) {
    assert.ok(!text.includes(secret.toLowerCase()), `log contains ${secret}`);
  }
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

test("accepted message is posted with the secret and not forwarded", async () => {
  const message = fakeMessage();
  const fetchImpl = fakeFetch(201);
  const result = await handleEmail(message, ENV, fetchImpl);
  assert.deepEqual(result, { outcome: "ingested", status: 201 });
  const [{ url, init }] = fetchImpl.calls;
  assert.equal(url, ENV.INGEST_URL);
  assert.equal(init.method, "POST");
  assert.equal(init.headers.authorization, `Bearer ${SECRET}`);
  assert.equal(init.headers["content-type"], "application/json");
  assert.deepEqual(Object.keys(JSON.parse(init.body)), PAYLOAD_FIELDS);
  assert.deepEqual(message.forwardedTo, []);
  assert.equal(message.rejected, null);
});

test("duplicate (HTTP 200) counts as accepted", async () => {
  const result = await handleEmail(fakeMessage(), ENV, fakeFetch(200));
  assert.equal(result.outcome, "ingested");
});

for (const to of ["a@example.com", "a@sub.leaktrap.xyz", "a@leaktrap.xyz.evil.com", ""]) {
  test(`other recipient domain is rejected without calling the backend: ${to || "(empty)"}`, async () => {
    const message = fakeMessage({ to });
    const fetchImpl = fakeFetch(201);
    const result = await handleEmail(message, ENV, fetchImpl);
    assert.equal(result.outcome, "rejected");
    assert.ok(message.rejected);
    assert.equal(fetchImpl.calls.length, 0);
  });
}

for (const status of [401, 413, 422, 500, 503]) {
  test(`backend HTTP ${status} forwards to fallback`, async () => {
    const message = fakeMessage();
    const result = await handleEmail(message, { ...ENV, FALLBACK_ADDRESS: "me@example.com" }, fakeFetch(status));
    assert.equal(result.outcome, "forwarded_to_fallback");
    assert.deepEqual(message.forwardedTo, ["me@example.com"]);
    assert.match(logged.join(), new RegExp(`HTTP ${status}`));
    assertNothingSensitiveLogged();
  });
}

test("backend failure without fallback throws so it is visible", async () => {
  const message = fakeMessage();
  await assert.rejects(handleEmail(message, ENV, fakeFetch(500)), /HTTP 500/);
  assert.deepEqual(message.forwardedTo, []);
  assertNothingSensitiveLogged();
});

test("network error goes to fallback", async () => {
  const message = fakeMessage();
  const result = await handleEmail(
    message, { ...ENV, FALLBACK_ADDRESS: "me@example.com" }, fakeFetch(new TypeError("fetch failed")),
  );
  assert.equal(result.outcome, "forwarded_to_fallback");
  assert.match(result.reason, /network error: TypeError/);
});

for (const [name, env] of [
  ["missing secret", { ...ENV, INGEST_SECRET: "" }],
  ["short secret", { ...ENV, INGEST_SECRET: "short" }],
  ["missing URL", { ...ENV, INGEST_URL: "" }],
  ["plain http URL", { ...ENV, INGEST_URL: "http://api.example.test/ingest/email" }],
  ["localhost http URL", { ...ENV, INGEST_URL: "http://localhost:8000/ingest/email" }],
]) {
  test(`misconfiguration (${name}) never calls the backend and is not silent`, async () => {
    const fetchImpl = fakeFetch(201);
    await assert.rejects(handleEmail(fakeMessage(), env, fetchImpl), /misconfigured/);
    assert.equal(fetchImpl.calls.length, 0);
    assertNothingSensitiveLogged();
  });
}

test("failing fallback forward is not swallowed", async () => {
  const message = fakeMessage({ async forward() { throw new Error("destination not verified"); } });
  await assert.rejects(
    handleEmail(message, { ...ENV, FALLBACK_ADDRESS: "me@example.com" }, fakeFetch(500)),
    /destination not verified/,
  );
});

test("default export exposes an email handler", () => {
  assert.equal(typeof worker.email, "function");
});
