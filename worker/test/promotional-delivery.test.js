import assert from "node:assert/strict";
import { test } from "node:test";

import { handleEmail } from "../src/index.js";

const ENV = {
  ALIAS_DOMAIN: "leaktrap.xyz",
  INGEST_URL: "https://api.example.test/ingest/email",
  INGEST_SECRET: "s".repeat(40),
  FALLBACK_ADDRESS: "inbox@example.com",
};
const FAST = { timeouts: [20, 40] };

function message(subject, extraHeaders = {}) {
  return {
    to: "alias123@leaktrap.xyz", from: "bounce@example.com",
    headers: new Headers({ subject, from: "Offers <offers@example.com>", ...extraHeaders }),
    forwarded: [], rejected: null,
    async forward(address) { this.forwarded.push(address); },
    setReject(reason) { this.rejected = reason; },
    get raw() { throw new Error("email body must not be read"); },
  };
}

function backend(status, preference, metadataStatus = 201) {
  const calls = [];
  const fetchImpl = async (url) => {
    calls.push(url);
    return url.endsWith("/alias-status")
      ? new Response(JSON.stringify({ status, block_promotional_emails: preference }), { status: 200 })
      : new Response(null, { status: metadataStatus });
  };
  fetchImpl.calls = calls;
  return fetchImpl;
}

test("disabled preference keeps delivering promotional metadata", async () => {
  const mail = message("Summer sale 40% off");
  const fetchImpl = backend("active", false);
  assert.equal((await handleEmail(mail, ENV, fetchImpl, FAST)).outcome, "forwarded_and_recorded");
  assert.deepEqual(mail.forwarded, [ENV.FALLBACK_ADDRESS]);
  assert.equal(fetchImpl.calls.length, 2);
});

test("enabled preference blocks confident promotion before forwarding or metadata ingestion", async () => {
  const mail = message("Summer sale 40% off");
  const fetchImpl = backend("active", true);
  const lines = [];
  const originalLog = console.log;
  try {
    console.log = (line) => lines.push(line);
    assert.equal((await handleEmail(mail, ENV, fetchImpl, FAST)).outcome, "promotional_blocked");
  } finally {
    console.log = originalLog;
  }
  assert.deepEqual(mail.forwarded, []);
  assert.match(mail.rejected, /Promotional email blocked/);
  assert.deepEqual(fetchImpl.calls, ["https://api.example.test/ingest/alias-status"]);
  assert.match(lines.join(" "), /blocked \(promo_signals\)/);
  assert.ok(!lines.join(" ").includes("Summer") && !lines.join(" ").includes("alias123"));
});

test("enabled preference delivers transactional and uncertain messages", async () => {
  for (const subject of ["Password reset requested", "Your invoice is ready", "A note for you",
    "Order confirmation and 20% off your next purchase"]) {
    const mail = message(subject);
    assert.equal((await handleEmail(mail, ENV, backend("active", true), FAST)).outcome,
      "forwarded_and_recorded", subject);
    assert.deepEqual(mail.forwarded, [ENV.FALLBACK_ADDRESS]);
  }
});

test("revoked and unverifiable aliases are rejected before any classification or forwarding", async () => {
  for (const status of ["revoked", "unverifiable"]) {
    const mail = message("Summer sale 40% off");
    const fetchImpl = backend(status, true);
    assert.equal((await handleEmail(mail, ENV, fetchImpl, FAST)).outcome,
      status === "revoked" ? "alias_revoked" : "alias_unverified");
    assert.deepEqual(mail.forwarded, []);
    assert.equal(fetchImpl.calls.length, 1);
  }
});

test("missing or malformed preference in an active status cannot bypass filtering", async () => {
  for (const preference of [undefined, "false", null]) {
    const mail = message("Summer sale 40% off");
    const fetchImpl = backend("active", preference);
    assert.equal((await handleEmail(mail, ENV, fetchImpl, FAST)).outcome, "alias_unverified");
    assert.deepEqual(mail.forwarded, []);
    assert.equal(fetchImpl.calls.length, 1);
  }
});

test("status retry and missing fallback cannot bypass an enabled promotional filter", async () => {
  let requests = 0;
  const fetchImpl = async (url) => {
    assert.ok(url.endsWith("/alias-status"));
    requests += 1;
    return requests === 1 ? new Response(null, { status: 503 })
      : new Response(JSON.stringify({ status: "active", block_promotional_emails: true }), { status: 200 });
  };
  const mail = message("Coupon discount sale");
  assert.equal((await handleEmail(mail, { ...ENV, FALLBACK_ADDRESS: "" }, fetchImpl, FAST)).outcome,
    "promotional_blocked");
  assert.equal(requests, 2);
  assert.deepEqual(mail.forwarded, []);
});

test("malformed optional headers leave the message deliverable", async () => {
  const mail = message("Summer sale 40% off");
  mail.headers = { get(name) { if (name === "list-id") throw new Error("bad header"); return null; } };
  const fetchImpl = backend("active", true);
  assert.equal((await handleEmail(mail, ENV, fetchImpl, FAST)).outcome, "forwarded_and_recorded");
  assert.deepEqual(mail.forwarded, [ENV.FALLBACK_ADDRESS]);
});
