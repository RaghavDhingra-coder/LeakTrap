// Regression tests for the secret setup scripts (scripts/secret-input.mjs).
// No network and no Wrangler: fetch and the upload step are injected.
import assert from "node:assert/strict";
import { PassThrough, Readable } from "node:stream";
import { test } from "node:test";

import { decodeOneLine, readAll, run, validate } from "../scripts/secret-input.mjs";

const TOKEN = "Zq3vN8x_L2mP-7rT9wYb4cKd6fHj1sAe5uGi0oQnXlVyRzWtBpCaDeFgHkJmNo2";  // token_urlsafe(48) shape
const ADDRESS = "me.inbox@example.com";
const URL_ = "https://backend.example.test/ingest/email";

function sink() {
  const out = { text: "", write(s) { out.text += s; return true; } };
  return out;
}

function piped(...chunks) {
  return Readable.from(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c))));
}

/** A fake terminal: chunks are delivered with real delays, like typing or pasting. */
function terminal(...events) {
  const stream = new PassThrough();
  stream.isTTY = true;
  stream.rawModes = [];
  stream.setRawMode = (on) => { stream.rawModes.push(on); return stream; };
  (async () => {
    for (const event of events) {
      if (typeof event === "number") await new Promise((r) => setTimeout(r, event));
      else stream.write(Buffer.from(event));
    }
  })();
  return stream;
}

function backend(status) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    if (status instanceof Error) throw status;
    return new Response(null, { status });
  };
  impl.calls = calls;
  return impl;
}

function uploader(code = 0) {
  const calls = [];
  const impl = async (name, value) => { calls.push({ name, value }); return code; };
  impl.calls = calls;
  return impl;
}

async function go(argv, stdin, { status = 422, uploadCode = 0 } = {}) {
  const stdout = sink();
  const stderr = sink();
  const fetchImpl = backend(status);
  const upload = uploader(uploadCode);
  const code = await run({ argv, stdin, stdout, stderr, fetchImpl, upload, url: URL_ });
  const all = stdout.text + stderr.text;
  // Nothing written may contain the value or any part of an address.
  for (const secret of [TOKEN, ADDRESS, "me.inbox", "other@example"]) assert.ok(!all.includes(secret), `output contains ${secret}`);
  return { code, out: stdout.text, err: stderr.text, fetchImpl, upload };
}

// ---------- inputs that actually happened ----------

test("REGRESSION: a copied dashboard row (address + tab + 'Verified') is refused and not uploaded", async () => {
  const r = await go(["FALLBACK_ADDRESS"], piped(`${ADDRESS}\tVerified\n`));
  assert.equal(r.code, 1);
  assert.match(r.err, /address plus other text/);
  assert.equal(r.upload.calls.length, 0);
});

test("REGRESSION: two copied rows / two addresses on two lines are refused as multi-line", async () => {
  for (const input of [`${ADDRESS}\nother@example.com\n`, `${ADDRESS} Verified\r\nother@example.com Verified\r\n`]) {
    const r = await go(["FALLBACK_ADDRESS"], piped(input));
    assert.equal(r.code, 1);
    assert.match(r.err, /contains 2 lines; enter exactly one value on one line/);
    assert.equal(r.upload.calls.length, 0);
  }
});

test("REGRESSION: the generated token entered as FALLBACK_ADDRESS is refused", async () => {
  const r = await go(["FALLBACK_ADDRESS"], piped(TOKEN));
  assert.equal(r.code, 1);
  assert.match(r.err, /looks like a generated token/);
  assert.equal(r.upload.calls.length, 0);
});

test("REGRESSION: multi-line text as INGEST_SECRET is refused before Render is asked or anything is uploaded", async () => {
  const r = await go(["INGEST_SECRET"], piped(`${ADDRESS} Verified\nother@example.com Verified padding padding\n`));
  assert.equal(r.code, 1);
  assert.match(r.err, /contains 2 lines/);
  assert.equal(r.fetchImpl.calls.length, 0);
  assert.equal(r.upload.calls.length, 0);
});

test("REGRESSION: an address as INGEST_SECRET is refused", async () => {
  const r = await go(["INGEST_SECRET"], piped(`${ADDRESS}-padding-padding-padding`));
  assert.equal(r.code, 1);
  assert.match(r.err, /contains @/);
  assert.equal(r.fetchImpl.calls.length, 0);
});

test("REGRESSION: multi-byte characters split across stdin chunks decode correctly", async () => {
  const bytes = Buffer.from("é@example.com");
  const { bytes: read } = await readAll(piped(bytes.subarray(0, 1), bytes.subarray(1)));
  assert.equal(decodeOneLine(read).text, "é@example.com");
});

test("REGRESSION: both scripts give the same verdict for the same bytes", async () => {
  const { run: runCheck } = await import("../scripts/secret-input.mjs");
  for (const input of [ADDRESS, `${ADDRESS}\n`, `${ADDRESS}\n\n`, `  ${ADDRESS}`, `${ADDRESS} `, `${ADDRESS}​`,
    `﻿${ADDRESS}`, `${ADDRESS}\tVerified`, TOKEN]) {
    const a = sink(); const b = sink();
    const codeA = await runCheck({ argv: ["FALLBACK_ADDRESS", "--check-only"], stdin: piped(input), stdout: a, stderr: a, upload: uploader() });
    const codeB = await runCheck({ argv: ["FALLBACK_ADDRESS", "--check-only"], stdin: piped(input), stdout: b, stderr: b, upload: uploader() });
    assert.equal(codeA, codeB, JSON.stringify(input));
    assert.equal(a.text, b.text);
  }
});

// ---------- decoding and validation policy ----------

for (const [label, input, expected] of [
  ["one trailing LF from a pipe", `${TOKEN}\n`, TOKEN],
  ["one trailing CRLF", `${TOKEN}\r\n`, TOKEN],
]) {
  test(`accepted: ${label}`, () => {
    const line = decodeOneLine(Buffer.from(input));
    assert.equal(validate("INGEST_SECRET", line.text).value, expected);
  });
}

for (const [label, bytes, problem] of [
  ["two trailing newlines", Buffer.from(`${TOKEN}\n\n`), /contains 2 lines/],
  ["a bare CR inside", Buffer.from(`${TOKEN}\rmore`), /contains 2 lines/],
  ["a byte-order mark", Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(TOKEN)]), /byte-order mark/],
  ["invalid UTF-8", Buffer.from([0x61, 0xff, 0x62]), /not valid UTF-8/],
  ["nothing", Buffer.alloc(0), /empty/],
  ["only a newline", Buffer.from("\n"), /empty/],
]) {
  test(`refused at decoding: ${label}`, () => {
    assert.match(decodeOneLine(bytes).problem, problem);
  });
}

for (const [name, text, problem] of [
  ["INGEST_SECRET", ` ${TOKEN}`, /blank characters before or after/],
  ["INGEST_SECRET", `${TOKEN} `, /blank characters before or after/],
  ["INGEST_SECRET", "tiny-value-9", /shorter than 32/],
  ["INGEST_SECRET", `${TOKEN} ${TOKEN}`, /spaces or tabs/],
  ["INGEST_SECRET", `${TOKEN}…`, /non-ASCII/],
  ["FALLBACK_ADDRESS", ` ${ADDRESS}`, /blank characters before or after/],
  ["FALLBACK_ADDRESS", `${ADDRESS} `, /blank characters before or after/],
  ["FALLBACK_ADDRESS", `${ADDRESS}​`, /invisible characters/],
  ["FALLBACK_ADDRESS", `"${ADDRESS}"`, /not a plain address \(it has surrounding quotes\)/],
  ["FALLBACK_ADDRESS", `Me <${ADDRESS}>`, /not a plain address/],
  ["FALLBACK_ADDRESS", `mailto:${ADDRESS}`, /not a plain address/],
  ["FALLBACK_ADDRESS", "me.inbox@example", /domain after @/],
  ["FALLBACK_ADDRESS", `${ADDRESS},other@example.com`, /2 email addresses/],
]) {
  test(`refused by validation: ${name} ${JSON.stringify(text).slice(0, 30)}`, () => {
    const result = validate(name, text);
    assert.equal(result.value, undefined);
    assert.match(result.problem, problem);
    assert.ok(!result.problem.includes(text.trim()));
  });
}

test("a valid single address is accepted exactly (domain lowercased only)", () => {
  assert.deepEqual(validate("FALLBACK_ADDRESS", "First.Last+tag@Example.COM"), { value: "First.Last+tag@example.com" });
});

// ---------- the Render gate and uploading ----------

test("INGEST_SECRET equal to Render's (HTTP 422): uploaded exactly, without a newline", async () => {
  const r = await go(["INGEST_SECRET"], piped(`${TOKEN}\n`));
  assert.equal(r.code, 0);
  assert.deepEqual(r.upload.calls, [{ name: "INGEST_SECRET", value: TOKEN }]);
  const [{ url, init }] = r.fetchImpl.calls;
  assert.equal(url, URL_);
  assert.equal(init.headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(init.body, "{}");  // invalid payload: nothing can be stored
  assert.match(r.out, /Render holds the same value/);
});

for (const [status, problem] of [
  [401, /LEAKTRACE_INGEST_SECRET on Render holds a different value/],
  [503, /ingestion disabled/],
  [500, /unexpected response from the backend \(HTTP 500\)/],
  [201, /unexpected response from the backend \(HTTP 201\)/],
  [new TypeError("fetch failed"), /could not be reached \(TypeError\)/],
]) {
  test(`INGEST_SECRET not uploaded when the backend answers ${status instanceof Error ? "with a network error" : `HTTP ${status}`}`, async () => {
    const r = await go(["INGEST_SECRET"], piped(TOKEN), { status });
    assert.equal(r.code, 1);
    assert.match(r.err, problem);
    assert.equal(r.upload.calls.length, 0);
  });
}

test("--check-only never uploads", async () => {
  for (const [name, value] of [["INGEST_SECRET", TOKEN], ["FALLBACK_ADDRESS", ADDRESS]]) {
    const r = await go([name, "--check-only"], piped(value));
    assert.equal(r.code, 0);
    assert.match(r.out, /Check only: nothing uploaded/);
    assert.equal(r.upload.calls.length, 0);
  }
});

test("FALLBACK_ADDRESS valid: uploaded without asking the backend", async () => {
  const r = await go(["FALLBACK_ADDRESS"], piped(`${ADDRESS}\n`));
  assert.equal(r.code, 0);
  assert.deepEqual(r.upload.calls, [{ name: "FALLBACK_ADDRESS", value: ADDRESS }]);
  assert.equal(r.fetchImpl.calls.length, 0);
  assert.match(r.out, /Verified under Email Routing/);
});

test("a failed Wrangler upload is reported, not claimed as success", async () => {
  const r = await go(["FALLBACK_ADDRESS"], piped(ADDRESS), { uploadCode: 1 });
  assert.equal(r.code, 1);
  assert.match(r.err, /Upload failed: Wrangler exited with code 1/);
  assert.doesNotMatch(r.out, /uploaded to the leaktrace-email Worker/);
});

test("usage errors exit 2 and read nothing", async () => {
  for (const argv of [[], ["OTHER"], ["INGEST_SECRET", "--force"]]) {
    const r = await go(argv, piped(TOKEN));
    assert.equal(r.code, 2);
    assert.equal(r.upload.calls.length, 0);
  }
});

// ---------- hidden terminal prompt ----------

test("hidden prompt: typed value is read without echo; raw mode is switched on and off", async () => {
  const stdin = terminal(TOKEN.slice(0, 10), 20, TOKEN.slice(10), 20, "\r");
  const r = await go(["INGEST_SECRET", "--check-only"], stdin);
  assert.equal(r.code, 0);
  assert.deepEqual(stdin.rawModes, [true, false]);
  assert.match(r.out, /INGEST_SECRET \(input hidden, press Enter\): /);
  assert.equal(r.fetchImpl.calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
});

test("hidden prompt: backspace edits the value", async () => {
  const r = await go(["INGEST_SECRET", "--check-only"], terminal(`${TOKEN}x\x7f\r`));
  assert.equal(r.code, 0);
  assert.equal(r.fetchImpl.calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
});

test("REGRESSION: hidden prompt refuses a multi-line paste instead of taking the first line", async () => {
  const r = await go(["INGEST_SECRET"], terminal(`${TOKEN}\r${ADDRESS} Verified\r`));
  assert.equal(r.code, 1);
  assert.match(r.err, /pasted text contains more than one line/);
  assert.equal(r.fetchImpl.calls.length, 0);
  assert.equal(r.upload.calls.length, 0);
});

test("hidden prompt: Ctrl-C cancels without uploading", async () => {
  const r = await go(["INGEST_SECRET"], terminal("abc\x03"));
  assert.equal(r.code, 1);
  assert.match(r.err, /cancelled/);
  assert.equal(r.upload.calls.length, 0);
});

test("hidden prompt: FALLBACK_ADDRESS is asked twice and must match", async () => {
  const same = await go(["FALLBACK_ADDRESS"], terminal(`${ADDRESS}\r`, 300, `${ADDRESS}\r`));
  assert.equal(same.code, 0);
  assert.deepEqual(same.upload.calls, [{ name: "FALLBACK_ADDRESS", value: ADDRESS }]);
  const typo = await go(["FALLBACK_ADDRESS"], terminal(`${ADDRESS}\r`, 300, "me.inbx@example.com\r"));
  assert.equal(typo.code, 1);
  assert.match(typo.err, /the two entries differ/);
  assert.equal(typo.upload.calls.length, 0);
});
