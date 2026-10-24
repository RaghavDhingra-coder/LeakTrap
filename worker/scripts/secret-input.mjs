// Reading, validating and uploading the Worker's secrets, shared by
// set-secret.mjs and check-address.mjs so both always give the same verdict.
//
// Input comes from a hidden terminal prompt (nothing is echoed) or, when piped,
// from stdin (e.g. `security find-generic-password ... -w |`). The clipboard is
// never read. The value is never printed, logged or passed as an argument; the
// only things written out are verdicts that describe it.
//
// Policy: the value must already be exactly one clean value. Nothing is
// repaired here. One trailing line ending from a piped command is the only
// thing removed; anything else (a second line, surrounding spaces, invisible
// characters, a byte-order mark, a dashboard row) is refused with the reason.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { ingestSecretProblem, parseFallbackAddress } from "../src/index.js";

export const WORKER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
export const SECRET_NAMES = ["INGEST_SECRET", "FALLBACK_ADDRESS"];
const MAX_INPUT_BYTES = 4096;
// A paste arrives in one burst; keys typed after Enter would arrive much later.
const PASTE_SETTLE_MS = 150;

/** Read a whole stream as bytes (never decoded piece by piece). */
export async function readAll(stream) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += bytes.length;
    if (size > MAX_INPUT_BYTES) return { problem: `the input is longer than ${MAX_INPUT_BYTES} bytes` };
    chunks.push(bytes);
  }
  return { bytes: Buffer.concat(chunks) };
}

/**
 * Bytes -> one line of text, or a problem. Removes exactly one trailing line
 * ending (piped commands add one); refuses everything else that is not part of
 * a single clean value.
 */
export function decodeOneLine(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { problem: "it starts with an invisible byte-order mark (BOM); save or copy it as plain text" };
  }
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return { problem: "it is not valid UTF-8 text" };
  }
  text = text.replace(/\r?\n$/, "");
  if (/[\r\n]/.test(text)) {
    const lines = text.split(/\r\n|\r|\n/).length;
    return { problem: `it contains ${lines} lines; enter exactly one value on one line` };
  }
  if (text === "") return { problem: "it is empty" };
  return { text };
}

/** Validate a decoded value for a secret name. Returns { value } or { problem }. */
export function validate(name, text) {
  if (/[​-‍⁠﻿]/.test(text)) return { problem: "it contains invisible characters (such as a zero-width space)" };
  if (text !== text.trim() || /^[\s ]|[\s ]$/.test(text)) {
    return { problem: "it has spaces or other blank characters before or after it" };
  }
  if (name === "INGEST_SECRET") {
    const problem = ingestSecretProblem(text);
    return problem ? { problem: problem.replace(/^INGEST_SECRET /, "it ") } : { value: text };
  }
  if (name === "FALLBACK_ADDRESS") {
    const { address, problem, repaired } = parseFallbackAddress(text);
    if (problem) return { problem };
    if (repaired.length) return { problem: `it is not a plain address (it has ${repaired.join(", ")}); enter only name@example.com` };
    return { value: address };  // identical to the input except for a lowercased domain
  }
  return { problem: `unknown secret name ${name}` };
}

/**
 * Read one line from a terminal without echoing it. A multi-line paste is
 * refused: any input that arrives right after Enter means more than one line.
 */
export function readHidden(input, output, prompt) {
  return new Promise((resolve) => {
    const bytes = [];
    let done = false;
    let extra = false;
    let settle = null;
    const finish = (result) => {
      clearTimeout(settle);
      input.removeListener("data", onData);
      input.setRawMode?.(false);
      input.pause();
      output.write("\n");
      resolve(result);
    };
    const onData = (chunk) => {
      for (const byte of Buffer.from(chunk)) {
        if (done) { extra = true; continue; }
        if (byte === 0x03) return finish({ problem: "cancelled" });                 // Ctrl-C
        if (byte === 0x04 && bytes.length === 0) return finish({ problem: "it is empty" });  // Ctrl-D
        if (byte === 0x0d || byte === 0x0a) {                                        // Enter
          done = true;
          settle = setTimeout(() => finish(extra
            ? { problem: "the pasted text contains more than one line; enter exactly one value on one line" }
            : { bytes: Buffer.from(bytes) }), PASTE_SETTLE_MS);
          continue;
        }
        if (byte === 0x7f || byte === 0x08) { bytes.pop(); continue; }                // Backspace
        bytes.push(byte);
        if (bytes.length > MAX_INPUT_BYTES) return finish({ problem: `the input is longer than ${MAX_INPUT_BYTES} bytes` });
      }
    };
    output.write(prompt);
    input.setRawMode?.(true);
    input.resume();
    input.on("data", onData);
  });
}

export function ingestUrl(workerDir = WORKER_DIR) {
  const toml = readFileSync(join(workerDir, "wrangler.toml"), "utf8");
  return /^INGEST_URL\s*=\s*"([^"]+)"/m.exec(toml)?.[1] ?? null;
}

/**
 * Ask the backend whether LEAKTRACE_INGEST_SECRET equals this value. It POSTs
 * "{}" with the value as the Bearer token; the backend checks the token before
 * reading the body, so 422 means "same value" and 401 "different value".
 * Nothing is stored either way.
 */
export async function renderVerdict(url, secret, fetchImpl = fetch) {
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: { authorization: `Bearer ${secret}`, "content-type": "application/json" },
      body: "{}",
      signal: AbortSignal.timeout(60_000),  // lets a sleeping free instance wake
    });
  } catch (error) {
    return { match: false, problem: `the backend could not be reached (${error?.name ?? "Error"}); try again once ${new URL(url).origin}/health/ready responds` };
  }
  if (response.status === 422) return { match: true };
  if (response.status === 401) {
    return { match: false, problem: "the backend rejected it (HTTP 401): LEAKTRACE_INGEST_SECRET on Render holds a different value" };
  }
  if (response.status === 503) return { match: false, problem: "the backend has ingestion disabled (LEAKTRACE_INGEST_SECRET missing or too short on Render)" };
  return { match: false, problem: `unexpected response from the backend (HTTP ${response.status})` };
}

/** Upload with Wrangler, value on stdin (never an argument). Resolves to the exit code. */
export function wranglerUpload(name, value) {
  return new Promise((resolve) => {
    const child = spawn("npx", ["--yes", "wrangler@4", "secret", "put", name],
      { cwd: WORKER_DIR, stdio: ["pipe", "inherit", "inherit"] });
    child.on("error", () => resolve(1));
    child.on("close", (code) => resolve(code ?? 1));
    child.stdin.end(value);
  });
}

function describe(name, value) {
  if (name === "FALLBACK_ADDRESS") {
    return `one plain address, ${value.length} characters, domain ${value.split("@")[1]}`;
  }
  return `${value.length} characters, URL-safe token format`;
}

/**
 * The whole workflow. Every dependency is injectable for tests.
 * Returns the process exit code: 0 success, 1 refused or failed, 2 usage.
 */
export async function run({
  argv, stdin, stdout, stderr, fetchImpl = fetch, upload = wranglerUpload, url = undefined,
}) {
  const say = (line) => stdout.write(`${line}\n`);
  const refuse = (line) => { stderr.write(`${line}\n`); return 1; };
  const [name, ...flags] = argv;
  const checkOnly = flags.includes("--check-only");
  const unknown = flags.filter((f) => f !== "--check-only");
  if (!SECRET_NAMES.includes(name) || unknown.length) {
    stderr.write("Usage: node scripts/set-secret.mjs INGEST_SECRET|FALLBACK_ADDRESS [--check-only]\n"
      + "  Type or paste the value at the hidden prompt, or pipe it in from a password manager.\n");
    return 2;
  }

  let read;
  if (stdin.isTTY) {
    read = await readHidden(stdin, stdout, `${name} (input hidden, press Enter): `);
    if (!read.problem && name === "FALLBACK_ADDRESS") {
      // Addresses are typed, so ask twice to catch typos.
      const again = await readHidden(stdin, stdout, `${name} again to confirm: `);
      if (again.problem) read = again;
      else if (!again.bytes.equals(read.bytes)) read = { problem: "the two entries differ" };
    }
  } else {
    read = await readAll(stdin);
  }
  if (read.problem) return refuse(`Not uploaded: ${name}: ${read.problem}.`);
  const line = decodeOneLine(read.bytes);
  if (line.problem) return refuse(`Not uploaded: ${name}: ${line.problem}.`);
  const checked = validate(name, line.text);
  if (checked.problem) return refuse(`Not uploaded: ${name}: ${checked.problem}.`);
  say(`${name} format is valid (${describe(name, checked.value)}).`);

  if (name === "INGEST_SECRET") {
    const target = url === undefined ? ingestUrl() : url;
    if (!target) return refuse("Not uploaded: INGEST_URL is not set in wrangler.toml.");
    say("Asking the backend whether LEAKTRACE_INGEST_SECRET on Render holds the same value…");
    const verdict = await renderVerdict(target, checked.value, fetchImpl);
    if (!verdict.match) return refuse(`Not uploaded: ${verdict.problem}.`);
    say("Render holds the same value (HTTP 422 for the empty test payload; nothing stored).");
  } else {
    say("It must also be listed as Verified under Email Routing > Destination addresses.");
  }

  if (checkOnly) {
    say("Check only: nothing uploaded.");
    return 0;
  }
  const code = await upload(name, checked.value);
  if (code !== 0) return refuse(`Upload failed: Wrangler exited with code ${code}.`);
  say(`${name} uploaded to the leaktrace-email Worker.`);
  return 0;
}
