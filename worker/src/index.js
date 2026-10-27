// LeakTrace email Worker.
//
// For each message routed to it, the Worker checks the recipient domain and
// verifies the exact alias is active with the authenticated backend. Only then:
//   1. forwards the original message, unchanged, to FALLBACK_ADDRESS (a Worker
//      secret holding one verified Email Routing destination), and
//   2. POSTs a minimal JSON payload (no body, no attachments) to the backend.
// It never reads message.raw. Cloudflare runs the Worker once per envelope
// recipient, so message.to is the one alias this copy was delivered to; the
// backend attributes the message by that address only, never by To/Cc headers.
//
// After the status check, forwarding comes before metadata ingestion so a
// slow ingestion request cannot delay an otherwise authorized delivery. After
// a successful forward the Worker never throws, because a thrown error makes
// the sender retry and the retry would forward a second copy. Recording retries
// within this run instead; the backend deduplicates by Message-ID, so a retry
// never stores a message twice. When the message can be neither forwarded nor
// recorded, the Worker throws so the failure is visible and the sender is told,
// rather than the message being silently dropped.
//
// Logs never contain addresses, subjects, secrets or message content.

import { classifyPromotionalMetadata } from "./promotional.js";

const MAX_HEADER_LENGTH = 998;
// Must match MAX_AUTH_RESULTS_LENGTH in backend/schemas/mail_ingest.py.
const MAX_AUTH_RESULTS_LENGTH = 2000;
const MIN_SECRET_LENGTH = 32;
// One timeout per attempt. The first request also wakes a sleeping backend
// (Render's free plan sleeps when idle), so the retry waits longer.
export const INGEST_TIMEOUTS_MS = [10_000, 30_000];
// Worth retrying: gateway errors and unavailability. Other statuses are final.
const RETRY_STATUSES = new Set([502, 503, 504]);

// Must match MailIngestRequest in backend/schemas/mail_ingest.py.
export const PAYLOAD_FIELDS = [
  "recipient", "envelope_from", "from_header", "subject", "message_id", "received_at", "auth_results",
];

function aliasStatusEndpoint(ingestUrl) {
  const url = new URL(ingestUrl);
  if (url.protocol !== "https:" || !url.pathname.endsWith("/ingest/email")) return null;
  url.pathname = `${url.pathname.slice(0, -"/email".length)}/alias-status`;
  url.search = "";
  url.hash = "";
  return url.toString();
}

function header(message, name, maxLength = MAX_HEADER_LENGTH) {
  const value = message.headers?.get(name);
  return value ? value.slice(0, maxLength) : null;
}

function promotionalAssessment(message) {
  try {
    const get = (name) => message.headers?.get(name) ?? null;
    return classifyPromotionalMetadata({
      subject: get("subject"),
      listId: get("list-id"),
      listUnsubscribe: get("list-unsubscribe"),
      from: get("from"),
      replyTo: get("reply-to"),
    });
  } catch {
    return { outcome: "uncertain", reason: "malformed" };
  }
}

export function buildPayload(message, receivedAt = new Date()) {
  return {
    recipient: String(message.to ?? "").trim().toLowerCase(),
    envelope_from: message.from ? String(message.from).trim() : null,
    from_header: header(message, "from"),
    subject: header(message, "subject"),
    message_id: header(message, "message-id"),
    received_at: receivedAt.toISOString(),
    // SPF/DKIM/DMARC verdicts added by Email Routing; the backend keeps only
    // the instance that names Cloudflare's server.
    auth_results: header(message, "arc-authentication-results", MAX_AUTH_RESULTS_LENGTH),
  };
}

/**
 * Why INGEST_SECRET cannot be sent as a Bearer token, or null. Never contains
 * the value. Surrounding whitespace is ignored (fetch strips it from header
 * values too). A line break inside the value makes the runtime's fetch throw
 * "TypeError: Invalid header value."; the other checks catch values that are
 * clearly not the generated token, such as copied addresses.
 */
export function ingestSecretProblem(raw) {
  if (raw === undefined || raw === null || String(raw).trim() === "") return "INGEST_SECRET is not set";
  const value = String(raw).trim();
  if (/[\r\n]/.test(value)) return "INGEST_SECRET contains a line break (it looks like copied multi-line text, not the generated token)";
  if (value.includes("@")) return "INGEST_SECRET contains @ (it looks like an email address, not the generated token)";
  if (/[ \t]/.test(value)) return "INGEST_SECRET contains spaces or tabs";
  if (/[^\x21-\x7E]/.test(value)) return "INGEST_SECRET contains non-ASCII or control characters";
  if (value.length < MIN_SECRET_LENGTH) return `INGEST_SECRET is shorter than ${MIN_SECRET_LENGTH} characters`;
  return null;
}

function configProblem(env) {
  const secretProblem = ingestSecretProblem(env.INGEST_SECRET);
  if (secretProblem) return secretProblem;
  let url;
  try {
    url = new URL(env.INGEST_URL);
  } catch {
    return "INGEST_URL missing or invalid";
  }
  if (url.protocol !== "https:") return "INGEST_URL must use https";
  if (!url.pathname.endsWith("/ingest/email")) return "INGEST_URL must end in /ingest/email";
  return null;
}

const INVISIBLE = /[\u200B-\u200D\u2060\uFEFF]/;
const LOCAL_PART = /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}$/;
const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

function normalizeAliasRecipient(raw, aliasDomain) {
  const recipient = String(raw ?? "").trim().toLowerCase();
  const parts = recipient.split("@");
  if (!DOMAIN.test(aliasDomain) || parts.length !== 2 || parts[1] !== aliasDomain
      || recipient.length > 320 || !LOCAL_PART.test(parts[0])
      || parts[0].startsWith(".") || parts[0].endsWith(".") || parts[0].includes("..")) return null;
  return recipient;
}

/**
 * Normalize the FALLBACK_ADDRESS secret to one bare address.
 *
 * Returns { address, problem, repaired }: address is null when the secret is
 * unset or invalid; problem says why it is invalid; repaired lists what was
 * removed from an otherwise valid value. Neither ever contains the value, so
 * both are safe to log.
 */
export function parseFallbackAddress(raw) {
  const repaired = [];
  if (raw === undefined || raw === null || String(raw).trim() === "") {
    return { address: null, problem: null, repaired };
  }
  let value = String(raw);
  if (INVISIBLE.test(value)) {
    value = value.replace(new RegExp(INVISIBLE.source, "g"), "");
    repaired.push("invisible characters");
  }
  value = value.replace(/\u00A0/g, " ");
  if (value !== value.trim()) {
    value = value.trim();
    repaired.push("surrounding whitespace");
  }
  for (const [open, close] of [['"', '"'], ["'", "'"]]) {
    if (value.length >= 2 && value.startsWith(open) && value.endsWith(close)) {
      value = value.slice(1, -1).trim();
      repaired.push("surrounding quotes");
    }
  }
  if (/^mailto:/i.test(value)) {
    value = value.slice(7).trim();
    repaired.push("mailto: prefix");
  }
  const bracketed = /^[^<>]*<([^<>]*)>$/.exec(value);
  if (bracketed) {
    value = bracketed[1].trim();
    repaired.push("display name or angle brackets");
  }
  if (!value) return { address: null, problem: "it is empty after removing quotes or brackets", repaired };
  const addresses = value.match(/[^\s,;<>"']+@[^\s,;<>"']+/g) ?? [];
  if (addresses.length > 1) {
    return { address: null, problem: `it contains ${addresses.length} email addresses; store exactly one`, repaired };
  }
  if (addresses.length === 1 && addresses[0] !== value) {
    return { address: null, problem: "it contains an address plus other text (for example a copied dashboard row); store only the address", repaired };
  }
  if (!value.includes("@") && /^[A-Za-z0-9_-]{32,}$/.test(value)) {
    return { address: null, problem: "it looks like a generated token, not an email address (was the INGEST_SECRET value entered here?)", repaired };
  }
  if (/[\s,;]/.test(value)) {
    return { address: null, problem: "it contains spaces, commas or semicolons; use exactly one plain address", repaired };
  }
  const at = value.split("@").length - 1;
  if (at !== 1) return { address: null, problem: `it must contain exactly one @ (found ${at})`, repaired };
  const [local, domain] = value.split("@");
  if (!local) return { address: null, problem: "the user part before @ is missing", repaired };
  if (!LOCAL_PART.test(local)) return { address: null, problem: "the user part before @ has invalid characters", repaired };
  if (!DOMAIN.test(domain.toLowerCase())) {
    return { address: null, problem: "the domain after @ is missing or invalid", repaired };
  }
  return { address: `${local}@${domain.toLowerCase()}`, problem: null, repaired };
}

/**
 * Text safe to log: exact secret values, email addresses and long token-like
 * strings are replaced, and the length is capped.
 */
function redact(text, env = {}) {
  let out = String(text);
  for (const secret of [env.INGEST_SECRET, env.FALLBACK_ADDRESS]) {
    for (const form of new Set([secret, typeof secret === "string" ? secret.trim() : null])) {
      if (typeof form === "string" && form.length >= 4) out = out.split(form).join("<redacted>");
    }
  }
  return out
    .replace(/[^\s<>"'@]+@[^\s<>"'@]+/g, "<address>")
    .replace(/[A-Za-z0-9_-]{24,}/g, "<redacted>")
    .slice(0, 300);
}

function errorText(error, env) {
  return redact(`${error?.name ?? "Error"}: ${error?.message ?? ""}`, env);
}

/** One log line per event, labelled with the failing stage. */
function log(level, stage, text, env) {
  console[level === "error" ? "error" : "log"](`LeakTrace [${stage}] ${redact(text, env)}`);
}

async function forwardOriginal(message, address, env) {
  try {
    await message.forward(address);
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: errorText(error, env) };
  }
}

function statusReason(status) {
  if (status === 401) {
    return "backend rejected INGEST_SECRET (HTTP 401): it does not match LEAKTRACE_INGEST_SECRET on Render";
  }
  if (status === 422) return "backend rejected the payload (HTTP 422)";
  return `backend returned HTTP ${status}`;
}

/**
 * Send the message's metadata to the backend. Never throws.
 * Returns { ok, status, attempts, history } or { ok: false, reason, attempts, history };
 * history lists what happened on each attempt, for the log.
 */
async function recordMetadata(message, env, fetchImpl, timeouts) {
  const problem = configProblem(env);
  if (problem) return { ok: false, reason: `misconfigured: ${problem}`, attempts: 0, history: [] };
  // The same body on every attempt, so a retry is an exact duplicate.
  const body = JSON.stringify(buildPayload(message));
  const history = [];
  for (const timeout of timeouts) {
    try {
      const response = await fetchImpl(env.INGEST_URL, {
        method: "POST",
        headers: { "authorization": `Bearer ${String(env.INGEST_SECRET).trim()}`, "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(timeout),
      });
      // 201 accepted, 200 duplicate or reprocessed: the backend has it.
      if (response.ok) return { ok: true, status: response.status, attempts: history.length + 1, history };
      history.push(statusReason(response.status));
      if (!RETRY_STATUSES.has(response.status)) break;
    } catch (error) {
      history.push(`network error (${errorText(error, env)})`);
    }
  }
  return { ok: false, reason: history.at(-1), attempts: history.length, history };
}

async function checkAliasStatus(recipient, env, fetchImpl, timeouts) {
  const configurationProblem = configProblem(env);
  if (configurationProblem) return { ok: false, reason: "Worker configuration is not ready" };
  let endpoint;
  try { endpoint = aliasStatusEndpoint(env.INGEST_URL); } catch { return { ok: false, reason: "status endpoint is invalid" }; }
  if (!endpoint) return { ok: false, reason: "status endpoint cannot be derived from INGEST_URL" };
  const history = [];
  for (const timeout of timeouts) {
    try {
      const response = await fetchImpl(endpoint, {
        method: "POST",
        headers: { "authorization": `Bearer ${String(env.INGEST_SECRET).trim()}`, "content-type": "application/json" },
        body: JSON.stringify({ recipient }),
        signal: AbortSignal.timeout(timeout),
        redirect: "manual",
      });
      if (response.status !== 200) {
        history.push(`HTTP ${response.status}`);
        if (!RETRY_STATUSES.has(response.status)) break;
        continue;
      }
      let body;
      try {
        const raw = await response.text();
        if (raw.length > 256) return { ok: false, reason: "status response exceeded size limit" };
        body = JSON.parse(raw);
      } catch { return { ok: false, reason: "status response was not JSON" }; }
      if (body?.status === "active" && typeof body.block_promotional_emails === "boolean") {
        return { ok: true, blockPromotionalEmails: body.block_promotional_emails };
      }
      if (body?.status === "revoked") return { ok: false, revoked: true, reason: "alias is revoked" };
      return { ok: false, reason: "alias status is unverifiable" };
    } catch (error) {
      history.push(`network error (${errorText(error, env)})`);
    }
  }
  return { ok: false, reason: history.at(-1) ?? "alias status could not be verified" };
}

function attemptsText(recorded) {
  return recorded.history.map((h, i) => `attempt ${i + 1}: ${h}`).join("; ") || recorded.reason;
}

export async function handleEmail(message, env, fetchImpl = fetch, { timeouts = INGEST_TIMEOUTS_MS } = {}) {
  const domain = String(env.ALIAS_DOMAIN ?? "").trim().toLowerCase();
  const recipient = normalizeAliasRecipient(message.to, domain);
  if (!recipient) {
    message.setReject("Recipient alias is invalid or outside the configured domain");
    return { outcome: "rejected" };
  }

  const ingestProblem = configProblem(env);
  if (ingestProblem) log("error", "config", `${ingestProblem}; alias status cannot be checked`, env);

  // Delivery is fail-closed: only an explicit active result can continue.
  // In particular, never send revoked or unverifiable mail to FALLBACK_ADDRESS.
  const status = await checkAliasStatus(recipient, env, fetchImpl, timeouts);
  if (!status.ok) {
    const reason = status.revoked ? "Alias has been revoked" : "Alias status could not be verified; message was not forwarded";
    message.setReject(reason);
    log(status.revoked ? "info" : "error", "alias_status", status.reason, env);
    return { outcome: status.revoked ? "alias_revoked" : "alias_unverified" };
  }

  if (status.blockPromotionalEmails) {
    const assessment = promotionalAssessment(message);
    if (assessment.outcome === "promotional") {
      message.setReject("Promotional email blocked by recipient preference");
      log("info", "promotional_filter", `blocked (${assessment.reason})`, env);
      return { outcome: "promotional_blocked" };
    }
    // Transactional and uncertain mail continue through the usual forwarding path.
  }

  const fallback = parseFallbackAddress(env.FALLBACK_ADDRESS);
  if (env.FALLBACK_ADDRESS && env.INGEST_SECRET
      && String(env.FALLBACK_ADDRESS).trim() === String(env.INGEST_SECRET).trim()) {
    fallback.address = null;
    fallback.problem = "it holds the same value as INGEST_SECRET";
  }
  if (fallback.problem) {
    log("error", "config", `FALLBACK_ADDRESS is invalid: ${fallback.problem}`, env);
  } else if (fallback.repaired.length) {
    log("error", "config", `FALLBACK_ADDRESS was normalized (removed ${fallback.repaired.join(", ")}); `
      + "set the secret to the plain address", env);
  }
  if (fallback.address) {
    const forwarded = await forwardOriginal(message, fallback.address, env);
    if (!forwarded.ok) {
      // Not delivered. Still record it (a retry by the sender is deduplicated),
      // then fail so the sender is told instead of the message vanishing.
      const recorded = await recordMetadata(message, env, fetchImpl, timeouts);
      log("error", "forward", `forwarding failed (${forwarded.reason}); metadata `
        + `${recorded.ok ? `recorded (HTTP ${recorded.status})` : `not recorded (${attemptsText(recorded)})`}`, env);
      throw new Error(redact(`LeakTrace could not forward the message (${forwarded.reason})`, env));
    }
    const recorded = await recordMetadata(message, env, fetchImpl, timeouts);
    if (recorded.ok) {
      log("info", "done", `forwarded and recorded (HTTP ${recorded.status}, attempt ${recorded.attempts})`, env);
      return { outcome: "forwarded_and_recorded", status: recorded.status, attempts: recorded.attempts };
    }
    // Delivered but not recorded. Do not throw: that would forward a second copy.
    log("error", "record", `forwarded, but metadata was not recorded (${attemptsText(recorded)})`, env);
    return { outcome: "forwarded_not_recorded", reason: recorded.reason, attempts: recorded.attempts };
  }

  // No usable forwarding address: the backend record is the only copy kept.
  const recorded = await recordMetadata(message, env, fetchImpl, timeouts);
  const recordedText = recorded.ok ? `recorded (HTTP ${recorded.status})` : `not recorded (${attemptsText(recorded)})`;
  if (fallback.problem) {
    log("error", "forward", `message not forwarded because FALLBACK_ADDRESS is invalid; metadata ${recordedText}`, env);
    throw new Error(`LeakTrace could not forward the message (FALLBACK_ADDRESS is invalid: ${fallback.problem})`);
  }
  if (!recorded.ok) {
    log("error", "record", `ingest failed (${attemptsText(recorded)}); no FALLBACK_ADDRESS configured`, env);
    throw new Error(redact(`LeakTrace ingest failed (${recorded.reason})`, env));
  }
  log("error", "forward", `recorded (HTTP ${recorded.status}) but not forwarded: no FALLBACK_ADDRESS configured`, env);
  return { outcome: "recorded_not_forwarded", status: recorded.status, attempts: recorded.attempts };
}

export default {
  async email(message, env, ctx) {
    await handleEmail(message, env);
  },
};
