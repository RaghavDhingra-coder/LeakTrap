// LeakTrace email Worker.
//
// For each message routed to it, the Worker checks the recipient domain and
// POSTs a minimal JSON payload (no body, no attachments) to the backend. It
// never reads message.raw. Cloudflare runs the Worker once per envelope
// recipient, so message.to is the one alias this copy was delivered to; the
// backend attributes the message by that address only, never by To/Cc headers. If the backend does not accept the message, the
// original is forwarded to FALLBACK_ADDRESS when configured; otherwise the
// Worker throws so the failure is visible in Cloudflare's logs instead of the
// message being silently dropped.

const MAX_HEADER_LENGTH = 998;
// Must match MAX_AUTH_RESULTS_LENGTH in backend/schemas/mail_ingest.py.
const MAX_AUTH_RESULTS_LENGTH = 2000;
const REQUEST_TIMEOUT_MS = 10_000;
const MIN_SECRET_LENGTH = 32;

// Must match MailIngestRequest in backend/schemas/mail_ingest.py.
export const PAYLOAD_FIELDS = [
  "recipient", "envelope_from", "from_header", "subject", "message_id", "received_at", "auth_results",
];

function header(message, name, maxLength = MAX_HEADER_LENGTH) {
  const value = message.headers?.get(name);
  return value ? value.slice(0, maxLength) : null;
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

function configProblem(env) {
  if (!env.INGEST_SECRET || env.INGEST_SECRET.length < MIN_SECRET_LENGTH) return "INGEST_SECRET missing or too short";
  let url;
  try {
    url = new URL(env.INGEST_URL);
  } catch {
    return "INGEST_URL missing or invalid";
  }
  if (url.protocol !== "https:") return "INGEST_URL must use https";
  return null;
}

async function deliveryFailed(message, env, reason) {
  // Log the reason only: never addresses, subjects or the secret.
  if (env.FALLBACK_ADDRESS) {
    console.error(`LeakTrace ingest failed (${reason}); forwarding to fallback address`);
    await message.forward(env.FALLBACK_ADDRESS);
    return { outcome: "forwarded_to_fallback", reason };
  }
  console.error(`LeakTrace ingest failed (${reason}); no FALLBACK_ADDRESS configured`);
  throw new Error(`LeakTrace ingest failed (${reason})`);
}

export async function handleEmail(message, env, fetchImpl = fetch) {
  const domain = String(env.ALIAS_DOMAIN ?? "").trim().toLowerCase();
  const recipient = String(message.to ?? "").trim().toLowerCase();
  if (!domain || !recipient.endsWith(`@${domain}`)) {
    message.setReject("Recipient domain is not handled here");
    return { outcome: "rejected" };
  }

  const problem = configProblem(env);
  if (problem) return deliveryFailed(message, env, `misconfigured: ${problem}`);

  let response;
  try {
    response = await fetchImpl(env.INGEST_URL, {
      method: "POST",
      headers: {
        "authorization": `Bearer ${env.INGEST_SECRET}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(buildPayload(message)),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (error) {
    return deliveryFailed(message, env, `network error: ${error?.name ?? "Error"}`);
  }
  // 201 accepted, 200 duplicate (already stored): both mean the backend has it.
  if (response.ok) return { outcome: "ingested", status: response.status };
  return deliveryFailed(message, env, `backend returned HTTP ${response.status}`);
}

export default {
  async email(message, env, ctx) {
    await handleEmail(message, env);
  },
};
