// LeakTrace personal dashboard. Plain JavaScript, no dependencies.
// All data is rendered with textContent / DOM nodes, never as HTML.
// Signed-in state lives in an HttpOnly session cookie; every state-changing
// request also sends the CSRF token returned by /auth/me.
"use strict";

const API = "/dashboard/api";
const PAGE_SIZE = 20;
const STATUS_LABELS = {
  matched: "Matched", ambiguous: "Ambiguous", no_match: "No match", unprocessed: "Unprocessed",
};
const ACTION_LABELS = { accepted: "Accepted", declined: "Declined", notice_only: "Only saw the notice" };
const INBOX_STATUS_LABELS = { matched: "Matched", unmatched: "Unmatched", failed: "Failed" };
const REASON_LABELS = {
  not_linked: "Not linked to any of your websites. The website may have been deleted.",
  analysis_failed: "Linked to your website, but the leak analysis failed. It runs again if the message is redelivered.",
  unknown_alias: "Sent to an address that is not one of your aliases.",
  unowned_alias: "Sent to an alias that is not linked to an account.",
  ambiguous_alias: "The recipient matched more than one alias, so it was not linked.",
};
const POLL_INTERVAL_MS = 30_000;
const MAX_POLL_INTERVAL_MS = 5 * 60_000;
const MAX_NOTIFICATIONS = 5;
const state = {
  me: null, offsets: { websites: 0, receipts: 0, emails: 0, investigations: 0, inbox: 0 },
  emailStatus: "", websiteQuery: "", websiteFilter: "all", pairCode: null,
  inboxFilter: "all", openEmailId: null, latestEmailId: null, pollTimer: null, pollDelay: POLL_INTERVAL_MS,
};

// ---------- helpers ----------

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child !== null && child !== undefined && child !== false) node.append(child instanceof Node ? child : String(child));
  }
  return node;
}

const timeFormat = new Intl.DateTimeFormat("en-GB", {
  year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  timeZone: "UTC", hour12: false,
});

function formatTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : `${timeFormat.format(date)} UTC`;
}

function statusBadge(status) {
  const key = status ?? "unprocessed";
  return el("span", { class: `badge badge-${key}` }, STATUS_LABELS[key] ?? key);
}

function setStatus(section, message, isError = false) {
  const box = section.querySelector("[data-status]");
  box.textContent = message;
  box.classList.toggle("error", isError);
  box.setAttribute("role", isError ? "alert" : "status");
}

function say(id, message, kind = "") {
  const box = document.getElementById(id);
  box.textContent = message;
  box.className = `status ${kind}`.trim();
  box.setAttribute("role", kind === "error" ? "alert" : "status");
}

function siteLabel(name, domain) {
  return name ? `${name}${domain ? ` (${domain})` : ""}` : "—";
}

// ---------- inbox text (pure: no DOM) ----------

/** Who the message was addressed to, as the website knows the user. */
function identityText(m) {
  if (m.identity) return m.identity;
  if (m.identity_kind === "real_name") return "your real name";
  return m.alias ?? "an unknown alias";
}

function notificationText(m) {
  const site = m.site_name ? ` on ${m.site_name}` : "";
  return `New email received for ${identityText(m)}${site}`;
}

function senderText(m) {
  if (m.sender_name && m.sender_email) return `${m.sender_name} <${m.sender_email}>`;
  return m.sender_name ?? m.sender_email ?? (m.sender_domain ? `someone at ${m.sender_domain}` : "Unknown sender");
}

function reasonText(reason) {
  return reason ? (REASON_LABELS[reason] ?? "Not linked to any of your websites.") : null;
}

function unreadLabel(count) {
  return count === 1 ? "1 unread email" : `${count} unread emails`;
}

// Form labels for request fields, used in validation messages.
const FIELD_LABELS = {
  signup_id: "Signup ID", action: "What you did", source_url: "Privacy notice URL",
  notice_version: "Notice version", notice_text: "Notice text", content_hash: "Notice text hash",
  consent_text: "Consent prompt wording", reported_occurred_at: "When it happened",
  recipient: "Recipient address", sender: "Sender address", subject: "Subject", nickname: "Nickname",
  surname_variant: "Surname", user_id: "User ID", limit: "Page size", offset: "Page position", status: "Status filter",
  email: "Email", password: "Password", current_password: "Current password", new_password: "New password",
  confirm: "Confirmation", code: "Code", filter: "Show",
};
const MAX_SHOWN_ERRORS = 3;

class RequestError extends Error {
  constructor(message, fields = [], status = 0) {
    super(message);
    this.fields = fields;
    this.status = status;
  }
}

function humanizeFields(text, keys) {
  return keys.reduce((out, key) => out.replace(new RegExp(`\\b${key}\\b`, "g"), FIELD_LABELS[key]), text);
}

/**
 * Field-specific messages from a 422 "detail" list. Only each error's location
 * and reason are used; submitted values (FastAPI's "input") are never shown.
 */
function validationErrors(detail) {
  return detail.filter((d) => d && typeof d === "object").map((d) => {
    const loc = Array.isArray(d.loc) ? d.loc.filter((p) => typeof p === "string" && !["body", "query", "path"].includes(p)) : [];
    const field = loc.at(-1) ?? null;
    let message = String(d.msg ?? "is invalid").replace(/^Value error, /, "");
    if (message === "Extra inputs are not permitted") message = "is not an accepted field";
    if (field && message.startsWith(`${field} `)) message = message.slice(field.length + 1);
    // Field-specific messages may name other fields; form-level ones list them.
    const keys = Object.keys(FIELD_LABELS).filter((k) => !field || k.includes("_"));
    message = humanizeFields(message, keys);
    if (!field) return { field, text: message.charAt(0).toUpperCase() + message.slice(1) };
    return { field, text: `${FIELD_LABELS[field] ?? field}: ${message}` };
  });
}

function validationSummary(errors) {
  if (!errors.length) return "The request was not accepted. Check the highlighted values.";
  // Messages may already end with a full stop; avoid "..".
  const shown = errors.slice(0, MAX_SHOWN_ERRORS).map((e) => e.text.replace(/\.+$/, "")).join("; ");
  const more = errors.length - MAX_SHOWN_ERRORS;
  return more > 0 ? `${shown}; and ${more} more.` : `${shown}.`;
}

/**
 * Mark the form controls named in the errors, link them to the message that
 * explains the problem, and focus the first one.
 */
function markInvalid(form, fields = [], messageId = null) {
  for (const control of form.elements) {
    control.removeAttribute("aria-invalid");
    if (control.getAttribute("aria-describedby") === messageId) control.removeAttribute("aria-describedby");
  }
  const names = fields.map((f) => (f === "content_hash" ? "notice_text" : f));
  const controls = names.map((n) => form.elements.namedItem(n)).filter((c) => c && c.setAttribute);
  for (const control of controls) {
    control.setAttribute("aria-invalid", "true");
    if (messageId) control.setAttribute("aria-describedby", messageId);
  }
  controls[0]?.focus();
}

/** Same-origin JSON request. Sends the CSRF token on state-changing methods. */
async function api(url, { method = "GET", body } = {}) {
  const headers = { accept: "application/json" };
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && state.me?.csrf_token) headers["x-csrf-token"] = state.me.csrf_token;
  let response;
  try {
    response = await fetch(url, { method, headers, credentials: "same-origin", cache: "no-store",
      body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new RequestError("Could not reach the LeakTrace server.");
  }
  let data = null;
  try { data = await response.json(); } catch { /* empty or non-JSON */ }
  if (response.status === 401 && state.me && !url.startsWith("/auth/login")) {
    signedOut("Your session ended. Sign in again.");
    throw new RequestError("Your session ended. Sign in again.", [], 401);
  }
  if (!response.ok) {
    if (typeof data?.detail === "string") throw new RequestError(data.detail, [], response.status);
    if (Array.isArray(data?.detail)) {
      const errors = validationErrors(data.detail);
      throw new RequestError(validationSummary(errors), errors.map((e) => e.field).filter(Boolean), response.status);
    }
    throw new RequestError(`Request failed (HTTP ${response.status}).`, [], response.status);
  }
  return data ?? {};
}

const getJSON = (url) => api(url);

function renderPager(name, page, reload) {
  const pager = document.querySelector(`[data-pager="${name}"]`);
  const from = page.total === 0 ? 0 : page.offset + 1;
  const to = page.offset + page.items.length;
  pager.replaceChildren(
    el("button", { type: "button", "aria-label": "Previous page",
      onclick: () => { state.offsets[name] = Math.max(0, page.offset - page.limit); reload(); } }, "Previous"),
    el("span", { "aria-live": "polite" }, `${from}–${to} of ${page.total}`),
    el("button", { type: "button", "aria-label": "Next page",
      onclick: () => { state.offsets[name] = page.offset + page.limit; reload(); } }, "Next"),
  );
  pager.children[0].disabled = page.offset === 0;
  pager.children[2].disabled = to >= page.total;
}

function list(items) {
  return el("ul", {}, ...items.map((item) => el("li", {}, item)));
}

function copyButton(label, value) {
  const button = el("button", { type: "button", class: "secondary" }, `Copy ${label}`);
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = `Copied ${label}`;
    } catch {
      button.textContent = `Copy failed — select the ${label} and copy it manually`;
    }
  });
  return button;
}

// ---------- sign in / out ----------

function show(view) {
  document.getElementById("auth-view").hidden = view !== "auth";
  document.getElementById("app-view").hidden = view !== "app";
  document.getElementById("account-bar").hidden = view !== "app";
}

function signedOut(message = "") {
  state.me = null;
  stopPolling();
  dismissNotifications();
  show("auth");
  document.getElementById("verify-banner").hidden = true;
  if (message) say("login-status", message, "error");
}

function renderVerifyBanner() {
  const banner = document.getElementById("verify-banner");
  if (!state.me || state.me.email_verified) {
    banner.hidden = true;
    return;
  }
  banner.hidden = false;
  banner.textContent = state.me.email_delivery_configured
    ? "Your email address is not verified yet. Check your inbox for the verification link."
    : "Your email address is not verified. Email delivery is not configured on this server, so no verification email has been sent.";
}

async function signedIn(me) {
  state.me = me;
  document.getElementById("account-email").textContent = `Signed in as ${me.email}`;
  show("app");
  renderVerifyBanner();
  showPairCard();
  selectTab(currentTab());
  schedulePoll(0);
}

async function login(event) {
  event.preventDefault();
  const form = event.target;
  markInvalid(form, [], "login-status");
  say("login-status", "Signing in…");
  try {
    const me = await api("/auth/login", { method: "POST", body: {
      email: form.elements.email.value, password: form.elements.password.value } });
    form.reset();
    say("login-status", "");
    await signedIn(me);
  } catch (error) {
    say("login-status", error.message, "error");
    markInvalid(form, error.fields, "login-status");
  }
}

async function register(event) {
  event.preventDefault();
  const form = event.target;
  markInvalid(form, [], "register-status");
  say("register-status", "Creating…");
  try {
    const result = await api("/auth/register", { method: "POST", body: {
      email: form.elements.email.value, password: form.elements.password.value } });
    document.getElementById("login-email").value = form.elements.email.value;
    form.reset();
    say("register-status", result.detail, "ok");
    document.getElementById("login-password").focus();
  } catch (error) {
    say("register-status", error.message, "error");
    markInvalid(form, error.fields, "register-status");
  }
}

async function signOut() {
  try {
    await api("/auth/logout", { method: "POST" });
  } catch {
    // Signed out locally either way.
  }
  signedOut();
  say("login-status", "Signed out.", "ok");
}

// ---------- extension pairing approval ----------

function readPairCode() {
  const match = /^#pair=([A-Za-z2-9]{4}-?[A-Za-z2-9]{4})$/.exec(location.hash);
  return match ? match[1].toUpperCase() : null;
}

function showPairCard() {
  const card = document.getElementById("pair-card");
  card.hidden = !state.pairCode;
  if (!state.pairCode) return;
  document.getElementById("pair-code").textContent = state.pairCode;
  say("pair-status", "");
  card.focus();
}

function clearPairing() {
  state.pairCode = null;
  history.replaceState(null, "", location.pathname + location.search);
  document.getElementById("pair-card").hidden = true;
}

async function approvePairing() {
  const button = document.getElementById("pair-approve");
  button.disabled = true;
  say("pair-status", "Approving…");
  try {
    const result = await api("/extension/pairings/approve", { method: "POST", body: { code: state.pairCode } });
    say("pair-status", result.detail, "ok");
    state.pairCode = null;
    history.replaceState(null, "", location.pathname + location.search);
  } catch (error) {
    say("pair-status", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

// ---------- overview ----------

function cardList(entries) {
  return entries.map(([label, value, hint]) => el("div", {}, el("dt", {}, label), el("dd", {}, value),
    hint ? el("p", { class: "hint" }, hint) : null));
}

async function loadOverview() {
  const section = document.getElementById("view-overview");
  const cards = document.getElementById("overview-cards");
  const more = document.getElementById("overview-more");
  setStatus(section, "Loading…");
  cards.replaceChildren();
  more.replaceChildren();
  try {
    const d = await getJSON(`${API}/overview`);
    cards.replaceChildren(...cardList([
      ["Websites", d.websites], ["Aliases", d.aliases], ["Emails received", d.emails_total],
      ["Unread", d.unread, d.unread ? "In your inbox" : null],
    ]));
    more.replaceChildren(...cardList([
      ["Nicknames", d.nicknames], ["Consent receipts", d.receipts], ["Matched", d.matched],
      ["Ambiguous", d.ambiguous], ["No match", d.no_match], ["Investigations", d.investigations],
    ]));
    setUnreadBadge(d.unread);
    setStatus(section, d.websites === 0 ? "No websites yet. Create a signup with the LeakTrace extension to start." : "");
  } catch (error) {
    setStatus(section, error.message, true);
  }
  await loadRecent();
}

async function loadRecent() {
  const listBox = document.getElementById("recent-list");
  say("recent-status", "Loading…");
  listBox.replaceChildren();
  try {
    const page = await getJSON(`${API}/inbox?${new URLSearchParams({ limit: 5 })}`);
    listBox.replaceChildren(...page.items.map((m) => inboxCard(m, { compact: true })));
    say("recent-status", page.total === 0 ? "No email has arrived at your aliases yet." : "");
  } catch (error) {
    say("recent-status", error.message, "error");
  }
}

// ---------- my websites ----------

async function loadWebsites() {
  const section = document.getElementById("view-websites");
  const body = document.getElementById("websites-body");
  setStatus(section, "Loading…");
  body.replaceChildren();
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.websites, filter: state.websiteFilter });
  if (state.websiteQuery) params.set("q", state.websiteQuery);
  try {
    const page = await getJSON(`${API}/signups?${params}`);
    body.replaceChildren(...page.items.map((s) => el("tr", {},
      el("td", {}, siteLabel(s.site_name, s.site_domain)),
      el("td", { class: "marker" }, s.alias ?? "—"),
      el("td", {}, s.nickname ?? (s.real_name_required ? "Real name required" : "—")),
      el("td", {}, formatTime(s.created_at)),
      el("td", {}, s.receipt_count),
      el("td", {}, s.email_count),
      el("td", {}, el("button", { type: "button", "aria-label": `Show details for ${s.site_name}`,
        onclick: () => showWebsite(s.id) }, "Details")))));
    renderPager("websites", page, loadWebsites);
    const filtered = state.websiteQuery || state.websiteFilter !== "all";
    setStatus(section, page.total === 0 ? (filtered ? "No websites match this search." : "No websites yet.") : "");
  } catch (error) {
    setStatus(section, error.message, true);
  }
}

async function showWebsite(id) {
  const panel = document.getElementById("website-detail");
  const body = document.getElementById("website-detail-body");
  panel.hidden = false;
  body.replaceChildren(el("p", { role: "status" }, "Loading…"));
  try {
    const d = await getJSON(`${API}/signups/${encodeURIComponent(id)}`);
    const rows = [
      ["Website", d.site_name], ["Domain", d.site_domain ?? "—"], ["Signup ID", `#${d.id}`],
      ["Alias", d.alias ?? "—"], ["Nickname", d.nickname ?? "—"], ["Surname variant", d.surname_variant ?? "—"],
      ["Real name required", d.real_name_required ? "Yes" : "No"], ["Signed up", formatTime(d.created_at)],
    ];
    body.replaceChildren(
      el("dl", {}, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      el("div", { class: "row" }, d.alias ? copyButton("alias", d.alias) : null, d.nickname ? copyButton("nickname", d.nickname) : null),
      el("h4", {}, "Consent receipts"),
      d.receipts.length ? list(d.receipts.map((r) => `${formatTime(r.recorded_at)} — ${ACTION_LABELS[r.action] ?? "Not recorded"}`
        + `${r.evidence_basis === "user_reported" ? " · user-reported (not verified)" : ""}`)) : el("p", { class: "hint" }, "None yet."),
      el("h4", {}, "Email received at this alias"),
      d.emails.length ? list(d.emails.map((m) => el("span", {}, formatTime(m.received_at), " ", statusBadge(m.match_status),
        m.sender_domain ? ` from ${m.sender_domain} (claimed)` : ""))) : el("p", { class: "hint" }, "None yet."),
      el("p", { class: "notice", role: "note" }, d.notice));
  } catch (error) {
    body.replaceChildren(el("p", { class: "error", role: "alert" }, error.message));
  }
  panel.focus();
}

// ---------- consent receipts ----------

function actionLabel(action) {
  return action ? (ACTION_LABELS[action] ?? action) : "Not recorded";
}

function sourceLabel(r) {
  return r.evidence_basis === "user_reported" ? "Manual · user-reported (not verified)" : "Unknown source";
}

async function loadReceipts() {
  const section = document.getElementById("view-receipts");
  const body = document.getElementById("receipts-body");
  setStatus(section, "Loading…");
  body.replaceChildren();
  try {
    const page = await getJSON(`/consent-receipts?${new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.receipts })}`);
    body.replaceChildren(...page.items.map((r) => {
      const kept = [r.source_url ? "URL" : null, r.content_hash ? "hash" : null,
        r.notice_text_stored ? "notice text" : null, r.consent_text_stored ? "consent wording" : null,
        r.notice_version ? "version" : null].filter(Boolean).join(", ") || "none";
      return el("tr", {},
        el("td", {}, formatTime(r.recorded_at)),
        el("td", {}, r.site_name ? siteLabel(r.site_name, r.site_domain) : "Signup deleted"),
        el("td", {}, actionLabel(r.action)),
        el("td", {}, sourceLabel(r)),
        el("td", {}, kept),
        el("td", {}, el("button", { type: "button", "aria-label": `Show details for receipt ${r.id}`,
          onclick: () => showReceiptDetail(r.id) }, "Details")));
    }));
    renderPager("receipts", page, loadReceipts);
    setStatus(section, page.total === 0 ? "No consent receipts yet." : "");
  } catch (error) {
    setStatus(section, error.message, true);
  }
}

async function showReceiptDetail(id) {
  const panel = document.getElementById("receipt-detail");
  const body = document.getElementById("receipt-detail-body");
  panel.hidden = false;
  body.replaceChildren(el("p", { role: "status" }, "Loading…"));
  try {
    const r = await getJSON(`/consent-receipts/${encodeURIComponent(id)}`);
    const rows = [
      ["Site", r.site_name ? siteLabel(r.site_name, r.site_domain) : "Signup deleted"],
      ["Reported action", actionLabel(r.action)],
      ["Source", sourceLabel(r)],
      ["Recorded by LeakTrace (server time)", formatTime(r.recorded_at)],
      ["Reported event time (unverified)", r.reported_occurred_at ? formatTime(r.reported_occurred_at) : "Not reported"],
      ["Notice URL (not fetched)", r.source_url ?? "—"],
      ["Notice version", r.notice_version ?? "—"],
      ["Notice hash", r.content_hash ?? "—"],
    ];
    body.replaceChildren(
      el("p", { class: "notice", role: "note" }, r.legal_notice),
      el("dl", {}, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      el("p", { class: "hint" }, r.timestamp_note),
      el("h4", {}, "Notice text"),
      r.notice_text ? el("div", { class: "prewrap" }, r.notice_text) : el("p", {}, "Not stored."),
      el("h4", {}, "Consent prompt wording"),
      r.consent_text ? el("div", { class: "prewrap" }, r.consent_text) : el("p", {}, "Not stored."));
  } catch (error) {
    body.replaceChildren(el("p", { class: "error", role: "alert" }, error.message));
  }
  panel.focus();
}

async function sha256Hex(text) {
  if (!globalThis.crypto?.subtle) throw new Error("This browser cannot compute the hash here; tick “Also store the notice text”.");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function createReceipt(event) {
  event.preventDefault();
  const form = event.target;
  const status = document.getElementById("receipt-form-status");
  status.classList.remove("error");
  markInvalid(form, [], "receipt-form-status");
  status.textContent = "Saving…";
  try {
    const payload = {};
    for (const [key, value] of new FormData(form)) {
      if (String(value).trim()) payload[key] = key === "notice_text" || key === "consent_text" ? String(value) : String(value).trim();
    }
    payload.signup_id = Number(payload.signup_id);
    if (payload.reported_occurred_at) {
      const when = new Date(payload.reported_occurred_at);
      if (Number.isNaN(when.getTime())) throw new RequestError("When it happened: not a valid date.", ["reported_occurred_at"]);
      payload.reported_occurred_at = when.toISOString();
    }
    if (payload.notice_text && !document.getElementById("receipt-store-text").checked) {
      payload.content_hash = await sha256Hex(payload.notice_text);
      delete payload.notice_text;
    }
    const saved = await api("/consent-receipts", { method: "POST", body: payload });
    form.reset();
    status.textContent = `Saved receipt ${saved.id} as user-reported.`;
    state.offsets.receipts = 0;
    await loadReceipts();
  } catch (error) {
    status.textContent = error.message;
    status.classList.add("error");
    markInvalid(form, error.fields, "receipt-form-status");
  }
}

// ---------- inbox ----------

function setUnreadBadge(count) {
  const badge = document.getElementById("unread-badge");
  badge.hidden = !count;
  badge.textContent = count > 99 ? "99+" : String(count);
  badge.setAttribute("aria-label", unreadLabel(count));
}

function inboxStatusBadge(m) {
  return el("span", { class: `badge badge-inbox-${m.status}` }, INBOX_STATUS_LABELS[m.status] ?? m.status);
}

function inboxCard(m, { compact = false } = {}) {
  const title = m.tracked ? (m.subject ?? "(no subject)") : "Recorded before inbox tracking";
  const meta = [
    el("span", {}, formatTime(m.received_at)),
    el("span", {}, m.site_name ? siteLabel(m.site_name, m.site_domain) : "No website"),
    m.alias ? el("span", { class: "marker" }, m.alias) : null,
  ];
  return el("li", { class: `card${m.unread ? " unread" : ""}`, "data-id": m.id },
    el("article", { "aria-label": `${m.unread ? "Unread: " : ""}${title}` },
      el("div", { class: "card-head" },
        m.unread ? el("span", { class: "dot", "aria-hidden": "true" }) : null,
        m.unread ? el("span", { class: "sr-only" }, "Unread. ") : null,
        el("strong", { class: "card-title" }, title),
        inboxStatusBadge(m)),
      el("p", { class: "card-line" }, m.tracked && m.status !== "unmatched" ? notificationText(m) : reasonText(m.status_reason) ?? ""),
      el("p", { class: "card-line hint" }, m.tracked ? `From ${senderText(m)}` : "Sender and subject were not stored for this record."),
      el("p", { class: "card-meta hint" }, ...meta.filter(Boolean).flatMap((node, i) => (i ? [" · ", node] : [node]))),
      compact ? null : el("button", { type: "button", "aria-label": `Open message: ${title}`,
        onclick: () => showInboxDetail(m.id) }, "Open")));
}

async function loadInbox() {
  const section = document.getElementById("view-inbox");
  const listBox = document.getElementById("inbox-list");
  const retry = document.getElementById("inbox-retry");
  retry.hidden = true;
  setStatus(section, "Loading…");
  listBox.setAttribute("aria-busy", "true");
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.inbox, filter: state.inboxFilter });
  try {
    const page = await getJSON(`${API}/inbox?${params}`);
    listBox.replaceChildren(...page.items.map((m) => inboxCard(m)));
    renderPager("inbox", page, loadInbox);
    setUnreadBadge(page.unread);
    document.getElementById("inbox-read-all").disabled = page.unread === 0;
    document.getElementById("inbox-notice").textContent = page.notice;
    const empty = {
      all: "No email has arrived at your aliases yet.", unread: "No unread email.",
      matched: "No email linked to your websites.", unmatched: "No unmatched email.", failed: "No failed messages.",
    }[state.inboxFilter];
    setStatus(section, page.total === 0 ? empty : `${unreadLabel(page.unread)}.`);
  } catch (error) {
    listBox.replaceChildren();
    setStatus(section, error.message, true);
    retry.hidden = false;
  } finally {
    listBox.removeAttribute("aria-busy");
  }
}

function setInboxFilter(filter) {
  state.inboxFilter = filter;
  state.offsets.inbox = 0;
  for (const button of document.querySelectorAll("#inbox-filters [data-filter]")) {
    button.setAttribute("aria-pressed", String(button.dataset.filter === filter));
  }
  document.getElementById("inbox-detail").hidden = true;
  loadInbox();
}

function inboxDetailRows(d) {
  return [
    ["Received", formatTime(d.received_at)],
    ["Sent to", d.identity ? `${d.identity} (${d.alias ?? "no alias"})` : (d.alias ?? "—")],
    ["Website", d.site_name ? `#${d.signup_id} ${siteLabel(d.site_name, d.site_domain)}` : "Not linked"],
    ["Status", inboxStatusBadge(d)],
    d.status_reason ? ["Why", reasonText(d.status_reason)] : null,
    ["From", d.tracked ? senderText(d) : "Not stored"],
    ["Subject", d.tracked ? (d.subject ?? "(no subject)") : "Not stored"],
    ["Sender domain (claimed)", d.sender_domain ?? "—"],
    ["Authentication (Cloudflare, unverified)", d.auth_results ?? "Not available"],
    ["Leak match", d.match_status ? el("span", {}, statusBadge(d.match_status), ` confidence: ${d.match_confidence ?? "—"}`) : "Not analysed"],
    ["Read", d.read_at ? formatTime(d.read_at) : (d.tracked ? "Unread" : "—")],
  ].filter(Boolean);
}

async function showInboxDetail(id) {
  const panel = document.getElementById("inbox-detail");
  const body = document.getElementById("inbox-detail-body");
  const unreadButton = document.getElementById("inbox-detail-unread");
  state.openEmailId = id;
  panel.hidden = false;
  unreadButton.hidden = true;
  body.replaceChildren(el("p", { role: "status" }, "Loading…"));
  try {
    let d = await getJSON(`${API}/inbox/${encodeURIComponent(id)}`);
    if (d.unread) {
      d = await api(`${API}/inbox/${encodeURIComponent(id)}/read`, { method: "POST", body: { read: true } });
      refreshUnread();
    }
    body.replaceChildren(
      el("dl", {}, ...inboxDetailRows(d).flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      el("p", { class: "notice", role: "note" }, "A message linked to a website is not proof that the website leaked, sold or shared your data."));
    unreadButton.hidden = !d.tracked;
    replaceCard(d);
  } catch (error) {
    body.replaceChildren(el("p", { class: "error", role: "alert" }, error.message));
  }
  panel.focus();
}

/** Re-render one message's card in the inbox list after its read state changed. */
function replaceCard(m) {
  document.querySelector(`#inbox-list li[data-id="${Number(m.id)}"]`)?.replaceWith(inboxCard(m));
}

async function markOpenEmailUnread() {
  if (!state.openEmailId) return;
  try {
    await api(`${API}/inbox/${encodeURIComponent(state.openEmailId)}/read`, { method: "POST", body: { read: false } });
    document.getElementById("inbox-detail").hidden = true;
    await loadInbox();
  } catch (error) {
    setStatus(document.getElementById("view-inbox"), error.message, true);
  }
}

async function markAllRead() {
  const section = document.getElementById("view-inbox");
  try {
    const result = await api(`${API}/inbox/read-all`, { method: "POST" });
    await loadInbox();
    setStatus(section, result.marked === 1 ? "Marked 1 email as read." : `Marked ${result.marked} emails as read.`);
  } catch (error) {
    setStatus(section, error.message, true);
  }
}

// ---------- polling and notifications ----------

async function refreshUnread() {
  try {
    const updates = await getJSON(`${API}/inbox/updates`);
    setUnreadBadge(updates.unread);
  } catch {
    // The badge is refreshed again by the next poll.
  }
}

function notify(items) {
  const region = document.getElementById("notifications");
  const listBox = document.getElementById("notification-list");
  for (const m of [...items].reverse()) {
    listBox.prepend(el("li", {}, el("strong", {}, notificationText(m)), " — ",
      `${senderText(m)}: ${m.subject ?? "(no subject)"} · ${formatTime(m.received_at)} · ${m.alias ?? ""}`,
      " ", el("button", { type: "button", class: "link", onclick: () => openFromNotification(m.id) }, "View")));
  }
  while (listBox.children.length > MAX_NOTIFICATIONS) listBox.lastElementChild.remove();
  region.hidden = listBox.children.length === 0;
}

function dismissNotifications() {
  document.getElementById("notification-list").replaceChildren();
  document.getElementById("notifications").hidden = true;
}

function openFromNotification(id) {
  selectTab(document.getElementById("tab-inbox"));
  showInboxDetail(id);
}

async function poll() {
  state.pollTimer = null;
  if (!state.me) return;
  try {
    const params = state.latestEmailId === null ? "" : `?${new URLSearchParams({ after_id: state.latestEmailId })}`;
    const updates = await getJSON(`${API}/inbox/updates${params}`);
    if (!state.me) return;
    setUnreadBadge(updates.unread);
    const fresh = updates.new.filter((m) => m.status !== "unmatched");
    if (fresh.length) notify(fresh);
    if (updates.new.length && currentTab()?.id === "tab-inbox" && state.offsets.inbox === 0) loadInbox();
    if (updates.new.length && currentTab()?.id === "tab-overview") loadRecent();
    state.latestEmailId = updates.latest_id;
    state.pollDelay = POLL_INTERVAL_MS;
  } catch (error) {
    if (!state.me) return;
    // Back off while the server is unreachable; the next success resets it.
    state.pollDelay = Math.min(state.pollDelay * 2, MAX_POLL_INTERVAL_MS);
  }
  schedulePoll();
}

function schedulePoll(delay = state.pollDelay) {
  clearTimeout(state.pollTimer);
  state.pollTimer = setTimeout(poll, delay);
}

function stopPolling() {
  clearTimeout(state.pollTimer);
  state.pollTimer = null;
  state.latestEmailId = null;
  state.pollDelay = POLL_INTERVAL_MS;
}

// ---------- leak activity ----------

async function loadActivity() {
  await Promise.all([loadEmails(), loadInvestigations()]);
}

async function loadEmails() {
  const section = document.getElementById("view-activity");
  const body = document.getElementById("emails-body");
  setStatus(section, "Loading…");
  body.replaceChildren();
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.emails });
  if (state.emailStatus) params.set("status", state.emailStatus);
  try {
    const page = await getJSON(`${API}/emails?${params}`);
    body.replaceChildren(...page.items.map((m) => el("tr", {},
      el("td", {}, formatTime(m.received_at)),
      el("td", {}, statusBadge(m.match_status)),
      el("td", {}, m.match_confidence ?? "—"),
      el("td", {}, m.site_name ? siteLabel(m.site_name, m.site_domain) : m.recipient_known ? "Known alias" : "Unknown alias"),
      el("td", {}, m.sender_domain ?? "—"),
      el("td", {}, el("button", { type: "button", "aria-label": `Show match details for email ${m.id}`,
        onclick: () => showEmailDetail(m.id) }, "Details")))));
    renderPager("emails", page, loadEmails);
    setStatus(section, page.total === 0 ? "No email received at your aliases yet." : "");
  } catch (error) {
    setStatus(section, error.message, true);
  }
}

async function showEmailDetail(id) {
  const panel = document.getElementById("email-detail");
  const body = document.getElementById("email-detail-body");
  panel.hidden = false;
  body.replaceChildren(el("p", { role: "status" }, "Loading…"));
  try {
    const d = await getJSON(`${API}/emails/${encodeURIComponent(id)}`);
    const rows = [
      ["Status", statusBadge(d.match_status)], ["Confidence", d.match_confidence ?? "—"],
      ["Received", formatTime(d.received_at)], ["Recorded", formatTime(d.created_at)],
      ["Website", d.signup_id ? `#${d.signup_id} ${siteLabel(d.site_name, d.site_domain)}` : "Recipient alias not recognised"],
      ["Sender domain (claimed)", d.sender_domain ?? "—"],
    ];
    body.replaceChildren(
      el("p", { class: "notice", role: "note" }, d.notice),
      el("dl", {}, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      el("p", { class: "hint" }, d.stored_details),
      el("h4", {}, "Limitations"), list(d.limitations));
  } catch (error) {
    body.replaceChildren(el("p", { class: "error", role: "alert" }, error.message));
  }
  panel.focus();
}

async function loadInvestigations() {
  const body = document.getElementById("investigations-body");
  say("investigations-status", "Loading…");
  body.replaceChildren();
  try {
    const page = await getJSON(`${API}/investigations?${new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.investigations })}`);
    body.replaceChildren(...page.items.map((i) => el("tr", {},
      el("td", {}, formatTime(i.created_at)),
      el("td", {}, statusBadge(i.result)),
      el("td", {}, i.confidence ?? "—"),
      el("td", {}, i.matched_site ?? (i.candidate_count ? `${i.candidate_count} possible websites` : "—")),
      el("td", {}, i.signal_types.join(", ") || "—"),
      el("td", {}, i.sender_domain ?? "—"))));
    renderPager("investigations", page, loadInvestigations);
    say("investigations-status", page.total === 0 ? "No investigations recorded yet." : "");
  } catch (error) {
    say("investigations-status", error.message, "error");
  }
}

// ---------- match check ----------

async function runCheck(event) {
  event.preventDefault();
  const section = document.getElementById("view-check");
  const result = document.getElementById("check-result");
  const payload = {};
  for (const [key, value] of new FormData(event.target)) {
    if (String(value).trim()) payload[key] = String(value).trim();
  }
  if (document.getElementById("check-record").checked) payload.record_incident = true;
  result.replaceChildren();
  markInvalid(event.target, [], "check-status");
  setStatus(section, "Checking…");
  try {
    const r = await api("/matcher/check", { method: "POST", body: payload });
    const matches = r.matches.length === 0 ? [el("p", {}, "None of your websites match these clues.")]
      : r.matches.map((m) => el("article", { class: "result" },
        el("h4", {}, `${siteLabel(m.site_name, m.site_domain)} — confidence: ${m.confidence}`),
        list(m.signals.map((s) => `${s.type}: ${s.explanation}`))));
    result.replaceChildren(
      el("p", {}, "Result: ", statusBadge(r.status), ` confidence: ${r.confidence}`),
      ...matches,
      ...(r.warnings.length ? [el("h4", {}, "Warnings"), list(r.warnings)] : []),
      el("h4", {}, "Limitations"), list(r.limitations),
      r.incident_id ? el("p", { class: "hint" }, "Recorded under Leak activity.") : null);
    setStatus(section, "");
  } catch (error) {
    setStatus(section, error.message, true);
    markInvalid(event.target, error.fields, "check-status");
  }
}

// ---------- settings ----------

async function loadSettings() {
  const section = document.getElementById("view-settings");
  setStatus(section, "");
  const me = state.me;
  document.getElementById("account-details").replaceChildren(
    el("dt", {}, "Email"), el("dd", {}, me.email),
    el("dt", {}, "Verification"), el("dd", {}, me.email_verified ? "Verified" : "Not verified"));
  document.getElementById("resend-verification").hidden = me.email_verified;
  await loadExtensions();
}

async function loadExtensions() {
  const listBox = document.getElementById("extensions-list");
  say("extensions-status", "Loading…");
  listBox.replaceChildren();
  try {
    const sessions = await getJSON("/extension/sessions");
    listBox.replaceChildren(...sessions.map((s) => el("li", {},
      `${s.label ?? "Browser extension"} — connected ${formatTime(s.created_at)}, last used ${formatTime(s.last_used_at)}, expires ${formatTime(s.expires_at)} `,
      el("button", { type: "button", class: "secondary", "aria-label": `Revoke extension connection ${s.id}`,
        onclick: () => revokeExtension(s.id) }, "Revoke"))));
    say("extensions-status", sessions.length ? "" : "No browser extension is connected.");
  } catch (error) {
    say("extensions-status", error.message, "error");
  }
}

async function revokeExtension(id) {
  try {
    await api(`/extension/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadExtensions();
    say("extensions-status", "Connection revoked. That extension can no longer use your account.", "ok");
  } catch (error) {
    say("extensions-status", error.message, "error");
  }
}

async function resendVerification() {
  try {
    const result = await api("/auth/verification/resend", { method: "POST" });
    say("verification-status", result.detail, result.verification_email_sent ? "ok" : "");
  } catch (error) {
    say("verification-status", error.message, "error");
  }
}

async function changePassword(event) {
  event.preventDefault();
  const form = event.target;
  markInvalid(form, [], "password-status");
  say("password-status", "Saving…");
  try {
    await api("/auth/password", { method: "POST", body: {
      current_password: form.elements.current_password.value, new_password: form.elements.new_password.value } });
    form.reset();
    say("password-status", "Password changed. Your other sessions and browser extensions were signed out.", "ok");
    await loadExtensions();
  } catch (error) {
    say("password-status", error.message, "error");
    markInvalid(form, error.fields, "password-status");
  }
}

async function deleteAccount(event) {
  event.preventDefault();
  const form = event.target;
  markInvalid(form, [], "delete-status");
  if (form.elements.confirm.value !== "DELETE") {
    say("delete-status", "Confirmation: type DELETE in capital letters.", "error");
    markInvalid(form, ["confirm"], "delete-status");
    return;
  }
  say("delete-status", "Deleting…");
  try {
    await api("/account", { method: "DELETE", body: { password: form.elements.password.value, confirm: "DELETE" } });
    form.reset();
    signedOut();
    say("login-status", "Your account and its records were deleted.", "ok");
  } catch (error) {
    say("delete-status", error.message, "error");
    markInvalid(form, error.fields, "delete-status");
  }
}

// ---------- tabs ----------

const loaders = {
  overview: loadOverview, websites: loadWebsites, inbox: loadInbox, receipts: loadReceipts, activity: loadActivity,
  check: () => {}, settings: loadSettings,
};

function selectTab(tab, focus = false) {
  for (const t of document.querySelectorAll('[role="tab"]')) {
    const selected = t === tab;
    t.setAttribute("aria-selected", String(selected));
    t.tabIndex = selected ? 0 : -1;
    document.getElementById(t.getAttribute("aria-controls")).hidden = !selected;
  }
  if (focus) tab.focus();
  loaders[tab.id.replace("tab-", "")]();
}

function currentTab() {
  return document.querySelector('[role="tab"][aria-selected="true"]');
}

document.addEventListener("DOMContentLoaded", async () => {
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  for (const tab of tabs) {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => {
      const index = tabs.indexOf(tab);
      const next = { ArrowRight: index + 1, ArrowLeft: index - 1, Home: 0, End: tabs.length - 1 }[event.key];
      if (next === undefined) return;
      event.preventDefault();
      selectTab(tabs[(next + tabs.length) % tabs.length], true);
    });
  }
  document.getElementById("login-form").addEventListener("submit", login);
  document.getElementById("register-form").addEventListener("submit", register);
  document.getElementById("sign-out").addEventListener("click", signOut);
  document.getElementById("pair-approve").addEventListener("click", approvePairing);
  document.getElementById("pair-cancel").addEventListener("click", clearPairing);
  document.getElementById("websites-search").addEventListener("submit", (event) => {
    event.preventDefault();
    state.websiteQuery = document.getElementById("websites-q").value.trim();
    state.websiteFilter = document.getElementById("websites-filter").value;
    state.offsets.websites = 0;
    loadWebsites();
  });
  document.getElementById("website-detail-close").addEventListener("click", () => { document.getElementById("website-detail").hidden = true; });
  document.getElementById("receipt-form").addEventListener("submit", createReceipt);
  document.getElementById("receipt-detail-close").addEventListener("click", () => { document.getElementById("receipt-detail").hidden = true; });
  document.getElementById("email-status").addEventListener("change", (event) => {
    state.emailStatus = event.target.value;
    state.offsets.emails = 0;
    loadEmails();
  });
  document.getElementById("email-detail-close").addEventListener("click", () => { document.getElementById("email-detail").hidden = true; });
  for (const button of document.querySelectorAll("#inbox-filters [data-filter]")) {
    button.addEventListener("click", () => setInboxFilter(button.dataset.filter));
  }
  document.getElementById("inbox-read-all").addEventListener("click", markAllRead);
  document.getElementById("inbox-retry").addEventListener("click", loadInbox);
  document.getElementById("inbox-detail-unread").addEventListener("click", markOpenEmailUnread);
  document.getElementById("inbox-detail-close").addEventListener("click", () => {
    document.getElementById("inbox-detail").hidden = true;
    state.openEmailId = null;
  });
  document.getElementById("recent-open-inbox").addEventListener("click", () => selectTab(document.getElementById("tab-inbox"), true));
  document.getElementById("notifications-dismiss").addEventListener("click", dismissNotifications);
  document.addEventListener("visibilitychange", () => {
    if (state.me && document.visibilityState === "visible") schedulePoll(0);
  });
  document.getElementById("check-form").addEventListener("submit", runCheck);
  document.getElementById("resend-verification").addEventListener("click", resendVerification);
  document.getElementById("password-form").addEventListener("submit", changePassword);
  document.getElementById("delete-form").addEventListener("submit", deleteAccount);

  state.pairCode = readPairCode();
  try {
    const response = await fetch("/auth/me", { credentials: "same-origin", cache: "no-store", headers: { accept: "application/json" } });
    if (response.ok) {
      await signedIn(await response.json());
      return;
    }
  } catch {
    // fall through to the sign-in view
  }
  signedOut();
  if (state.pairCode) say("login-status", "Sign in to approve the browser extension.");
});
