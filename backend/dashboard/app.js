// LeakTrace personal dashboard. Plain JavaScript, no dependencies.
// All data is rendered with textContent / DOM nodes, never as HTML.
// Signed-in state lives in an HttpOnly session cookie; every state-changing
// request also sends the CSRF token returned by /auth/me.
// Nothing on these pages is sample data: every number comes from the API.
"use strict";

const API = "/dashboard/api";
const PAGE_SIZE = 20;
const STATUS_LABELS = {
  matched: "Matched", unmatched: "Unmatched", failed: "Failed", ambiguous: "Ambiguous", no_match: "No match", unprocessed: "Unprocessed",
};
const ACTION_LABELS = { accepted: "Accepted", declined: "Declined", notice_only: "Only saw the notice" };
const INBOX_STATUS_LABELS = { unprocessed: "Unprocessed", matched: "Matched", unmatched: "Unmatched", failed: "Failed" };
const REASON_LABELS = {
  legacy_unprocessed: "This historical record has no recorded recipient attribution.",
  invalid_alias_association: "The recorded recipient no longer has a valid association with this account and website.",
  not_linked: "Not linked to any of your websites. The website may have been deleted.",
  analysis_failed: "Linked to your website, but the leak analysis failed. It runs again if the message is redelivered.",
  unknown_alias: "Sent to an address that is not one of your aliases.",
  unowned_alias: "Sent to an alias that is not linked to an account.",
  ambiguous_alias: "The recipient matched more than one alias, so it was not linked.",
};
const PAGE_TITLES = {
  overview: "Overview", websites: "Websites & aliases", inbox: "Inbox", sms: "SMS analyzer", receipts: "Consent receipts",
  activity: "Leak activity", check: "Match check", settings: "Settings",
};
const POLL_INTERVAL_MS = 30_000;
const MAX_POLL_INTERVAL_MS = 5 * 60_000;
const MAX_NOTIFICATIONS = 5;
const MAX_TOASTS = 3;
const CHART_DAYS = 14;
const CHART_SAMPLE = 100;  // the API's largest page
const THEME_KEY = "leaktrace.theme";
const state = {
  me: null, offsets: { websites: 0, receipts: 0, emails: 0, investigations: 0, inbox: 0, sms: 0 },
  sms: { exclude: [], additions: [], analysis: null, saved: null },
  emailStatus: "", websiteQuery: "", websiteFilter: "all", pairCode: null, deviceCode: null,
  inboxFilter: "all", openEmailId: null, latestEmailId: null, pollTimer: null, pollDelay: POLL_INTERVAL_MS,
  autoEvidenceAttempts: new Set(),
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

/** An inline icon from the sprite in index.html. Decorative: hidden from screen readers. */
function icon(name, extraClass = "") {
  const svg = document.getElementById("icon-template").content.firstElementChild.cloneNode(true);
  svg.firstElementChild.setAttribute("href", `#i-${name}`);
  if (extraClass) svg.setAttribute("class", `icon ${extraClass}`);
  return svg;
}

const timeFormat = new Intl.DateTimeFormat("en-GB", {
  year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
  timeZone: "UTC", hour12: false,
});
const dayFormat = new Intl.DateTimeFormat("en-GB", { day: "numeric", month: "short", timeZone: "UTC" });
const weekdayFormat = new Intl.DateTimeFormat("en-GB", { weekday: "short", day: "numeric", month: "short", timeZone: "UTC" });

function formatTime(iso) {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : `${timeFormat.format(date)} UTC`;
}

function formatNumber(n) {
  return typeof n === "number" ? n.toLocaleString("en-GB") : "—";
}

function statusBadge(status) {
  const key = status ?? "unprocessed";
  return el("span", { class: `badge badge-${key}` }, STATUS_LABELS[key] ?? key);
}

function setStatus(section, message, isError = false) {
  const box = section.querySelector("[data-status]");
  box.textContent = message;
  box.classList.toggle("error", isError);
  box.classList.remove("sr-only");
  box.setAttribute("role", isError ? "alert" : "status");
}

/** A status message for screen readers only, when the page shows it visually some other way. */
function setQuietStatus(section, message) {
  setStatus(section, message);
  if (message) section.querySelector("[data-status]").classList.add("sr-only");
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

// ---------- chart data (pure: no DOM) ----------

/**
 * Count messages per UTC day for the `days` days ending today.
 *
 * `times` are received_at values of the newest messages, newest first. When
 * `complete` is false the list was cut off at the API's page size, so days
 * older than the oldest loaded message are marked covered: false instead of
 * being reported as zero.
 */
function emailsPerDay(times, { now = new Date(), days = CHART_DAYS, complete = true } = {}) {
  const dayKey = (d) => d.toISOString().slice(0, 10);
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  const counts = new Map();
  let oldest = null;
  for (const t of times) {
    const date = new Date(t);
    if (Number.isNaN(date.getTime())) continue;
    counts.set(dayKey(date), (counts.get(dayKey(date)) ?? 0) + 1);
    if (oldest === null || date < oldest) oldest = date;
  }
  const oldestDay = oldest === null ? null
    : Date.UTC(oldest.getUTCFullYear(), oldest.getUTCMonth(), oldest.getUTCDate());
  const result = [];
  for (let i = days - 1; i >= 0; i -= 1) {
    const start = today - i * 86_400_000;
    const key = dayKey(new Date(start));
    // The oldest loaded day may itself be partial when the list was cut off.
    const covered = complete || (oldestDay !== null && start > oldestDay);
    result.push({ date: key, count: covered ? (counts.get(key) ?? 0) : null, covered });
  }
  return result;
}

function percentText(part, total) {
  if (!total) return "0%";
  const p = (part / total) * 100;
  return p > 0 && p < 1 ? "<1%" : `${Math.round(p)}%`;
}

// Form labels for request fields, used in validation messages.
const FIELD_LABELS = {
  signup_id: "Signup ID", action: "What you did", source_url: "Privacy notice URL",
  notice_version: "Notice version", notice_text: "Notice text", content_hash: "Notice text hash",
  consent_text: "Consent prompt wording", reported_occurred_at: "When it happened",
  recipient: "Recipient address", sender: "Sender address", subject: "Subject", nickname: "Nickname",
  surname_variant: "Surname", user_id: "User ID", limit: "Page size", offset: "Page position", status: "Status filter",
  email: "Email", password: "Password", current_password: "Current password", new_password: "New password",
  confirm: "Confirmation", code: "Code", filter: "Show", site_name: "Website name", site_domain: "Website domain",
  real_name_required: "Real name required", received_at: "Received", candidate_key: "Source",
};
// Labels for single-word field names. Used only to name the field an error is
// about, never to rewrite words inside messages ("Notice text" stays as is).
const PREFIX_LABELS = {
  ...FIELD_LABELS, text: "Message text", label: "Where you received it", exclude: "Corrections",
  additions: "Added details", value: "Value", type: "Type",
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
    return { field, text: `${PREFIX_LABELS[field] ?? field}: ${message}` };
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

// ---------- shared components ----------

function renderPager(name, page, reload) {
  const pager = document.querySelector(`[data-pager="${name}"]`);
  if (page.total <= page.limit && page.offset === 0) {
    pager.replaceChildren();
    return;
  }
  const from = page.total === 0 ? 0 : page.offset + 1;
  const to = page.offset + page.items.length;
  pager.replaceChildren(
    el("button", { type: "button", class: "btn btn-secondary btn-sm", "aria-label": "Previous page",
      onclick: () => { state.offsets[name] = Math.max(0, page.offset - page.limit); reload(); } }, icon("chev-left"), "Previous"),
    el("span", { "aria-live": "polite" }, `${from}–${to} of ${formatNumber(page.total)}`),
    el("button", { type: "button", class: "btn btn-secondary btn-sm", "aria-label": "Next page",
      onclick: () => { state.offsets[name] = page.offset + page.limit; reload(); } }, "Next", icon("chev-right")),
  );
  pager.children[0].disabled = page.offset === 0;
  pager.children[2].disabled = to >= page.total;
}

function list(items) {
  return el("ul", {}, ...items.map((item) => el("li", {}, item)));
}

/** A short confirmation in the corner; announced by screen readers. */
function toast(message, kind = "ok") {
  const region = document.getElementById("toasts");
  const node = el("div", { class: `toast toast-${kind}` }, icon(kind === "error" ? "alert" : "check"), el("p", {}, message));
  region.append(node);
  while (region.children.length > MAX_TOASTS) region.firstElementChild.remove();
  setTimeout(() => node.remove(), kind === "error" ? 7000 : 4000);
}

async function copyText(value, label, button = null) {
  try {
    await navigator.clipboard.writeText(value);
    toast(`Copied ${label} to the clipboard.`);
    if (button) {
      button.classList.add("copied");
      button.replaceChildren(icon("check"));
      setTimeout(() => { button.classList.remove("copied"); button.replaceChildren(icon("copy")); }, 1600);
    }
    return true;
  } catch {
    toast(`Copy failed. Select the ${label} and copy it manually.`, "error");
    return false;
  }
}

function copyButton(label, value) {
  const button = el("button", { type: "button", class: "btn btn-secondary btn-sm" }, icon("copy"), `Copy ${label}`);
  button.addEventListener("click", async () => {
    const ok = await copyText(value, label);
    button.lastChild.textContent = ok ? `Copied ${label}` : `Copy failed — select the ${label} and copy it manually`;
  });
  return button;
}

function copyIconButton(label, value) {
  const button = el("button", { type: "button", class: "icon-btn", "aria-label": `Copy ${label}`, title: `Copy ${label}` }, icon("copy"));
  button.addEventListener("click", () => copyText(value, label, button));
  return button;
}

function emptyState({ iconName = "info", title, text = "", action = null }) {
  return el("div", { class: "empty" }, icon(iconName, "icon-xl"), el("p", { class: "empty-title" }, title),
    text ? el("p", { class: "hint" }, text) : null, action);
}

function errorState(message, retry) {
  return el("div", { class: "empty" }, icon("alert", "icon-xl"), el("p", { class: "empty-title" }, "Could not load this"),
    el("p", { class: "hint" }, message),
    retry ? el("button", { type: "button", class: "btn btn-secondary", onclick: retry }, icon("refresh"), "Try again") : null);
}

/** One full-width row inside a table body (empty and error states). */
function tableMessage(tbody, node) {
  const columns = tbody.closest("table").querySelectorAll("thead th").length;
  tbody.replaceChildren(el("tr", {}, el("td", { colspan: columns, class: "empty-cell" }, node)));
}

function tableSkeleton(tbody, rows = 4) {
  const columns = tbody.closest("table").querySelectorAll("thead th").length;
  const widths = ["w-80", "w-60", "w-40"];
  tbody.replaceChildren(...Array.from({ length: rows }, (_, r) => el("tr", { "aria-hidden": "true" },
    ...Array.from({ length: columns }, (_, c) => el("td", {}, el("span", { class: `skeleton ${widths[(r + c) % 3]}` }))))));
}

function listSkeleton(listBox, rows = 3) {
  listBox.replaceChildren(...Array.from({ length: rows }, () => el("li", { class: "card skeleton-card", "aria-hidden": "true" },
    el("span", { class: "skeleton w-60" }), el("span", { class: "skeleton w-80" }), el("span", { class: "skeleton w-40" }))));
}

/** A modal confirmation built on <dialog>. Resolves to true only when confirmed. */
function confirmAction({ title, body, confirmLabel, danger = true }) {
  const dialog = document.getElementById("confirm-dialog");
  const ok = document.getElementById("confirm-ok");
  document.getElementById("confirm-title").textContent = title;
  document.getElementById("confirm-body").textContent = body;
  ok.textContent = confirmLabel;
  ok.className = danger ? "btn btn-danger" : "btn btn-primary";
  const opener = document.activeElement;
  return new Promise((resolve) => {
    const done = (value) => {
      ok.onclick = null;
      document.getElementById("confirm-cancel").onclick = null;
      dialog.onclose = null;
      if (dialog.open) dialog.close();
      opener?.focus?.();
      resolve(value);
    };
    ok.onclick = () => done(true);
    document.getElementById("confirm-cancel").onclick = () => done(false);
    dialog.onclose = () => done(false);  // Escape
    dialog.showModal();
    document.getElementById("confirm-cancel").focus();
  });
}

// ---------- theme ----------

function storedTheme() {
  try { return localStorage.getItem(THEME_KEY); } catch { return null; }
}

function applyTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  const toggle = document.getElementById("theme-toggle");
  const label = next === "dark" ? "Switch to light theme" : "Switch to dark theme";
  toggle.setAttribute("aria-label", label);
  toggle.title = label;
  toggle.replaceChildren(icon(next === "dark" ? "sun" : "moon"));
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.setAttribute("aria-pressed", String(button.dataset.themeChoice === next));
  }
}

function setTheme(theme) {
  applyTheme(theme);
  try { localStorage.setItem(THEME_KEY, theme); } catch { /* per-browser preference only */ }
}

// ---------- mobile navigation ----------

function setNavOpen(open) {
  document.getElementById("app-view").classList.toggle("nav-open", open);
  document.getElementById("nav-scrim").hidden = !open;
  document.getElementById("nav-open").setAttribute("aria-expanded", String(open));
  if (open) document.querySelector('[role="tab"][aria-selected="true"]')?.focus();
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
  const email = document.getElementById("account-email");
  email.textContent = `Signed in as ${me.email}`;
  email.title = me.email;
  show("app");
  renderVerifyBanner();
  showPairCard();
  selectTab(tabFromHash() ?? currentTab());
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

function metric(label, value, { iconName, hint = null, highlight = false } = {}) {
  return el("div", { class: highlight ? "highlight" : null },
    el("dt", {}, iconName ? icon(iconName) : null, label), el("dd", {}, value),
    hint ? el("p", { class: "hint" }, hint) : null);
}

function cardList(entries) {
  return entries.map(([label, value, hint]) => metric(label, formatNumber(value), { hint }));
}

async function loadOverview() {
  const section = document.getElementById("view-overview");
  const cards = document.getElementById("overview-cards");
  const more = document.getElementById("overview-more");
  setStatus(section, "Loading…");
  cards.replaceChildren(...Array.from({ length: 4 }, () => el("div", { "aria-hidden": "true" },
    el("span", { class: "skeleton w-40" }), el("span", { class: "skeleton w-60" }))));
  more.replaceChildren();
  document.getElementById("match-breakdown").replaceChildren(el("span", { class: "skeleton w-80" }));
  try {
    const d = await getJSON(`${API}/overview`);
    cards.replaceChildren(
      metric("Websites", formatNumber(d.websites), { iconName: "globe" }),
      metric("Aliases", formatNumber(d.aliases), { iconName: "at",
        hint: d.websites > d.aliases ? `${formatNumber(d.websites - d.aliases)} website${d.websites - d.aliases === 1 ? "" : "s"} without an alias` : null }),
      metric("Emails received", formatNumber(d.emails_total), { iconName: "mail" }),
      metric("Unread", formatNumber(d.unread), { iconName: "inbox", hint: d.unread ? "In your inbox" : null, highlight: d.unread > 0 }),
    );
    more.replaceChildren(...cardList([
      ["Nicknames", d.nicknames], ["Consent receipts", d.receipts], ["Investigations", d.investigations],
    ]));
    renderBreakdown(d);
    setUnreadBadge(d.unread);
    setStatus(section, d.websites === 0 ? "No websites yet. Create an alias here or with the LeakTrace extension to start." : "");
  } catch (error) {
    cards.replaceChildren();
    document.getElementById("match-breakdown").replaceChildren();
    setStatus(section, error.message, true);
  }
  await Promise.all([loadRecent(), loadEmailChart()]);
}

function renderBreakdown(d) {
  const box = document.getElementById("match-breakdown");
  const parts = [
    ["Matched", d.matched, "tone-accent"], ["Failed", d.failed, "tone-warn"],
    ["Unmatched", d.unmatched, "tone-muted"], ["Unprocessed", d.unprocessed, "tone-faint"],
  ];
  const total = d.emails_total;
  if (!total) {
    box.replaceChildren(emptyState({ iconName: "activity", title: "No results yet",
      text: "Match results appear once email arrives at one of your aliases." }));
    return;
  }
  const bar = el("div", { class: "stackbar", role: "img",
    "aria-label": parts.map(([label, n]) => `${label}: ${n}`).join(", ") });
  for (const [, n, tone] of parts) {
    if (!n) continue;
    const segment = el("span", { class: tone });
    segment.style.flexGrow = String(n);
    bar.append(segment);
  }
  box.replaceChildren(
    el("div", { class: "breakdown-total" }, el("strong", {}, formatNumber(total)), el("span", { class: "hint" }, "emails analysed")),
    bar,
    el("ul", { class: "legend" }, ...parts.map(([label, n, tone]) => el("li", {},
      el("span", { class: `swatch ${tone}`, "aria-hidden": "true" }), el("span", {}, label),
      el("span", { class: "num" }, formatNumber(n)), el("span", { class: "pct" }, percentText(n, total))))),
  );
}

async function loadEmailChart() {
  const chart = document.getElementById("email-chart");
  const note = document.getElementById("email-chart-note");
  chart.replaceChildren(el("span", { class: "skeleton w-80" }));
  note.textContent = "";
  try {
    const page = await getJSON(`${API}/inbox?${new URLSearchParams({ limit: CHART_SAMPLE })}`);
    const complete = page.items.length >= page.total;
    const days = emailsPerDay(page.items.map((m) => m.received_at), { complete });
    renderChart(chart, days);
    const counted = days.reduce((sum, d) => sum + (d.count ?? 0), 0);
    if (page.total === 0) note.textContent = "No email has arrived at your aliases yet.";
    else if (!complete && days.some((d) => !d.covered)) {
      note.textContent = `Based on your ${CHART_SAMPLE} most recent messages; hatched days are older than those and are not counted.`;
    } else note.textContent = `${formatNumber(counted)} message${counted === 1 ? "" : "s"} in the last ${CHART_DAYS} days.`;
  } catch (error) {
    chart.replaceChildren(errorState(error.message, loadEmailChart));
  }
}

function renderChart(chart, days) {
  const max = Math.max(1, ...days.map((d) => d.count ?? 0));
  const step = max <= 4 ? 1 : Math.ceil(max / 4);
  const top = Math.ceil(max / step) * step;
  const bars = days.map((d) => {
    const label = weekdayFormat.format(new Date(`${d.date}T00:00:00Z`));
    const tip = d.covered ? `${label}: ${d.count} email${d.count === 1 ? "" : "s"}` : `${label}: not loaded`;
    const col = el("div", { class: `bar-col${!d.covered ? " no-data" : d.count === 0 ? " zero" : ""}`, "data-tip": tip },
      el("span", { class: "bar" }));
    if (d.covered && d.count > 0) col.firstChild.style.height = `${(d.count / top) * 100}%`;
    return col;
  });
  const gridlines = [0.5, 1].map((f) => {
    const line = el("div", { class: "gridline", "aria-hidden": "true" }, el("span", {}, formatNumber(Math.round(top * f))));
    line.style.bottom = `${f * 100}%`;
    return line;
  });
  const summary = days.map((d) => `${dayFormat.format(new Date(`${d.date}T00:00:00Z`))}: ${d.covered ? d.count : "not loaded"}`).join("; ");
  chart.replaceChildren(
    el("div", { class: "chart", role: "img", "aria-label": `Emails per day, last ${CHART_DAYS} days. ${summary}` }, ...gridlines, ...bars),
    el("div", { class: "chart-axis", "aria-hidden": "true" },
      ...days.map((d) => el("span", {}, dayFormat.format(new Date(`${d.date}T00:00:00Z`))))));
}

async function loadRecent() {
  const listBox = document.getElementById("recent-list");
  say("recent-status", "Loading…");
  listSkeleton(listBox, 2);
  try {
    const page = await getJSON(`${API}/inbox?${new URLSearchParams({ limit: 5 })}`);
    listBox.replaceChildren(...page.items.map((m) => inboxCard(m, { compact: true })));
    say("recent-status", page.total === 0 ? "No email has arrived at your aliases yet." : "");
  } catch (error) {
    listBox.replaceChildren();
    say("recent-status", error.message, "error");
  }
}

// ---------- websites & aliases ----------

async function loadWebsites() {
  const section = document.getElementById("view-websites");
  const body = document.getElementById("websites-body");
  setStatus(section, "Loading…");
  tableSkeleton(body);
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.websites, filter: state.websiteFilter });
  if (state.websiteQuery) params.set("q", state.websiteQuery);
  try {
    const page = await getJSON(`${API}/signups?${params}`);
    body.replaceChildren(...page.items.map((s) => el("tr", {},
      el("td", {}, el("span", { class: "cell-title" }, s.site_name), s.site_domain ? el("span", { class: "cell-sub" }, s.site_domain) : null),
      el("td", {}, s.alias ? el("span", { class: "alias-cell" }, el("span", { class: "marker" }, s.alias), copyIconButton("alias", s.alias),
        el("span", { class: `badge ${s.alias_status === "revoked" ? "badge-ambiguous" : "badge-inbox-matched"}` },
          s.alias_status === "revoked" ? "Revoked" : "Active"))
        : el("span", { class: "dim" }, "No alias")),
      el("td", {}, s.nickname ?? (s.real_name_required ? el("span", { class: "badge badge-neutral" }, "Real name required") : el("span", { class: "dim" }, "—"))),
      el("td", { class: "time" }, formatTime(s.created_at)),
      el("td", { class: "num" }, formatNumber(s.receipt_count)),
      el("td", { class: "num" }, formatNumber(s.email_count)),
      el("td", { class: "actions" }, el("div", { class: "row" },
        el("button", { type: "button", class: "btn btn-secondary btn-sm", "aria-label": `Show details for ${s.site_name}`,
          onclick: () => showWebsite(s.id) }, "Details"),
        s.alias ? el("button", { type: "button", class: "btn btn-secondary btn-sm",
          "aria-label": `${s.alias_status === "revoked" ? "Restore" : "Revoke"} alias for ${s.site_name}`,
          onclick: () => setWebsiteAliasStatus(s, s.alias_status === "revoked" ? "active" : "revoked") },
        s.alias_status === "revoked" ? "Restore alias" : "Revoke alias") : null,
        el("button", { type: "button", class: "icon-btn", "aria-label": `Delete ${s.site_name}`, title: "Delete",
          onclick: () => deleteWebsite(s) }, icon("trash")))))));
    renderPager("websites", page, loadWebsites);
    const filtered = state.websiteQuery || state.websiteFilter !== "all";
    if (page.total === 0) {
      const message = filtered ? "No websites match this search." : "No websites yet.";
      tableMessage(body, filtered
        ? emptyState({ iconName: "search", title: message, text: "Try a different search or show all websites." })
        : emptyState({ iconName: "at", title: message, text: "Create an alias for a website you are about to sign up to.",
          action: el("button", { type: "button", class: "btn btn-primary", onclick: openAliasDialog }, icon("plus"), "New alias") }));
      setQuietStatus(section, message);
    } else setStatus(section, "");
  } catch (error) {
    tableMessage(body, errorState(error.message, loadWebsites));
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
      ["Alias", d.alias ? el("span", { class: "marker" }, d.alias) : "—"], ["Nickname", d.nickname ?? "—"],
      ["Alias status", d.alias ? (d.alias_status === "revoked" ? "Revoked" : "Active") : "No alias"],
      ["Status changed", d.alias ? formatTime(d.alias_status_changed_at) : "—"],
      ["Surname variant", d.surname_variant ?? "—"],
      ["Real name required", d.real_name_required ? "Yes" : "No"], ["Signed up", formatTime(d.created_at)],
    ];
    body.replaceChildren(
      el("dl", {}, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      d.alias ? promotionalFilterControl(d) : null,
      el("div", { class: "row detail-actions" }, d.alias ? copyButton("alias", d.alias) : null, d.nickname ? copyButton("nickname", d.nickname) : null,
        d.alias ? el("button", { type: "button", class: `btn ${d.alias_status === "revoked" ? "btn-primary" : "btn-secondary"}`,
          onclick: () => setWebsiteAliasStatus(d, d.alias_status === "revoked" ? "active" : "revoked") },
        d.alias_status === "revoked" ? "Restore alias" : "Revoke alias") : null,
        el("button", { type: "button", class: "btn btn-ghost btn-sm", onclick: () => deleteWebsite(d) }, icon("trash"), "Delete website")),
      el("h4", {}, "Consent receipts"),
      d.receipts.length ? list(d.receipts.map((r) => `${formatTime(r.recorded_at)} — ${ACTION_LABELS[r.action] ?? "Not recorded"}`
        + `${r.evidence_basis === "user_reported" ? " · user-reported (not verified)" : ""}`)) : el("p", { class: "hint" }, "None yet."),
      el("h4", {}, "Email received at this alias"),
      d.emails.length ? list(d.emails.map((m) => el("div", {},
        el("span", {}, formatTime(m.received_at), " ", statusBadge(m.status),
          m.sender_domain ? ` from ${m.sender_domain} (claimed)` : ""),
        ...exposureCards(m.exposure)))) : el("p", { class: "hint" }, "None yet."),
      el("h4", {}, "SMS investigations"),
      d.sms_investigations?.length ? el("ul", {}, ...d.sms_investigations.map((m) => el("li", {},
        `${formatTime(m.created_at)} — `, m.confirmed ? sourceBadge("confirmed") : sourceBadge(m.status ?? "unknown"),
        m.confirmed ? " · you confirmed this website" : " · suggested, not confirmed", " ",
        el("button", { type: "button", class: "link", onclick: () => openSavedSms(m.id) }, "Open"))))
        : el("p", { class: "hint" }, "None saved."),
      el("p", { class: "notice", role: "note" }, d.notice));
  } catch (error) {
    body.replaceChildren(el("p", { class: "error", role: "alert" }, error.message));
  }
  panel.focus();
}

function promotionalFilterControl(signup) {
  const input = el("input", { type: "checkbox", "aria-label": `Block promotional emails for ${signup.site_name}` });
  input.checked = signup.block_promotional_emails === true;
  input.addEventListener("change", async () => {
    const enabled = input.checked;
    input.disabled = true;
    try {
      await api(`/signups/${encodeURIComponent(signup.id)}/promotional-filter`, {
        method: "PATCH", body: { block_promotional_emails: enabled },
      });
      toast(`Promotional email filter ${enabled ? "enabled" : "disabled"} for ${signup.site_name}.`);
      await Promise.all([loadWebsites(), showWebsite(signup.id)]);
    } catch (error) {
      input.checked = !enabled;
      input.disabled = false;
      toast(error.message, "error");
    }
  });
  return el("div", { class: "alias-filter-control" },
    el("label", { class: "check-label" }, input, " Block promotional emails"),
    el("p", { class: "hint" },
      "Filters promotional messages while allowing receipts, account alerts, and other important emails. Uncertain messages are allowed."));
}

async function setWebsiteAliasStatus(signup, aliasStatus) {
  const revoke = aliasStatus === "revoked";
  const confirmed = await confirmAction({
    title: `${revoke ? "Revoke" : "Restore"} this alias?`,
    body: revoke
      ? `Mail sent to ${signup.alias} will be rejected by LeakTrace when the routing Worker can verify the revocation. Existing email history remains available.`
      : `Mail sent to ${signup.alias} will be forwarded again when the routing Worker can verify the active status.`,
    confirmLabel: revoke ? "Revoke alias" : "Restore alias",
    danger: revoke,
  });
  if (!confirmed) return;
  try {
    await api(`/signups/${encodeURIComponent(signup.id)}/alias-status`, { method: "PATCH", body: { alias_status: aliasStatus } });
    toast(`${revoke ? "Revoked" : "Restored"} alias for ${signup.site_name}.`);
    await Promise.all([loadWebsites(), showWebsite(signup.id)]);
  } catch (error) {
    toast(error.message, "error");
  }
}

async function deleteWebsite(s) {
  const confirmed = await confirmAction({
    title: `Delete ${s.site_name}?`,
    body: `${s.alias ? `Its alias ${s.alias} will no longer be linked to this website. ` : ""}`
      + "Email records and consent receipts are kept but unlinked. This cannot be undone.",
    confirmLabel: "Delete website",
  });
  if (!confirmed) return;
  try {
    await api(`/signups/${encodeURIComponent(s.id)}`, { method: "DELETE" });
    document.getElementById("website-detail").hidden = true;
    toast(`Deleted ${s.site_name}.`);
    await loadWebsites();
  } catch (error) {
    toast(error.status === 409 ? "This website is still referenced by other records and cannot be deleted." : error.message, "error");
  }
}

function openAliasDialog({ siteName = "", siteDomain = "" } = {}) {
  const dialog = document.getElementById("alias-dialog");
  const form = document.getElementById("alias-form");
  form.reset();
  // Prefilled only when called from the SMS analyzer; a click event passes no names.
  form.elements.site_name.value = typeof siteName === "string" ? siteName : "";
  form.elements.site_domain.value = typeof siteDomain === "string" ? siteDomain : "";
  form.hidden = false;
  document.getElementById("alias-created").hidden = true;
  markInvalid(form, [], "alias-status");
  say("alias-status", "");
  dialog.showModal();
  document.getElementById("alias-site-name").focus();
}

async function createAlias(event) {
  event.preventDefault();
  const form = event.target;
  const submit = document.getElementById("alias-submit");
  markInvalid(form, [], "alias-status");
  const name = form.elements.site_name.value.trim();
  if (!name) {
    say("alias-status", "Website name: enter the name of the website.", "error");
    markInvalid(form, ["site_name"], "alias-status");
    return;
  }
  const payload = { site_name: name, real_name_required: form.elements.real_name_required.checked };
  const domain = form.elements.site_domain.value.trim();
  const surname = form.elements.surname_variant.value.trim();
  if (domain) payload.site_domain = domain;
  if (surname) payload.surname_variant = surname;
  submit.disabled = true;
  say("alias-status", "Creating…");
  try {
    const created = await api("/signups", { method: "POST", body: payload });
    say("alias-status", "");
    form.hidden = true;
    const done = document.getElementById("alias-created");
    done.hidden = false;
    document.getElementById("alias-created-body").replaceChildren(
      el("p", { class: "hint" }, `Use this alias when you sign up to ${created.site_name}.`),
      created.alias ? el("div", { class: "created-alias" }, el("span", { class: "marker" }, created.alias), copyButton("alias", created.alias))
        : el("p", {}, "No alias was generated."),
      created.nickname ? el("p", {}, "Nickname: ", el("strong", {}, created.nickname), created.surname_variant ? ` ${created.surname_variant}` : "")
        : el("p", { class: "hint" }, "No nickname: this site uses your real name, which LeakTrace does not store."),
      el("p", { class: "hint" }, "LeakTrace only receives email for this alias if mail routing for the alias domain is set up."));
    done.querySelector("button.btn-primary")?.focus();
    toast(`Created an alias for ${created.site_name}.`);
    state.offsets.websites = 0;
    if (currentTab()?.id === "tab-websites") loadWebsites();
  } catch (error) {
    say("alias-status", error.message, "error");
    markInvalid(form, error.fields, "alias-status");
  } finally {
    submit.disabled = false;
  }
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
  tableSkeleton(body, 3);
  try {
    const page = await getJSON(`/consent-receipts?${new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.receipts })}`);
    body.replaceChildren(...page.items.map((r) => {
      const kept = [r.source_url ? "URL" : null, r.content_hash ? "hash" : null,
        r.notice_text_stored ? "notice text" : null, r.consent_text_stored ? "consent wording" : null,
        r.notice_version ? "version" : null].filter(Boolean).join(", ") || "none";
      return el("tr", {},
        el("td", { class: "time" }, formatTime(r.recorded_at)),
        el("td", {}, r.site_name ? siteLabel(r.site_name, r.site_domain) : el("span", { class: "dim" }, "Signup deleted")),
        el("td", {}, el("span", { class: "badge badge-neutral" }, actionLabel(r.action))),
        el("td", {}, sourceLabel(r)),
        el("td", {}, kept),
        el("td", { class: "actions" }, el("button", { type: "button", class: "btn btn-secondary btn-sm",
          "aria-label": `Show details for receipt ${r.id}`, onclick: () => showReceiptDetail(r.id) }, "Details")));
    }));
    renderPager("receipts", page, loadReceipts);
    if (page.total === 0) {
      tableMessage(body, emptyState({ iconName: "receipt", title: "No consent receipts yet.",
        text: "Record what a website showed you and what you agreed to, using the form below." }));
      setQuietStatus(section, "No consent receipts yet.");
    } else setStatus(section, "");
  } catch (error) {
    tableMessage(body, errorState(error.message, loadReceipts));
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
      ["Notice hash", r.content_hash ? el("span", { class: "marker" }, r.content_hash) : "—"],
    ];
    body.replaceChildren(
      el("p", { class: "notice", role: "note" }, r.legal_notice),
      el("dl", {}, ...rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      el("p", { class: "hint" }, r.timestamp_note),
      el("h4", {}, "Notice text"),
      r.notice_text ? el("div", { class: "prewrap" }, r.notice_text) : el("p", { class: "hint" }, "Not stored."),
      el("h4", {}, "Consent prompt wording"),
      r.consent_text ? el("div", { class: "prewrap" }, r.consent_text) : el("p", { class: "hint" }, "Not stored."));
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
  status.className = "status";
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
    status.classList.add("ok");
    toast(`Saved receipt ${saved.id}.`);
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

function exposureCards(signals) {
  return (signals ?? []).map((item) => el("details", { class: "exposure-card" },
    el("summary", {}, icon("alert"),
      el("span", {}, `Possible source: ${item.site_name}`),
      el("span", { class: "exposure-confidence" }, item.confidence === "medium" ? "Alias evidence" : "Name clue")),
    el("div", { class: "exposure-body" },
      el("p", {}, item.explanation),
      el("dl", { class: "exposure-facts" },
        el("dt", {}, "Your recorded detail"), el("dd", {}, item.marker),
        el("dt", {}, "Recorded website"), el("dd", {}, item.site_name),
        el("dt", {}, "Expected domain"), el("dd", {}, item.expected_domain ?? "Not recorded"),
        el("dt", {}, "Observed source"), el("dd", {}, item.observed_source ?? "Unverified")),
      el("p", { class: "hint" }, item.caveat))));
}

function inboxStatusBadge(m) {
  return el("span", { class: `badge badge-inbox-${m.status}` }, INBOX_STATUS_LABELS[m.status] ?? m.status);
}

const SENDER_STATUS_LABELS = {
  "Verified Sender": "Verified Sender",
  "Possible Third-Party Exposure": "Possible Third-Party Exposure",
  Suspicious: "Suspicious",
  Unknown: "Unknown",
};
const DOMAIN_RELATIONSHIP_LABELS = {
  same_domain: "Same domain as the registered website",
  sender_parent_domain: "Sender is a parent domain of the registered website",
  sender_subdomain: "Sender is a subdomain of the registered website",
};
function senderStatusLabel(value) {
  const status = typeof value === "string" ? value : value?.status;
  return SENDER_STATUS_LABELS[status] ?? "Unknown";
}

function evidenceSourceLabel(url, websiteLabel, dnsLabel) {
  try { return new URL(url).hostname === "dns.google" ? dnsLabel : websiteLabel; }
  catch { return websiteLabel; }
}

function senderAttributionView(value, domainMatch) {
  if (!value) return null;
  const evidence = value.sender_domain_evidence;
  const auth = value.authentication ?? {};
  const statusClass = String(value.status ?? "Unknown").toLowerCase().replaceAll(" ", "-");
  const matchStatus = ["Verified", "Not Verified"].includes(domainMatch?.status) ? domainMatch.status : "Review";
  return el("section", { class: `sender-attribution sender-${statusClass}`, "aria-label": "Sender attribution" },
    domainMatch ? el("div", { class: `domain-match domain-match-${matchStatus.toLowerCase().replaceAll(" ", "-")}` },
      el("strong", {}, `Domain match: ${matchStatus}`),
      el("p", {}, domainMatch.explanation)) : null,
    el("strong", {}, `Sender assessment: ${senderStatusLabel(value)}`),
    el("dl", { class: "sender-attribution-facts" },
      el("dt", {}, "Registered website"), el("dd", {}, value.registered_website ?? "Not linked"),
      el("dt", {}, "Recipient alias"), el("dd", {}, value.recipient_alias ?? "—"),
      el("dt", {}, "Claimed From address"), el("dd", {}, value.claimed_sender_address ?? "Unavailable"),
      el("dt", {}, "Sender domain"), el("dd", {}, value.sender_domain ?? "Unavailable"),
      el("dt", {}, "Sender organization"), el("dd", {}, value.sender_organization ?? "Unknown"),
      value.domain_relationship ? [el("dt", {}, "Domain relationship"),
        el("dd", {}, DOMAIN_RELATIONSHIP_LABELS[value.domain_relationship] ?? "Not established")] : null,
      value.sender_service_provider ? [el("dt", {}, "Mail provider"), el("dd", {}, value.sender_service_provider)] : null,
      value.possible_source ? [el("dt", {}, "Possible source"), el("dd", {}, value.possible_source)] : null,
      el("dt", {}, "Authentication"), el("dd", {}, auth.status === "passed" ? "SPF, DKIM and DMARC reported passed" :
        Object.keys(auth.results ?? {}).length
          ? `${Object.entries(auth.results).map(([k, v]) => `${k.toUpperCase()} ${v}`).join(", ")}. Verification requires all three to pass.`
          : "Authentication unavailable"),
      el("dt", {}, "Evidence"), el("dd", {}, `Sender: ${value.evidence_status?.sender_domain ?? "Insufficient evidence"}; registered website: ${value.evidence_status?.registered ?? "Insufficient evidence"}`),
    el("dt", {}, "Sender evidence"), el("dd", {}, evidence?.checked_at
      ? evidence?.website?.error ? "Public DNS collected; official website unavailable" : "Public DNS and official-site evidence"
      : "No evidence collected"),
      evidence?.checked_at ? [el("dt", {}, "Sender evidence checked"), el("dd", {}, formatTime(evidence.checked_at))] : null,
      el("dt", {}, "Website evidence checked"), el("dd", {}, value.registered_domain_evidence?.checked_at
        ? formatTime(value.registered_domain_evidence.checked_at) : "Not available"),
      el("dt", {}, "Last evaluated"), el("dd", {}, formatTime(value.evaluated_at))),
    el("p", {}, value.explanation),
    value.possible_exposure ? el("p", { class: "hint" }, "This is a possible exposure signal, not proof that the registered website shared or sold the address.") : null,
    ...[...(evidence?.source_urls ?? []).map((url) => [evidenceSourceLabel(url, "Sender website evidence", "Sender DNS evidence"), url]),
      ...(value.registered_domain_evidence?.source_urls ?? []).map((url) => [evidenceSourceLabel(url, "Registered website evidence", "Registered website DNS evidence"), url]),
      ...(evidence?.gemini_interpretation?.source_urls ?? []).map((url) => ["Search lead (unverified)", url]),
      ...(value.registered_domain_evidence?.gemini_interpretation?.source_urls ?? []).map((url) => ["Registered website search lead (unverified)", url])]
      .filter(([, url]) => { try { return new URL(url).protocol === "https:"; } catch { return false; } })
      .map(([label, url]) => el("p", { class: "hint" }, label, ": ", el("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, "open source"))),
    el("details", {}, el("summary", {}, "Evidence limits"), el("ul", {}, ...(value.limitations ?? []).map((text) => el("li", {}, text)))));
}

function inboxCard(m, { compact = false } = {}) {
  const title = m.tracked ? (m.subject ?? "(no subject)") : "Recorded before inbox tracking";
  const meta = [
    el("span", { class: "time" }, formatTime(m.received_at)),
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
      el("p", { class: "card-line hint" }, m.tracked ? `Claimed From: ${senderText(m)}` : "Sender and subject were not stored for this record."),
      senderAttributionView(m.sender_attribution, m.domain_match),
      el("p", { class: "card-meta hint" }, ...meta.filter(Boolean)),
      ...exposureCards(m.exposure),
      compact ? null : el("div", { class: "card-foot" }, el("button", { type: "button", class: "btn btn-secondary btn-sm",
        "aria-label": `Open message: ${title}`, onclick: () => showInboxDetail(m.id) }, "Open"), reportAction(m))));
}

const INBOX_EMPTY = {
  unprocessed: ["No unprocessed email.", "Historical records without recorded recipient attribution appear here."],
  all: ["No email has arrived at your aliases yet.", "Email sent to any of your aliases appears here within about 30 seconds."],
  unread: ["No unread email.", "You are all caught up."],
  matched: ["No email linked to your websites.", "Messages sent to one of your aliases are linked to its website."],
  unmatched: ["No unmatched email.", "Messages appear here when they are no longer linked to a website."],
  failed: ["No failed messages.", "A message is marked failed when its leak analysis could not run."],
};

async function loadInbox() {
  const section = document.getElementById("view-inbox");
  const listBox = document.getElementById("inbox-list");
  const retry = document.getElementById("inbox-retry");
  retry.hidden = true;
  setStatus(section, "Loading…");
  listBox.setAttribute("aria-busy", "true");
  listSkeleton(listBox);
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.inbox, filter: state.inboxFilter });
  try {
    const page = await getJSON(`${API}/inbox?${params}`);
    listBox.replaceChildren(...page.items.map((m) => inboxCard(m)));
    renderPager("inbox", page, loadInbox);
    setUnreadBadge(page.unread);
    document.getElementById("inbox-read-all").disabled = page.unread === 0;
    document.getElementById("inbox-notice").textContent = page.notice;
    const [empty, hint] = INBOX_EMPTY[state.inboxFilter];
    if (page.total === 0) {
      listBox.replaceChildren(el("li", {}, emptyState({ iconName: "inbox", title: empty, text: hint })));
      setQuietStatus(section, empty);
    } else setStatus(section, `${unreadLabel(page.unread)}.`);
    const pending = page.items.filter((item) => item.attribution_pending && !state.autoEvidenceAttempts.has(item.id))
      .slice(0, 10).map((item) => item.id);
    if (pending.length) {
      pending.forEach((id) => state.autoEvidenceAttempts.add(id));
      void reevaluateInbox({ mailLogIds: pending });
    }
  } catch (error) {
    listBox.replaceChildren();
    setStatus(section, error.message, true);
    retry.hidden = false;
  } finally {
    listBox.removeAttribute("aria-busy");
  }
}

async function reevaluateInbox({ mailLogIds = null } = {}) {
  const button = document.getElementById("inbox-reevaluate");
  const section = document.getElementById("view-inbox");
  if (button.disabled) return;
  button.disabled = true;
  setStatus(section, "Refreshing sender evidence for up to 10 matched emails…");
  try {
    const result = await api(`${API}/inbox/reevaluate?limit=10&offset=${state.offsets.inbox}`,
      { method: "POST", body: mailLogIds ? { mail_log_ids: mailLogIds } : undefined });
    await loadInbox();
    setStatus(section, `Evidence refreshed for ${result.refreshed} email${result.refreshed === 1 ? "" : "s"}; ${result.skipped} already current.`);
  } catch (error) {
    setStatus(section, error.message, true);
  } finally {
    button.disabled = false;
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
    ["Claimed From (unverified)", d.tracked ? senderText(d) : "Not stored"],
    ["Subject", d.tracked ? (d.subject ?? "(no subject)") : "Not stored"],
    ["Sender domain (claimed)", d.sender_domain ?? "—"],
    ["Authentication (Cloudflare, unverified)", d.auth_results ?? "Not available"],
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
      senderAttributionView(d.sender_attribution, d.domain_match),
      reportAction(d),
      ...exposureCards(d.exposure),
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

// ---------- SMS analyzer ----------

const SOURCE_LABELS = { confirmed: "Confirmed source", strong: "Strong match", possible: "Possible match", unknown: "Unknown source" };
const SOURCE_EXPLAINED = {
  confirmed: "You confirmed which website or service this message relates to.",
  strong: "Several independent pieces of evidence point to the same service.",
  possible: "There is some evidence, but not enough to point to one service.",
  unknown: "The message does not contain enough reliable information to suggest a source.",
};
const ENTITY_LABELS = {
  email: "Email address", phone: "Phone number", url: "Link", domain: "Domain", person: "Name", business: "Business",
  reference: "Reference", date: "Date or time", code: "Verification code", card: "Card number",
};
const CERTAINTY_LABELS = { validated: "Validated", pattern: "Pattern", uncertain: "Uncertain", user_added: "Added by you" };
const SIGNAL_LABELS = {
  alias_in_message: "Your alias appears", nickname_in_message: "Your nickname appears",
  surname_in_message: "Your surname variant appears", domain_in_message: "Domain mentioned",
  name_in_message: "Name mentioned", sender_previously_confirmed: "Sender confirmed before", sender_id_name: "Sender ID matches name",
};
const SMS_SAMPLES = {
  clinic: { sender: "ExmplClinic", text: "Your appointment at Example Clinic is confirmed for 12 Oct at 3:30pm. Contact us at appointments@exampleclinic.com or call +44 20 7946 0958. Ref APT-20481" },
  otp: { sender: "62820", text: "123456 is your Example Shop verification code. Do not share it. Reset your password: shop.example.com/reset?token=abcdEFGH1234ijklMNOP" },
  parcel: { sender: "+44 7700 900123", text: "Hi Alex, your parcel 7781 is waiting. Pay the redelivery fee at bit.ly/3xYzQ1 - Parcel Express" },
  none: { sender: "", text: "Hey, are we still on for tonight?" },
};

/** replaceChildren, skipping empty values and flattening lists (like el()). */
function fill(node, ...children) {
  node.replaceChildren(...children.flat(Infinity).filter((c) => c !== null && c !== undefined && c !== false)
    .map((c) => (c instanceof Node ? c : String(c))));
}

function sourceBadge(status) {
  return el("span", { class: `badge badge-src-${status}` }, SOURCE_LABELS[status] ?? status);
}

function smsRequest() {
  const form = document.getElementById("sms-form");
  const payload = { text: form.elements.text.value };
  const sender = form.elements.sender.value.trim();
  const label = form.elements.label.value.trim();
  if (sender) payload.sender = sender;
  if (label) payload.label = label;
  if (form.elements.received_at.value) {
    const when = new Date(form.elements.received_at.value);
    if (Number.isNaN(when.getTime())) throw new RequestError("Received: not a valid date.", ["received_at"]);
    payload.received_at = when.toISOString();
  }
  if (state.sms.exclude.length) payload.exclude = state.sms.exclude;
  if (state.sms.additions.length) payload.additions = state.sms.additions;
  return payload;
}

function updateSmsCounter() {
  const n = document.getElementById("sms-text").value.length;
  const counter = document.getElementById("sms-count");
  counter.textContent = `${formatNumber(n)} / 2,000 characters`;
  counter.classList.toggle("error", n > 2000);
}

function loadSmsSample(name) {
  const sample = SMS_SAMPLES[name];
  if (!sample) return;
  const form = document.getElementById("sms-form");
  form.elements.text.value = sample.text;
  form.elements.sender.value = sample.sender;
  form.elements.label.value = "Fictional sample";
  form.elements.received_at.value = "";
  state.sms.exclude = [];
  state.sms.additions = [];
  updateSmsCounter();
  document.getElementById("sms-text").focus();
}

function clearSms() {
  document.getElementById("sms-form").reset();
  document.getElementById("sms-sample").value = "";
  state.sms = { exclude: [], additions: [], analysis: null, saved: null };
  updateSmsCounter();
  markInvalid(document.getElementById("sms-form"), [], null);
  setStatus(document.getElementById("view-sms"), "");
  document.getElementById("sms-result").replaceChildren(emptyState({ iconName: "sms", title: "No message analysed yet",
    text: "Paste a message, or load a fictional sample, and select Analyze message." }));
}

async function analyzeSms(event) {
  event?.preventDefault();
  const form = document.getElementById("sms-form");
  const section = document.getElementById("view-sms");
  const result = document.getElementById("sms-result");
  const button = document.getElementById("sms-analyze");
  markInvalid(form, [], null);
  if (!form.elements.text.value.trim()) {
    setStatus(section, "Message text: paste the message you want to analyse.", true);
    markInvalid(form, ["text"], null);
    return;
  }
  button.disabled = true;
  setStatus(section, "Analysing…");
  result.replaceChildren(el("div", { class: "skeleton-card", "aria-hidden": "true" },
    el("span", { class: "skeleton w-60" }), el("span", { class: "skeleton w-80" }), el("span", { class: "skeleton w-40" })));
  try {
    const request = smsRequest();
    const analysis = await api(`${API}/sms/analyze`, { method: "POST", body: request });
    state.sms.analysis = analysis;
    state.sms.request = request;
    state.sms.saved = null;
    renderSmsAnalysis(analysis);
    setStatus(section, `${SOURCE_LABELS[analysis.status]}. ${analysis.entities.length} detail${analysis.entities.length === 1 ? "" : "s"} found.`);
  } catch (error) {
    result.replaceChildren(errorState(error.message, null));
    setStatus(section, error.message, true);
    markInvalid(form, error.fields, null);
  } finally {
    button.disabled = false;
  }
}

function signalItem(s) {
  return el("li", { class: s.weak ? "signal weak" : "signal" },
    el("span", { class: "signal-type" }, SIGNAL_LABELS[s.type] ?? s.type, s.weak ? " · weak" : ""),
    el("span", {}, s.explanation),
    s.excerpt ? el("q", { class: "excerpt" }, s.excerpt) : null);
}

function candidateCard(c, { saved = null } = {}) {
  const related = c.signup_id && c.email_count !== undefined && c.email_count !== null
    ? el("p", { class: "hint" }, `${formatNumber(c.email_count)} email${c.email_count === 1 ? "" : "s"} received at this website's alias`
      + (c.last_email_at ? `, latest ${formatTime(c.last_email_at)}` : "")
      + (c.sms_count ? ` · ${formatNumber(c.sms_count)} saved SMS investigation${c.sms_count === 1 ? "" : "s"}` : "") + ".")
    : null;
  const rejected = saved?.rejected?.includes(c.key);
  const confirmedHere = saved?.confirmed?.key === c.key;
  const actions = el("div", { class: "row candidate-actions" });
  if (saved) {
    if (!confirmedHere) actions.append(el("button", { type: "button", class: "btn btn-primary btn-sm",
      onclick: () => smsAction("confirm", { candidate_key: c.key }) }, icon("check"), "Confirm this source"));
    if (!rejected) actions.append(el("button", { type: "button", class: "btn btn-secondary btn-sm",
      onclick: () => smsAction("reject", { candidate_key: c.key }) }, "Not this source"));
  }
  if (c.signup_id) {
    actions.append(el("button", { type: "button", class: "btn btn-ghost btn-sm",
      onclick: () => { selectTab(document.getElementById("tab-websites")); showWebsite(c.signup_id); } }, "View website and email activity"));
  } else {
    actions.append(el("button", { type: "button", class: "btn btn-ghost btn-sm",
      onclick: () => openAliasDialog({ siteName: c.name, siteDomain: c.domain }) }, icon("plus"), "Create a website for this service"));
  }
  const signals = c.signals.map((s) => (typeof s === "string" ? { type: s, explanation: SIGNAL_LABELS[s] ?? s, weak: false } : s));
  return el("article", { class: `candidate${rejected ? " rejected" : ""}`, "data-key": c.key },
    el("div", { class: "card-head" },
      el("strong", { class: "card-title" }, c.name),
      c.signup_id ? el("span", { class: "badge badge-neutral" }, "Your website") : null,
      confirmedHere ? sourceBadge("confirmed") : sourceBadge(c.status),
      rejected ? el("span", { class: "badge badge-inbox-failed" }, "You rejected this") : null),
    c.domain && c.domain !== c.name ? el("p", { class: "hint marker" }, c.domain) : null,
    el("h4", {}, "Evidence"), el("ul", { class: "signals" }, ...signals.map(signalItem)),
    c.unknowns?.length ? [el("h4", {}, "What remains unknown"), list(c.unknowns)] : null,
    related, actions.children.length ? actions : null);
}

function entityRow(e) {
  const excluded = state.sms.exclude.includes(e.key) || e.excluded;
  return el("tr", { class: excluded ? "excluded" : null },
    el("td", {}, ENTITY_LABELS[e.type] ?? e.type, e.sensitive ? el("span", { class: "badge badge-ambiguous" }, "Sensitive") : null),
    el("td", {}, el("span", { class: e.type === "email" || e.type === "url" || e.type === "domain" ? "marker" : null }, e.display)),
    el("td", {}, el("span", { class: "badge badge-neutral" }, CERTAINTY_LABELS[e.certainty] ?? e.certainty)),
    el("td", {}, e.relation ?? e.note ?? "—"),
    el("td", { class: "actions" }, e.key.startsWith("added:") ? el("button", { type: "button", class: "btn btn-ghost btn-sm",
      onclick: () => { state.sms.additions.splice(Number(e.key.split(":")[1]), 1); analyzeSms(); } }, "Remove")
      : el("button", { type: "button", class: "btn btn-ghost btn-sm", "aria-pressed": String(!excluded),
        "aria-label": `${excluded ? "Use" : "Ignore"} ${ENTITY_LABELS[e.type] ?? e.type} ${e.display}`,
        onclick: () => toggleSmsEntity(e.key) }, excluded ? "Use" : "Ignore")));
}

function toggleSmsEntity(key) {
  const i = state.sms.exclude.indexOf(key);
  if (i >= 0) state.sms.exclude.splice(i, 1);
  else state.sms.exclude.push(key);
  analyzeSms();
}

function addSmsDetail(event) {
  event.preventDefault();
  const form = event.target;
  const value = form.elements.value.value.trim();
  if (!value) return;
  state.sms.additions.push({ type: form.elements.type.value, value });
  analyzeSms();
}

function renderSmsAnalysis(a) {
  const result = document.getElementById("sms-result");
  const overview = el("div", { class: "sms-summary" },
    el("div", { class: "result-summary" }, sourceBadge(a.status), el("span", { class: "hint" }, SOURCE_EXPLAINED[a.status])),
    el("dl", { class: "details" },
      el("dt", {}, "Sender"), el("dd", {}, a.sender ? `${a.sender.display} (${a.sender.type.replace("_", " ")})` : "Not given"),
      el("dt", {}, "Received"), el("dd", {}, a.received_at ? formatTime(a.received_at) : "Not given"),
      a.label ? [el("dt", {}, "Where"), el("dd", {}, a.label)] : null,
      el("dt", {}, "Services"), el("dd", {}, a.candidates.map((c) => c.name).join(", ") || "None identified"),
      el("dt", {}, "Links and domains"), el("dd", {}, a.entities.filter((e) => ["url", "domain"].includes(e.type)).map((e) => e.display).join(", ") || "None"),
      el("dt", {}, "Email domains"), el("dd", {}, [...new Set(a.entities.filter((e) => e.type === "email").map((e) => e.display.split("@")[1]))].join(", ") || "None")),
    a.sender_notes.length ? list(a.sender_notes) : null);
  const candidates = a.candidates.length ? a.candidates.map((c) => candidateCard(c, { saved: state.sms.saved }))
    : [el("div", { class: "missing" }, el("h4", {}, "Why no source is suggested"), list(a.missing),
      el("p", { class: "hint" }, "If you know which website this relates to, save the investigation and link it to one of your websites."))];
  const addForm = el("form", { class: "toolbar add-detail", onsubmit: addSmsDetail },
    el("label", { for: "sms-add-type", class: "sr-only" }, "Type"),
    el("select", { id: "sms-add-type", name: "type" }, ...["email", "phone", "domain", "business", "person"].map((t) =>
      el("option", { value: t }, ENTITY_LABELS[t]))),
    el("label", { for: "sms-add-value", class: "sr-only" }, "Value"),
    el("input", { id: "sms-add-value", name: "value", type: "text", maxlength: "200", placeholder: "A detail the analyzer missed" }),
    el("button", { type: "submit", class: "btn btn-secondary btn-sm" }, icon("plus"), "Add and re-analyse"));
  fill(result,
    overview,
    a.risk?.exposure?.length ? el("section", { "aria-label": "Possible sources of your details" },
      el("h3", { class: "section-title" }, "Where your detail may have come from"),
      ...exposureCards(a.risk.exposure)) : null,
    el("h3", { class: "section-title" }, "Scam assessment"),
    a.risk ? el("div", { class: "notice" },
      el("strong", {}, `${a.risk.assessment} · ${a.risk.risk_level}`),
      list(a.risk.reasons.map((r) => `${r.message}${r.evidence ? ` (${r.evidence})` : ""}`)),
      list(a.risk.next_steps), el("p", {}, a.risk.notice))
      : el("p", {}, "No scam assessment is stored for this investigation."),
    a.warnings.length ? el("div", { class: "notice", role: "note" }, list(a.warnings)) : null,
    el("h3", { class: "section-title" }, "Possible sources"), ...candidates,
    el("h3", { class: "section-title" }, "Personal and other details found"),
    a.entities.length ? el("div", { class: "table-wrap" }, el("table", { class: "table" },
      el("caption", { class: "sr-only" }, "Details found in the message"),
      el("thead", {}, el("tr", {}, ...["Type", "Detail", "Certainty", "Relation to your records", "Correction"].map((h, i) =>
        el("th", { scope: "col" }, i === 4 ? el("span", { class: "sr-only" }, h) : h)))),
      el("tbody", {}, ...a.entities.map(entityRow))))
      : el("p", { class: "hint" }, "No details were found."),
    addForm,
    el("p", { class: "hint unavailable" }, icon("info"), " Adding a phone number to your tracked details is not available yet: LeakTrace has no storage for phone numbers."),
    el("h3", { class: "section-title" }, "Message (sensitive values hidden)"), el("div", { class: "prewrap" }, a.redacted_text),
    smsSaveBar(),
    el("p", { class: "notice", role: "note" }, a.notice),
    el("details", {}, el("summary", {}, "Limitations"), list(a.limitations)));
}

function smsSaveBar() {
  if (state.sms.saved) return smsSavedBar(state.sms.saved);
  const keep = el("input", { type: "checkbox", id: "sms-store-text" });
  return el("div", { class: "save-bar" },
    el("label", { class: "check-label", for: "sms-store-text" }, keep, "Also keep the message text, with codes, card numbers and sensitive links removed"),
    el("button", { type: "button", class: "btn btn-primary", id: "sms-save", onclick: saveSms }, "Save investigation"));
}

function smsSavedBar(saved) {
  const select = el("select", { id: "sms-link-site", "aria-label": "Link to one of your websites" }, el("option", { value: "" }, "Link to one of your websites…"));
  getJSON(`${API}/signups?${new URLSearchParams({ limit: 100 })}`).then((page) => {
    select.append(...page.items.map((s) => el("option", { value: s.id }, siteLabel(s.site_name, s.site_domain))));
  }).catch(() => select.append(el("option", { value: "", disabled: true }, "Could not load your websites")));
  return el("div", { class: "save-bar saved" },
    el("p", {}, icon("check"), ` Saved as investigation #${saved.id}`, saved.reviewed ? " · reviewed" : "",
      saved.confirmed ? ` · confirmed: ${saved.confirmed.name}` : ""),
    el("div", { class: "row" },
      select,
      el("button", { type: "button", class: "btn btn-secondary btn-sm", onclick: () => {
        if (select.value) smsAction("confirm", { signup_id: Number(select.value) });
      } }, "Link"),
      el("button", { type: "button", class: "btn btn-secondary btn-sm",
        onclick: () => smsAction(saved.reviewed ? "unreviewed" : "reviewed") }, saved.reviewed ? "Mark as not reviewed" : "Mark as reviewed"),
      saved.confirmed ? el("button", { type: "button", class: "btn btn-ghost btn-sm", onclick: () => smsAction("clear") }, "Clear confirmation") : null,
      el("button", { type: "button", class: "btn btn-ghost btn-sm", onclick: () => deleteSms(saved) }, icon("trash"), "Delete")));
}

async function saveSms() {
  const section = document.getElementById("view-sms");
  try {
    const body = { ...state.sms.request, store_text: document.getElementById("sms-store-text").checked };
    const r = await api(`${API}/sms/investigations`, { method: "POST", body });
    state.sms.saved = r.investigation;
    toast(r.duplicate ? `This message was already saved as investigation #${r.investigation.id}.` : `Saved investigation #${r.investigation.id}.`);
    renderSmsAnalysis(state.sms.analysis);
    loadSmsHistory();
    loadTimeline();
    setStatus(section, "");
  } catch (error) {
    setStatus(section, error.message, true);
  }
}

async function smsAction(action, extra = {}) {
  const saved = state.sms.saved;
  if (!saved) return;
  try {
    state.sms.saved = await api(`${API}/sms/investigations/${encodeURIComponent(saved.id)}/actions`, { method: "POST", body: { action, ...extra } });
    toast({ confirm: "Source confirmed.", reject: "Marked as not the source.", clear: "Confirmation cleared.",
      reviewed: "Marked as reviewed.", unreviewed: "Marked as not reviewed." }[action]);
    // A live analysis keeps its full report; a saved one opened from history shows what was stored.
    if (state.sms.analysis) renderSmsAnalysis(state.sms.analysis);
    else renderSavedSms(state.sms.saved);
    loadSmsHistory();
    loadTimeline();
  } catch (error) {
    toast(error.message, "error");
  }
}

async function deleteSms(saved) {
  const ok = await confirmAction({ title: `Delete investigation #${saved.id}?`,
    body: "The saved record and your decisions about it are removed. This cannot be undone.", confirmLabel: "Delete" });
  if (!ok) return;
  try {
    await api(`${API}/sms/investigations/${encodeURIComponent(saved.id)}`, { method: "DELETE" });
    toast(`Deleted investigation #${saved.id}.`);
    state.sms.saved = null;
    if (state.sms.analysis) renderSmsAnalysis(state.sms.analysis);
    else clearSms();
    loadSmsHistory();
    loadTimeline();
  } catch (error) {
    toast(error.message, "error");
  }
}

/** A saved investigation opened from the history: only what was stored. */
function renderSavedSms(saved) {
  state.sms.analysis = null;
  state.sms.saved = saved;
  const result = document.getElementById("sms-result");
  fill(result,
    el("div", { class: "result-summary" }, sourceBadge(saved.status), el("span", { class: "hint" }, SOURCE_EXPLAINED[saved.status])),
    el("dl", { class: "details" },
      el("dt", {}, "Saved"), el("dd", {}, formatTime(saved.created_at)),
      el("dt", {}, "Sender"), el("dd", {}, saved.sender ? `${saved.sender.display} (${saved.sender.type.replace("_", " ")})` : "Not given"),
      el("dt", {}, "Received"), el("dd", {}, saved.received_at ? formatTime(saved.received_at) : "Not given"),
      saved.label ? [el("dt", {}, "Where"), el("dd", {}, saved.label)] : null,
      el("dt", {}, "Details found"), el("dd", {}, Object.entries(saved.entity_counts).map(([t, n]) => `${n} ${ENTITY_LABELS[t]?.toLowerCase() ?? t}`).join(", ") || "None"),
      el("dt", {}, "Domains"), el("dd", {}, saved.domains.join(", ") || "None")),
    el("p", { class: "hint" }, "Evidence quotations and personal details are not stored; analyse the message again to see them."),
    el("h3", { class: "section-title" }, "Possible sources"),
    ...(saved.candidates.length ? saved.candidates.map((c) => candidateCard(c, { saved }))
      : [el("div", { class: "missing" }, el("h4", {}, "Why no source was suggested"), list(saved.missing))]),
    saved.stored_text ? [el("h3", { class: "section-title" }, "Message (sensitive values hidden)"), el("div", { class: "prewrap" }, saved.stored_text)] : null,
    smsSavedBar(saved),
    el("p", { class: "notice", role: "note" }, saved.notice));
}

async function openSavedSms(id) {
  if (currentTab()?.id !== "tab-sms") selectTab(document.getElementById("tab-sms"));
  const section = document.getElementById("view-sms");
  try {
    renderSavedSms(await getJSON(`${API}/sms/investigations/${encodeURIComponent(id)}`));
    setStatus(section, "");
    document.getElementById("sms-result").closest("section").scrollIntoView({ block: "start" });
  } catch (error) {
    setStatus(section, error.message, true);
  }
}

async function loadSmsHistory() {
  const listBox = document.getElementById("sms-history");
  say("sms-history-status", "Loading…");
  try {
    const page = await getJSON(`${API}/sms/investigations?${new URLSearchParams({ limit: 10, offset: state.offsets.sms })}`);
    listBox.replaceChildren(...page.items.map((s) => el("li", {},
      el("div", {}, el("span", { class: "cell-title" }, s.confirmed?.name ?? s.matched_site ?? (s.candidates[0]?.name ?? "No source suggested")),
        el("span", { class: "cell-sub" }, `#${s.id} · saved ${formatTime(s.created_at)}${s.sender ? ` · from ${s.sender.display}` : ""}`)),
      el("div", { class: "row" }, sourceBadge(s.status), s.reviewed ? el("span", { class: "badge badge-neutral" }, "Reviewed") : null,
        el("button", { type: "button", class: "btn btn-secondary btn-sm", "aria-label": `Open SMS investigation ${s.id}`,
          onclick: () => openSavedSms(s.id) }, "Open")))));
    renderPager("sms", page, loadSmsHistory);
    say("sms-history-status", page.total === 0 ? "No saved SMS investigations yet." : "");
  } catch (error) {
    say("sms-history-status", error.message, "error");
  }
}

async function loadTimeline() {
  const listBox = document.getElementById("timeline-list");
  say("timeline-status", "Loading…");
  try {
    const data = await getJSON(`${API}/timeline?${new URLSearchParams({ limit: 20 })}`);
    listBox.replaceChildren(...data.items.map((i) => el("li", { class: `timeline-item channel-${i.channel}` },
      el("span", { class: "timeline-icon", "aria-hidden": "true" }, icon(i.channel === "sms" ? "sms" : "mail")),
      el("div", { class: "timeline-body" },
        el("span", { class: "cell-title" }, i.title),
        el("span", { class: "cell-sub" }, `${formatTime(i.at)} · ${i.linked ? `linked to ${i.site_name}` : "not linked to a website"}`)),
      el("button", { type: "button", class: "btn btn-ghost btn-sm", "aria-label": `Open ${i.channel === "sms" ? "SMS investigation" : "email"} ${i.id}`,
        onclick: () => (i.channel === "sms" ? openSavedSms(i.id) : openFromNotification(i.id)) }, "Open"))));
    say("timeline-status", data.items.length ? "" : "Nothing yet: received email and saved SMS investigations appear here.");
  } catch (error) {
    say("timeline-status", error.message, "error");
  }
}

async function loadSms() {
  updateSmsCounter();
  await Promise.all([loadSmsHistory(), loadTimeline()]);
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
    if (updates.new.length && currentTab()?.id === "tab-overview") { loadRecent(); loadEmailChart(); }
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
  await Promise.all([loadEmails(), loadInvestigations(), loadCalls(), loadMyReports()]);
}

function reportEligible(m) {
  return m.status === "matched" && Boolean(m.site_domain) &&
    ["Suspicious", "Unknown", "Possible Third-Party Exposure"].includes(m.sender_attribution?.status);
}

function reportAction(m) {
  if (!reportEligible(m)) return null;
  return el("button", { type: "button", class: "btn btn-secondary btn-sm",
    "aria-label": `Report possible data exposure associated with ${m.site_domain}`,
    onclick: (event) => confirmWebsiteReport(m, event.currentTarget) }, "Report possible data exposure");
}

async function confirmWebsiteReport(m, button) {
  const domain = m.site_domain;
  if (!window.confirm(`Report possible data exposure associated with ${domain}?\n\nThis is a community report, not proof that the website leaked or shared data. Only the website domain and report metadata will be sent.`)) return;
  button.disabled = true;
  const section = button.closest('[role="tabpanel"]');
  try {
    await api("/website-reports", { method: "POST", body: { email_id: m.id, confirmed_domain: domain } });
    button.textContent = "Reported";
    setStatus(section, `Report submitted for ${domain}.`);
    await loadMyReports();
  } catch (error) {
    setStatus(section, error.status === 409 ? `You have already reported ${domain}.` : error.message, error.status !== 409);
    if (error.status === 409) button.textContent = "Already reported";
    if (error.status !== 409) button.disabled = false;
  }
}

async function loadMyReports() {
  const listBox = document.getElementById("my-reports-list");
  if (!listBox) return;
  say("my-reports-status", "Loading reports…");
  try {
    const page = await getJSON("/website-reports/my?limit=100");
    listBox.replaceChildren(...page.items.map((r) => el("li", { class: "card" },
      el("strong", {}, r.domain), " · ",
      r.status === "dismissed" ? "Dismissed" : r.status === "under_review" ? "Under review" : "Community reported",
      el("span", { class: "hint" }, ` · ${formatTime(r.created_at)}`))));
    say("my-reports-status", page.total ? `${page.total} website report${page.total === 1 ? "" : "s"}.` : "You have not submitted a website report.");
  } catch (error) { say("my-reports-status", error.message, "error"); }
}

async function loadCalls() {
  const listBox = document.getElementById("calls-list");
  if (!listBox) return;
  say("calls-status", "Loading…");
  try {
    const page = await getJSON(`${API}/calls?limit=20`);
    listBox.replaceChildren(...page.items.map((call) => el("li", { class: "card" },
      el("details", {},
        el("summary", {}, `Call analysis · ${formatTime(call.created_at)} · ${call.status}`),
        el("p", { class: "hint" }, call.notice),
        el("p", {}, call.redacted_transcript || "Transcript was not saved."),
        ...exposureCards(call.exposure),
        el("h4", {}, "Extracted details"),
        el("ul", {}, ...call.entities.filter((e) => !e.excluded).map((e) =>
          el("li", {}, `${e.type}: ${e.display}${e.relation ? ` · ${e.relation}` : ""}`))),
        el("h4", {}, "Supporting evidence"),
        el("ul", {}, ...call.candidates.flatMap((c) => c.signals.map((s) =>
          el("li", {}, `${c.name}: ${s.explanation}`)))),
        el("button", { type: "button", class: "btn btn-secondary btn-sm", onclick: async () => {
          await api(`${API}/calls/${encodeURIComponent(call.id)}`, { method: "DELETE" });
          loadCalls();
        } }, "Delete saved call analysis")))));
    say("calls-status", page.total ? `Showing ${page.items.length} of ${page.total} saved analyses.` : "No saved call analysis.");
  } catch (error) {
    say("calls-status", error.message);
  }
}

async function loadEmails() {
  const section = document.getElementById("view-activity");
  const body = document.getElementById("emails-body");
  setStatus(section, "Loading…");
  tableSkeleton(body);
  const params = new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.emails });
  if (state.emailStatus) params.set("status", state.emailStatus);
  try {
    const page = await getJSON(`${API}/emails?${params}`);
    body.replaceChildren(...page.items.map((m) => el("tr", {},
      el("td", { class: "time" }, formatTime(m.received_at)),
      el("td", {}, senderAttributionView(m.sender_attribution, m.domain_match)),
      el("td", {}, m.alias ?? "—"),
      el("td", {}, m.site_name ? siteLabel(m.site_name, m.site_domain) : el("span", { class: "dim" }, m.recipient_known ? "Known alias" : "Unknown alias"),
        m.exposure?.length ? el("span", { class: "exposure-inline" }, ` · Possible source: ${m.exposure.map((x) => x.site_name).join(", ")}`) : null),
      el("td", {}, m.sender_domain ? el("span", { class: "marker" }, m.sender_domain) : "—"),
      el("td", { class: "actions" }, el("button", { type: "button", class: "btn btn-secondary btn-sm",
        "aria-label": `Show match details for email ${m.id}`, onclick: () => showEmailDetail(m.id) }, "Details"), reportAction(m)))));
    renderPager("emails", page, loadEmails);
    if (page.total === 0) {
      const message = state.emailStatus ? "No email with this match status." : "No email received at your aliases yet.";
      tableMessage(body, emptyState({ iconName: "activity", title: message,
        text: state.emailStatus ? "Choose All to see every message." : "Matches appear here once email arrives at one of your aliases." }));
      setQuietStatus(section, message);
    } else setStatus(section, "");
  } catch (error) {
    tableMessage(body, errorState(error.message, loadEmails));
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
      ["Status", statusBadge(d.status)], ["Recipient alias", d.alias ?? "—"], ["Reason", d.status_reason ?? "—"],
      ["Received", formatTime(d.received_at)], ["Recorded", formatTime(d.created_at)],
      ["Website", d.signup_id ? `#${d.signup_id} ${siteLabel(d.site_name, d.site_domain)}` : "Recipient alias not recognised"],
      ["Sender domain (claimed)", d.sender_domain ?? "—"],
    ];
    body.replaceChildren(
      el("p", { class: "notice", role: "note" }, d.notice),
      senderAttributionView(d.sender_attribution, d.domain_match),
      reportAction(d),
      ...exposureCards(d.exposure),
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
  tableSkeleton(body, 2);
  try {
    const page = await getJSON(`${API}/investigations?${new URLSearchParams({ limit: PAGE_SIZE, offset: state.offsets.investigations })}`);
    body.replaceChildren(...page.items.map((i) => el("tr", {},
      el("td", { class: "time" }, formatTime(i.created_at)),
      el("td", {}, i.channel === "sms" ? "SMS" : i.channel === "email" ? "Email" : i.channel),
      el("td", {}, i.channel === "sms" ? sourceBadge(i.result ?? "unknown") : statusBadge(i.result)),
      el("td", {}, i.confidence ?? "—"),
      el("td", {}, i.matched_site ?? (i.candidate_count ? `${i.candidate_count} possible websites` : "—")),
      el("td", {}, i.signal_types.map((t) => SIGNAL_LABELS[t] ?? t).join(", ") || "—"),
      el("td", {}, i.sender_domain ? el("span", { class: "marker" }, i.sender_domain) : "—"))));
    renderPager("investigations", page, loadInvestigations);
    if (page.total === 0) {
      tableMessage(body, emptyState({ iconName: "search", title: "No investigations recorded yet.",
        text: "Run a Match check with “Record the result” ticked to save one here." }));
      say("investigations-status", "");
    } else say("investigations-status", "");
  } catch (error) {
    tableMessage(body, errorState(error.message, loadInvestigations));
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
  result.replaceChildren(el("div", { class: "skeleton-card", "aria-hidden": "true" },
    el("span", { class: "skeleton w-60" }), el("span", { class: "skeleton w-80" })));
  markInvalid(event.target, [], "check-status");
  setStatus(section, "Checking…");
  try {
    const r = await api("/matcher/check", { method: "POST", body: payload });
    const matches = r.matches.length === 0
      ? [emptyState({ iconName: "shield", title: "No match", text: "None of your websites match these clues." })]
      : r.matches.map((m) => el("article", { class: "result" },
        el("h4", {}, `${siteLabel(m.site_name, m.site_domain)} — confidence: ${m.confidence}`),
        list(m.signals.map((s) => `${s.type}: ${s.explanation}`))));
    result.replaceChildren(
      el("div", { class: "result-summary" }, el("span", {}, "Result:"), statusBadge(r.status),
        el("span", { class: "hint" }, `confidence: ${r.confidence}`)),
      ...matches,
      ...(r.warnings.length ? [el("h4", {}, "Warnings"), list(r.warnings)] : []),
      el("h4", {}, "Limitations"), list(r.limitations),
      r.incident_id ? el("p", { class: "hint" }, "Recorded under Leak activity.") : null);
    setStatus(section, "");
  } catch (error) {
    result.replaceChildren();
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
    el("dt", {}, "Verification"), el("dd", {}, me.email_verified
      ? el("span", { class: "badge badge-inbox-matched" }, "Verified")
      : el("span", { class: "badge badge-ambiguous" }, "Not verified")));
  document.getElementById("resend-verification").hidden = me.email_verified;
  const verificationSettings = document.getElementById("domain-verification-settings");
  verificationSettings.hidden = !me.is_domain_verification_admin;
  document.getElementById("website-report-review").hidden = !me.is_domain_verification_admin;
  if (me.is_domain_verification_admin) await Promise.all([loadDomainVerificationSettings(), loadWebsiteReportReview()]);
  await loadExtensions();
  await loadDevices();
}

async function loadWebsiteReportReview() {
  const listBox = document.getElementById("website-report-review-list");
  say("website-report-review-status", "Loading…");
  try {
    const page = await getJSON("/website-reports/review?limit=100");
    listBox.replaceChildren(...page.items.map((r) => el("li", { class: "card" },
      el("strong", {}, r.domain), ` · ${r.status === "dismissed" ? "Dismissed" : r.status === "under_review" ? "Under review" : "Community reported"}`,
      el("span", { class: "hint" }, ` · ${formatTime(r.created_at)}`),
      el("div", { class: "row" },
        ...["under_review", "dismissed", "community_reported"].filter((status) => status !== r.status &&
          (status !== "community_reported" || r.status === "dismissed")).map((status) =>
          el("button", { type: "button", class: "btn btn-secondary btn-sm", onclick: async (event) => {
            if (!window.confirm(`${status === "dismissed" ? "Dismiss" : status === "community_reported" ? "Restore" : "Mark for review"} this community report for ${r.domain}?`)) return;
            event.currentTarget.disabled = true;
            try {
              await api(`/website-reports/${encodeURIComponent(r.id)}/review`, { method: "PATCH", body: { status } });
              await loadWebsiteReportReview();
            } catch (error) {
              say("website-report-review-status", error.message, "error");
              event.currentTarget.disabled = false;
            }
          } }, status === "dismissed" ? "Dismiss" : status === "community_reported" ? "Restore" : "Mark for review"))))));
    say("website-report-review-status", page.total ? `${page.total} community reports.` : "No community reports to review.");
  } catch (error) { say("website-report-review-status", error.message, "error"); }
}

async function loadDomainVerificationSettings() {
  const stateLabel = document.getElementById("gemini-key-state");
  const testButton = document.getElementById("gemini-key-test");
  const removeButton = document.getElementById("gemini-key-remove");
  const saveButton = document.getElementById("gemini-key-save");
  try {
    const config = await getJSON("/dashboard/api/domain-verification/settings");
    stateLabel.textContent = config.server_managed ? `Server-managed key active: ${config.masked_api_key}` :
      config.saved_key ? `Saved key: ${config.masked_api_key}` : "No Gemini key is configured.";
    if (!config.encryption_ready) stateLabel.textContent += " Server-side encryption is not configured.";
    testButton.disabled = !config.configured;
    removeButton.disabled = !config.saved_key;
    saveButton.disabled = !config.encryption_ready;
  } catch (error) {
    stateLabel.textContent = error.message;
    testButton.disabled = true;
    removeButton.disabled = true;
    saveButton.disabled = true;
  }
}

async function saveGeminiKey(event) {
  event.preventDefault();
  const section = document.getElementById("domain-verification-settings");
  const input = document.getElementById("gemini-api-key");
  const button = document.getElementById("gemini-key-save");
  if (!input.value) { say("gemini-key-status", "Enter an API key to save.", "error"); return; }
  button.disabled = true;
  say("gemini-key-status", "Saving encrypted key…");
  try {
    await api("/dashboard/api/domain-verification/settings", { method: "PUT", body: { api_key: input.value } });
    input.value = "";
    await loadDomainVerificationSettings();
    say("gemini-key-status", "Gemini key saved encrypted on this server.", "ok");
  } catch (error) {
    say("gemini-key-status", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function testGeminiKey() {
  const button = document.getElementById("gemini-key-test");
  button.disabled = true;
  say("gemini-key-status", "Testing connection…");
  try {
    const result = await api("/dashboard/api/domain-verification/test", { method: "POST" });
    say("gemini-key-status", result.detail, "ok");
  } catch (error) {
    say("gemini-key-status", error.message, "error");
  } finally {
    await loadDomainVerificationSettings();
    button.disabled = false;
  }
}

async function removeGeminiKey() {
  const confirmed = await confirmAction({
    title: "Remove the Gemini API key?",
    body: "Domain evidence collection will continue, but Gemini will no longer interpret public evidence until a key is saved.",
    confirmLabel: "Remove key",
  });
  if (!confirmed) return;
  const button = document.getElementById("gemini-key-remove");
  button.disabled = true;
  try {
    await api("/dashboard/api/domain-verification/settings", { method: "DELETE" });
    await loadDomainVerificationSettings();
    say("gemini-key-status", "Gemini key removed.", "ok");
  } catch (error) {
    say("gemini-key-status", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function loadExtensions() {
  const listBox = document.getElementById("extensions-list");
  say("extensions-status", "Loading…");
  listBox.replaceChildren();
  try {
    const sessions = await getJSON("/extension/sessions");
    listBox.replaceChildren(...sessions.map((s) => el("li", {},
      el("div", {}, el("span", { class: "cell-title" }, s.label ?? "Browser extension"),
        el("span", { class: "cell-sub" }, `Connected ${formatTime(s.created_at)} · last used ${formatTime(s.last_used_at)} · expires ${formatTime(s.expires_at)}`)),
      el("button", { type: "button", class: "btn btn-secondary btn-sm", "aria-label": `Revoke extension connection ${s.id}`,
        onclick: () => revokeExtension(s.id) }, "Revoke"))));
    say("extensions-status", sessions.length ? "" : "No browser extension is connected.");
  } catch (error) {
    say("extensions-status", error.message, "error");
  }
}

async function revokeExtension(id) {
  const confirmed = await confirmAction({
    title: "Revoke this extension connection?",
    body: "That extension will no longer be able to create or look up your aliases until it is connected again.",
    confirmLabel: "Revoke",
  });
  if (!confirmed) return;
  try {
    await api(`/extension/sessions/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadExtensions();
    say("extensions-status", "Connection revoked. That extension can no longer use your account.", "ok");
  } catch (error) {
    say("extensions-status", error.message, "error");
  }
}

// ---------- mobile devices ----------

async function loadDevices() {
  const listBox = document.getElementById("devices-list");
  say("devices-status", "Loading…");
  listBox.replaceChildren();
  try {
    const devices = await getJSON("/mobile/devices");
    listBox.replaceChildren(...devices.map((d) => el("li", {},
      el("div", {}, el("span", { class: "cell-title" }, d.label ?? "Mobile device"),
        el("span", { class: "cell-sub" }, `Connected ${formatTime(d.created_at)} · last used ${formatTime(d.last_used_at)} · expires ${formatTime(d.expires_at)}`)),
      el("button", { type: "button", class: "btn btn-secondary btn-sm", "aria-label": `Revoke mobile device ${d.id}`,
        onclick: () => revokeDevice(d.id) }, "Revoke"))));
    say("devices-status", devices.length ? "" : "No mobile device is connected.");
  } catch (error) {
    say("devices-status", error.message, "error");
  }
}

function resetDeviceApproval() {
  state.deviceCode = null;
  document.getElementById("device-approval").hidden = true;
  document.getElementById("device-approval-label").textContent = "";
}

// Shows which device a code belongs to; approving is a separate, explicit step.
async function checkDeviceCode(event) {
  event.preventDefault();
  const form = event.target;
  const code = form.elements.code.value.trim().toUpperCase();
  resetDeviceApproval();
  markInvalid(form, [], "device-pair-status");
  say("device-pair-status", "Checking…");
  try {
    const pending = await api("/mobile/pairings/preview", { method: "POST", body: { code } });
    state.deviceCode = code;
    document.getElementById("device-approval-label").textContent = pending.device_label;
    document.getElementById("device-approval").hidden = false;
    say("device-pair-status", `Code valid until ${formatTime(pending.expires_at)}.`);
  } catch (error) {
    say("device-pair-status", error.message, "error");
    markInvalid(form, error.fields, "device-pair-status");
  }
}

async function approveDevice() {
  const button = document.getElementById("device-approve");
  button.disabled = true;
  say("device-pair-status", "Approving…");
  try {
    const result = await api("/extension/pairings/approve", { method: "POST", body: { code: state.deviceCode, kind: "mobile" } });
    resetDeviceApproval();
    document.getElementById("device-code-form").reset();
    say("device-pair-status", result.detail, "ok");
  } catch (error) {
    say("device-pair-status", error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function revokeDevice(id) {
  const confirmed = await confirmAction({
    title: "Revoke this mobile device?",
    body: "That device will be signed out of your account until it is connected again.",
    confirmLabel: "Revoke",
  });
  if (!confirmed) return;
  try {
    await api(`/mobile/devices/${encodeURIComponent(id)}`, { method: "DELETE" });
    await loadDevices();
    say("devices-status", "Device revoked. It can no longer use your account.", "ok");
  } catch (error) {
    say("devices-status", error.message, "error");
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
    say("password-status", "Password changed. Your other sessions, browser extensions and mobile devices were signed out.", "ok");
    toast("Password changed.");
    await loadExtensions();
    await loadDevices();
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

// ---------- tabs and routing ----------

const loaders = {
  overview: loadOverview, websites: loadWebsites, inbox: loadInbox, sms: loadSms, receipts: loadReceipts, activity: loadActivity,
  check: () => {}, settings: loadSettings,
};

function tabName(tab) {
  return tab.id.replace("tab-", "");
}

function selectTab(tab, focus = false) {
  for (const t of document.querySelectorAll('[role="tab"]')) {
    const selected = t === tab;
    t.setAttribute("aria-selected", String(selected));
    t.tabIndex = selected ? 0 : -1;
    document.getElementById(t.getAttribute("aria-controls")).hidden = !selected;
  }
  const name = tabName(tab);
  document.getElementById("topbar-title").textContent = PAGE_TITLES[name];
  document.title = `${PAGE_TITLES[name]} · LeakTrace`;
  // Keep a #pair= link intact until the pairing is approved or cancelled.
  if (!state.pairCode) history.replaceState(null, "", `${location.pathname}${location.search}#${name}`);
  setNavOpen(false);
  if (focus) tab.focus();
  loaders[name]();
}

function currentTab() {
  return document.querySelector('[role="tab"][aria-selected="true"]');
}

function tabFromHash() {
  const name = /^#([a-z]+)$/.exec(location.hash)?.[1];
  return name && loaders[name] ? document.getElementById(`tab-${name}`) : null;
}

document.addEventListener("DOMContentLoaded", async () => {
  applyTheme(storedTheme() ?? "dark");
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  for (const tab of tabs) {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (event) => {
      const index = tabs.indexOf(tab);
      const next = {
        ArrowRight: index + 1, ArrowDown: index + 1, ArrowLeft: index - 1, ArrowUp: index - 1, Home: 0, End: tabs.length - 1,
      }[event.key];
      if (next === undefined) return;
      event.preventDefault();
      selectTab(tabs[(next + tabs.length) % tabs.length], true);
    });
  }
  window.addEventListener("hashchange", () => {
    const tab = tabFromHash();
    if (state.me && tab && tab !== currentTab()) selectTab(tab);
  });
  document.getElementById("nav-open").addEventListener("click", () => setNavOpen(true));
  document.getElementById("nav-close").addEventListener("click", () => setNavOpen(false));
  document.getElementById("nav-scrim").addEventListener("click", () => setNavOpen(false));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && document.getElementById("app-view").classList.contains("nav-open")) {
      setNavOpen(false);
      document.getElementById("nav-open").focus();
    }
  });
  document.getElementById("theme-toggle").addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });
  for (const button of document.querySelectorAll("[data-theme-choice]")) {
    button.addEventListener("click", () => setTheme(button.dataset.themeChoice));
  }
  document.getElementById("login-form").addEventListener("submit", login);
  document.getElementById("register-form").addEventListener("submit", register);
  document.getElementById("sign-out").addEventListener("click", signOut);
  document.getElementById("pair-approve").addEventListener("click", approvePairing);
  document.getElementById("pair-cancel").addEventListener("click", clearPairing);
  document.getElementById("device-code-form").addEventListener("submit", checkDeviceCode);
  document.getElementById("device-approve").addEventListener("click", approveDevice);
  document.getElementById("device-cancel").addEventListener("click", () => {
    resetDeviceApproval();
    say("device-pair-status", "");
  });
  document.getElementById("websites-search").addEventListener("submit", (event) => {
    event.preventDefault();
    state.websiteQuery = document.getElementById("websites-q").value.trim();
    state.websiteFilter = document.getElementById("websites-filter").value;
    state.offsets.websites = 0;
    loadWebsites();
  });
  document.getElementById("websites-filter").addEventListener("change", () => {
    document.getElementById("websites-search").requestSubmit();
  });
  document.getElementById("new-alias").addEventListener("click", openAliasDialog);
  document.getElementById("alias-form").addEventListener("submit", createAlias);
  for (const button of document.querySelectorAll("[data-close-dialog]")) {
    button.addEventListener("click", () => button.closest("dialog").close());
  }
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
  document.getElementById("inbox-reevaluate").addEventListener("click", reevaluateInbox);
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
  document.getElementById("sms-form").addEventListener("submit", analyzeSms);
  document.getElementById("sms-text").addEventListener("input", updateSmsCounter);
  document.getElementById("sms-sample").addEventListener("change", (event) => loadSmsSample(event.target.value));
  document.getElementById("sms-clear").addEventListener("click", clearSms);
  document.getElementById("check-form").addEventListener("submit", runCheck);
  document.getElementById("resend-verification").addEventListener("click", resendVerification);
  document.getElementById("password-form").addEventListener("submit", changePassword);
  document.getElementById("delete-form").addEventListener("submit", deleteAccount);
  document.getElementById("gemini-key-form").addEventListener("submit", saveGeminiKey);
  document.getElementById("gemini-key-test").addEventListener("click", testGeminiKey);
  document.getElementById("gemini-key-remove").addEventListener("click", removeGeminiKey);

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
