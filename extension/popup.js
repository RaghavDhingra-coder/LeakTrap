// LeakTrace popup. Nothing is sent to the backend until the user reviews a
// request and clicks Confirm (or, for alias recall, clicks "Find my alias").
// Autofill: when the popup opens on a website, the detector in
// content/autofill.js is injected into that tab only (activeTab). It reports
// form-field descriptions, never values, and fills only after the user clicks
// Fill in this popup. Nothing is ever submitted.
import {
  ApiError, RECONNECT_MESSAGE, addNeverSite, buildFillPlan, buildReceiptPayload, buildSignupPayload, canInspectTab, copyText,
  createApi, describePayload, describeScanStats, fillOptions, fillTargetCheck, hostnameFromTabUrl, normalizeNeverSites,
  parseStoredAuth, policyUrlFromPage, removeNeverSite,
} from "./src/lib.js";
import { definitionList, el, show } from "./src/dom.js";

const $ = (id) => document.getElementById(id);
const state = { api: null, auth: null, tab: null, tabUrl: null, host: null, selected: null };
// Autofill state lives only in this popup's memory.
const autofill = {
  port: null, fields: [], signups: null, chosenId: null, options: [], unavailable: null,
  detected: false, stats: null, rescanWaiters: [],
};
const RESCAN_TIMEOUT_MS = 1500;
const FIELD_KINDS = { email: "Email", username: "Username", nickname: "Nickname", name: "Name" };

function setStatus(id, message, kind = "") {
  const node = $(id);
  node.textContent = message;
  node.className = `status ${kind}`.trim();
  node.setAttribute("role", kind === "error" ? "alert" : "status");
}

function setBusy(form, busy) {
  for (const control of form.elements) control.disabled = busy;
}

function copyButton(label, value) {
  const button = el("button", { type: "button", class: "secondary" }, `Copy ${label}`);
  button.addEventListener("click", async () => {
    const ok = await copyText(value);
    button.textContent = ok ? `Copied ${label}` : `Copy failed — select the ${label} and copy it manually`;
  });
  return button;
}

// ---------- selected signup (session storage: memory only, cleared on browser exit) ----------

async function saveSelected(signup) {
  state.selected = signup;
  try {
    if (signup) await chrome.storage.session.set({ selected: signup });
    else await chrome.storage.session.remove("selected");
  } catch {
    // Selection still works for this popup; it just will not survive closing it.
  }
  renderSelected();
}

function updateSignupMismatch() {
  const note = $("signup-mismatch");
  const typed = $("receipt-signup").value.trim();
  const s = state.selected;
  const differs = Boolean(s && typed && typed !== String(s.id));
  note.hidden = !differs;
  note.textContent = differs ? `This receipt will be attached to signup #${typed}, not the selected signup #${s.id}.` : "";
}

function renderSelected() {
  const container = $("selected-signup");
  const s = state.selected;
  if (!s) {
    $("receipt-signup").value = "";
    show(container, el("p", { class: "hint" }, "No signup selected. Create one above, or enter a signup ID from the dashboard."));
    return;
  }
  $("receipt-signup").value = String(s.id);
  show(container, el("div", { class: "panel" },
    el("p", {}, "Selected signup ", el("strong", {}, `#${s.id}`), ` — ${s.siteName}${s.siteDomain ? ` (${s.siteDomain})` : ""}`),
    s.alias ? el("p", {}, "Alias: ", el("span", { class: "marker" }, s.alias), " ", copyButton("alias", s.alias)) : null,
    s.nickname ? el("p", {}, "Nickname: ", el("span", { class: "marker" }, s.nickname), " ", copyButton("nickname", s.nickname)) : null,
    fillAction(s),
    el("button", { type: "button", class: "secondary", onclick: forget }, "Forget")));
  updateSignupMismatch();
}

async function forget() {
  await saveSelected(null);
  clearAutofillState();
  if (!$("autofill-section").hidden) {
    setStatus("autofill-status", "Forgot the selected signup and this tab's autofill state. Reopen LeakTrace to look for fields again.");
  }
}

// ---------- signup ----------

function renderSignupResult(signup) {
  const rows = [["Signup ID", `#${signup.id}`], ["Website", `${signup.siteName}${signup.siteDomain ? ` (${signup.siteDomain})` : ""}`]];
  const parts = [definitionList(rows)];
  if (signup.alias) {
    parts.push(el("p", {}, "Email alias: ", el("span", { class: "marker" }, signup.alias)), copyButton("alias", signup.alias));
  } else {
    parts.push(el("p", { class: "hint" }, "No alias was returned by the backend."));
  }
  if (signup.nickname) {
    parts.push(el("p", {}, "Nickname: ", el("span", { class: "marker" }, signup.nickname)), copyButton("nickname", signup.nickname));
  }
  parts.push(fillAction(signup));
  parts.push(el("p", { class: "hint" },
    "Use these when signing up. Mail to the alias only arrives once Cloudflare Email Routing and the LeakTrace Worker are set up; generating it does not guarantee delivery."));
  show($("signup-result"), el("div", { class: "panel" }, parts));
}

function confirmPanel(title, payload, onConfirm, onCancel) {
  const confirm = el("button", { type: "button" }, "Confirm and send");
  const cancel = el("button", { type: "button", class: "secondary" }, "Edit");
  confirm.addEventListener("click", () => { confirm.disabled = true; cancel.disabled = true; onConfirm(); });
  cancel.addEventListener("click", onCancel);
  return el("div", { class: "panel", role: "group", "aria-label": title },
    el("p", {}, el("strong", {}, title)),
    el("p", { class: "hint" }, `Will be sent to ${state.api.origin}:`),
    definitionList(describePayload(payload)),
    el("div", { class: "row" }, confirm, cancel));
}

function reviewSignup(event) {
  event.preventDefault();
  if (!state.api) return;
  setStatus("signup-status", "");
  show($("signup-result"));
  let payload;
  try {
    payload = buildSignupPayload({
      siteName: $("site-name").value, siteDomain: $("site-domain").value,
      realNameRequired: $("real-name").checked, generateNickname: $("gen-nickname").checked,
    });
  } catch (error) {
    setStatus("signup-status", error.message, "error");
    return;
  }
  setBusy($("signup-form"), true);
  const cancel = () => { show($("signup-confirm")); setBusy($("signup-form"), false); };
  show($("signup-confirm"), confirmPanel("Create a signup marker", payload, async () => {
    setStatus("signup-status", "Creating…");
    try {
      const signup = await state.api.createSignup(payload);
      show($("signup-confirm"));
      setStatus("signup-status", "Created.", "ok");
      renderSignupResult(signup);
      await saveSelected({ id: signup.id, siteName: signup.siteName, siteDomain: signup.siteDomain, alias: signup.alias,
        nickname: signup.nickname, realNameRequired: signup.realNameRequired });
      if (autofill.signups !== null && signup.siteDomain === state.host) {
        autofill.signups = [signup];
        autofill.chosenId = signup.id;
        renderSuggestion();
      }
    } catch (error) {
      show($("signup-confirm"));
      if (isUnauthorized(error)) await disconnected();
      setStatus("signup-status", error instanceof ApiError ? error.message : "Something went wrong.", "error");
    } finally {
      setBusy($("signup-form"), false);
    }
  }, cancel));
}

// ---------- receipt ----------

async function reviewReceipt(event) {
  event.preventDefault();
  if (!state.api) return;
  setStatus("receipt-status", "");
  let payload;
  try {
    payload = await buildReceiptPayload({
      signupId: $("receipt-signup").value, action: $("receipt-action").value,
      sourceUrl: $("receipt-url").value, noticeVersion: $("receipt-version").value,
      noticeText: $("receipt-notice").value, storeNoticeText: $("store-text").checked,
      consentText: $("receipt-consent").value, occurredAt: $("receipt-when").value,
    });
  } catch (error) {
    setStatus("receipt-status", error.message, "error");
    return;
  }
  const form = $("receipt-form");
  setBusy(form, true);
  const cancel = () => { show($("receipt-confirm")); setBusy(form, false); };
  show($("receipt-confirm"), confirmPanel("Save a user-reported consent receipt", payload, async () => {
    setStatus("receipt-status", "Saving…");
    try {
      const receipt = await state.api.createReceipt(payload);
      show($("receipt-confirm"));
      form.reset();
      renderSelected();
      updateSignupMismatch();
      setStatus("receipt-status",
        `Saved receipt #${receipt.id} for ${receipt.site_name ?? "the signup"} as user-reported (not verified).`, "ok");
    } catch (error) {
      show($("receipt-confirm"));
      if (isUnauthorized(error)) await disconnected();
      setStatus("receipt-status", error instanceof ApiError ? error.message : "Something went wrong.", "error");
    } finally {
      setBusy(form, false);
    }
  }, cancel));
}


// ---------- autofill ----------

function stopDetector() {
  const port = autofill.port;
  autofill.port = null;
  if (!port) return;
  try {
    port.postMessage({ type: "stop" });
    port.disconnect();
  } catch {
    // already disconnected
  }
}

function clearAutofillState() {
  stopDetector();
  Object.assign(autofill, { fields: [], signups: null, chosenId: null, options: [], detected: false, stats: null });
  show($("autofill-fields"));
  show($("autofill-suggestion"));
  setStatus("autofill-result", "");
  $("autofill-lookup").hidden = true;
}

async function autofillSettings() {
  try {
    const { autofillEnabled, neverSites } = await chrome.storage.local.get(["autofillEnabled", "neverSites"]);
    return { enabled: autofillEnabled !== false, neverSites: normalizeNeverSites(neverSites) };
  } catch {
    return { enabled: false, neverSites: [] };
  }
}

function validField(f) {
  return f && typeof f.id === "string" && FIELD_KINDS[f.kind] && typeof f.label === "string"
    && typeof f.form === "string" && typeof f.empty === "boolean";
}

async function startAutofill() {
  clearAutofillState();
  $("autofill-allow").hidden = true;
  if (!state.tab?.id || !canInspectTab(state.tab.url)) {
    autofill.unavailable = "LeakTrace can't fill forms on this page (browser and extension pages are not supported).";
    $("autofill-section").hidden = true;
    return;
  }
  $("autofill-section").hidden = false;
  const settings = await autofillSettings();
  if (!settings.enabled) {
    autofill.unavailable = "Autofill is turned off in Settings.";
    setStatus("autofill-status", "Autofill suggestions are turned off in Settings.");
    return;
  }
  if (settings.neverSites.includes(state.host)) {
    autofill.unavailable = `You chose never to autofill on ${state.host}. Use “Allow suggestions on this site again” to change that.`;
    setStatus("autofill-status", `You chose never to get autofill suggestions on ${state.host}.`);
    $("autofill-allow").hidden = false;
    return;
  }
  if (!state.api) {
    autofill.unavailable = "Set a backend in Settings to use autofill.";
    setStatus("autofill-status", "Set a backend in Settings to use autofill.");
    return;
  }
  if (!state.auth) {
    autofill.unavailable = "Connect LeakTrace to your account in Settings to use autofill.";
    setStatus("autofill-status", autofill.unavailable);
    return;
  }
  if (!chrome.scripting?.executeScript) {
    // Happens when Chrome still runs an older copy of the extension without the scripting permission.
    autofill.unavailable = "LeakTrace needs to be reloaded: open chrome://extensions and click the reload icon on LeakTrace.";
    setStatus("autofill-status", autofill.unavailable, "error");
    return;
  }
  setStatus("autofill-status", "Looking for sign-up or login fields on this tab…");
  try {
    await chrome.scripting.executeScript({ target: { tabId: state.tab.id }, files: ["content/autofill.js"] });
    const port = chrome.tabs.connect(state.tab.id, { name: "leaktrace-autofill" });
    autofill.port = port;
    port.onMessage.addListener(onDetectorMessage);
    port.onDisconnect.addListener(() => {
      if (autofill.port !== port) return;
      autofill.port = null;
      autofill.unavailable = "Lost the connection to this page (it may have reloaded). Reopen LeakTrace to fill it.";
    });
    autofill.unavailable = null;
  } catch {
    autofill.unavailable = "LeakTrace can't look at the fields on this page.";
    setStatus("autofill-status", autofill.unavailable, "error");
  }
}

/** Ask the page to scan again; resolves true when it answers, false on timeout. */
function requestRescan() {
  if (!autofill.port) return Promise.resolve(false);
  return new Promise((resolve) => {
    autofill.rescanWaiters.push(resolve);
    setTimeout(() => {
      const index = autofill.rescanWaiters.indexOf(resolve);
      if (index !== -1) {
        autofill.rescanWaiters.splice(index, 1);
        resolve(false);
      }
    }, RESCAN_TIMEOUT_MS);
    try {
      autofill.port.postMessage({ type: "rescan" });
    } catch {
      resolve(false);
    }
  });
}

/** "Fill form on this page…": opens the per-field review for this exact signup. */
function fillAction(signup) {
  if (!signup.alias && !signup.nickname) return null;
  const note = el("p", { class: "hint", role: "status" });
  const button = el("button", { type: "button" }, "Fill form on this page…");
  button.addEventListener("click", () => offerFill(signup, note));
  return el("div", {}, button, note);
}

async function offerFill(signup, note) {
  note.classList.remove("error");
  const check = fillTargetCheck(signup, state.host);
  let problem = check.ok ? null : check.reason;
  if (!problem && !autofill.port) problem = autofill.unavailable ?? "LeakTrace isn't connected to this page. Reopen LeakTrace on it.";
  if (!problem) {
    // Look again: the page may have moved to another step since the popup opened.
    // Clear any earlier review first so an outdated field list is never shown.
    show($("autofill-suggestion"));
    setStatus("autofill-result", "");
    note.textContent = "Checking the page's fields…";
    const answered = await requestRescan();
    if (!answered && !autofill.detected) {
      problem = "The page didn't answer LeakTrace (it may still be loading). Reopen LeakTrace on it and try again.";
    } else if (!autofill.port) {
      problem = autofill.unavailable ?? "Lost the connection to this page. Reopen LeakTrace to fill it.";
    } else if (!autofill.fields.length) {
      problem = "No supported email, username or nickname fields were found on this page."
        + (autofill.stats ? ` ${describeScanStats(autofill.stats)}` : "");
    }
  }
  if (problem) {
    note.textContent = problem;
    note.classList.add("error");
    return;
  }
  note.textContent = "Review the fields under Autofill, then click Fill. Nothing is submitted.";
  // Older session entries may lack the flag: assume a real name is required, so name fields are never offered.
  autofill.signups = [{ ...signup, realNameRequired: signup.realNameRequired !== false }];
  autofill.chosenId = signup.id;
  $("autofill-lookup").hidden = true;
  setStatus("autofill-result", "");
  renderSuggestion();
  $("autofill-section").scrollIntoView({ block: "start" });
  $("autofill-suggestion").querySelector("input")?.focus();
}

function onDetectorMessage(message) {
  if (message?.type === "fields" && Array.isArray(message.fields)) {
    autofill.fields = message.fields.filter(validField);
    autofill.detected = true;
    autofill.stats = message.stats && typeof message.stats === "object" ? message.stats : null;
    for (const resolve of autofill.rescanWaiters.splice(0)) resolve(true);
    renderDetected();
    if (autofill.signups !== null) renderSuggestion();
  } else if (message?.type === "filled" && Array.isArray(message.results)) {
    renderFillResults(message.results);
  }
}

function renderDetected() {
  const fields = autofill.fields;
  if (!fields.length) {
    setStatus("autofill-status", "No supported email or username fields found on this tab yet.");
    show($("autofill-fields"), autofill.stats ? el("p", { class: "hint" }, describeScanStats(autofill.stats)) : null);
    $("autofill-lookup").hidden = true;
    return;
  }
  const forms = new Set(fields.map((f) => f.form));
  const what = forms.has("signup") ? "a sign-up form" : forms.has("login") ? "a login form" : "an email or username field";
  setStatus("autofill-status", `Found ${what} on ${state.host}.`);
  show($("autofill-fields"), el("ul", {}, fields.map((f) =>
    el("li", {}, `${FIELD_KINDS[f.kind]} field “${f.label}”${f.frame ? " (in a frame)" : ""}${f.empty ? "" : " — already has a value"}`))));
  const lookup = $("autofill-lookup");
  lookup.textContent = `Find my alias for ${state.host}`;
  lookup.hidden = autofill.signups !== null;
}

async function lookupAlias() {
  const button = $("autofill-lookup");
  button.disabled = true;
  setStatus("autofill-result", "Looking up…");
  try {
    const signups = await state.api.lookupSignups(state.host);
    autofill.signups = signups;
    autofill.chosenId = signups.length === 1 ? signups[0].id : null;
    button.hidden = true;
    setStatus("autofill-result", "");
    renderSuggestion();
  } catch (error) {
    if (isUnauthorized(error)) await disconnected();
    setStatus("autofill-result", error instanceof ApiError ? error.message : "The lookup failed.", "error");
  } finally {
    button.disabled = false;
  }
}

function chosenSignup() {
  return (autofill.signups ?? []).find((s) => s.id === autofill.chosenId) ?? null;
}

function renderSuggestion() {
  const box = $("autofill-suggestion");
  const signups = autofill.signups ?? [];
  if (!signups.length) {
    show(box, el("div", { class: "panel" },
      el("p", {}, `No LeakTrace signup is saved for ${state.host}.`),
      el("p", { class: "hint" }, "Signups for other subdomains are not used. LeakTrace creates nothing unless you ask."),
      el("button", { type: "button", onclick: createFromAutofill }, "Create one for this site")));
    return;
  }
  const parts = [];
  if (signups.length > 1) {
    parts.push(el("fieldset", {},
      el("legend", {}, `${signups.length} signups are saved for ${state.host}. Choose one:`),
      signups.map((s) => el("label", { class: "inline" },
        el("input", { type: "radio", name: "autofill-signup", value: String(s.id), checked: s.id === autofill.chosenId,
          onchange: () => { autofill.chosenId = s.id; renderSuggestion(); } }),
        `#${s.id} ${s.siteName}${s.alias ? ` — ${s.alias}` : " — no alias"}`))));
  }
  const signup = chosenSignup();
  if (!signup) {
    autofill.options = [];
    show(box, el("div", { class: "panel" }, parts));
    return;
  }
  autofill.options = fillOptions(autofill.fields, signup);
  if (!signup.alias) parts.push(el("p", { class: "hint" }, "This signup has no alias, so identifier fields cannot be filled."));
  if (!autofill.options.length) {
    parts.push(el("p", {}, "None of the detected fields can be filled with this signup's markers."));
    show(box, el("div", { class: "panel" }, parts));
    return;
  }
  parts.push(
    el("p", {}, el("strong", {}, "Use your LeakTrace alias for this site?")),
    signup.alias ? el("p", {}, "Saved alias: ", el("span", { class: "marker" }, signup.alias)) : null,
    el("fieldset", {}, el("legend", {}, "Fields to fill (nothing is submitted)"),
      autofill.options.map((o) => el("div", {},
        el("label", { class: "inline" },
          el("input", { type: "checkbox", id: `fill-${o.id}`, checked: o.ticked }),
          `${o.kindLabel} “${o.label}” ← ${o.value}`),
        o.empty ? null : el("p", { class: "hint" }, "Already has a value. Tick it only if you want to replace that value.")))),
    el("div", { class: "row" },
      el("button", { type: "button", onclick: () => fillNow(signup) }, "Fill"),
      el("button", { type: "button", class: "secondary", onclick: notNow }, "Not now"),
      el("button", { type: "button", class: "secondary", onclick: neverForSite }, "Never for this site")));
  show(box, el("div", { class: "panel", role: "group", "aria-label": "Autofill suggestion" }, parts));
}

function fillNow(signup) {
  const selected = autofill.options.filter((o) => $(`fill-${o.id}`)?.checked).map((o) => o.id);
  let plan;
  try {
    plan = buildFillPlan(autofill.options, selected, signup);
  } catch (error) {
    setStatus("autofill-result", error.message, "error");
    return;
  }
  if (!autofill.port) {
    setStatus("autofill-result", "Lost the connection to this tab. Reopen LeakTrace to try again.", "error");
    return;
  }
  setStatus("autofill-result", "Filling…");
  autofill.port.postMessage({ type: "fill", plan });
}

function renderFillResults(results) {
  const filled = results.filter((r) => r?.filled === true).length;
  const skipped = results.filter((r) => r?.filled !== true);
  const labelOf = (id) => autofill.options.find((o) => o.id === id)?.label ?? "a field";
  const notes = skipped.map((r) => `“${labelOf(r.id)}”: ${typeof r.reason === "string" ? r.reason : "not filled"}`);
  const message = filled
    ? `Filled ${filled} field${filled === 1 ? "" : "s"}. LeakTrace did not submit the form; check it and submit it yourself.`
    : "Nothing was filled.";
  setStatus("autofill-result", notes.length ? `${message} Skipped: ${notes.join("; ")}.` : message, filled ? "ok" : "error");
}

function notNow() {
  stopDetector();
  autofill.unavailable = "Suggestions were dismissed. Reopen LeakTrace to fill this page.";
  show($("autofill-suggestion"));
  setStatus("autofill-result", "Dismissed for now. Nothing was filled.");
}

async function neverForSite() {
  try {
    const { neverSites } = await chrome.storage.local.get("neverSites");
    await chrome.storage.local.set({ neverSites: addNeverSite(neverSites, state.host) });
  } catch {
    setStatus("autofill-result", "Could not save that choice.", "error");
    return;
  }
  clearAutofillState();
  setStatus("autofill-status", `You chose never to get autofill suggestions on ${state.host}.`);
  $("autofill-allow").hidden = false;
}

async function allowAgain() {
  try {
    const { neverSites } = await chrome.storage.local.get("neverSites");
    await chrome.storage.local.set({ neverSites: removeNeverSite(neverSites, state.host) });
  } catch {
    setStatus("autofill-status", "Could not update that choice.", "error");
    return;
  }
  await startAutofill();
}

function createFromAutofill() {
  $("site-name").value ||= state.host;
  $("site-domain").value = state.host;
  $("signup-section").scrollIntoView({ block: "start" });
  $("site-name").focus();
  setStatus("signup-status", `Review and confirm to create a signup for ${state.host}. Nothing is created until you confirm.`);
}

// ---------- start ----------

async function readActiveTab() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab ?? null;
  } catch {
    return null;
  }
}

function isUnauthorized(error) {
  return error instanceof ApiError && error.status === 401;
}

/** The token was rejected (expired or revoked): forget it and ask to reconnect. */
async function disconnected() {
  state.auth = null;
  try {
    await chrome.storage.session.remove("auth");
  } catch {
    // nothing stored
  }
  showConnectionState();
  stopDetector();
  autofill.unavailable = RECONNECT_MESSAGE;
}

function showConnectionState() {
  const connected = Boolean(state.api && state.auth);
  $("not-connected").hidden = !state.api || connected;
  for (const id of ["signup-form", "receipt-form"]) setBusy($(id), !connected);
  if (!state.api) $("backend").textContent = "Backend: not configured";
  else if (!state.auth) $("backend").textContent = `Backend: ${state.api.origin} · not connected to an account`;
  else $("backend").textContent = `Signed in as ${state.auth.email} · ${state.api.origin} (local development)`;
}

async function init() {
  $("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("open-options").addEventListener("click", () => chrome.runtime.openOptionsPage());
  $("open-connect").addEventListener("click", () => chrome.runtime.openOptionsPage());

  let baseUrl = null;
  try {
    ({ baseUrl } = await chrome.storage.local.get("baseUrl"));
    const { auth } = await chrome.storage.session.get("auth");
    state.auth = parseStoredAuth(auth);
    if (baseUrl) state.api = createApi(baseUrl, globalThis.fetch, state.auth?.token ?? null);
  } catch {
    state.api = null;
  }
  if (!state.api) {
    $("not-configured").hidden = false;
    $("open-dashboard").disabled = true;
  }
  showConnectionState();

  // The tab address stays in the popup; it is only sent if you confirm a request containing it.
  state.tab = await readActiveTab();
  state.tabUrl = state.tab?.url ?? null;
  const host = hostnameFromTabUrl(state.tabUrl);
  state.host = host;
  if (host) {
    $("current-site").textContent = host;
    $("site-name").value = host;
    $("site-domain").value = host;
  } else {
    $("current-site").textContent = "This tab has no website address. Enter the site details below.";
  }
  $("use-page-url").disabled = !policyUrlFromPage(state.tabUrl) || !state.api;
  $("use-page-url").addEventListener("click", () => {
    const url = policyUrlFromPage(state.tabUrl);
    if (url) $("receipt-url").value = url;
  });

  $("real-name").addEventListener("change", (e) => { if (e.target.checked) $("gen-nickname").checked = false; });
  $("signup-form").addEventListener("submit", reviewSignup);
  $("receipt-form").addEventListener("submit", reviewReceipt);
  $("receipt-signup").addEventListener("input", updateSignupMismatch);
  $("open-dashboard").addEventListener("click", () => {
    if (state.api) chrome.tabs.create({ url: `${state.api.origin}/dashboard` });
  });

  try {
    const { selected } = await chrome.storage.session.get("selected");
    state.selected = selected && Number.isSafeInteger(selected.id) ? selected : null;
  } catch {
    state.selected = null;
  }
  renderSelected();

  $("autofill-lookup").addEventListener("click", lookupAlias);
  $("autofill-allow").addEventListener("click", allowAgain);
  await startAutofill();
}

init();
