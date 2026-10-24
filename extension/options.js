import {
  ApiError, DEFAULT_BASE_URL, createApi, newPairingSecret, normalizeNeverSites, parseStoredAuth, removeNeverSite, sha256Hex,
  validateBaseUrl,
} from "./src/lib.js";
import { el, show } from "./src/dom.js";

const form = document.getElementById("settings-form");
const input = document.getElementById("base-url");
const status = document.getElementById("status");

function say(message, isError = false) {
  status.textContent = message;
  status.classList.toggle("error", isError);
}

/** Check the saved backend and explain any problem (wrong port, outdated server, not running). */
async function checkSavedBackend(baseUrl, savedNow = false) {
  const prefix = savedNow ? `Saved ${baseUrl}. ` : "";
  say(`${prefix}Checking the backend…`);
  const result = await createApi(baseUrl).checkBackend();
  if (result.ok) say(`${prefix}The backend at ${baseUrl} is a current LeakTrace API.`);
  else say(`${prefix}${result.message}`, true);
  return result.ok;
}

async function saveBaseUrl(value) {
  try {
    const baseUrl = validateBaseUrl(value);
    await chrome.storage.local.set({ baseUrl });
    input.value = baseUrl;
    await checkSavedBackend(baseUrl, true);
  } catch (error) {
    say(error.message, true);
  }
}

try {
  const { baseUrl } = await chrome.storage.local.get("baseUrl");
  if (baseUrl) {
    input.value = baseUrl;
    await checkSavedBackend(baseUrl);
  }
} catch {
  say("Could not read the saved setting.", true);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  await saveBaseUrl(input.value);
});

document.getElementById("use-default").addEventListener("click", () => saveBaseUrl(DEFAULT_BASE_URL));

document.getElementById("clear").addEventListener("click", async () => {
  try {
    await chrome.storage.local.remove("baseUrl");
    input.value = "";
    say("Cleared. The popup is disabled until a backend URL is saved.");
  } catch {
    say("Could not clear the setting.", true);
  }
});

// ---------- autofill settings ----------

const autofillToggle = document.getElementById("autofill-enabled");
const neverList = document.getElementById("never-list");
const autofillStatus = document.getElementById("autofill-status");

function sayAutofill(message, isError = false) {
  autofillStatus.textContent = message;
  autofillStatus.classList.toggle("error", isError);
}

async function renderNeverList() {
  const { neverSites } = await chrome.storage.local.get("neverSites");
  const sites = normalizeNeverSites(neverSites);
  if (!sites.length) {
    show(neverList, el("li", { class: "hint" }, "None."));
    return;
  }
  show(neverList, sites.map((host) => el("li", {}, `${host} `, el("button", {
    type: "button", class: "secondary", "aria-label": `Allow suggestions on ${host} again`,
    onclick: async () => {
      await chrome.storage.local.set({ neverSites: removeNeverSite(sites, host) });
      sayAutofill(`Suggestions allowed again on ${host}.`);
      await renderNeverList();
    },
  }, "Remove"))));
}

try {
  const { autofillEnabled } = await chrome.storage.local.get("autofillEnabled");
  autofillToggle.checked = autofillEnabled !== false;
  await renderNeverList();
} catch {
  sayAutofill("Could not read the autofill settings.", true);
}

autofillToggle.addEventListener("change", async () => {
  try {
    await chrome.storage.local.set({ autofillEnabled: autofillToggle.checked });
    sayAutofill(autofillToggle.checked ? "Autofill suggestions are on." : "Autofill suggestions are off.");
  } catch {
    sayAutofill("Could not save the autofill setting.", true);
  }
});

document.getElementById("never-clear").addEventListener("click", async () => {
  try {
    await chrome.storage.local.set({ neverSites: [] });
    sayAutofill("Cleared. Suggestions may appear again on those sites.");
    await renderNeverList();
  } catch {
    sayAutofill("Could not clear the list.", true);
  }
});

// ---------- account connection (dashboard-approved pairing) ----------

const POLL_MS = 2000;
const accountStatus = document.getElementById("account-status");
const connectButton = document.getElementById("connect");
const disconnectButton = document.getElementById("disconnect");
const pairingNote = document.getElementById("pairing");
let polling = null;

function sayAccount(message, isError = false) {
  accountStatus.textContent = message;
  accountStatus.classList.toggle("error", isError);
}

async function savedApi(token = null) {
  const { baseUrl } = await chrome.storage.local.get("baseUrl");
  if (!baseUrl) throw new ApiError("Save the local backend URL above first.");
  return createApi(baseUrl, globalThis.fetch, token);
}

async function showConnection() {
  const { auth } = await chrome.storage.session.get("auth");
  const current = parseStoredAuth(auth);
  connectButton.hidden = Boolean(current);
  disconnectButton.hidden = !current;
  if (current) {
    const until = new Date(current.expiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    sayAccount(`Connected as ${current.email} until ${until}.`);
  } else {
    if (auth) await chrome.storage.session.remove("auth");
    sayAccount("Not connected.");
  }
}

function stopPolling() {
  clearTimeout(polling);
  polling = null;
  pairingNote.hidden = true;
  pairingNote.textContent = "";
  connectButton.disabled = false;
}

connectButton.addEventListener("click", async () => {
  connectButton.disabled = true;
  try {
    const api = await savedApi();
    const secret = newPairingSecret();
    const pairing = await api.startPairing(await sha256Hex(secret));
    pairingNote.hidden = false;
    pairingNote.textContent = `Approve code ${pairing.code} in the dashboard tab that just opened. Only approve it if you see this same code here.`;
    sayAccount("Waiting for approval in the dashboard…");
    await chrome.tabs.create({ url: `${api.origin}${pairing.approvePath}` });
    const poll = async () => {
      if (Date.now() > pairing.expiresAt) {
        stopPolling();
        sayAccount("The code expired before it was approved. Try again.", true);
        return;
      }
      try {
        const result = await api.exchangePairing(pairing.pairingId, secret);
        if (result.pending) {
          polling = setTimeout(poll, POLL_MS);
          return;
        }
        await chrome.storage.session.set({ auth: result });
        stopPolling();
        await showConnection();
      } catch (error) {
        stopPolling();
        sayAccount(error instanceof ApiError ? error.message : "Connecting failed.", true);
      }
    };
    polling = setTimeout(poll, POLL_MS);
  } catch (error) {
    stopPolling();
    sayAccount(error instanceof ApiError ? error.message : "Connecting failed.", true);
  }
});

disconnectButton.addEventListener("click", async () => {
  const { auth } = await chrome.storage.session.get("auth");
  const current = parseStoredAuth(auth);
  try {
    if (current) await (await savedApi(current.token)).disconnect();
  } catch {
    // Revocation failed (backend unreachable or token already invalid); forget it locally anyway.
  }
  await chrome.storage.session.remove("auth");
  await showConnection();
  sayAccount("Disconnected. This extension can no longer use your account.");
});

try {
  await showConnection();
} catch {
  sayAccount("Could not read the connection state.", true);
}
