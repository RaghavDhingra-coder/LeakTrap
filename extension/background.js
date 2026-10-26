// Badge-only community warning for the active website. No page content is read
// or modified. The local backend receives one bare hostname, never a page URL.
import { ApiError, createApi, parseStoredAuth, reputationHostFromTabUrl } from "./src/lib.js";

const checks = new Map();
const CATEGORY_LABELS = {
  personal_marker_match: "tracked marker seen in a message",
  suspicious_message_link: "link seen in a suspicious SMS",
};

async function setBadge(tabId, text, title) {
  await chrome.action.setBadgeText({ tabId, text });
  await chrome.action.setTitle({ tabId, title });
  if (text) {
    await chrome.action.setBadgeBackgroundColor({ tabId, color: "#f2bd5c" });
  }
}

export async function checkTab(tabId, url) {
  const check = Symbol();
  checks.set(tabId, check);
  const host = reputationHostFromTabUrl(url);
  try {
    await setBadge(tabId, "", "LeakTrace");
    if (!host) return;
    const [{ baseUrl }, { auth }] = await Promise.all([
      chrome.storage.local.get("baseUrl"), chrome.storage.session.get("auth"),
    ]);
    const connected = parseStoredAuth(auth);
    if (!baseUrl || !connected) {
      await setBadge(tabId, "", baseUrl ? "LeakTrace: connect your account in Settings to check reports."
        : "LeakTrace: configure the local backend in Settings to check reports.");
      return;
    }
    const reputation = await createApi(baseUrl, globalThis.fetch, connected.token).websiteReputation(host);
    if (checks.get(tabId) !== check || !reputation.report_count) return;
    const count = reputation.reporter_count;
    const categories = reputation.categories.map((item) => CATEGORY_LABELS[item.category] ?? item.category).join(", ");
    const title = `LeakTrace: ${count} ${count === 1 ? "person has" : "people have"} reported ${host}. `
      + `${categories}. Reports are observations, not proof of a breach. Open LeakTrace for details.`;
    await setBadge(tabId, count > 99 ? "99+" : String(count), title);
  } catch (error) {
    if (checks.get(tabId) !== check) return;
    const title = error instanceof ApiError && error.status === 401
      ? "LeakTrace: reconnect your account to check community reports."
      : "LeakTrace: could not check community reports. Open LeakTrace for details.";
    try { await setBadge(tabId, "", title); } catch { /* the tab may have closed */ }
  }
}

async function checkActiveTabs() {
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  await Promise.all(tabs.filter((tab) => tab.id != null).map((tab) => checkTab(tab.id, tab.url)));
}

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (tab.active && (change.url || change.status === "complete")) void checkTab(tabId, tab.url);
});
chrome.tabs.onActivated.addListener(({ tabId }) => {
  void chrome.tabs.get(tabId).then((tab) => checkTab(tabId, tab.url)).catch(() => {});
});
chrome.tabs.onRemoved.addListener((tabId) => checks.delete(tabId));
chrome.storage.onChanged.addListener((changes) => {
  if (changes.auth || changes.baseUrl) void checkActiveTabs().catch(() => {});
});
chrome.runtime.onStartup.addListener(() => { void checkActiveTabs().catch(() => {}); });
chrome.runtime.onInstalled.addListener(() => { void checkActiveTabs().catch(() => {}); });
