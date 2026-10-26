import assert from "node:assert/strict";
import { test } from "node:test";

const listeners = {};
const badge = new Map();
const titles = new Map();
let storedAuth = { token: "t".repeat(43), email: "person@example.com", expiresAt: Date.now() + 60_000 };
let response = null;
const requests = [];

globalThis.chrome = {
  action: {
    async setBadgeText({ tabId, text }) { badge.set(tabId, text); },
    async setTitle({ tabId, title }) { titles.set(tabId, title); },
    async setBadgeBackgroundColor() {},
    async setBadgeTextColor() {},
  },
  storage: {
    local: { async get() { return { baseUrl: "http://127.0.0.1:8000" }; } },
    session: { async get() { return { auth: storedAuth }; } },
    onChanged: { addListener(fn) { listeners.storageChanged = fn; } },
  },
  tabs: {
    onUpdated: { addListener(fn) { listeners.updated = fn; } },
    onActivated: { addListener(fn) { listeners.activated = fn; } },
    onRemoved: { addListener(fn) { listeners.removed = fn; } },
    async get(tabId) { return { id: tabId, url: "https://www.cricbuzz.com/live" }; },
    async query() { return [{ id: 1, url: "https://www.cricbuzz.com/live" }]; },
  },
  runtime: {
    onStartup: { addListener(fn) { listeners.startup = fn; } },
    onInstalled: { addListener(fn) { listeners.installed = fn; } },
  },
};
globalThis.fetch = async (url, init) => {
  requests.push({ url, init });
  return new Response(JSON.stringify(response), { status: 200 });
};

const { checkTab } = await import("../background.js");

const oneReport = { domain: "cricbuzz.com", report_count: 1, reporter_count: 1, unverified_count: 1, verified_count: 0,
  categories: [{ category: "personal_marker_match", unverified_count: 1, verified_count: 0 }] };

test("revisiting www host shows report count on badge and does not send page path", async () => {
  response = oneReport;
  requests.length = 0;
  await checkTab(1, "https://www.cricbuzz.com/live?private=secret");
  assert.equal(badge.get(1), "1");
  assert.match(titles.get(1), /1 person has reported www\.cricbuzz\.com/);
  assert.doesNotMatch(titles.get(1), /unverified|verified/);
  assert.match(titles.get(1), /not proof of a breach/);
  assert.equal(requests[0].url, "http://127.0.0.1:8000/website-reports/reputation?domain=cricbuzz.com");
  assert.equal(requests[0].init.headers.authorization, `Bearer ${storedAuth.token}`);
  assert.ok(!requests[0].url.includes("private"));
  assert.ok(listeners.updated && listeners.activated && listeners.startup);
});

test("unrelated subdomain and zero reports clear the badge", async () => {
  response = { domain: "scores.cricbuzz.com", report_count: 0, reporter_count: 0, unverified_count: 0, verified_count: 0, categories: [] };
  await checkTab(1, "https://scores.cricbuzz.com/");
  assert.equal(requests.at(-1).url, "http://127.0.0.1:8000/website-reports/reputation?domain=scores.cricbuzz.com");
  assert.equal(badge.get(1), "");
  await checkTab(1, "chrome://extensions/");
  assert.equal(badge.get(1), "");
});

test("badge counts people rather than two categories from the same person", async () => {
  response = { domain: "cricbuzz.com", report_count: 2, reporter_count: 1, unverified_count: 2, verified_count: 0,
    categories: [{ category: "personal_marker_match", unverified_count: 1, verified_count: 0 },
      { category: "suspicious_message_link", unverified_count: 1, verified_count: 0 }] };
  await checkTab(1, "https://cricbuzz.com/");
  assert.equal(badge.get(1), "1");
  assert.match(titles.get(1), /1 person has reported/);
});

test("no account connection sends no reputation request", async () => {
  storedAuth = null;
  const before = requests.length;
  await checkTab(2, "https://www.cricbuzz.com/");
  assert.equal(requests.length, before);
  assert.equal(badge.get(2), "");
});
