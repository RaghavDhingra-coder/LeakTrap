import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url)));

test("Manifest V3", () => assert.equal(manifest.manifest_version, 3));

test("only the minimal permissions are requested", () => {
  // tabs observes navigation so the badge can warn before the popup opens.
  // scripting still works only with activeTab; no website host access is granted.
  assert.deepEqual(manifest.permissions, ["activeTab", "tabs", "scripting", "storage"]);
  assert.deepEqual(manifest.host_permissions, ["http://127.0.0.1/*"]);
  assert.equal(manifest.optional_permissions, undefined);
  assert.equal(manifest.optional_host_permissions, undefined);
});

test("no broad or sensitive permissions anywhere", () => {
  const text = JSON.stringify(manifest);
  for (const banned of ["<all_urls>", "*://*/*", "https://*/*", "history", "cookies", "webRequest",
    "clipboardRead", "downloads", "bookmarks", "identity", "nativeMessaging", "debugger"]) {
    assert.ok(!text.includes(banned), banned);
  }
});

test("badge worker but no static content scripts or web-accessible resources", () => {
  assert.deepEqual(manifest.background, { service_worker: "background.js", type: "module" });
  for (const key of ["content_scripts", "web_accessible_resources", "externally_connectable"]) {
    assert.equal(manifest[key], undefined, key);
  }
});

test("strict content security policy limits connections to 127.0.0.1", () => {
  const csp = manifest.content_security_policy.extension_pages;
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /object-src 'none'/);
  assert.match(csp, /connect-src http:\/\/127\.0\.0\.1:\*/);
  assert.ok(!csp.includes("unsafe"));
});

test("popup and options pages are declared and exist", () => {
  assert.equal(manifest.action.default_popup, "popup.html");
  assert.equal(manifest.options_ui.page, "options.html");
  for (const file of ["popup.html", "options.html", "popup.js", "options.js", "popup.css", "background.js"]) {
    readFileSync(new URL(`../${file}`, import.meta.url));
  }
});

test("host access is limited to the local backend, so scripting can only reach the activeTab tab", () => {
  assert.deepEqual(manifest.host_permissions, ["http://127.0.0.1/*"]);
  assert.ok(!JSON.stringify(manifest.host_permissions).includes("*://"));
});
