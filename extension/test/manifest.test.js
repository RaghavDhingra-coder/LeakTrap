import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url)));

test("Manifest V3", () => assert.equal(manifest.manifest_version, 3));

test("only the minimal permissions are requested", () => {
  // scripting (Phase 9) only works together with activeTab here: there is no host access to websites.
  assert.deepEqual(manifest.permissions, ["activeTab", "scripting", "storage"]);
  assert.deepEqual(manifest.host_permissions, ["http://127.0.0.1/*"]);
  assert.equal(manifest.optional_permissions, undefined);
  assert.equal(manifest.optional_host_permissions, undefined);
});

test("no broad or sensitive permissions anywhere", () => {
  const text = JSON.stringify(manifest);
  for (const banned of ["<all_urls>", "*://*/*", "https://*/*", "tabs\"", "history", "cookies", "webRequest",
    "clipboardRead", "downloads", "bookmarks", "identity", "nativeMessaging", "debugger"]) {
    assert.ok(!text.includes(banned), banned);
  }
});

test("no static content scripts, background worker or web-accessible resources", () => {
  for (const key of ["content_scripts", "background", "web_accessible_resources", "externally_connectable"]) {
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
  for (const file of ["popup.html", "options.html", "popup.js", "options.js", "popup.css"]) {
    readFileSync(new URL(`../${file}`, import.meta.url));
  }
});

test("host access is limited to the local backend, so scripting can only reach the activeTab tab", () => {
  assert.deepEqual(manifest.host_permissions, ["http://127.0.0.1/*"]);
  assert.ok(!JSON.stringify(manifest.host_permissions).includes("*://"));
});
