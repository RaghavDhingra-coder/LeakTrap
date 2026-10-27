import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { communityWarningText, createApi } from "../src/lib.js";

test("reputation lookup sends only the normalized domain with paired authentication", async () => {
  const calls = [];
  const api = createApi("http://127.0.0.1:8000", async (url, options) => {
    calls.push({ url, options });
    return new Response(JSON.stringify({ domain: "shop.example.com", reported_domain: "shop.example.com",
      unique_reporters: 12, status: "community_reported", last_reported_at: "2026-10-27T00:00:00Z" }), { status: 200 });
  }, "test-token");
  assert.equal((await api.websiteReputation("WWW.Shop.Example.COM")).unique_reporters, 12);
  assert.equal(calls[0].url, "http://127.0.0.1:8000/website-reports/reputation?domain=shop.example.com");
  assert.equal(calls[0].options.headers.authorization, "Bearer test-token");
  assert.equal(calls[0].options.body, undefined);
});

test("popup shows only positive community counts and no report on zero", () => {
  const popup = readFileSync(new URL("../popup.js", import.meta.url), "utf8");
  const html = readFileSync(new URL("../popup.html", import.meta.url), "utf8");
  assert.match(html, /id="community-warning"[^>]*hidden/);
  assert.match(popup, /communityWarningText\(reputation\)/);
  assert.match(popup, /warning\.hidden = false/);
  assert.equal(communityWarningText({ domain: "example.com", unique_reporters: 0 }), null);
  assert.equal(communityWarningText({ domain: "example.com", unique_reporters: 1, status: "community_reported" }),
    "1 user reported possible data exposure associated with example.com. Community reported; not a confirmed leak.");
  assert.equal(communityWarningText({ domain: "shop.example.com", reported_domain: "example.com", unique_reporters: 12, status: "under_review" }),
    "12 users reported possible data exposure associated with example.com. Under review.");
});
