import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyPromotionalMetadata } from "../src/promotional.js";

const classify = (input) => classifyPromotionalMetadata(input).outcome;

test("sales and discount offers need multiple promotional signals", () => {
  assert.equal(classify({ subject: "SUMMER SALE — 40% OFF" }), "promotional");
  assert.equal(classify({ subject: "Coupon code for your next purchase", listUnsubscribe: "<mailto:unsubscribe@example.com>" }), "promotional");
  assert.equal(classify({ subject: "Sale" }), "uncertain");
  assert.equal(classify({ listUnsubscribe: "<mailto:unsubscribe@example.com>" }), "uncertain");
});

test("marketing newsletter headers require independent evidence", () => {
  assert.equal(classify({ listId: "Weekly Newsletter <newsletter.example.com>",
    listUnsubscribe: "<https://example.com/unsubscribe>", from: "Newsletter <news@example.com>" }), "promotional");
  assert.equal(classify({ listId: "Weekly Newsletter <newsletter.example.com>",
    listUnsubscribe: "<https://example.com/unsubscribe>" }), "uncertain");
});

test("receipts, invoices, password resets, security alerts, and shipping messages are transactional", () => {
  for (const subject of ["Receipt for order 123", "Your invoice is ready", "Password reset requested",
    "Security alert: new login", "Order confirmation #123", "Shipping update for your order", "Payment failed"]) {
    assert.equal(classify({ subject, listUnsubscribe: "<mailto:leave@example.com>" }), "transactional", subject);
  }
});

test("explicit promotional and transactional content in one subject stays uncertain", () => {
  assert.equal(classify({ subject: "Order confirmation and 20% off your next purchase" }), "uncertain");
  assert.equal(classify({ subject: "Your password reset plus a coupon" }), "uncertain");
});

test("unknown, missing, and malformed metadata cannot be promotional", () => {
  assert.equal(classify({ subject: "A note for you" }), "uncertain");
  assert.equal(classify({}), "uncertain");
  assert.equal(classify({ subject: ["SALE 40% OFF"] }), "uncertain");
  assert.equal(classify(null), "uncertain");
  assert.equal(classify({ subject: "SALE 40% OFF", listId: { bad: true } }), "uncertain");
});

test("inputs are bounded and normalized without including message bodies", () => {
  assert.equal(classify({ subject: "  SuMmEr\tSaLe 40%  OFF  " }), "promotional");
  assert.equal(classify({ subject: "x".repeat(998) + " SALE 40% OFF" }), "uncertain");
  assert.equal(classify({ subject: "SALE 40% OFF" + "x".repeat(998) }), "uncertain");
  assert.equal(classify({ body: "SALE 40% OFF" }), "uncertain");
});
