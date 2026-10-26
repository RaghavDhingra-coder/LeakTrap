const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const source = fs.readFileSync(path.join(__dirname, '../backend/dashboard/app.js'), 'utf8')
  .split('document.addEventListener("DOMContentLoaded", async () => {')[0];

class Element {
  constructor(tag = 'div') {
    this.tag = tag;
    this.children = [];
    this.attributes = {};
    this.listeners = {};
    this.textContent = '';
    this.hidden = false;
    this.disabled = false;
  }
  setAttribute(name, value) { this.attributes[name] = value; if (name === 'disabled') this.disabled = true; }
  removeAttribute(name) { delete this.attributes[name]; }
  append(...children) { this.children.push(...children.flat().filter((x) => x !== null && x !== undefined && x !== false)); }
  replaceChildren(...children) { this.children = []; this.append(...children); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  click() { return this.listeners.click?.({ currentTarget: this }); }
  focus() {}
  querySelector() { return new Element(); }
  remove() {}
  showModal() { this.open = true; }
  close() { this.open = false; }
  get lastChild() { return this.children.at(-1); }
}

function descendants(node) {
  if (!(node instanceof Element)) return [];
  return [node, ...node.children.flatMap(descendants)];
}
function label(node) {
  return descendants(node).map((item) => item.textContent + item.children.filter((child) => typeof child === 'string').join('')).join('');
}
function buttons(node) { return descendants(node).filter((item) => item.tag === 'button' && label(item).includes('Report Website')); }

function dashboard(fixtures, postResult = { already_reported: false }) {
  const elements = new Map();
  const calls = [];
  const document = {
    activeElement: new Element(),
    createElement: (tag) => new Element(tag),
    querySelector: () => null,
    getElementById: (id) => {
      if (!elements.has(id)) elements.set(id, new Element(id === 'confirm-dialog' ? 'dialog' : 'div'));
      return elements.get(id);
    },
  };
  const fetch = async (url, options = {}) => {
    calls.push({ url, options });
    const result = options.method === 'POST' ? postResult : fixtures[url];
    return { ok: !(result instanceof Error), status: result instanceof Error ? 500 : (options.method === 'POST' ? 201 : 200),
      json: async () => result instanceof Error ? { detail: result.message } : result };
  };
  const context = vm.createContext({ document, fetch, Node: Element, URL, URLSearchParams, console, setTimeout, clearTimeout });
  vm.runInContext(source, context);
  vm.runInContext('state.me = { csrf_token: "csrf" }; icon = () => document.createElement("svg");', context);
  return { context, document, elements, calls };
}

const matched = { id: 9, signup_id: 3, site_name: 'Example', site_domain: 'shop.example.com', alias: 'marker@alias.example',
  status: 'matched', tracked: true, subject: 'Hello', sender_domain: 'outsider.example', sender_name: 'Sender',
  received_at: '2026-10-26T10:00:00Z', created_at: '2026-10-26T10:00:00Z', exposure: [], unread: false };

async function submit(ui, button) {
  const pending = button.click();
  assert.equal(ui.calls.filter((call) => call.url === '/website-reports').length, 0, 'confirmation precedes submission');
  const dialog = ui.document.getElementById('confirm-dialog');
  assert.equal(dialog.open, true);
  ui.document.getElementById('confirm-ok').onclick();
  await pending;
  return ui.calls.find((call) => call.url === '/website-reports');
}

test('Website details renders an actionable report only with a matched alias observation', async () => {
  const detail = { id: 3, site_name: 'Example', site_domain: 'shop.example.com', alias: matched.alias, nickname: null,
    surname_variant: null, real_name_required: false, created_at: matched.created_at, receipts: [],
    emails: [matched], sms_investigations: [], notice: 'Not proof.' };
  const ui = dashboard({ '/dashboard/api/signups/3': detail });
  await vm.runInContext('showWebsite(3)', ui.context);
  const body = ui.document.getElementById('website-detail-body');
  const [button] = buttons(body);
  assert.equal(ui.document.getElementById('website-detail').hidden, false);
  assert.ok(button && !button.disabled, 'visible, enabled Report Website action');
  const call = await submit(ui, button);
  assert.deepEqual(JSON.parse(call.options.body), { domain: 'shop.example.com', category: 'personal_marker_match' });
  assert.equal(call.options.headers['x-csrf-token'], 'csrf');
  assert.match(label(body), /Your report was added/);
  assert.ok(!call.options.body.includes('Hello'));

  detail.emails = [];
  await vm.runInContext('showWebsite(3)', ui.context);
  assert.equal(buttons(body).length, 1);
  assert.equal(buttons(body)[0].disabled, true, 'an unused website is not treated as a finding');
});

test('Inbox card and details render Report Website for eligible matches only', async () => {
  const ui = dashboard({ '/dashboard/api/inbox/9': matched });
  const card = vm.runInContext(`inboxCard(${JSON.stringify(matched)})`, ui.context);
  assert.equal(buttons(card).length, 1);
  const call = await submit(ui, buttons(card)[0]);
  assert.deepEqual(JSON.parse(call.options.body), { domain: 'shop.example.com', category: 'personal_marker_match' });
  await vm.runInContext('showInboxDetail(9)', ui.context);
  assert.equal(buttons(ui.document.getElementById('inbox-detail-body')).length, 1);
  const unrelated = { ...matched, status: 'unmatched' };
  assert.equal(buttons(vm.runInContext(`inboxCard(${JSON.stringify(unrelated)})`, ui.context)).length, 0);
  const invalid = { ...matched, site_domain: 'https://shop.example.com/path' };
  assert.equal(buttons(vm.runInContext(`inboxCard(${JSON.stringify(invalid)})`, ui.context)).length, 0);
});

test('SMS analysis renders report for detected suspicious link and excludes inconclusive or added links', async () => {
  const analysis = { status: 'unknown', sender: null, received_at: null, label: null, candidates: [], missing: [],
    sender_notes: [], warnings: [], notice: 'Not proof.', limitations: [], redacted_text: '',
    risk: { assessment: 'Suspicious', risk_level: 'moderate', exposure: [], reasons: [], next_steps: [], notice: '' },
    entities: [{ type: 'url', display: 'https://alerts.example.com/path?secret=123', certainty: 'pattern', excluded: false,
      key: 'url1', sensitive: false, note: null, relation: null, signup_id: null }] };
  const ui = dashboard({});
  vm.runInContext(`renderSmsAnalysis(${JSON.stringify(analysis)})`, ui.context);
  const body = ui.document.getElementById('sms-result');
  assert.equal(buttons(body).length, 1);
  const call = await submit(ui, buttons(body)[0]);
  assert.deepEqual(JSON.parse(call.options.body), { domain: 'alerts.example.com', category: 'suspicious_message_link' });
  assert.ok(!call.options.body.includes('secret'));
  analysis.risk.risk_level = 'unknown';
  vm.runInContext(`renderSmsAnalysis(${JSON.stringify(analysis)})`, ui.context);
  assert.equal(buttons(body).length, 0);
  analysis.risk.risk_level = 'moderate';
  analysis.entities[0].certainty = 'user_added';
  vm.runInContext(`renderSmsAnalysis(${JSON.stringify(analysis)})`, ui.context);
  assert.equal(buttons(body).length, 0);
});

test('Report action shows duplicate and server error states', async () => {
  const duplicate = dashboard({}, { already_reported: true });
  const button = vm.runInContext('reportWebsiteButton("example.com", "personal_marker_match")', duplicate.context);
  await submit(duplicate, buttons(button)[0]);
  assert.match(label(button), /Already reported by you/);
  const failure = dashboard({}, new Error('Try again later'));
  const failed = vm.runInContext('reportWebsiteButton("example.com", "personal_marker_match")', failure.context);
  await submit(failure, buttons(failed)[0]);
  assert.match(label(failed), /Try again later/);
  assert.equal(buttons(failed)[0].disabled, false);
});


test('Cancelling report confirmation sends nothing', async () => {
  const ui = dashboard({});
  const container = vm.runInContext('reportWebsiteButton("example.com", "personal_marker_match")', ui.context);
  const pending = buttons(container)[0].click();
  ui.document.getElementById('confirm-cancel').onclick();
  await pending;
  assert.equal(ui.calls.length, 0);
});

test('Home actions are visible and wired to their existing flows', () => {
  const html = fs.readFileSync(path.join(__dirname, '../backend/dashboard/index.html'), 'utf8');
  for (const id of ['overview-analyze', 'overview-check', 'overview-new-alias', 'recent-open-inbox']) {
    assert.match(html, new RegExp(`<button[^>]+id="${id}"`));
    assert.match(fs.readFileSync(path.join(__dirname, '../backend/dashboard/app.js'), 'utf8'),
      new RegExp(`getElementById\\("${id}"\\)\\.addEventListener\\("click"`));
  }
  assert.ok(html.indexOf('id="recent-list"') < html.indexOf('id="overview-insights"'));
});

test('SMS keeps report action visible while technical details are expandable', () => {
  const analysis = { status: 'unknown', sender: null, received_at: null, label: null, candidates: [], missing: [],
    sender_notes: [], warnings: [], notice: 'Not proof.', limitations: [], redacted_text: '',
    risk: { assessment: 'Suspicious', risk_level: 'moderate', exposure: [], reasons: [], next_steps: [], notice: '' },
    entities: [{ type: 'url', display: 'https://alerts.example.com/path', certainty: 'pattern', excluded: false,
      key: 'url1', sensitive: false, note: null, relation: null, signup_id: null }] };
  const ui = dashboard({});
  vm.runInContext(`renderSmsAnalysis(${JSON.stringify(analysis)})`, ui.context);
  const body = ui.document.getElementById('sms-result');
  const disclosures = descendants(body).filter((item) => item.tag === 'details');
  assert.ok(disclosures.some((item) => label(item).includes('Analysis details')));
  assert.ok(disclosures.some((item) => label(item).includes('Details found in message')));
  assert.equal(buttons(body).length, 1);
});

test('Sensitive settings stay available behind explicit disclosures', () => {
  const html = fs.readFileSync(path.join(__dirname, '../backend/dashboard/index.html'), 'utf8');
  for (const [summary, form] of [
    ['Change password', 'password-form'], ['Connect a mobile device', 'device-code-form'], ['Delete account', 'delete-form'],
  ]) {
    const start = html.indexOf(`<summary>${summary}</summary>`);
    const end = html.indexOf('</details>', start);
    assert.ok(start >= 0 && html.indexOf(`id="${form}"`, start) < end, `${form} is in its disclosure`);
  }
});

test('manual check reports require an actual tracked marker observation', () => {
  const ui = dashboard({});
  const result = { status: 'matched' };
  const match = { site_domain: 'example.com', signals: [{ type: 'sender_domain' }] };
  assert.equal(vm.runInContext(`eligibleCheckReport(${JSON.stringify(result)}, ${JSON.stringify(match)})`, ui.context), false);
  match.signals = [{ type: 'alias_exact' }];
  assert.equal(vm.runInContext(`eligibleCheckReport(${JSON.stringify(result)}, ${JSON.stringify(match)})`, ui.context), true);
  result.status = 'ambiguous';
  assert.equal(vm.runInContext(`eligibleCheckReport(${JSON.stringify(result)}, ${JSON.stringify(match)})`, ui.context), false);
});

test('unknown sender asks for review; only reviewed DMARC-supported sender raises disclosure', () => {
  const ui = dashboard({});
  const assessment = { alias_attribution: 'matched', sender_domain_status: 'unreviewed',
    sender_authentication: 'provider_dmarc_pass', disclosure_status: 'review', confirmed_leak: false };
  const unknown = vm.runInContext(`emailFinding(${JSON.stringify({ ...matched, sender_assessment: assessment })})`, ui.context);
  assert.equal(unknown.concern, false);
  assert.match(unknown.text, /Sender domain not yet verified/);
  const potential = vm.runInContext(`emailFinding(${JSON.stringify({ ...matched, sender_assessment: {
    ...assessment, sender_domain_status: 'unexpected_by_user', disclosure_status: 'potential' } })})`, ui.context);
  assert.equal(potential.concern, true);
  assert.match(potential.text, /You marked this sender unexpected.*not a confirmed leak/);
  const spoof = vm.runInContext(`emailFinding(${JSON.stringify({ ...matched, sender_assessment: {
    ...assessment, sender_domain_status: 'unexpected_by_user', sender_authentication: 'provider_dmarc_fail' } })})`, ui.context);
  assert.equal(spoof.concern, false);
  assert.match(spoof.text, /claimed sender may be spoofed/);
  const unmatched = vm.runInContext(`emailFinding(${JSON.stringify({ ...matched, sender_assessment: {
    ...assessment, alias_attribution: 'not_matched' } })})`, ui.context);
  assert.equal(unmatched, null);
});

test('sender review requires confirmation and sends only domain and review choice', async () => {
  const ui = dashboard({});
  const item = { ...matched, sender_assessment: { alias_attribution: 'matched', sender_domain_status: 'unreviewed' } };
  const controls = vm.runInContext(`senderReviewControls(${JSON.stringify(item)}, async () => {})`, ui.context);
  const button = descendants(controls).find((node) => node.tag === 'button' && label(node).includes('Mark as expected'));
  const pending = button.click();
  assert.equal(ui.calls.length, 0);
  ui.document.getElementById('confirm-ok').onclick();
  await pending;
  const call = ui.calls.find((c) => c.url === '/dashboard/api/signups/3/sender-domains');
  assert.deepEqual(JSON.parse(call.options.body), { domain: 'outsider.example', review_status: 'expected' });
  assert.ok(!call.options.body.includes('Hello'));
});
