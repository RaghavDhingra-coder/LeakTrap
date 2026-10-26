import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';

const script = readFileSync(new URL('../popup.js', import.meta.url), 'utf8');
const flow = script.slice(script.indexOf('function reportCategoryLabel'), script.indexOf('async function loadReputation'));

class Node {
  constructor(tag = 'div') { this.tag = tag; this.children = []; this.listeners = {}; this.hidden = false; this.disabled = false; this.textContent = ''; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  setAttribute() {}
  focus() {}
  reset() {}
  click() { return this.listeners.click?.(); }
}
function find(node, text) {
  if (node instanceof Node && node.tag === 'button' && node.children.includes(text)) return node;
  for (const child of node.children ?? []) { const found = find(child, text); if (found) return found; }
  return null;
}
function setup(result = { domain: 'flipkart.com', category: 'personal_marker_match', already_reported: false }) {
  const nodes = new Map();
  const calls = [];
  let refreshed = 0;
  const context = vm.createContext({
    state: { host: 'flipkart.com', auth: { token: 'token' }, api: { submitWebsiteReport: async (...args) => { calls.push(args); return result; } } },
    $: (id) => { if (!nodes.has(id)) nodes.set(id, new Node()); return nodes.get(id); },
    el: (tag, attrs, ...children) => { const n = new Node(tag); n.children = children.flat(); return n; },
    show: (node, ...children) => node.replaceChildren(...children),
    setBusy: (node, busy) => { node.busy = busy; },
    setStatus: (id, message, kind) => { const n = nodes.get(id) ?? new Node(); n.textContent = message; n.kind = kind; nodes.set(id, n); },
    FormData: class { constructor(form) { this.form = form; } get(name) { return name === 'category' ? this.form.category : null; } },
    isUnauthorized: () => false,
    disconnected: async () => {},
    loadReputation: async () => { refreshed += 1; },
  });
  vm.runInContext(flow, context);
  return { context, nodes, calls, refreshed: () => refreshed };
}

test('extension report sends domain and selected category only after confirmation', async () => {
  const ui = setup();
  vm.runInContext('reviewWebsiteReport({ preventDefault() {}, target: { category: "personal_marker_match" } })', ui.context);
  assert.equal(ui.calls.length, 0);
  const confirm = find(ui.nodes.get('report-confirm'), 'Submit report');
  assert.ok(confirm);
  await confirm.click();
  assert.equal(ui.calls.length, 1);
  assert.deepEqual([...ui.calls[0]], ['flipkart.com', 'personal_marker_match']);
  assert.equal(ui.nodes.get('report-status').textContent, 'Your report was added.');
  assert.equal(ui.nodes.get('report-panel').hidden, true);
  assert.equal(ui.refreshed(), 1);
});

test('extension report requires a category and handles duplicate and error states', async () => {
  const missing = setup();
  vm.runInContext('reviewWebsiteReport({ preventDefault() {}, target: { category: null } })', missing.context);
  assert.equal(missing.calls.length, 0);
  assert.equal(missing.nodes.get('report-status').textContent, 'Choose what you observed.');
  const duplicate = setup({ already_reported: true });
  vm.runInContext('reviewWebsiteReport({ preventDefault() {}, target: { category: "suspicious_message_link" } })', duplicate.context);
  await find(duplicate.nodes.get('report-confirm'), 'Submit report').click();
  assert.equal(duplicate.nodes.get('report-status').textContent, 'You already reported this observation.');
  const failure = setup();
  failure.context.state.api.submitWebsiteReport = async () => { throw Object.assign(new Error('Try again'), { status: 500 }); };
  vm.runInContext('reviewWebsiteReport({ preventDefault() {}, target: { category: "personal_marker_match" } })', failure.context);
  const button = find(failure.nodes.get('report-confirm'), 'Submit report');
  await button.click();
  assert.equal(failure.nodes.get('report-status').textContent, 'Try again');
  assert.equal(button.disabled, false);
});
