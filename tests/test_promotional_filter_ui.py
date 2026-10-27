"""Exercise the alias detail toggle without a browser or live dashboard server."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parents[1] / "backend/dashboard/app.js"

SCRIPT = r"""
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const start = source.indexOf('function promotionalFilterControl(signup) {');
const end = source.indexOf('async function setWebsiteAliasStatus(', start);
if (!source.includes('d.alias ? promotionalFilterControl(d) : null')) throw new Error('toggle is not rendered in website details');
const calls = [];
const notices = [];
let fail = false;
function el(tag, attrs, ...children) {
  return { tag, attrs, children, listeners: {}, checked: false, disabled: false,
    addEventListener(name, callback) { this.listeners[name] = callback; } };
}
const context = { el, api: async (...args) => { calls.push(args); if (fail) throw Error('Save failed'); },
  toast: (...args) => notices.push(args), loadWebsites: async () => {}, showWebsite: async () => {}, Promise };
vm.runInNewContext(source.slice(start, end), context);
async function run() {
  const control = context.promotionalFilterControl({ id: 7, site_name: 'Shop', block_promotional_emails: false });
  const [label, hint] = control.children;
  const input = label.children[0];
  if (input.checked || !label.children.includes(' Block promotional emails') || !hint.children[0].includes('Uncertain messages are allowed')) {
    throw Error('initial toggle state or explanation is incorrect');
  }
  input.checked = true;
  await input.listeners.change();
  if (calls.length !== 1 || calls[0][0] !== '/signups/7/promotional-filter' ||
      calls[0][1].method !== 'PATCH' || calls[0][1].body.block_promotional_emails !== true) {
    throw Error('toggle did not send the expected authenticated API update');
  }
  fail = true;
  const retry = context.promotionalFilterControl({ id: 7, site_name: 'Shop', block_promotional_emails: true });
  const retryInput = retry.children[0].children[0];
  if (!retryInput.checked) throw Error('persisted enabled state was not rendered');
  retryInput.checked = false;
  await retryInput.listeners.change();
  if (!retryInput.checked || retryInput.disabled || notices.at(-1)[1] !== 'error') {
    throw Error('failed save did not restore the persisted state');
  }
  process.stdout.write(JSON.stringify({ calls: calls.length, feedback: notices.length }));
}
run().catch((error) => { process.stderr.write(error.message); process.exitCode = 1; });
"""


def test_alias_detail_filter_toggle_and_save_feedback():
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    result = subprocess.run([node, "-e", SCRIPT, str(APP)], capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == {"calls": 2, "feedback": 2}
