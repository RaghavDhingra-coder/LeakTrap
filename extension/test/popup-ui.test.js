import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const html = readFileSync(new URL('../popup.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('../popup.js', import.meta.url), 'utf8');

test('popup leads with current domain and reputation before optional tools', () => {
  assert.ok(html.indexOf('id="current-site"') < html.indexOf('id="site-tools"'));
  assert.ok(html.indexOf('id="reputation-result"') < html.indexOf('id="site-tools"'));
  assert.match(html, /<details id="site-tools"[^>]*><summary>Site tools<\/summary>/);
  assert.match(html, /<details id="signup-tool"[^>]*><summary>Create a signup alias<\/summary>/);
  assert.match(html, /<details id="receipt-tool"[^>]*><summary>Record consent<\/summary>/);
  assert.match(html, /<details id="reputation-details"[^>]*hidden>/);
  for (const id of ['autofill-section', 'signup-form', 'receipt-form']) {
    assert.ok(html.indexOf(`id="${id}"`) > html.indexOf('id="site-tools"'));
  }
});

test('reputation leads with people count and observation categories', () => {
  assert.match(script, /person has/);
  assert.match(script, /people have/);
  assert.match(script, /reputation\.reporter_count/);
  assert.match(script, /reputation\.categories\.map/);
  assert.doesNotMatch(script.slice(script.indexOf('async function loadReputation'), script.indexOf('// ---------- start ----------')), /verified finding|unverified community/);
  assert.match(script, /No community reports found/);
  assert.match(script, /This does not guarantee the site is safe/);
  assert.match(script, /\$\("reputation-details"\)\.hidden = false/);
  assert.match(script, /\$\("site-tools"\)\.open = true/);
  assert.match(script, /\$\("signup-tool"\)\.open = true/);
});

test('reporting the visited site requires choosing a category and a second confirmation', () => {
  assert.match(html, /id="report-website"/);
  assert.match(html, /id="report-form"/);
  assert.match(html, /value="personal_marker_match"/);
  assert.match(html, /value="suspicious_message_link"/);
  assert.match(script, /function reviewWebsiteReport\(event\)/);
  assert.match(script, /confirm\.addEventListener\("click", async \(\) =>/);
  assert.match(script, /state\.api\.submitWebsiteReport\(state\.host, category\)/);
  assert.match(script, /Only the domain and observation type are sent/);
});
