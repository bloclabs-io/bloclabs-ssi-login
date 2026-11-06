const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.resolve(__dirname, '../../assets/js/profile.js'), 'utf8');

function harness(replies, options = {}) {
 const timers = [], calls = [], elements = {}, replaced = [];
 let reloaded = 0;
 for (const key of ['start', 'panel', 'qr', 'open', 'status', 'cancel']) {
  elements[key] = { hidden: false, disabled: false, children: [],
   replaceChildren() { this.children = []; }, appendChild(child) { this.children.push(child); },
   removeAttribute(key) { delete this[key]; }, addEventListener(event, fn) { this[event] = fn; } };
 }
 const root = { querySelector: selector => elements[selector.match(/data-ssi-(\w+)/)[1]], querySelectorAll: () => [] };
 const fetch = async (url, options) => {
  calls.push({url, options});
  const reply = replies.shift();
  assert.ok(reply, 'unexpected fetch');
  return {ok: reply.ok !== false, json: async () => reply.data};
 };
 const window = {fetch, bloclabsSsiProfile: {restBase: 'https://example.test/api/', nonce: 'session-nonce', tokenHeader: 'X-Page-Token', token: 'page-token', schemes: ['openid4vp', 'https'], resumeParam: 'bloclabs_ssi_attempt', i18n: {waiting: 'waiting', resuming: 'resuming', unknown: 'unknown', error: 'error'}},
  setTimeout: fn => timers.push(fn), location: {reload: () => reloaded++, href: options.href},
  history: {state: null, replaceState(state, title, url) { replaced.push(url); }},
  qrcode: () => ({ addData() {}, make() {throw Error('oversize');} })};
 vm.runInNewContext(source, {window, fetch, URL, document: {getElementById: () => root, createElement: () => ({})}});
 return {elements, timers, calls, replaced, reloads: () => reloaded};
}
const flush = () => new Promise(setImmediate);

test('profile links through wallet flow with session nonce and purpose; completion reloads the profile', async () => {
 const h = harness([{data: {wallet_url: 'openid4vp://authorize?request=example', attempt: 'abc'}}, {data: {status: 'verified'}}, {data: {linked: true}}]);
 await h.elements.start.click();
 assert.equal(JSON.parse(h.calls[0].options.body).purpose, 'link');
 assert.equal(h.calls[0].options.headers['X-WP-Nonce'], 'session-nonce');
 assert.equal(h.calls[0].options.headers['X-Page-Token'], 'page-token');
 assert.equal(h.elements.open.hidden, false, 'QR overflow keeps the wallet link');
 await h.timers.shift()();
 await flush();
 assert.equal(h.calls[2].url, 'https://example.test/api/complete');
 assert.equal(h.reloads(), 1);
 assert.equal(h.elements.open.hidden, true);
});

test('cancellation discards stale responses and removes the wallet offer', async () => {
 const h = harness([{data: {wallet_url: 'openid4vp://authorize', attempt: 'abc'}}]);
 const started = h.elements.start.click();
 h.elements.cancel.click();
 await started;
 assert.equal(h.elements.open.href, undefined);
 assert.equal(h.timers.length, 0);
 assert.equal(h.elements.start.disabled, false);
});

test('unsafe wallet URL is refused before rendering or polling', async () => {
 const h = harness([{data: {wallet_url: 'javascript:alert(1)', attempt: 'abc'}}]);
 await h.elements.start.click();
 assert.equal(h.elements.open.href, undefined);
 assert.equal(h.timers.length, 0);
 assert.equal(h.elements.status.textContent, 'error');
});

test('a refused duplicate shows the server message without changing the session', async () => {
 const h = harness([{data: {wallet_url: 'openid4vp://authorize', attempt: 'abc'}}, {data: {status: 'verified'}}, {ok: false, data: {code: 'bloclabs_ssi_already_linked', message: 'Already linked to an account.'}}]);
 await h.elements.start.click();
 await h.timers.shift()();
 await flush();
 assert.equal(h.reloads(), 0);
 assert.equal(h.elements.status.textContent, 'Already linked to an account.');
 assert.equal(h.elements.start.disabled, false);
 assert.equal(h.elements.cancel.disabled, false);
});

// --- The same-device return (issue #96) --------------------------------------------------------

const ATTEMPT = 'c'.repeat(32);
const PROFILE = 'https://example.test/wp-admin/profile.php';

test('finishes the link a wallet on this device sent the holder back to, then shows the profile', async () => {
 const h = harness([{data: {status: 'verified'}}, {data: {linked: true}}], {href: PROFILE + '?bloclabs_ssi_attempt=' + ATTEMPT + '&response_code=c0ffee'});
 assert.deepEqual(h.replaced, [PROFILE], 'the attempt and the verifier\'s response code leave the address at once');
 assert.equal(h.elements.start.disabled, true);
 assert.equal(h.elements.panel.hidden, false);
 assert.equal(h.elements.open.hidden, true, 'no wallet link: the wallet already answered');
 assert.equal(h.elements.status.textContent, 'resuming');
 assert.equal(h.calls.length, 0, 'nothing is initiated: the attempt exists');
 assert.equal(h.timers.length, 1);
 await h.timers.shift()();
 await flush();
 assert.equal(h.calls[0].url, 'https://example.test/api/status/' + ATTEMPT);
 assert.equal(h.calls[0].options.headers['X-WP-Nonce'], 'session-nonce', 'the session and the binding cookie decide, as for every poll');
 assert.equal(h.calls[0].options.credentials, 'same-origin');
 assert.equal(h.calls[1].url, 'https://example.test/api/complete');
 assert.deepEqual(JSON.parse(h.calls[1].options.body), {attempt: ATTEMPT});
 assert.equal(h.reloads(), 1);
});

test('a link already made from another tab of this browser shows the profile; one this browser does not hold says so', async () => {
 const consumed = harness([{data: {status: 'consumed'}}], {href: PROFILE + '?bloclabs_ssi_attempt=' + ATTEMPT});
 await consumed.timers.shift()();
 await flush();
 assert.equal(consumed.reloads(), 1);
 assert.equal(consumed.calls.length, 1, 'no completion of a consumed attempt');

 const unknown = harness([{ok: false, data: {code: 'bloclabs_ssi_unknown', message: 'Unknown login request.'}}], {href: PROFILE + '?bloclabs_ssi_attempt=' + 'd'.repeat(32)});
 await unknown.timers.shift()();
 await flush();
 assert.equal(unknown.elements.status.textContent, 'unknown');
 assert.equal(unknown.elements.start.disabled, false);
 assert.equal(unknown.elements.panel.hidden, true);
 assert.equal(unknown.reloads(), 0);

 // An attempt this page started itself keeps the server's own message for a lost binding.
 const own = harness([{data: {wallet_url: 'openid4vp://authorize', attempt: 'abc'}}, {ok: false, data: {code: 'bloclabs_ssi_unknown', message: 'Unknown login request.'}}]);
 await own.elements.start.click();
 await own.timers.shift()();
 await flush();
 assert.equal(own.elements.status.textContent, 'Unknown login request.');
});

test('an address without a well-formed attempt starts nothing', async () => {
 for (const [href, replaced] of [[PROFILE, []], [PROFILE + '?bloclabs_ssi_attempt=' + 'C'.repeat(32), [PROFILE]], [undefined, []]]) {
  const h = harness([], {href});
  assert.deepEqual(h.replaced, replaced, String(href));
  assert.equal(h.timers.length, 0, String(href));
  assert.equal(h.calls.length, 0, String(href));
  assert.equal(h.elements.start.disabled, false, String(href));
 }
});

