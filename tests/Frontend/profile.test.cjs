const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.resolve(__dirname, '../../assets/js/profile.js'), 'utf8');

function harness(replies) {
 const timers = [], calls = [], elements = {};
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
 const window = {fetch, bloclabsSsiProfile: {restBase: 'https://example.test/api/', nonce: 'session-nonce', tokenHeader: 'X-Page-Token', token: 'page-token', schemes: ['openid4vp', 'https'], i18n: {waiting: 'waiting', error: 'error'}},
  setTimeout: fn => timers.push(fn), location: {reload: () => reloaded++},
  qrcode: () => ({ addData() {}, make() {throw Error('oversize');} })};
 vm.runInNewContext(source, {window, fetch, URL, document: {getElementById: () => root, createElement: () => ({})}});
 return {elements, timers, calls, reloads: () => reloaded};
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
