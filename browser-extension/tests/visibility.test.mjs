import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createVisibilityController, normalizeNavigation} from '../src/visibility.mjs';

const SESSION = 'a'.repeat(64);
const DIGEST = 'b'.repeat(64);
function signal() {
  const listeners = new Set();
  return {addListener: (listener) => listeners.add(listener), removeListener: (listener) => listeners.delete(listener), emit: (...args) => { for (const listener of listeners) listener(...args); }};
}
function fixture(options = {}) {
  const sent = [];
  const storageWrites = [];
  const port = {onMessage: signal(), onDisconnect: signal(), postMessage: (message) => sent.push(structuredClone(message)), disconnect() { this.onDisconnect.emit(); }};
  let connectCount = 0;
  let counter = 0;
  let currentTime = Date.parse('2026-10-27T12:00:00Z');
  const timers = new Map();
  const api = {
    runtime: {id: 'fixture-id', getManifest: () => ({version:'0.1.0'}), connectNative(name) { assert.equal(name, 'com.openems.browser'); connectCount++; if (options.hostMissing) throw Error('Fixture host is missing'); return port; }},
    tabs: {get: async (id) => { if (options.tabMissing) throw Error('Fixture tab is gone'); return {id, incognito: options.incognito ?? false}; }},
    storage: {local: {get: async () => options.saved ?? {}, set: async (value) => storageWrites.push(structuredClone(value))}},
  };
  const controller = createVisibilityController(api, {
    uuid: () => `00000000-0000-4000-8000-${String(++counter).padStart(12, '0')}`,
    now: () => currentTime,
    setTimer: (callback) => { const id = ++counter; timers.set(id, callback); return id; },
    clearTimer: (id) => timers.delete(id),
  });
  const ready = (patch = {}) => port.onMessage.emit({type:'ready', protocol:1, session_id:SESSION, policy_digest:DIGEST, enabled:true, url_mode:'origin', ...patch});
  const decide = (request, action, patch = {}) => port.onMessage.emit({type:'decision', protocol:1, request_id:request.request_id, session_id:SESSION, policy_digest:DIGEST, domain:request.domain, action, ...patch});
  return {controller, api, port, sent, ready, decide, storageWrites, timers, connectCount: () => connectCount, advance: (ms) => {currentTime += ms;}, expire: () => {const pending = [...timers.values()]; timers.clear(); pending.forEach((callback) => callback());}};
}
const navigation = (url = 'https://video.example.org/watch?token=SECRET#private', patch = {}) => ({url, tabId:4, frameId:0, timeStamp:Date.parse('2026-10-27T12:00:00Z'), documentLifecycle:'active', ...patch});
const turn = () => new Promise((resolve) => setImmediate(resolve));
async function enabledFixture(options = {}) { const f = fixture(options); await f.controller.initialize(); await f.controller.configure({enabled:true, includePath:false}); f.ready(); return f; }

test('disabled by default: no connection, lookup, observation or history write', async () => {
  const f = fixture(); await f.controller.initialize(); await f.controller.observe(navigation());
  assert.equal(f.connectCount(), 0); assert.deepEqual(f.sent, []); assert.deepEqual(f.storageWrites, []);
  assert.equal(f.controller.status().enabled, false);
});

test('explicit enable sends only hello until pairing; absent host collects nothing', async () => {
  const f = fixture(); await f.controller.initialize(); await f.controller.configure({enabled:true, includePath:false});
  await f.controller.observe(navigation()); assert.deepEqual(f.sent.map((message) => message.type), ['hello']);
  assert.equal(JSON.stringify(f.sent).includes('video.example.org'), false);
  const absent = fixture({hostMissing:true}); await absent.controller.initialize(); await absent.controller.configure({enabled:true, includePath:false}); await absent.controller.observe(navigation());
  assert.deepEqual(absent.sent, []); assert.equal(absent.controller.status().paired, false);
});

test('only booleans are stored and configure rejects malformed settings', async () => {
  const f = fixture(); await f.controller.initialize();
  await assert.rejects(() => f.controller.configure({enabled:'true', includePath:false}));
  await f.controller.configure({enabled:true, includePath:false});
  assert.deepEqual(f.storageWrites, [{enabled:true, includePath:false}]);
});

test('normalize excludes internal, credentialed, local and IP literal URLs', () => {
  for (const url of ['about:config','chrome://settings','file:///C:/secret','data:text/plain,secret','https://user:password@example.org/a','http://localhost/a','http://sub.localhost','http://127.0.0.1','http://10.2.3.4','http://[::1]/','https://intranet/','https://host.local/','https://host.internal/','https://8.8.8.8/']) {
    assert.equal(normalizeNavigation(navigation(url)), null, url);
  }
  assert.equal(normalizeNavigation(navigation(undefined, {frameId:3})), null);
  assert.equal(normalizeNavigation(navigation(undefined, {tabId:-1})), null);
  assert.equal(normalizeNavigation(navigation(undefined, {documentLifecycle:'prerender'})), null);
  assert.equal(normalizeNavigation(navigation(undefined, {documentLifecycle:'cached'})), null);
});

test('private or unavailable tabs do not produce policy lookups', async () => {
  for (const options of [{incognito:true}, {tabMissing:true}]) {
    const f = await enabledFixture(options); await f.controller.observe(navigation());
    assert.deepEqual(f.sent.map((message) => message.type), ['hello']);
  }
});

test('allow and block decisions never create navigation observations', async () => {
  for (const action of ['allow','block']) {
    const f = await enabledFixture(); const work = f.controller.observe(navigation()); await turn();
    const request = f.sent.at(-1); assert.equal(request.type, 'decide');
    assert.equal(request.domain, 'video.example.org'); assert.equal('url' in request, false);
    f.decide(request, action); await work;
    assert.deepEqual(f.sent.map((message) => message.type), ['hello','decide']);
    assert.equal(JSON.stringify(f.sent).includes('SECRET'), false);
  }
});

test('monitor defaults to origin only and strips query, fragment and path', async () => {
  const f = await enabledFixture(); const work = f.controller.observe(navigation()); await turn(); f.decide(f.sent.at(-1), 'monitor'); await work;
  const observation = f.sent.at(-1);
  assert.equal(observation.type, 'observation'); assert.equal(observation.url, 'https://video.example.org');
  assert.equal(observation.source, 'browser'); assert.equal(observation.kind, 'committed_navigation');
  assert.equal(observation.observed_at, '2026-10-27T12:00:00.000Z');
  assert.equal(JSON.stringify(f.sent).includes('SECRET'), false); assert.equal(JSON.stringify(f.storageWrites).includes('video.example.org'), false);
});

test('path inclusion requires independent local opt-in and native policy permission', async () => {
  for (const [localPath, nativePath, expected] of [[false,true,'https://video.example.org'], [true,false,'https://video.example.org'], [true,true,'https://video.example.org/watch']]) {
    const f = fixture(); await f.controller.initialize(); await f.controller.configure({enabled:true, includePath:localPath}); f.ready({url_mode:nativePath?'path':'origin'});
    const work = f.controller.observe(navigation()); await turn(); f.decide(f.sent.at(-1), 'monitor'); await work;
    assert.equal(f.sent.at(-1).url, expected); assert.equal(JSON.stringify(f.sent).includes('token='), false);
  }
});

test('opt out or native disconnect invalidates pending decisions and does not persist events', async () => {
  for (const action of ['disable','disconnect']) {
    const f = await enabledFixture(); const work = f.controller.observe(navigation()); await turn(); const request = f.sent.at(-1);
    if (action === 'disable') await f.controller.configure({enabled:false, includePath:false}); else f.port.onDisconnect.emit();
    f.decide(request, 'monitor'); await work;
    assert.equal(f.sent.filter((message) => message.type==='observation').length, 0);
    assert.equal(f.controller.status().pending, 0); assert.equal(f.controller.status().paired, false);
  }
});

test('malformed, mismatched or revised native policy cannot authorize collection', async () => {
  for (const patch of [{domain:'other.example.org'}, {policy_digest:'c'.repeat(64)}, {session_id:'d'.repeat(64)}, {action:'ALLOW'}, {request_id:'unknown'}]) {
    const f = await enabledFixture(); const work = f.controller.observe(navigation()); await turn(); const request = f.sent.at(-1);
    f.decide(request, 'monitor', patch); f.expire(); await work;
    assert.equal(f.sent.filter((message) => message.type==='observation').length, 0);
  }
});

test('invalid handshake stays inactive and cannot leak future hostname', async () => {
  for (const patch of [{session_id:'bad'}, {policy_digest:'bad'}, {enabled:false}, {protocol:2}, {url_mode:'full'}]) {
    const f = fixture(); await f.controller.initialize(); await f.controller.configure({enabled:true, includePath:false}); f.ready(patch); await f.controller.observe(navigation());
    assert.equal(f.controller.status().paired, false); assert.equal(f.sent.some((message) => message.type==='decide'), false);
  }
});

test('pending decisions are bounded and expire without a persisted retry queue', async () => {
  const f = await enabledFixture(); const work = Array.from({length:40}, (_, i) => f.controller.observe(navigation(`https://video${i}.example.org/secret`)));
  await turn(); assert.equal(f.controller.status().pending, 32); assert.equal(f.controller.status().dropped, 8);
  f.expire(); await Promise.all(work); assert.equal(f.controller.status().pending, 0);
  assert.equal(f.sent.filter((message) => message.type==='observation').length, 0);
  assert.deepEqual(f.storageWrites, [{enabled:true, includePath:false}]);
});

test('expired navigation and excessively long URLs are discarded', async () => {
  const f = await enabledFixture(); await f.controller.observe(navigation(undefined, {timeStamp:0}));
  await f.controller.observe(navigation(`https://video.example.org/${'a'.repeat(9000)}`));
  assert.deepEqual(f.sent.map((message) => message.type), ['hello']);
});

test('policy revision replaces pairing and invalidates an earlier authorization', async () => {
  const f = await enabledFixture(); const work = f.controller.observe(navigation()); await turn(); const request = f.sent.at(-1);
  f.ready({policy_digest:'c'.repeat(64)}); f.decide(request, 'monitor'); await work;
  assert.equal(f.sent.filter((message) => message.type==='observation').length, 0);
});

test('handshake timeout prevents a late ready reply from enabling collection', async () => {
  const f = fixture(); await f.controller.initialize(); await f.controller.configure({enabled:true, includePath:false});
  f.expire(); f.ready();
  assert.equal(f.controller.status().paired, false);
  assert.equal(f.sent.some((message) => message.type === 'decide'), false);
});

test('failed storage read keeps collection disabled', async () => {
  const f = fixture(); f.api.storage.local.get = async () => { throw Error('Storage unavailable'); };
  await f.controller.initialize(); await f.controller.observe(navigation());
  assert.equal(f.controller.status().enabled, false); assert.equal(f.controller.status().code, 'storage_error');
  assert.deepEqual(f.sent, []);
});

test('failed native write clears pairing and pending work', async () => {
  const f = await enabledFixture();
  f.port.postMessage = () => { throw Error('Native write unavailable'); };
  await f.controller.observe(navigation());
  assert.equal(f.controller.status().paired, false); assert.equal(f.controller.status().pending, 0);
});

test('failed opt-out storage write still stops collection in memory', async () => {
  const f = await enabledFixture();
  f.api.storage.local.set = async () => { throw Error('Storage unavailable'); };
  await assert.rejects(() => f.controller.configure({enabled:false, includePath:false}));
  await f.controller.observe(navigation());
  assert.equal(f.controller.status().enabled, false);
  assert.equal(f.controller.status().paired, false);
  assert.equal(f.connectCount(), 1);
});
