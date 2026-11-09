import assert from 'node:assert/strict';
import {test} from 'node:test';
import {classify, selectInitialContext} from '../deploy/browser_acceptance_contract.mjs';

const allowed = {
  case: 'allowed_https', target_url: 'https://example.org/', url: 'https://example.org/',
  document_uri: 'https://example.org/', status: 200, is_secure_context: true,
  title: 'Example Domain', text: 'This domain is for use in documentation examples without needing permission.', logo: false,
};
const blocked = {
  case: 'blocked_https', target_url: 'https://example.com/', url: 'https://example.com/',
  document_uri: 'https://example.com/', status: 200, is_secure_context: true,
  title: 'Acesso bloqueado', text: 'example.com', logo: true,
};

test('current allowed document is accepted with all origin and TLS guards', () => {
  assert.equal(classify(allowed).passed, true);
});

for (const [name, changes] of Object.entries({
  'wrong scheme': {url: 'http://example.org/'},
  'wrong origin': {url: 'https://attacker.invalid/'},
  'wrong target': {target_url: 'https://attacker.invalid/', url: 'https://attacker.invalid/'},
  'wrong port': {url: 'https://example.org:444/'},
  'bad status': {status: 503},
  'missing status': {status: undefined},
  'insecure context': {is_secure_context: false},
  'internal error': {document_uri: 'about:neterror'},
  'chrome error': {document_uri: 'chrome-error://chromewebdata/'},
  'wrong document origin': {document_uri: 'https://attacker.invalid/'},
  'wrong title': {title: 'Other document'},
  'wrong body': {text: 'Example Domain'},
  'missing body': {text: undefined},
  'block branding': {logo: true},
  'unknown case': {case: 'unknown'},
})) {
  test(`allowed document rejects ${name}`, () => assert.equal(classify({...allowed, ...changes}).passed, false));
}

test('blocked documents retain title, logo and domain checks', () => {
  assert.equal(classify(blocked).passed, true);
  for (const changes of [{logo: false}, {title: 'Example Domain'}, {text: 'Other domain'}, {status: 403}, {is_secure_context: false}]) {
    assert.equal(classify({...blocked, ...changes}).passed, false);
  }
});

test('HTTP upgrade is distinguished from a direct HTTP response', () => {
  const upgraded = classify({...blocked, case: 'blocked_http', target_url: 'http://example.com/'});
  assert.equal(upgraded.passed, true);
  assert.equal(upgraded.http_navigation_upgraded, true);
  assert.equal(upgraded.direct_http_validated, false);
  const direct = classify({...blocked, case: 'blocked_http', target_url: 'http://example.com/',
    url: 'http://example.com/', document_uri: 'http://example.com/', is_secure_context: false});
  assert.equal(direct.passed, true);
  assert.equal(direct.direct_http_validated, true);
});

const initial = {context: 'owned-context', url: 'about:blank', parent: null, children: []};
test('selects the single initial top-level blank context', () => {
  assert.equal(selectInitialContext({contexts: [initial]}), 'owned-context');
});
for (const [name, tree] of Object.entries({
  missing: {}, empty: {contexts: []}, multiple: {contexts: [initial, initial]},
  nonblank: {contexts: [{...initial, url: 'https://example.org/'}]},
  child: {contexts: [{...initial, parent: 'parent'}]},
  nested: {contexts: [{...initial, children: [initial]}]},
  truncated: {contexts: [{...initial, children: null}]},
  'missing id': {contexts: [{...initial, context: ''}]},
  'invalid id': {contexts: [{...initial, context: 1}]},
  'oversized id': {contexts: [{...initial, context: 'x'.repeat(1025)}]},
  'malformed list': {contexts: 'context'},
  oversized: {contexts: Array(513).fill(initial)},
})) {
  test(`context selection refuses ${name}`, () => assert.throws(() => selectInitialContext(tree)));
}
