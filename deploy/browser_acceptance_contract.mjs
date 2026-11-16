/** Pure observations for the disposable browser acceptance fixture. */
const targets = {
  blocked_https: 'https://example.com/',
  blocked_http: 'http://example.com/',
  allowed_https: 'https://example.org/',
};

export function classify(observation) {
  const value = observation ?? {};
  const failures = [];
  const expected = targets[value.case];
  let actual;
  let document;
  try { actual = new URL(value.url); } catch { failures.push('Invalid document URL'); }
  try { document = new URL(value.document_uri); } catch { failures.push('Invalid document URI'); }
  if (!expected || value.target_url !== expected) failures.push('Unknown case or target');
  const upgraded = value.case === 'blocked_http' && actual?.protocol === 'https:';
  const expectedUrl = expected && new URL(upgraded ? targets.blocked_https : expected);
  if (!actual || actual.origin !== expectedUrl?.origin || actual.username || actual.password) failures.push('Origin mismatch');
  if (!document || document.origin !== actual?.origin || !['http:', 'https:'].includes(document.protocol)) {
    failures.push('Internal browser error or document origin mismatch');
  }
  if (value.status !== 200) failures.push('Main document is not HTTP 200');
  if (actual?.protocol === 'https:' && value.is_secure_context !== true) failures.push('Insecure TLS context');
  if (value.case === 'blocked_http' || value.case === 'blocked_https') {
    const hasHostnameLine = typeof value.text === 'string' &&
      value.text.split(/\r?\n/).some(line => line.trim() === expectedUrl.hostname);
    if (value.title !== 'Acesso bloqueado' || value.logo !== true || !hasHostnameLine) {
      failures.push('RSM block page absent');
    }
  } else if (value.case === 'allowed_https') {
    if (value.logo !== false || value.title !== 'Example Domain' || typeof value.text !== 'string' ||
        !value.text.trimStart().startsWith('This domain is for use in documentation examples')) {
      failures.push('Allowed page absent');
    }
  }
  return {...value, passed: failures.length === 0, failures,
    http_navigation_upgraded: upgraded,
    direct_http_validated: value.case === 'blocked_http' && actual?.protocol === 'http:' && failures.length === 0};
}

export function selectInitialContext(tree) {
  if (!Array.isArray(tree?.contexts) || tree.contexts.length !== 1) {
    throw new Error('Exactly one initial top-level context is required');
  }
  const context = tree.contexts[0];
  if (!context || context.parent !== null || context.url !== 'about:blank' ||
      !Array.isArray(context.children) || context.children.length !== 0 ||
      typeof context.context !== 'string' || context.context.length < 1 || context.context.length > 1024) {
    throw new Error('Initial context is malformed, nested, truncated or already navigated');
  }
  return context.context;
}
