const HEX = /^[a-f0-9]{64}$/;
const MAX_PENDING = 32;

export function normalizeNavigation(details) {
  if (!details || details.frameId !== 0 || !Number.isInteger(details.tabId) || details.tabId < 0 || (details.documentLifecycle && details.documentLifecycle !== 'active') || typeof details.url !== 'string' || details.url.length > 8192) return null;
  try {
    const url = new URL(details.url);
    const domain = url.hostname.toLowerCase().replace(/\.$/, '');
    if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || !domain.includes('.') || domain.includes(':') || /^\d+(\.\d+){3}$/.test(domain) || /(^|\.)(localhost|local|internal|test|invalid)$/.test(domain) || !/^[a-z0-9.-]+$/.test(domain)) return null;
    return {domain, origin:url.origin, pathname:url.pathname};
  } catch { return null; }
}

export function createVisibilityController(api, dependencies = {}) {
  const now = dependencies.now ?? Date.now;
  const uuid = dependencies.uuid ?? (() => crypto.randomUUID());
  const setTimer = dependencies.setTimer ?? setTimeout;
  const clearTimer = dependencies.clearTimer ?? clearTimeout;
  let settings = {enabled:false, includePath:false};
  let port = null;
  let pairing = null;
  let generation = 0;
  let dropped = 0;
  let code = 'disabled';
  let handshakeTimer = null;
  const pending = new Map();
  function invalidate(nextCode) {
    pairing = null; generation++; code = nextCode;
    if (handshakeTimer !== null) clearTimer(handshakeTimer);
    handshakeTimer = null;
    for (const item of pending.values()) { clearTimer(item.timer); item.resolve(); }
    pending.clear();
  }
  function disconnect(nextCode) {
    const old = port; port = null; invalidate(nextCode);
    try { old?.disconnect(); } catch { code = nextCode; }
  }
  function send(message) {
    try { if (!port) return false; port.postMessage(message); return true; }
    catch { disconnect('host_unavailable'); return false; }
  }
  function receive(message, source) {
    if (source !== port || !settings.enabled) return;
    if (message?.type === 'ready') {
      invalidate('invalid_handshake');
      if (message.protocol !== 1 || !HEX.test(message.session_id ?? '') || !HEX.test(message.policy_digest ?? '') || message.enabled !== true || !['origin','path'].includes(message.url_mode)) return;
      pairing = {session_id:message.session_id, policy_digest:message.policy_digest, url_mode:message.url_mode};
      code = 'paired'; return;
    }
    if (message?.type !== 'decision' || !pairing) { invalidate('invalid_reply'); return; }
    const item = pending.get(message.request_id);
    if (!item || message.protocol !== 1 || message.domain !== item.domain || message.session_id !== pairing.session_id || message.policy_digest !== pairing.policy_digest || !['allow','block','monitor'].includes(message.action)) { invalidate('invalid_reply'); return; }
    pending.delete(message.request_id); clearTimer(item.timer);
    if (message.action === 'monitor' && item.generation === generation && settings.enabled) {
      send({type:'observation', protocol:1, request_id:message.request_id, observation_id:uuid(), session_id:pairing.session_id, policy_digest:pairing.policy_digest, domain:item.domain, observed_at:new Date(item.time).toISOString(), source:'browser', kind:'committed_navigation', url:item.url});
    }
    item.resolve();
  }
  function connect() {
    if (!settings.enabled || port) return;
    try {
      const connected = api.runtime.connectNative('com.openems.browser'); port = connected; code = 'pairing';
      connected.onMessage.addListener((message) => receive(message, connected));
      connected.onDisconnect.addListener(() => { if (port === connected) { port = null; invalidate('host_unavailable'); } });
      handshakeTimer = setTimer(() => disconnect('handshake_timeout'), 5000);
      send({type:'hello', protocol:1, version:api.runtime.getManifest().version});
    } catch { port = null; invalidate('host_unavailable'); }
  }
  return {
    async initialize() {
      try { const saved = await api.storage.local.get(['enabled','includePath']); settings = {enabled:saved.enabled === true, includePath:saved.includePath === true}; if (settings.enabled) connect(); }
      catch { settings = {enabled:false, includePath:false}; code = 'storage_error'; }
    },
    async configure(value) {
      if (typeof value?.enabled !== 'boolean' || typeof value?.includePath !== 'boolean') throw Error('Invalid visibility settings');
      const next = {enabled:value.enabled, includePath:value.includePath};
      settings = {enabled:false, includePath:false}; disconnect(next.enabled ? 'saving' : 'disabled');
      try { await api.storage.local.set(next); } catch { settings = {enabled:false, includePath:false}; disconnect('storage_error'); throw Error('Could not save visibility settings'); }
      disconnect(next.enabled ? 'inactive' : 'disabled'); settings = next;
      if (settings.enabled) connect();
    },
    status() { return {...settings, paired:pairing !== null, pending:pending.size, dropped, code}; },
    async observe(details) {
      if (!settings.enabled) return;
      const navigation = normalizeNavigation(details);
      const time = details?.timeStamp;
      if (!navigation || !Number.isFinite(time) || Math.abs(now() - time) > 30000) return;
      const currentGeneration = generation;
      try { const tab = await api.tabs.get(details.tabId); if (tab.incognito) return; } catch { return; }
      if (!settings.enabled || generation !== currentGeneration) return;
      if (!port) { connect(); return; }
      if (!pairing) return;
      if (pending.size >= MAX_PENDING) { dropped++; return; }
      const request_id = uuid();
      const url = navigation.origin + (settings.includePath && pairing.url_mode === 'path' ? navigation.pathname : '');
      await new Promise((resolve) => {
        const timer = setTimer(() => { pending.delete(request_id); dropped++; resolve(); }, 5000);
        pending.set(request_id, {resolve, timer, generation, domain:navigation.domain, url, time});
        if (!send({type:'decide', protocol:1, request_id, session_id:pairing.session_id, policy_digest:pairing.policy_digest, domain:navigation.domain})) { clearTimer(timer); pending.delete(request_id); resolve(); }
      });
    },
  };
}
