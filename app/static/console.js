"use strict";

// API values are rendered only as text; identifiers never enter HTML or script.
const element = (id) => document.getElementById(id);
let csrfToken = null;
let sessionRole = null;
let toastTimer;
let conditionSequence = 0;
const loadingPanels = new Set();

function node(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = String(text);
  if (className) result.className = className;
  return result;
}

function button(text, action, className = "ghost") {
  const result = node("button", text, className);
  result.type = "button";
  result.addEventListener("click", action);
  return result;
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

function toast(message, isError = false) {
  clearTimeout(toastTimer);
  const target = element("toast");
  target.textContent = message;
  target.classList.toggle("error", isError);
  target.hidden = false;
  toastTimer = setTimeout(() => { target.hidden = true; }, 7000);
}

function showError(id, message) {
  element(id).textContent = message;
  element(id).hidden = !message;
}

function updateSession(session) {
  csrfToken = session ? session.csrf_token : null;
  sessionRole = session ? session.role : null;
  element("session-user").textContent = session ? `${session.username} (${session.role})` : "";
  element("logout-btn").hidden = !session;
  const readOnly = sessionRole !== "admin";
  element("profile-fields").disabled = readOnly;
  element("rule-fields").disabled = readOnly;
}

function showLogin() {
  updateSession(null);
  const dialog = element("login-dialog");
  if (!dialog.open) dialog.showModal();
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const method = (options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method) && csrfToken) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetch(path, {
      ...options, headers, credentials: "same-origin", signal: controller.signal,
    });
    if (response.status === 401) {
      showLogin();
      throw new Error("Session expired. Sign in again.");
    }
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      const detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
      throw new Error(detail || `Request failed (${response.status})`);
    }
    return response.status === 204 ? null : await response.json();
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error("Request timed out. Try again.");
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function jsonRequest(body) {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}

function dateText(value) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function relativeTime(value) {
  if (!value) return "Never";
  const elapsed = Math.floor((Date.now() - new Date(value).getTime()) / 1000);
  if (!Number.isFinite(elapsed)) return String(value);
  if (elapsed < 60) return "Just now";
  if (elapsed < 3600) return `${Math.floor(elapsed / 60)} min ago`;
  return `${Math.floor(elapsed / 3600)} h ago`;
}

function policyState(endpoint) {
  if (endpoint.last_error) return "Error";
  const desired = endpoint.desired_profile;
  if (!desired) return "No policy";
  return endpoint.applied_vdom === desired.vdom &&
    endpoint.config_version === desired.version &&
    endpoint.applied_digest === desired.digest && Boolean(endpoint.last_applied)
    ? "Applied" : "Pending";
}

function emptyRow(columns, message) {
  const row = node("tr");
  const cell = node("td", message, "muted");
  cell.colSpan = columns;
  row.append(cell);
  return row;
}

function textRow(values) {
  const row = node("tr");
  values.forEach((value) => row.append(node("td", value ?? "–")));
  return row;
}

async function loadPanel(name, loader) {
  if (loadingPanels.has(name)) return;
  loadingPanels.add(name);
  element(`${name}-loading`).hidden = false;
  try {
    await loader();
    element(`${name}-error`).hidden = true;
  } catch (error) {
    const target = element(`${name}-error`);
    target.replaceChildren(node("span", `Could not refresh. Displayed data may be outdated. ${errorMessage(error)}`),
      button(`Retry ${name}`, () => loadPanel(name, loader)));
    target.hidden = false;
  } finally {
    element(`${name}-loading`).hidden = true;
    loadingPanels.delete(name);
  }
}

async function renderEndpoints() {
  const [endpoints, count] = await Promise.all([
    api("/api/v1/endpoints/index"), api("/api/v1/endpoints/count"),
  ]);
  const rows = endpoints.map((endpoint) => {
    const row = node("tr");
    const idCell = node("td");
    idCell.append(button(endpoint.devid, () => showDetail(endpoint.devid)));
    row.append(idCell, node("td", endpoint.hostname || "–"), node("td", endpoint.os || "–"),
      node("td", endpoint.online ? "Online" : "Offline"), node("td", policyState(endpoint)),
      node("td", relativeTime(endpoint.last_seen)), node("td", (endpoint.host_tags || []).join(", ")));
    return row;
  });
  element("endpoints").replaceChildren(...(rows.length ? rows : [emptyRow(7, "No endpoints registered")]));
  element("count").textContent = count.count;
}

async function showDetail(deviceId) {
  try {
    const endpoint = await api(`/api/v1/endpoints/detail?devid=${encodeURIComponent(deviceId)}`);
    const desired = endpoint.desired_profile;
    const list = node("dl", undefined, "kv");
    const values = [
      ["Device ID", endpoint.devid], ["Hostname", endpoint.hostname], ["OS", endpoint.os],
      ["Connection", endpoint.online ? "Online" : "Offline"], ["Policy status", policyState(endpoint)],
      ["Assigned group", endpoint.effective_vdom || endpoint.vdom],
      ["Desired policy", desired ? `${desired.vdom} · v${desired.version} · ${desired.digest}` : "None"],
      ["Confirmed applied policy", endpoint.last_applied ? `${endpoint.applied_vdom} · v${endpoint.config_version} · ${endpoint.applied_digest}` : "No successful confirmation"],
      ["Last application", dateText(endpoint.last_applied)],
      ["Last application error", endpoint.last_error ? (typeof endpoint.last_error === "string" ? endpoint.last_error : JSON.stringify(endpoint.last_error)) : "None"],
      ["Last seen", dateText(endpoint.last_seen)], ["Host tags", (endpoint.host_tags || []).join(", ") || "None"],
    ];
    values.forEach(([label, value]) => list.append(node("dt", label), node("dd", value || "–")));
    element("detail").replaceChildren(list);
    if (!element("endpoint-dialog").open) element("endpoint-dialog").showModal();
  } catch (error) { toast(errorMessage(error), true); }
}

function addCondition(condition = { field: "os", op: "contains", value: "Windows" }) {
  const identifier = ++conditionSequence;
  const container = node("div", undefined, "condition");
  const select = (suffix, label, values, current) => {
    const input = node("select");
    input.id = `condition-${identifier}-${suffix}`;
    input.dataset.part = suffix;
    const labelNode = node("label", label);
    labelNode.htmlFor = input.id;
    const options = values.includes(current) ? values : [...values, current];
    options.forEach((value) => {
      const option = node("option", value);
      option.value = value;
      input.append(option);
    });
    input.value = current;
    container.append(labelNode, input);
  };
  select("field", "Field", ["os", "hostname", "fctver", "vdom", "host_tag"], condition.field);
  select("op", "Operator", ["equals", "contains", "in", "has_tag"], condition.op);
  const input = node("input");
  input.id = `condition-${identifier}-value`;
  input.dataset.part = "value";
  input.value = JSON.stringify(condition.value);
  input.required = true;
  const label = node("label", "Value (JSON)");
  label.htmlFor = input.id;
  container.append(label, input, button("Remove condition", () => container.remove()));
  element("conditions").append(container);
}

function editRule(rule) {
  element("r-id").value = rule.id;
  element("r-vdom").value = rule.target_vdom;
  element("r-prio").value = rule.priority;
  element("r-enabled").checked = rule.enabled;
  element("conditions").replaceChildren();
  (rule.conditions || []).forEach(addCondition);
  showError("rule-error", "");
  element("r-id").focus();
}

async function renderRules() {
  const rules = await api("/api/v1/assignment_rules");
  const rows = rules.map((rule) => {
    const row = textRow([rule.priority, rule.id, rule.target_vdom,
      rule.conditions.map((condition) => `${condition.field} ${condition.op} ${JSON.stringify(condition.value)}`).join(" AND "),
      rule.enabled ? "Yes" : "No"]);
    const actions = node("td");
    const edit = button("Edit", () => editRule(rule));
    const remove = button("Delete", async () => {
      remove.disabled = true;
      try {
        await api(`/api/v1/assignment_rules/${encodeURIComponent(rule.id)}`, { method: "DELETE" });
        toast(`Rule ${rule.id} removed`);
        await Promise.all([loadRules(), loadAudit()]);
      } catch (error) { toast(errorMessage(error), true); }
      finally { remove.disabled = sessionRole !== "admin"; }
    });
    edit.disabled = remove.disabled = sessionRole !== "admin";
    actions.append(edit, remove);
    row.append(actions);
    return row;
  });
  element("rules").replaceChildren(...(rows.length ? rows : [emptyRow(6, "No rules")]));
}

async function renderProfiles() {
  const profiles = await api("/api/v1/profiles");
  const rows = profiles.map((profile) => textRow([profile.vdom, `v${profile.version}`,
    JSON.stringify(profile.body), dateText(profile.updated_at)]));
  element("profiles").replaceChildren(...(rows.length ? rows : [emptyRow(4, "No profiles")]));
}

async function renderAudit() {
  const audit = await api("/api/v1/audit?limit=50");
  const rows = audit.map((entry) => textRow([dateText(entry.ts), entry.actor, entry.action,
    entry.target || "–", JSON.stringify(entry.metadata || {})]));
  element("audit").replaceChildren(...(rows.length ? rows : [emptyRow(5, "No activity yet")]));
}

const loadEndpoints = () => loadPanel("endpoints", renderEndpoints);
const loadRules = () => loadPanel("rules", renderRules);
const loadProfiles = () => loadPanel("profiles", renderProfiles);
const loadAudit = () => loadPanel("audit", renderAudit);

async function refreshAll() {
  if (!csrfToken) return;
  element("refresh-btn").disabled = true;
  try { await Promise.all([loadEndpoints(), loadRules(), loadProfiles(), loadAudit()]); }
  finally { element("refresh-btn").disabled = false; }
}

function validatePolicy(body) {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("Policy must be a JSON object.");
  for (const key of Object.keys(body)) {
    if (!["web_filter", "app_control"].includes(key)) throw new Error(`Unsupported policy section: ${key}`);
  }
  for (const key of ["web_filter", "app_control"]) {
    if (body[key] === undefined) continue;
    const section = body[key];
    if (!section || typeof section !== "object" || Array.isArray(section) ||
        Object.keys(section).some((name) => name !== "blocked") ||
        !Array.isArray(section.blocked) || section.blocked.some((value) => typeof value !== "string")) {
      throw new Error(`${key} must contain a blocked list of strings.`);
    }
  }
  const domains = body.web_filter?.blocked || [];
  for (const domain of domains) {
    if (domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(domain)) {
      throw new Error(`Invalid domain: ${domain}. Enter an explicit hostname such as example.com.`);
    }
  }
  for (const process of body.app_control?.blocked || []) {
    if (!process.trim() || process !== process.trim() || /[\\/:*?"<>|\x00-\x1f]/.test(process)) {
      throw new Error(`Invalid process name: ${process}. Use a filename without a path.`);
    }
  }
  return body;
}

function policyBody() {
  const lines = (id) => element(id).value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  return validatePolicy(element("p-advanced").checked ? JSON.parse(element("p-body").value) : {
    web_filter: { blocked: [...new Set(lines("p-domains").map((value) => value.toLowerCase()))] },
    app_control: { blocked: [...new Set(lines("p-apps"))] },
  });
}

function updatePolicySummary() {
  try {
    const body = policyBody();
    element("profile-summary").textContent = `Publish to ${element("p-vdom").value.trim() || "…"}: ${body.web_filter?.blocked.length || 0} domain(s), ${body.app_control?.blocked.length || 0} process(es). Endpoints remain pending until the agent confirms application.`;
  } catch (error) { element("profile-summary").textContent = errorMessage(error); }
}

element("profile-form").addEventListener("input", updatePolicySummary);
element("profile-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("profile-error", "");
  const submit = element("publish-btn");
  submit.disabled = true;
  try {
    const vdom = element("p-vdom").value.trim();
    if (!vdom) throw new Error("Target group is required.");
    const body = policyBody();
    const result = await api(`/api/v1/profiles/${encodeURIComponent(vdom)}`, jsonRequest(body));
    toast(`Profile ${vdom} v${result.version} published; waiting for endpoint confirmation.`);
    await Promise.all([loadProfiles(), loadAudit(), loadEndpoints()]);
  } catch (error) { showError("profile-error", errorMessage(error)); }
  finally { submit.disabled = false; }
});

element("rule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("rule-error", "");
  const submit = element("save-rule-btn");
  submit.disabled = true;
  try {
    const priority = Number(element("r-prio").value);
    if (!Number.isSafeInteger(priority)) throw new Error("Priority must be an integer.");
    const conditions = [...element("conditions").children].map((container) => {
      const field = container.querySelector('[data-part="field"]').value;
      const op = container.querySelector('[data-part="op"]').value;
      const value = JSON.parse(container.querySelector('[data-part="value"]').value);
      if (op === "in" ? !Array.isArray(value) || value.some((item) => typeof item !== "string") : typeof value !== "string") {
        throw new Error("Use a JSON string for equals/contains/has_tag and a JSON list of strings for in.");
      }
      if ((field === "host_tag") !== (op === "has_tag")) throw new Error("Use host_tag with has_tag; other fields use equals, contains or in.");
      return { field, op, value };
    });
    const rule = { id: element("r-id").value.trim(), target_vdom: element("r-vdom").value.trim(),
      priority, enabled: element("r-enabled").checked, conditions };
    if (!rule.id || !rule.target_vdom) throw new Error("Rule ID and target group are required.");
    await api("/api/v1/assignment_rules", jsonRequest(rule));
    toast(`Rule ${rule.id} saved`);
    await Promise.all([loadRules(), loadAudit(), loadEndpoints()]);
  } catch (error) { showError("rule-error", errorMessage(error)); }
  finally { submit.disabled = false; }
});

element("new-rule-btn").addEventListener("click", () => {
  editRule({ id: "", target_vdom: "Strict", priority: 100, enabled: true, conditions: [{ field: "os", op: "contains", value: "Windows" }] });
});
element("add-condition-btn").addEventListener("click", () => addCondition());
element("close-detail-btn").addEventListener("click", () => element("endpoint-dialog").close());
element("refresh-btn").addEventListener("click", refreshAll);
element("login-dialog").addEventListener("cancel", (event) => event.preventDefault());
element("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  showError("login-error", "");
  element("login-btn").disabled = true;
  try {
    await api("/api/v1/auth/login", jsonRequest({ username: element("l-user").value, password: element("l-pass").value }));
    const session = await api("/api/v1/auth/session");
    updateSession(session);
    element("l-pass").value = "";
    element("login-dialog").close();
    await refreshAll();
  } catch (error) { showError("login-error", errorMessage(error)); }
  finally { element("login-btn").disabled = false; }
});
element("logout-btn").addEventListener("click", async () => {
  element("logout-btn").disabled = true;
  try {
    await api("/api/v1/auth/logout", { method: "POST" });
    ["endpoints", "rules", "profiles", "audit", "detail"].forEach((id) => element(id).replaceChildren());
    element("count").textContent = "–";
    showLogin();
  } catch (error) { toast(errorMessage(error), true); }
  finally { element("logout-btn").disabled = false; }
});

function connectionStatus() {
  const target = element("connection-status");
  target.hidden = navigator.onLine;
  target.textContent = "Offline. Displayed data may be outdated; endpoint enforcement continues using the last valid policy.";
  if (navigator.onLine && csrfToken) refreshAll();
}
window.addEventListener("offline", connectionStatus);
window.addEventListener("online", connectionStatus);

async function start() {
  addCondition();
  updatePolicySummary();
  updateSession(null);
  connectionStatus();
  try {
    updateSession(await api("/api/v1/auth/session"));
    await refreshAll();
  } catch (error) {
    showLogin();
    showError("login-error", errorMessage(error));
    ["endpoints", "rules", "profiles", "audit"].forEach((name) => { element(`${name}-loading`).hidden = true; });
  }
}
setInterval(() => { if (csrfToken && !document.hidden) loadEndpoints(); }, 5000);
start();
