// Form state is the complete document, not a projection of visible fields.
// Every update below copies the original object and patches only its target.
export const HANDLERS = {
  proxy: { label: 'Reverse proxy', field: 'upstream', placeholder: 'http://127.0.0.1:3000 or unix:/run/app.sock' },
  files: { label: 'Static files', field: 'root', placeholder: '/srv/www' },
  respond: { label: 'Fixed response', field: 'body', placeholder: 'ok' },
  redirect: { label: 'Redirect', field: 'to', placeholder: 'https://example.com/' },
};
export const isBuiltin = key => Object.hasOwn(HANDLERS, key);
const SITE_FIELDS = new Set(['name', 'hosts', 'listeners', 'allow_http', 'policies', 'routes']);
const ROUTE_FIELDS = new Set(['name', 'method', 'path', 'policies']);
export const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const clone = value => JSON.parse(JSON.stringify(value));
export const siteID = site => site.name || site.hosts?.[0] || '';

export function handlerKeys(subject, route = false) {
  const fields = route ? ROUTE_FIELDS : SITE_FIELDS;
  return Object.keys(subject).filter(key => !fields.has(key));
}
export function handlerConfig(subject, kind) {
  const value = subject[kind];
  return typeof value === 'string' && isBuiltin(kind) ? { [HANDLERS[kind].field]: value } : value ?? {};
}
export function setField(subject, key, value) {
  const next = { ...subject };
  if (value === '' || value === undefined) delete next[key];
  else next[key] = value;
  return next;
}
export function changeHandler(subject, kind, route = false) {
  const next = { ...subject };
  for (const key of handlerKeys(subject, route)) delete next[key];
  return { ...next, [kind]: { [HANDLERS[kind]?.field ?? '']: '' } };
}
export function updateHandler(subject, kind, key, value) {
  return { ...subject, [kind]: setField(handlerConfig(subject, kind), key, value) };
}
export function updateItem(subject, key, index, value) {
  return { ...subject, [key]: subject[key].map((item, i) => i === index ? value : item) };
}
export function addRoute(site) {
  if (Array.isArray(site.routes)) return { ...site, routes: [...site.routes, { path: site.routes.length ? '/api/' : '/', proxy: { upstream: '' } }] };
  // Convert shorthand only when adding another route; keep the original handler.
  const next = { ...site };
  const route = {};
  for (const key of handlerKeys(site)) { route[key] = site[key]; delete next[key]; }
  next.routes = [...(Object.keys(route).length ? [route] : []), { path: Object.keys(route).length ? '/api/' : '/', proxy: { upstream: '' } }];
  return next;
}

function object(value, label) {
  if (!isObject(value)) throw new Error(`${label} must be a JSON object. Keep this configuration in JSON mode until corrected.`);
}
function list(value, label, items) {
  if (value === undefined || value === null) return;
  if (!Array.isArray(value)) throw new Error(`${label} must be an array.`);
  value.forEach((item, index) => items(item, `${label} ${index + 1}`));
}
function strings(value, label) {
  list(value, label, (item, name) => { if (typeof item !== 'string') throw new Error(`${name} must be text.`); });
}
function handler(subject, route) {
  for (const key of handlerKeys(subject, route)) {
    if (!isBuiltin(key)) continue; // Extensions are preserved without interpreting them.
    const value = subject[key];
    if (typeof value !== 'string') object(value, key);
    if (key === 'respond' && isObject(value) && value.headers != null) object(value.headers, 'Response headers');
  }
}
export function prepareSite(value) {
  object(value, 'Site');
  strings(value.hosts, 'Hosts'); strings(value.listeners, 'Listeners'); strings(value.policies, 'Policies');
  handler(value, false);
  list(value.routes, 'Routes', (route, label) => {
    object(route, label); strings(route.policies, 'Route policies'); handler(route, true);
  });
  return clone(value);
}
export function prepareConfig(value) {
  object(value, 'Configuration');
  for (const key of ['server', 'tls']) if (value[key] != null) object(value[key], key);
  if (value.tls?.acme != null) object(value.tls.acme, 'ACME settings');
  list(value.tls?.certificates, 'Certificates', object);
  list(value.listeners, 'Listeners', (listener, label) => {
    object(listener, label); strings(listener.trusted_proxies, 'Trusted proxies'); strings(listener.policies, 'Listener policies');
  });
  list(value.policies, 'Policies', (policy, label) => {
    object(policy, label);
    for (const key of ['request', 'rate_limit', 'concurrency']) if (policy[key] != null) object(policy[key], key);
  });
  // Sites and unknown top-level/nested fields are intentionally untouched.
  return clone(value);
}
export function describe(site) {
  if (site.routes?.length) {
    if (site.routes.length === 1) return describeHandler(site.routes[0], true);
    return `${site.routes.length} routes`;
  }
  return describeHandler(site, false);
}
function describeHandler(subject, route) {
  const kind = handlerKeys(subject, route)[0];
  if (!kind) return '—';
  return isBuiltin(kind) ? `${kind} ${handlerConfig(subject, kind)[HANDLERS[kind].field] ?? ''}` : kind;
}
