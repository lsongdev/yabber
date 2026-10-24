// yabber's UI conventions on top of the shared components: the management API
// returns plain JSON with an ETag, and writes send it back in If-Match so a
// concurrent edit fails with 412 instead of being lost.
import { html, useCallback } from './lib/html.js';
import { useResource as useShellResource } from './lib/hooks.js';
import { usePanel } from './lib/panel.js';
import { Badge as ShellBadge, Notice } from './lib/ui.js';

// useRequest returns request(method, path, { body, etag }) → { data, etag }.
export function useRequest() {
  const { api } = usePanel();
  return useCallback((method, path, { body, etag } = {}) =>
    api.request(method, path, { body, headers: etag ? { 'If-Match': etag } : {}, raw: true }), [api]);
}

// useResource loads a GET endpoint, optionally refreshing every interval
// milliseconds, and returns [{ data, etag, error, loading }, reload].
export function useResource(path, interval = 0) {
  const { api } = usePanel();
  const r = useShellResource(signal => api.request('GET', path, { signal, raw: true }), [path], { interval });
  return [{ data: r.data?.data, etag: r.data?.etag, error: r.error, loading: r.data === undefined && !r.error }, r.reload];
}

export function ErrorBox({ error }) {
  if (!error) return null;
  const hint = error.status === 412 ? ' Reload to see the current version, then make your change again.' : '';
  return html`<${Notice}>${error.message}${hint}<//>`;
}

const tones = { good: 'green', bad: 'red', warn: 'amber', neutral: 'gray' };

export function Badge({ tone = 'neutral', children }) {
  return html`<${ShellBadge} tone=${tones[tone] || tone}>${children}<//>`;
}

const units = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]];

// ago formats how long ago a time was, such as "3m ago".
export function ago(time) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(time)) / 1000));
  for (const [unit, size] of units) {
    if (seconds >= size) return `${Math.floor(seconds / size)}${unit} ago`;
  }
  return 'just now';
}

export const dateTime = time => new Date(time).toLocaleString();

export const daysUntil = time => Math.floor((new Date(time) - Date.now()) / 86400000);
