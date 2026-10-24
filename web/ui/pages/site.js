import { html, useEffect, useState } from '../lib/html.js';
import { Page, Field, Loading } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useRequest, ErrorBox } from '../yabber.js';

export const HANDLERS = {
  proxy: { field: 'upstream', label: 'Upstream', placeholder: 'http://127.0.0.1:3000 or unix:/run/app.sock' },
  files: { field: 'root', label: 'Directory', placeholder: '/srv/www' },
  respond: { field: 'body', label: 'Response body', placeholder: 'ok' },
  redirect: { field: 'to', label: 'Redirect to', placeholder: 'https://example.com/' },
};
const SITE_FIELDS = new Set(['name', 'hosts', 'listeners', 'allow_http', 'policies', 'routes', ...Object.keys(HANDLERS)]);

// describe summarizes what a site does.
export function describe(site) {
  if (site.routes?.length) return `${site.routes.length} route${site.routes.length > 1 ? 's' : ''}`;
  for (const kind of Object.keys(HANDLERS)) {
    if (site[kind]) return `${kind} ${site[kind][HANDLERS[kind].field] ?? ''}`;
  }
  const extensions = Object.keys(site).filter(key => !SITE_FIELDS.has(key));
  return extensions.join(', ') || '—';
}

export const siteID = site => site.name || site.hosts?.[0] || '';

// simpleForm returns form fields for a site the simple form can represent
// without losing anything, or null.
function simpleForm(site) {
  const keys = Object.keys(site).filter(key => site[key] !== undefined);
  const kinds = keys.filter(key => key in HANDLERS);
  const rest = keys.filter(key => !['name', 'hosts', 'allow_http'].includes(key) && !(key in HANDLERS));
  if (kinds.length > 1 || rest.length > 0) return null;
  const kind = kinds[0] ?? 'proxy';
  const value = site[kind] ?? {};
  const field = HANDLERS[kind].field;
  if (Object.keys(value).some(key => key !== field)) return null;
  return {
    name: site.name ?? '',
    hosts: (site.hosts ?? []).join(' '),
    allowHTTP: Boolean(site.allow_http),
    kind,
    target: value[field] ?? '',
  };
}

function siteFromForm(form) {
  const site = { hosts: form.hosts.split(/[\s,]+/).filter(Boolean) };
  if (form.name.trim()) site.name = form.name.trim();
  if (form.allowHTTP) site.allow_http = true;
  site[form.kind] = { [HANDLERS[form.kind].field]: form.target };
  return site;
}

const blankForm = { name: '', hosts: '', allowHTTP: false, kind: 'proxy', target: '' };

// SiteEditor creates a site (no id) or edits one. Sites the simple form
// cannot represent open as JSON, so nothing is dropped silently.
export default function SiteEditor({ params: { id } }) {
  const { href, navigate } = usePanel();
  const request = useRequest();
  const [loaded, setLoaded] = useState(id === undefined ? { site: {}, etag: '' } : null);
  const [form, setForm] = useState(blankForm);
  const [json, setJSON] = useState('');
  const [mode, setMode] = useState('form');
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (id === undefined) return;
    request('GET', `/sites/${encodeURIComponent(id)}`).then(({ data, etag }) => {
      setLoaded({ site: data, etag });
      const simple = simpleForm(data);
      setForm(simple ?? blankForm);
      setJSON(JSON.stringify(data, null, 2));
      setMode(simple ? 'form' : 'json');
    }, setError);
  }, [id]);

  const title = id === undefined ? 'Add site' : `Site ${id}`;
  const back = html`<a class="btn" href=${href('/sites')}>Back</a>`;
  if (!loaded) return html`<${Page} title=${title} actions=${back}>${error ? html`<${ErrorBox} error=${error} />` : html`<${Loading} />`}<//>`;

  const set = field => event => {
    const value = event.target.type === 'checkbox' ? event.target.checked : event.target.value;
    setForm({ ...form, [field]: value });
  };

  function switchMode(next) {
    setError(null);
    if (next === 'json') {
      setJSON(JSON.stringify(siteFromForm(form), null, 2));
      setMode('json');
      return;
    }
    try {
      const simple = simpleForm(JSON.parse(json));
      if (!simple) throw new Error('This site uses settings the form cannot show; keep editing it as JSON.');
      setForm(simple);
      setMode('form');
    } catch (e) {
      setError(e);
    }
  }

  async function save(event) {
    event.preventDefault();
    setError(null);
    let site;
    try {
      site = mode === 'form' ? siteFromForm(form) : JSON.parse(json);
    } catch (e) {
      setError(new Error(`Invalid JSON: ${e.message}`));
      return;
    }
    setSaving(true);
    try {
      if (id === undefined) {
        await request('POST', '/sites', { body: site });
      } else {
        await request('PUT', `/sites/${encodeURIComponent(id)}`, { body: site, etag: loaded.etag });
      }
      navigate('/sites');
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  }

  const handler = HANDLERS[form.kind];
  return html`<${Page} title=${title} actions=${html`
      <span class="segmented">
        <button type="button" class=${`btn ${mode === 'form' ? 'active' : ''}`} onClick=${() => switchMode('form')}>Form</button>
        <button type="button" class=${`btn ${mode === 'json' ? 'active' : ''}`} onClick=${() => switchMode('json')}>JSON</button>
      </span>
      ${back}`}>
    <form class="form card" onSubmit=${save}>
      ${mode === 'form' ? html`
        <${Field} label="Hosts" required hint="Separate with spaces. Use *.example.com for one level of subdomains, or * for anything else.">
          <input class="input" value=${form.hosts} onInput=${set('hosts')} placeholder="example.com www.example.com" required />
        <//>
        <div class="form-grid">
          <${Field} label="Handler">
            <select class="input" value=${form.kind} onChange=${set('kind')}>
              ${Object.keys(HANDLERS).map(kind => html`<option value=${kind}>${kind}</option>`)}
            </select>
          <//>
          <${Field} label="Name" hint="Optional; defaults to the first host">
            <input class="input" value=${form.name} onInput=${set('name')} disabled=${id !== undefined} />
          <//>
        </div>
        <${Field} label=${handler.label} required=${form.kind !== 'respond'}>
          ${form.kind === 'respond'
            ? html`<textarea class="input" rows="4" value=${form.target} onInput=${set('target')} placeholder=${handler.placeholder}></textarea>`
            : html`<input class="input" value=${form.target} onInput=${set('target')} placeholder=${handler.placeholder} required />`}
        <//>
        <label class="check">
          <input type="checkbox" checked=${form.allowHTTP} onChange=${set('allowHTTP')} />
          Serve plain HTTP instead of redirecting to HTTPS
        </label>` : html`
        <${Field} label="Site configuration (JSON)" hint="Same fields as the YAML configuration: routes, policies, listeners, proxy options and more.">
          <textarea class="input code" rows="18" spellcheck="false" value=${json} onInput=${e => setJSON(e.target.value)}></textarea>
        <//>`}
      <${ErrorBox} error=${error} />
      <div class="form-actions">
        <button class="btn btn-primary" type="submit" disabled=${saving}>${saving ? 'Saving…' : 'Save'}</button>
        <a class="btn" href=${href('/sites')}>Cancel</a>
      </div>
    </form>
  <//>`;
}
