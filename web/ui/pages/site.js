import { html, useEffect, useRef, useState } from '../lib/html.js';
import { Page, Field, Notice, Loading } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useRequest, ErrorBox } from '../yabber.js';
import { prepareSite, addRoute, updateItem } from '../config-model.js';
import { HandlerFields, TextField, Toggle, StringList, SelectField } from '../components/config-fields.js';
export { HANDLERS, describe, siteID } from '../config-model.js';

const blankSite = () => ({ hosts: [], proxy: { upstream: '' } });

function RouteEditor({ route, index, count, onChange, onRemove, onMove }) {
  return html`<fieldset class="editor-card route-card">
    <legend>Route ${index + 1}${route.name ? ` · ${route.name}` : ''}</legend>
    <div class="editor-row-actions">
      <button class="button button-small" type="button" disabled=${index === 0} aria-label=${`Move route ${index + 1} up`} onClick=${() => onMove(-1)}>Move up</button>
      <button class="button button-small" type="button" disabled=${index === count - 1} aria-label=${`Move route ${index + 1} down`} onClick=${() => onMove(1)}>Move down</button>
      <button class="button button-small button-danger" type="button" aria-label=${`Remove route ${index + 1}`} onClick=${onRemove}>Remove route</button>
    </div>
    <div class="form-grid">
      <${SelectField} value=${route} name="method" label="HTTP method" placeholder="Any method" options=${['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','CONNECT','TRACE']} onChange=${onChange} />
      <${TextField} value=${route} name="path" label="Path pattern" placeholder="/" hint="/api/ matches a subtree; /health is exact; /{$} matches only the root." onChange=${onChange} />
    </div>
    <${HandlerFields} value=${route} route onChange=${onChange} />
    <details class="editor-details"><summary>Route name and policies</summary><div class="editor-details-body">
      <${TextField} value=${route} name="name" label="Route name" placeholder="Optional label for logs and metrics" onChange=${onChange} />
      <${StringList} value=${route} name="policies" label="Route policies" placeholder="Policy name" onChange=${onChange} />
    </div></details>
  </fieldset>`;
}

export default function SiteEditor({ params: { id } }) {
  const { href, navigate } = usePanel();
  const request = useRequest();
  const formElement = useRef(null);
  const [loaded, setLoaded] = useState(null);
  const [draft, setDraft] = useState(blankSite);
  const [json, setJSON] = useState('');
  const [mode, setMode] = useState('form');
  const [error, setError] = useState(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let active = true;
    setError(null);
    setLoaded(null);
    if (id === undefined) {
      setDraft(blankSite()); setMode('form'); setLoaded({ id, etag: '' });
      return;
    }
    request('GET', `/sites/${encodeURIComponent(id)}`).then(({ data, etag }) => {
      if (!active) return;
      setJSON(JSON.stringify(data, null, 2));
      try { setDraft(prepareSite(data)); setMode('form'); }
      catch (e) { setMode('json'); setError(e); }
      setLoaded({ id, etag });
    }, e => { if (active) setError(e); });
    return () => { active = false; };
  }, [id, request]);

  function switchMode(next) {
    if (next === mode) return;
    // An incomplete header row has not been committed to the document yet.
    const invalid = formElement.current?.querySelector('[aria-invalid="true"]');
    if (invalid) { invalid.reportValidity(); return; }
    setError(null);
    if (next === 'json') { setJSON(JSON.stringify(draft, null, 2)); setMode(next); return; }
    try { setDraft(prepareSite(JSON.parse(json))); setMode(next); }
    catch (e) { setError(e); }
  }

  async function save(event) {
    event.preventDefault();
    setError(null);
    let site;
    try {
      site = mode === 'form' ? draft : JSON.parse(json);
      if (mode === 'form' && !site.hosts?.length) throw new Error('Add at least one host.');
      if (mode === 'form' && Array.isArray(site.routes) && !site.routes.length) throw new Error('Add at least one route.');
    } catch (e) { setError(e); return; }
    setSaving(true);
    try {
      if (id === undefined) await request('POST', '/sites', { body: site });
      else await request('PUT', `/sites/${encodeURIComponent(id)}`, { body: site, etag: loaded.etag });
      navigate('/sites');
    } catch (e) { setError(e); }
    finally { setSaving(false); }
  }

  const title = id === undefined ? 'Add site' : `Site ${id}`;
  const back = html`<a class="button" href=${href('/sites')}>Back</a>`;
  if (!loaded || loaded.id !== id) return html`<${Page} title=${title} actions=${back}>${error ? html`<${ErrorBox} error=${error} />` : html`<${Loading} />`}<//>`;
  const routes = draft.routes;
  const move = (index, direction) => {
    const next = [...routes];
    [next[index], next[index + direction]] = [next[index + direction], next[index]];
    setDraft({ ...draft, routes: next });
  };
  return html`<${Page} title=${title} subtitle="Edit hosts and routing. Additional configuration is preserved when using the form." actions=${html`
    <span class="segmented" aria-label="Editor mode">
      <button type="button" class=${`button ${mode === 'form' ? 'active' : ''}`} aria-pressed=${mode === 'form'} disabled=${saving} onClick=${() => switchMode('form')}>Form</button>
      <button type="button" class=${`button ${mode === 'json' ? 'active' : ''}`} aria-pressed=${mode === 'json'} disabled=${saving} onClick=${() => switchMode('json')}>JSON</button>
    </span>${back}`}>
    <form class="form site-editor" ref=${formElement} onSubmit=${save}>
      <fieldset class="editor-content" disabled=${saving}>
      ${mode === 'form' ? html`
        <section class="card editor-section"><h2>Site</h2>
          <${StringList} value=${draft} name="hosts" label="Hosts" placeholder="example.com" hint="One host per row. Supports *.example.com and * as a catch-all." onChange=${setDraft} />
          <${TextField} value=${draft} name="name" label="Name" hint="Defaults to the first host. Existing site IDs cannot be renamed here." disabled=${id !== undefined} onChange=${setDraft} />
          <${Toggle} value=${draft} name="allow_http" label="Serve plain HTTP instead of redirecting to HTTPS" onChange=${setDraft} />
          <details class="editor-details"><summary>Listeners and site policies</summary><div class="editor-details-body form-grid">
            <${StringList} value=${draft} name="listeners" label="Listeners" placeholder="https" hint="Leave empty to serve on every listener." onChange=${setDraft} />
            <${StringList} value=${draft} name="policies" label="Site policies" placeholder="Policy name" hint="Use policy names from Configuration." onChange=${setDraft} />
          </div></details>
        </section>
        <section class="card editor-section"><div class="editor-section-header"><div><h2>Routing</h2><p class="field-hint">Match requests by method and path, then choose how to handle them.</p></div>
          <button class="button" type="button" onClick=${() => setDraft(addRoute(draft))}>Add route</button>
        </div>
          ${Array.isArray(routes) ? routes.map((route, index) => html`<${RouteEditor} key=${index} route=${route} index=${index} count=${routes.length}
            onChange=${value => setDraft(updateItem(draft, 'routes', index, value))} onRemove=${() => setDraft({ ...draft, routes: routes.filter((_, i) => i !== index) })} onMove=${direction => move(index, direction)} />`)
            : html`<${HandlerFields} value=${draft} onChange=${setDraft} />`}
          ${Array.isArray(routes) && !routes.length ? html`<${Notice} tone="info">No routes. Add a route to choose a handler.<//>` : null}
        </section>` : html`
        <section class="card"><${Field} label="Site configuration (JSON)" hint="Edit the complete configuration, including extension settings.">
          <textarea class="input code" rows="24" spellcheck="false" value=${json} onInput=${e => setJSON(e.currentTarget.value)}></textarea>
        <//></section>`}
      </fieldset>
      <${ErrorBox} error=${error} />
      <div class="form-actions"><button class="button button-primary" type="submit" disabled=${saving}>${saving ? 'Saving…' : 'Save'}</button><a class="button" href=${href('/sites')}>Cancel</a></div>
    </form>
  <//>`;
}
