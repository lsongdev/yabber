import { html, useEffect, useState } from '../lib/html.js';
import { Page, Notice, Loading } from '../lib/ui.js';
import { useResource, useRequest, ErrorBox } from '../yabber.js';

// Config edits the whole configuration as JSON.
export default function Config() {
  const request = useRequest();
  const [state, reload] = useResource('/config');
  const [text, setText] = useState('');
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState('');
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (state.data) setText(JSON.stringify(state.data, null, 2));
  }, [state.data]);

  async function save(event) {
    event.preventDefault();
    setError(null);
    setNotice('');
    let config;
    try {
      config = JSON.parse(text);
    } catch (e) {
      setError(new Error(`Invalid JSON: ${e.message}`));
      return;
    }
    setSaving(true);
    try {
      await request('PUT', '/config', { body: config, etag: state.etag });
      setNotice('Applied and saved.');
      reload();
    } catch (e) {
      setError(e);
    } finally {
      setSaving(false);
    }
  }

  return html`<${Page} title="Configuration"
    actions=${html`<button type="button" class="btn" onClick=${() => { setError(null); setNotice(''); reload(); }}>Reload</button>`}>
    <${ErrorBox} error=${state.error} />
    ${state.loading ? html`<${Loading} />` : html`<form class="form card" onSubmit=${save}>
      <textarea class="input code" rows="28" spellcheck="false" value=${text} onInput=${e => setText(e.target.value)}></textarea>
      <span class="field-hint">
        Changes are validated and applied atomically; an invalid configuration changes nothing.
        They are saved to the configuration file, which loses its comments; the previous file is kept as .bak.
      </span>
      <${ErrorBox} error=${error} />
      ${notice ? html`<${Notice} tone="info">${notice}<//>` : null}
      <div class="form-actions">
        <button class="btn btn-primary" type="submit" disabled=${saving}>${saving ? 'Applying…' : 'Apply'}</button>
      </div>
    </form>`}
  <//>`;
}
