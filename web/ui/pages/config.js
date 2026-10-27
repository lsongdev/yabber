import { html, useEffect, useRef, useState } from '../lib/html.js';
import { Page, Field, Notice, Loading } from '../lib/ui.js';
import { useResource, useRequest, ErrorBox } from '../yabber.js';
import { prepareConfig } from '../config-model.js';
import GatewayConfig from '../components/gateway-config.js';

export default function Config() {
  const request = useRequest();
  const [state, reload] = useResource('/config');
  const [draft, setDraft] = useState(null);
  const [text, setText] = useState('');
  const [mode, setMode] = useState('form');
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState('');
  const [saving, setSaving] = useState(false);
  const savedETag = useRef('');

  useEffect(() => {
    if (!state.data) return;
    setText(JSON.stringify(state.data, null, 2));
    savedETag.current = state.etag;
    try { setDraft(prepareConfig(state.data)); }
    catch (e) { setMode('json'); setError(e); }
  }, [state.data]);

  function switchMode(next) {
    if (next === mode) return;
    setError(null);
    if (next === 'json') { setText(JSON.stringify(draft, null, 2)); setMode(next); return; }
    try { setDraft(prepareConfig(JSON.parse(text))); setMode(next); }
    catch (e) { setError(e); }
  }

  async function save(event) {
    event.preventDefault(); setError(null); setNotice('');
    let config;
    try { config = mode === 'form' ? draft : JSON.parse(text); }
    catch (e) { setError(new Error(`Invalid JSON: ${e.message}`)); return; }
    setSaving(true);
    try {
      const result = await request('PUT', '/config', { body: config, etag: savedETag.current });
      // Commit the returned document/ETag together; do not overwrite a newer draft
      // with a separate reload which might finish after the user starts editing.
      savedETag.current = result.etag;
      const applied = result.data ?? config;
      setText(JSON.stringify(applied, null, 2));
      try { setDraft(prepareConfig(applied)); } catch { setMode('json'); }
      setNotice('Applied and saved.');
    } catch (e) { setError(e); }
    finally { setSaving(false); }
  }

  return html`<${Page} title="Configuration" subtitle="Common settings are editable as a form. Unshown settings are retained in the complete configuration."
    actions=${html`<span class="segmented" aria-label="Editor mode">
      <button type="button" class=${`button ${mode==='form'?'active':''}`} aria-pressed=${mode==='form'} disabled=${saving||!state.data} onClick=${()=>switchMode('form')}>Form</button>
      <button type="button" class=${`button ${mode==='json'?'active':''}`} aria-pressed=${mode==='json'} disabled=${saving||!state.data} onClick=${()=>switchMode('json')}>JSON</button>
    </span><button type="button" class="button" disabled=${saving} onClick=${()=>{setError(null);setNotice('');reload();}}>Reload</button>`}>
    <${ErrorBox} error=${state.error} />
    ${state.loading ? html`<${Loading} />` : state.data ? html`<form class="form config-editor" onSubmit=${save}>
      <fieldset class="editor-content" disabled=${saving}>
      ${mode==='form' && draft ? html`<${GatewayConfig} value=${draft} onChange=${setDraft} />` : html`<section class="card"><${Field} label="Gateway configuration (JSON)">
        <textarea class="input code" rows="28" spellcheck="false" value=${text} onInput=${e=>setText(e.currentTarget.value)}></textarea>
      <//></section>`}
      </fieldset>
      <p class="field-hint">Changes are validated before they are applied. Form edits preserve settings that are not displayed.</p>
      <${ErrorBox} error=${error} />
      ${notice ? html`<${Notice} tone="info">${notice}<//>` : null}
      <div class="form-actions"><button class="button button-primary" type="submit" disabled=${saving}>${saving?'Applying…':'Apply'}</button></div>
    </form>` : null}
  <//>`;
}
