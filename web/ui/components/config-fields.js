import { html, useEffect, useRef, useState } from '../lib/html.js';
import { Field, ListInput, Notice } from '../lib/ui.js';
import { HANDLERS, isBuiltin, handlerKeys, handlerConfig, setField, changeHandler } from '../config-model.js';

export function TextField({ value, name, label, onChange, type = 'text', hint, placeholder, required = false, min, max, disabled = false }) {
  return html`<${Field} label=${label} hint=${hint} required=${required}>
    <input class="input" type=${type} value=${value[name] ?? ''} placeholder=${placeholder} required=${required}
      min=${min} max=${max} step=${type === 'number' ? 'any' : undefined} disabled=${disabled}
      onInput=${e => onChange(setField(value, name, type === 'number' && e.currentTarget.value !== '' ? Number(e.currentTarget.value) : e.currentTarget.value))} />
  <//>`;
}
export function Toggle({ value, name, label, onChange }) {
  return html`<label class="field-check"><input type="checkbox" checked=${Boolean(value[name])}
    onChange=${e => onChange({ ...value, [name]: e.currentTarget.checked })} />${label}</label>`;
}
export function StringList({ value, name, label, onChange, hint, placeholder }) {
  // Field wraps one control; list editors have several independently labelled inputs.
  return html`<div class="field"><span class="field-label">${label}</span>
    <${ListInput} values=${value[name] ?? []} placeholder=${placeholder} removeLabel=${`Remove ${label.toLowerCase()} entry`}
      onChange=${items => onChange({ ...value, [name]: items.filter(item => item.trim()).map(item => item.trim()) })} />
    ${hint ? html`<span class="field-hint">${hint}</span>` : null}
  </div>`;
}
export function SelectField({ value, name, label, onChange, options, placeholder = 'Default' }) {
  return html`<${Field} label=${label}><select class="input" value=${value[name] ?? ''} onChange=${e => onChange(setField(value, name, e.currentTarget.value))}>
    <option value="">${placeholder}</option>
    ${value[name] && !options.some(option => String(Array.isArray(option) ? option[0] : option) === String(value[name])) ? html`<option value=${value[name]}>${value[name]}</option>` : null}
    ${options.map(option => { const [key, label] = Array.isArray(option) ? option : [option, option]; return html`<option value=${key}>${label}</option>`; })}
  </select><//>`;
}
export function Fields({ value, onChange, fields }) {
  return html`<div class="form-grid">${fields.map(([name, label, placeholder, type = 'text', hint]) => html`
    <${TextField} key=${name} value=${value} name=${name} label=${label} placeholder=${placeholder} type=${type} min=${type === 'number' ? 0 : undefined} hint=${hint} onChange=${onChange} />`)}</div>`;
}
export function ExtraFields({ value, known }) {
  const keys = Object.keys(value).filter(key => !known.includes(key));
  return keys.length ? html`<p class="field-hint">Additional settings preserved: ${keys.join(', ')}. Use JSON to edit them.</p>` : null;
}

function Headers({ value, onChange }) {
  const source = value.headers;
  const previous = useRef(source);
  const [rows, setRows] = useState(() => Object.entries(source ?? {}));
  useEffect(() => {
    if (source !== previous.current) { previous.current = source; setRows(Object.entries(source ?? {})); }
  }, [source]);
  function commit(next) {
    setRows(next);
    const headers = Object.fromEntries(next.filter(([key]) => key.trim()).map(([key, val]) => [key.trim(), val]));
    previous.current = headers;
    onChange({ ...value, headers });
  }
  return html`<div class="field"><span class="field-label">Response headers</span>
    ${rows.map(([key, val], index) => {
      const duplicate = key && rows.some(([other], i) => i !== index && other.trim().toLowerCase() === key.trim().toLowerCase());
      return html`<div class="header-row" key=${index}>
        <input class="input" aria-label=${`Header ${index + 1} name`} value=${key} placeholder="Content-Type" required=${Boolean(val)}
          aria-invalid=${duplicate || (val && !key.trim()) ? 'true' : undefined} ref=${input => input?.setCustomValidity(duplicate ? 'Header names must be unique.' : val && !key.trim() ? 'Enter a header name.' : '')}
          onInput=${e => commit(rows.map((row, i) => i === index ? [e.currentTarget.value, val] : row))} />
        <input class="input" aria-label=${`Header ${index + 1} value`} value=${val} placeholder="text/plain"
          onInput=${e => commit(rows.map((row, i) => i === index ? [key, e.currentTarget.value] : row))} />
        <button type="button" class="button" aria-label=${`Remove header ${index + 1}`} onClick=${() => commit(rows.filter((_, i) => i !== index))}>Remove</button>
      </div>`;
    })}
    <button type="button" class="button button-small" onClick=${() => setRows([...rows, ['', '']])}>Add header</button>
  </div>`;
}

export function HandlerFields({ value, onChange, route = false }) {
  const keys = handlerKeys(value, route);
  const kind = keys[0] ?? 'proxy';
  const settings = handlerConfig(value, kind);
  const change = next => onChange({ ...value, [kind]: next });
  return html`<div class="handler-fields">
    <${Field} label="Handler"><select class="input" value=${kind} onChange=${e => onChange(changeHandler(value, e.currentTarget.value, route))}>
      ${Object.entries(HANDLERS).map(([key, item]) => html`<option value=${key}>${item.label}</option>`)}
      ${keys.filter(key => !isBuiltin(key)).map(key => html`<option value=${key}>${key} (extension)</option>`)}
    </select><//>
    ${keys.length > 1 ? html`<${Notice} tone="warn">Multiple handlers are configured. Their values are preserved; use JSON to resolve this configuration.<//>` : null}
    ${!isBuiltin(kind) ? html`<${Notice} tone="info">The ${kind} extension is preserved. Its settings can be edited in JSON mode.<//>` : html`
      ${kind === 'respond' ? html`
        <${Field} label="Response body"><textarea class="input" rows="4" value=${settings.body ?? ''} onInput=${e => change({ ...settings, body: e.currentTarget.value })} placeholder="ok"></textarea><//>
        <${TextField} value=${settings} name="status" label="Status code" placeholder="200" type="number" min="100" max="599" onChange=${change} />
        <${Headers} value=${settings} onChange=${change} />
        <${ExtraFields} value=${settings} known=${['body', 'status', 'headers']} />` : html`
        <${TextField} value=${settings} name=${HANDLERS[kind].field} label=${{proxy:'Upstream',files:'Directory',redirect:'Redirect to'}[kind]} required placeholder=${HANDLERS[kind].placeholder} onChange=${change} />
        <details class="editor-details"><summary>Handler options</summary><div class="editor-details-body">
          ${kind === 'proxy' ? html`
            <${Fields} value=${settings} onChange=${change} fields=${[
              ['strip_prefix','Strip path prefix','/api'], ['host_header','Upstream Host header','Preserve client Host'],
              ['dial_timeout','Connection timeout','5s'], ['response_header_timeout','Response header timeout','Unlimited'],
              ['max_conns','Maximum connections','0 (unlimited)','number'],
            ]} />
            <${Toggle} value=${settings} name="insecure_skip_verify" label="Skip upstream TLS certificate verification" onChange=${change} />
            <${ExtraFields} value=${settings} known=${['upstream','strip_prefix','host_header','dial_timeout','response_header_timeout','max_conns','insecure_skip_verify']} />` : null}
          ${kind === 'files' ? html`
            <${TextField} value=${settings} name="strip_prefix" label="Strip path prefix" placeholder="/assets" onChange=${change} />
            <${Toggle} value=${settings} name="browse" label="Allow directory browsing" onChange=${change} />
            <${ExtraFields} value=${settings} known=${['root','strip_prefix','browse']} />` : null}
          ${kind === 'redirect' ? html`
            <${SelectField} value=${settings} name="status" label="Redirect status" placeholder="308 Permanent Redirect" options=${[[301,'301 Moved Permanently'],[302,'302 Found'],[303,'303 See Other'],[307,'307 Temporary Redirect'],[308,'308 Permanent Redirect']]} onChange=${next => change(next.status ? {...next,status:Number(next.status)} : next)} />
            <${Toggle} value=${settings} name="preserve_path" label="Preserve request path and query" onChange=${change} />
            <${ExtraFields} value=${settings} known=${['to','status','preserve_path']} />` : null}
        </div></details>`}`}
  </div>`;
}
