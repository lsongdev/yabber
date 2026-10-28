import { html } from '../lib/html.js';
import { Notice } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { setField, updateItem } from '../config-model.js';
import { TextField, Toggle, StringList, SelectField, Fields, ExtraFields } from './config-fields.js';

const SERVER_FIELDS = [
  ['read_header_timeout','Read header timeout','10s'],
  ['read_timeout','Read timeout','Unlimited', 'text', 'Bounds reading the entire request, including uploads.'],
  ['write_timeout','Write timeout','Unlimited', 'text', 'A limit also applies to streaming responses and long-lived connections.'],
  ['idle_timeout','Idle connection timeout','2m'], ['shutdown_timeout','Shutdown timeout','10s'],
  ['max_header_bytes','Maximum header bytes','65536','number'],
];
const ACME_FIELDS = [
  ['email','Contact email','admin@example.com'], ['directory','ACME directory','https://acme-v02.api.letsencrypt.org/directory'],
  ['account_key','Account key file','/etc/yabber/account.pem'], ['account_url','Account URL','Optional existing account URL'],
  ['ca_root','CA root file','Optional private CA root certificate'],
];

function Listener({ value, onChange, onRemove, index }) {
  return html`<fieldset class="editor-card"><legend>Listener ${index + 1}${value.name ? ` · ${value.name}` : ''}</legend>
    <div class="editor-row-actions"><button type="button" class="button button-small button-danger" onClick=${onRemove}>Remove listener</button></div>
    <div class="form-grid">
      <${TextField} value=${value} name="name" label="Listener name" placeholder="https" required onChange=${onChange} />
      <${TextField} value=${value} name="address" label="Listen address" placeholder=":443" required onChange=${onChange} />
    </div>
    <${Toggle} value=${value} name="tls" label="Enable TLS on this listener" onChange=${onChange} />
    <details class="editor-details"><summary>Trusted proxies and listener policies</summary><div class="editor-details-body form-grid">
      <${StringList} value=${value} name="trusted_proxies" label="Trusted proxies" placeholder="127.0.0.1 or 10.0.0.0/8" hint="Only these addresses may supply trusted forwarding headers." onChange=${onChange} />
      <${StringList} value=${value} name="policies" label="Listener policies" placeholder="Policy name" onChange=${onChange} />
    </div></details>
    <${ExtraFields} value=${value} known=${['name','address','tls','trusted_proxies','policies']} />
  </fieldset>`;
}

function Policy({ value, onChange, onRemove, index }) {
  const block = (name, config) => onChange(setField(value, name, config));
  return html`<fieldset class="editor-card"><legend>Policy ${index + 1}${value.name ? ` · ${value.name}` : ''}</legend>
    <div class="editor-row-actions"><button type="button" class="button button-small button-danger" onClick=${onRemove}>Remove policy</button></div>
    <${TextField} value=${value} name="name" label="Policy name" placeholder="public" required onChange=${onChange} />
    <p class="field-hint">Attach this name to a listener, site or route.</p>
    ${value.request ? html`<section class="limit-block"><h3>Request limits</h3>
      <${Fields} value=${value.request} onChange=${next => block('request', next)} fields=${[
        ['max_body_bytes','Maximum request body bytes','0 (unlimited)','number'], ['timeout','Request timeout','Unlimited','text','Also bounds WebSocket and streaming lifetimes.'],
      ]} /><${ExtraFields} value=${value.request} known=${['max_body_bytes','timeout']} />
      <button class="button button-small" type="button" onClick=${() => block('request', undefined)}>Remove request limits</button>
    </section>` : html`<button class="button" type="button" onClick=${() => block('request', {})}>Add request limits</button>`}
    ${value.rate_limit ? html`<section class="limit-block"><h3>Rate limit</h3>
      <${Fields} value=${value.rate_limit} onChange=${next => block('rate_limit', next)} fields=${[
        ['requests_per_second','Requests per second','10','number'], ['burst','Burst capacity','20','number'],
        ['max_keys','Maximum tracked clients','10000','number'], ['idle_timeout','Client idle timeout','10m'],
      ]} />
      <${SelectField} value=${value.rate_limit} name="key" label="Rate limit key" placeholder="Client IP" options=${[['client_ip','Client IP'],['global','Global']]} onChange=${next => block('rate_limit', next)} />
      <${ExtraFields} value=${value.rate_limit} known=${['requests_per_second','burst','max_keys','idle_timeout','key']} />
      <button class="button button-small" type="button" onClick=${() => block('rate_limit', undefined)}>Remove rate limit</button>
    </section>` : html`<button class="button" type="button" onClick=${() => block('rate_limit', {requests_per_second:10,burst:20})}>Add rate limit</button>`}
    ${value.concurrency ? html`<section class="limit-block"><h3>Concurrency limit</h3>
      <${TextField} value=${value.concurrency} name="max" label="Maximum concurrent requests" type="number" min="1" required onChange=${next => block('concurrency',next)} />
      <${ExtraFields} value=${value.concurrency} known=${['max']} />
      <button class="button button-small" type="button" onClick=${() => block('concurrency', undefined)}>Remove concurrency limit</button>
    </section>` : html`<button class="button" type="button" onClick=${() => block('concurrency', {max:100})}>Add concurrency limit</button>`}
    <${ExtraFields} value=${value} known=${['name','request','rate_limit','concurrency']} />
  </fieldset>`;
}

export default function GatewayConfig({ value, onChange }) {
  const { href } = usePanel();
  const tls = value.tls ?? {};
  const listeners = value.listeners ?? [];
  const policies = value.policies ?? [];
  const setTLS = next => onChange({ ...value, tls: next });
  const certificates = tls.certificates ?? [];
  return html`
    <section class="card editor-section">
      <label class="field-check"><input type="checkbox" checked=${!value.disabled}
        onChange=${e => { const { disabled, ...rest } = value; onChange(e.currentTarget.checked ? rest : { ...rest, disabled: true }); }} />Serve traffic</label>
      <p class="field-hint">When off, no listener is bound; sites and settings are kept.</p>
    </section>
    <section class="card editor-section"><div class="editor-section-header"><div><h2>Listeners</h2><p class="field-hint">Addresses where the gateway accepts HTTP and HTTPS traffic.</p></div>
      <button class="button" type="button" onClick=${() => onChange({...value,listeners:[...listeners,{name:'',address:''}]})}>Add listener</button>
    </div>
      ${!listeners.length ? html`<${Notice} tone="info">No explicit listeners. The gateway uses its default HTTP and HTTPS listeners when available.<//>` : null}
      ${listeners.map((listener,index) => html`<${Listener} key=${index} value=${listener} index=${index}
        onChange=${next => onChange(updateItem(value,'listeners',index,next))} onRemove=${() => onChange({...value,listeners:listeners.filter((_,i)=>i!==index)})} />`)}
    </section>
    <details class="card editor-section"><summary>Server timeouts and limits</summary><div class="editor-details-body">
      <p class="field-hint">Durations use units such as 30s or 2m. Blank values use the server defaults.</p>
      <${Fields} value=${value.server ?? {}} fields=${SERVER_FIELDS} onChange=${next=>onChange({...value,server:next})} />
      <${ExtraFields} value=${value.server ?? {}} known=${SERVER_FIELDS.map(([key])=>key)} />
    </div></details>
    <details class="card editor-section"><summary>TLS and certificates</summary><div class="editor-details-body">
      <${SelectField} value=${tls} name="min_version" label="Minimum TLS version" placeholder="TLS 1.2" options=${[['1.2','TLS 1.2'],['1.3','TLS 1.3']]} onChange=${setTLS} />
      <h3>Certificate files</h3><p class="field-hint">Paths are on the gateway server. Certificates managed externally can remain external.</p>
      ${certificates.map((certificate,index)=>html`<fieldset class="editor-card" key=${index}><legend>Certificate ${index+1}</legend>
        <${Fields} value=${certificate} fields=${[['cert','Certificate chain file','/etc/ssl/fullchain.pem'],['key','Private key file','/etc/ssl/privkey.pem']]} onChange=${next=>setTLS(updateItem(tls,'certificates',index,next))} />
        <${ExtraFields} value=${certificate} known=${['cert','key']} />
        <button class="button button-small button-danger" type="button" onClick=${()=>setTLS({...tls,certificates:certificates.filter((_,i)=>i!==index)})}>Remove certificate</button>
      </fieldset>`)}
      <button class="button" type="button" onClick=${()=>setTLS({...tls,certificates:[...certificates,{cert:'',key:''}]})}>Add certificate</button>
      ${tls.acme ? html`<section class="limit-block"><h3>Built-in ACME</h3>
        <p class="field-hint">Obtains certificates through HTTP-01. Enabling this accepts the certificate authority's terms of service.</p>
        <${Fields} value=${tls.acme} fields=${ACME_FIELDS} onChange=${next=>setTLS({...tls,acme:next})} />
        <${ExtraFields} value=${tls.acme} known=${ACME_FIELDS.map(([key])=>key)} />
        <button class="button button-small" type="button" onClick=${()=>setTLS(setField(tls,'acme',undefined))}>Remove built-in ACME</button>
      </section>` : html`<button class="button" type="button" onClick=${()=>setTLS({...tls,acme:{}})}>Configure built-in ACME</button>`}
      <${ExtraFields} value=${tls} known=${['min_version','certificates','acme']} />
    </div></details>
    <details class="card editor-section"><summary>Reusable policies (${policies.length})</summary><div class="editor-details-body">
      <p class="field-hint">Policies can limit request size, duration, rate and concurrency.</p>
      ${policies.map((policy,index)=>html`<${Policy} key=${index} value=${policy} index=${index} onChange=${next=>onChange(updateItem(value,'policies',index,next))} onRemove=${()=>onChange({...value,policies:policies.filter((_,i)=>i!==index)})} />`)}
      <button class="button" type="button" onClick=${()=>onChange({...value,policies:[...policies,{name:''}]})}>Add policy</button>
    </div></details>
    <section class="card editor-section"><div class="editor-section-header"><div><h2>Sites</h2><p class="field-hint">${(n => `${n} site definition${n === 1 ? ' is' : 's are'} preserved.`)(Array.isArray(value.sites) ? value.sites.length : 0)} Edit hosts and routes in the site editor.</p></div>
      <a class="button" href=${href('/sites')}>Manage sites</a></div>
      <${ExtraFields} value=${value} known=${['version','disabled','server','tls','listeners','policies','sites']} />
    </section>`;
}
