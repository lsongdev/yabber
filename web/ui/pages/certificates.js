import { html } from '../lib/html.js';
import { Page, Empty, Loading, Table } from '../lib/ui.js';
import { useResource, ErrorBox, Badge, dateTime, daysUntil } from '../yabber.js';

function Expiry({ certificate }) {
  if (!certificate.not_after) return html`<${Badge} tone="warn">pending<//>`;
  const days = daysUntil(certificate.not_after);
  const tone = days < 0 ? 'bad' : days < 14 ? 'warn' : 'good';
  const text = days < 0 ? 'expired' : `${days} days`;
  return html`<${Badge} tone=${tone}>${text}<//> <span class="muted">${dateTime(certificate.not_after)}</span>`;
}

export default function Certificates() {
  const [state] = useResource('/certificates', 30000);
  const certificates = state.data ?? [];
  return html`<${Page} title="Certificates">
    <${ErrorBox} error=${state.error} />
    ${state.loading ? html`<${Loading} />` : certificates.length === 0
      ? html`<${Empty}>No certificates. Sites on TLS listeners get them from tls.certificates or tls.acme.<//>`
      : html`<${Table}>
        <thead><tr><th>Names</th><th>Source</th><th>Expires</th><th>Status</th></tr></thead>
        <tbody>${certificates.map(certificate => html`<tr key=${certificate.names.join()}>
          <td>${certificate.names.map(name => html`<span class="host">${name}</span>`)}</td>
          <td>${certificate.managed ? 'ACME' : 'file'}</td>
          <td><${Expiry} certificate=${certificate} /></td>
          <td>${certificate.error
            ? html`<span style="color:var(--danger)">${certificate.error}</span><br/><span class="muted">retry ${dateTime(certificate.retry_at)}</span>`
            : html`<${Badge} tone="good">ok<//>`}</td>
        </tr>`)}</tbody>
      <//>`}
  <//>`;
}
