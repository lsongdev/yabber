import { html, useState } from '@lsongdev/panel/html.js';
import { PageHeader, Empty, Loading, Table } from '@lsongdev/scripts/react/components/index.js';
import { usePanel } from '@lsongdev/panel/panel.js';
import { useResource, useRequest, ErrorBox } from '../yabber.js';
import { Badge } from '@lsongdev/scripts/react/components/index.js';
import { siteID, describe } from './site.js';

export default function Sites() {
  const { href } = usePanel();
  const request = useRequest();
  const [state, reload] = useResource('/sites');
  const [error, setError] = useState(null);

  async function remove(site) {
    if (!window.confirm(`Delete site ${siteID(site)}? It stops serving immediately.`)) return;
    try {
      await request('DELETE', `/sites/${encodeURIComponent(siteID(site))}`, { etag: state.etag });
      setError(null);
    } catch (e) {
      setError(e);
    }
    reload();
  }

  const sites = state.data ?? [];
  return html`<${PageHeader} title="Sites" actions=${html`<a class="button button-primary" href=${href('/sites/new')}>Add site</a>`} />
    <${ErrorBox} error=${state.error || error} />
    ${state.loading ? html`<${Loading} />` : sites.length === 0
      ? html`<${Empty}>No sites yet. Add one to start serving.<//>`
      : html`<${Table}>
        <thead><tr><th>Site</th><th>Hosts</th><th>Handler</th><th class="actions"></th></tr></thead>
        <tbody>${sites.map(site => html`<tr key=${siteID(site)}>
          <td><a class="cell-main" href=${href(`/sites/${encodeURIComponent(siteID(site))}`)}>${siteID(site)}</a></td>
          <td>${site.hosts.map(host => html`<span class="host">${host}</span>`)}</td>
          <td class="mono">${describe(site)}
            ${site.allow_http ? html` <${Badge}>http<//>` : null}
            ${site.policies?.length > 0 ? html` <${Badge}>${site.policies.join(', ')}<//>` : null}</td>
          <td class="actions"><button class="button button-small button-danger" onClick=${() => remove(site)}>Delete</button></td>
        </tr>`)}</tbody>
      <//>`}`;
}
