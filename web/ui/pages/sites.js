import { html, useState } from '../lib/html.js';
import { Page, Empty, Loading, confirmDanger } from '../lib/ui.js';
import { usePanel } from '../lib/panel.js';
import { useResource, useRequest, ErrorBox, Badge } from '../yabber.js';
import { siteID, describe } from './site.js';

export default function Sites() {
  const { href } = usePanel();
  const request = useRequest();
  const [state, reload] = useResource('/sites');
  const [error, setError] = useState(null);

  async function remove(site) {
    if (!confirmDanger(`Delete site ${siteID(site)}? It stops serving immediately.`)) return;
    try {
      await request('DELETE', `/sites/${encodeURIComponent(siteID(site))}`, { etag: state.etag });
      setError(null);
    } catch (e) {
      setError(e);
    }
    reload();
  }

  const sites = state.data ?? [];
  return html`<${Page} title="Sites" actions=${html`<a class="btn btn-primary" href=${href('/sites/new')}>Add site</a>`}>
    <${ErrorBox} error=${state.error || error} />
    ${state.loading ? html`<${Loading} />` : sites.length === 0
      ? html`<${Empty}>No sites yet. Add one to start serving.<//>`
      : html`<div class="table-wrap"><table class="table">
        <thead><tr><th>Site</th><th>Hosts</th><th>Handler</th><th class="actions"></th></tr></thead>
        <tbody>${sites.map(site => html`<tr key=${siteID(site)}>
          <td><a class="cell-main" href=${href(`/sites/${encodeURIComponent(siteID(site))}`)}>${siteID(site)}</a></td>
          <td>${site.hosts.map(host => html`<span class="host">${host}</span>`)}</td>
          <td class="mono">${describe(site)}
            ${site.allow_http ? html` <${Badge}>http<//>` : null}
            ${site.policies?.length > 0 ? html` <${Badge}>${site.policies.join(', ')}<//>` : null}</td>
          <td class="actions"><button class="btn btn-sm btn-danger" onClick=${() => remove(site)}>Delete</button></td>
        </tr>`)}</tbody>
      </table></div>`}
  <//>`;
}
