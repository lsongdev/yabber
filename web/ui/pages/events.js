import { html } from '@lsongdev/panel/html.js';
import { PageHeader, Empty, Loading, Table } from '@lsongdev/scripts/react/components/index.js';
import { useResource, ErrorBox, ago, dateTime } from '../yabber.js';
import { Badge } from '@lsongdev/scripts/react/components/index.js';

const tones = { ERROR: 'danger', WARN: 'warning' };

export default function Events() {
  const [state] = useResource('/events', 5000);
  const events = [...(state.data ?? [])].reverse();
  return html`<${PageHeader} title="Events" />
    <${ErrorBox} error=${state.error} />
    ${state.loading ? html`<${Loading} />` : events.length === 0 ? html`<${Empty}>No events yet.<//>` : html`
      <${Table}>
        <thead><tr><th>When</th><th>Level</th><th>Event</th></tr></thead>
        <tbody>${events.map((event, i) => html`<tr key=${i}>
          <td class="nowrap" title=${dateTime(event.time)}>${ago(event.time)}</td>
          <td><${Badge} variant=${tones[event.level]}>${event.level.toLowerCase()}<//></td>
          <td>${event.message}
            ${Object.entries(event.attrs ?? {}).map(([key, value]) => html`
              <div class="attr"><span class="muted">${key}</span> <span class="mono">${value}</span></div>`)}
          </td>
        </tr>`)}</tbody>
      <//>`}`;
}
