import { html } from '../lib/html.js';
import { Page, Empty, Loading } from '../lib/ui.js';
import { useResource, ErrorBox, Badge, ago, dateTime } from '../yabber.js';

const tones = { ERROR: 'bad', WARN: 'warn', INFO: 'neutral' };

export default function Events() {
  const [state] = useResource('/events', 5000);
  const events = [...(state.data ?? [])].reverse();
  return html`<${Page} title="Events">
    <${ErrorBox} error=${state.error} />
    ${state.loading ? html`<${Loading} />` : events.length === 0 ? html`<${Empty}>No events yet.<//>` : html`
      <div class="table-wrap"><table class="table">
        <thead><tr><th>When</th><th>Level</th><th>Event</th></tr></thead>
        <tbody>${events.map((event, i) => html`<tr key=${i}>
          <td class="nowrap" title=${dateTime(event.time)}>${ago(event.time)}</td>
          <td><${Badge} tone=${tones[event.level] ?? 'neutral'}>${event.level.toLowerCase()}<//></td>
          <td>${event.message}
            ${Object.entries(event.attrs ?? {}).map(([key, value]) => html`
              <div class="attr"><span class="muted">${key}</span> <span class="mono">${value}</span></div>`)}
          </td>
        </tr>`)}</tbody>
      </table></div>`}
  <//>`;
}
