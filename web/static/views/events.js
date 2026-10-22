import { html } from '../lib.js'
import { useResource } from '../api.js'
import { ago, Badge, dateTime, Empty, Page } from '../ui.js'

const tones = { ERROR: 'bad', WARN: 'warn', INFO: 'neutral' }

export function Events () {
  const [state] = useResource('/events', 5000)
  const events = [...(state.data ?? [])].reverse()
  return html`
    <${Page} title="Events" state=${state}>
      ${events.length === 0
        ? html`<${Empty}>No events yet.<//>`
        : html`
          <table>
            <thead><tr><th>When</th><th>Level</th><th>Event</th></tr></thead>
            <tbody>
              ${events.map((event, i) => html`
                <tr key=${i}>
                  <td title=${dateTime(event.time)}>${ago(event.time)}</td>
                  <td><${Badge} tone=${tones[event.level] ?? 'neutral'}>${event.level.toLowerCase()}<//></td>
                  <td>${event.message}
                    ${Object.entries(event.attrs ?? {}).map(([key, value]) => html`
                      <div class="attr"><span class="muted">${key}</span> <span class="mono">${value}</span></div>`)}
                  </td>
                </tr>`)}
            </tbody>
          </table>`}
    <//>`
}
