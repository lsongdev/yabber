import { html } from '../lib.js'
import { useResource } from '../api.js'
import { ago, Badge, bytes, daysUntil, Empty, Page } from '../ui.js'

export function Overview () {
  const [status] = useResource('/status', 5000)
  const [metrics] = useResource('/metrics', 5000)
  const [events] = useResource('/events', 10000)
  const routes = metrics.data?.routes ?? []
  const total = routes.reduce((sum, route) => ({
    requests: sum.requests + route.requests,
    errors: sum.errors + route.errors,
    bytes: sum.bytes + route.response_bytes,
  }), { requests: 0, errors: 0, bytes: 0 })
  const expiring = (metrics.data?.certificates ?? []).filter((certificate) =>
    certificate.error || !certificate.not_after || daysUntil(certificate.not_after) < 14)

  return html`
    <${Page} title="Overview" state=${status}>
      <div class="cards">
        <div class="card">
          <span class="label">Health</span>
          ${status.data?.healthy
            ? html`<${Badge} tone="good">healthy<//>`
            : html`<${Badge} tone="bad">unhealthy<//>`}
        </div>
        <div class="card"><span class="label">Requests</span><strong>${total.requests}</strong></div>
        <div class="card"><span class="label">Errors</span><strong>${total.errors}</strong></div>
        <div class="card"><span class="label">Active</span><strong>${metrics.data?.active_requests ?? 0}</strong></div>
        <div class="card"><span class="label">Sent</span><strong>${bytes(total.bytes)}</strong></div>
      </div>

      ${expiring.length > 0 && html`
        <p class="warning">
          ${expiring.length} certificate${expiring.length > 1 ? 's need' : ' needs'} attention.
          <a href="#/certificates">Review certificates</a>
        </p>`}

      <h2>Listeners</h2>
      <table>
        <thead><tr><th>Name</th><th>Address</th><th>TLS</th><th>State</th></tr></thead>
        <tbody>
          ${(status.data?.listeners ?? []).map((listener) => html`
            <tr key=${listener.name}>
              <td>${listener.name}</td>
              <td class="mono">${listener.address}</td>
              <td>${listener.tls ? 'yes' : 'no'}</td>
              <td>${listener.running
                ? html`<${Badge} tone="good">running<//>`
                : html`<${Badge} tone="bad">${listener.error || 'stopped'}<//>`}</td>
            </tr>`)}
        </tbody>
      </table>

      <h2>Traffic</h2>
      ${routes.length === 0
        ? html`<${Empty}>No requests yet.<//>`
        : html`
          <table>
            <thead><tr>
              <th>Site</th><th>Route</th><th class="num">Requests</th><th class="num">Errors</th>
              <th class="num">2xx</th><th class="num">4xx</th><th class="num">5xx</th><th class="num">Avg</th>
            </tr></thead>
            <tbody>
              ${routes.map((route) => html`
                <tr key=${route.listener + route.site + route.route}>
                  <td>${route.site || html`<span class="muted">unmatched</span>`}</td>
                  <td class="mono">${route.route}</td>
                  <td class="num">${route.requests}</td>
                  <td class="num">${route.errors}</td>
                  <td class="num">${route.status_classes[2]}</td>
                  <td class="num">${route.status_classes[4]}</td>
                  <td class="num">${route.status_classes[5]}</td>
                  <td class="num">${route.requests ? (route.total_duration_ns / route.requests / 1e6).toFixed(1) : 0} ms</td>
                </tr>`)}
            </tbody>
          </table>`}

      <h2>Recent events</h2>
      ${(events.data ?? []).length === 0
        ? html`<${Empty}>No events yet.<//>`
        : html`
          <ul class="events">
            ${events.data.slice(-5).reverse().map((event, i) => html`
              <li key=${i}><span class="muted">${ago(event.time)}</span> ${event.message}</li>`)}
          </ul>
          <a href="#/events">All events</a>`}
    <//>`
}
