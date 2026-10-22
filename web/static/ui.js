// Shared components and formatting.
import { html } from './lib.js'

export function Loading () {
  return html`<p class="muted">Loading…</p>`
}

export function ErrorBox ({ error }) {
  if (!error) return null
  const hint = error.conflict ? ' Reload to see the current version, then make your change again.' : ''
  return html`<p class="error" role="alert">${error.message}${hint}</p>`
}

// Page renders a titled section with optional actions, handling the loading
// and error states of a resource.
export function Page ({ title, actions, state, children }) {
  return html`
    <section>
      <header class="page-header">
        <h1>${title}</h1>
        <div class="actions">${actions}</div>
      </header>
      ${state?.error && html`<${ErrorBox} error=${state.error} />`}
      ${state?.loading ? html`<${Loading} />` : children}
    </section>`
}

export function Badge ({ tone = 'neutral', children }) {
  return html`<span class=${`badge ${tone}`}>${children}</span>`
}

export function Empty ({ children }) {
  return html`<p class="muted empty">${children}</p>`
}

const units = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]]

// ago formats how long ago a time was, such as "3m ago".
export function ago (time) {
  const seconds = Math.max(0, Math.round((Date.now() - new Date(time)) / 1000))
  for (const [unit, size] of units) {
    if (seconds >= size) return `${Math.floor(seconds / size)}${unit} ago`
  }
  return 'just now'
}

export function daysUntil (time) {
  return Math.floor((new Date(time) - Date.now()) / 86400000)
}

export function bytes (n) {
  const scale = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (n >= 1024 && i < scale.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i ? 1 : 0)} ${scale[i]}`
}

export function dateTime (time) {
  return new Date(time).toLocaleString()
}
