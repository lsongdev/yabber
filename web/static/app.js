// The yabber management panel. Routes live in the URL hash, so the server
// only ever serves static files.
import { html, render, useEffect, useState } from './lib.js'
import { request, token } from './api.js'
import { ErrorBox } from './ui.js'
import { Overview } from './views/overview.js'
import { SiteEditor, Sites } from './views/sites.js'
import { Certificates } from './views/certificates.js'
import { Events } from './views/events.js'
import { Config } from './views/config.js'

const NAV = [
  ['#/', 'Overview'],
  ['#/sites', 'Sites'],
  ['#/certificates', 'Certificates'],
  ['#/events', 'Events'],
  ['#/config', 'Configuration'],
]

function route (hash) {
  const [, section = '', id] = hash.replace(/^#/, '').split('/')
  switch (section) {
    case 'sites':
      if (id === 'new') return html`<${SiteEditor} />`
      if (id) return html`<${SiteEditor} key=${id} id=${decodeURIComponent(id)} />`
      return html`<${Sites} />`
    case 'certificates': return html`<${Certificates} />`
    case 'events': return html`<${Events} />`
    case 'config': return html`<${Config} />`
    default: return html`<${Overview} />`
  }
}

function useHash () {
  const [hash, setHash] = useState(location.hash)
  useEffect(() => {
    const update = () => setHash(location.hash)
    addEventListener('hashchange', update)
    return () => removeEventListener('hashchange', update)
  }, [])
  return hash
}

function Login ({ onLogin }) {
  const [value, setValue] = useState('')
  const [error, setError] = useState(null)
  async function submit (event) {
    event.preventDefault()
    token.set(value.trim())
    try {
      await request('GET', '/status')
      onLogin()
    } catch (e) {
      setError(e)
    }
  }
  return html`
    <main class="login">
      <h1>yabber</h1>
      <form onSubmit=${submit}>
        <label>Admin token
          <input type="password" autocomplete="current-password" value=${value}
            onInput=${(e) => setValue(e.target.value)} autofocus required />
          <small>Find it in admin.token in the data directory, for example /var/lib/yabber/admin.token.</small>
        </label>
        <${ErrorBox} error=${error} />
        <button class="primary" type="submit">Sign in</button>
      </form>
    </main>`
}

function App () {
  const [signedIn, setSignedIn] = useState(Boolean(token.get()))
  const hash = useHash()
  useEffect(() => {
    const logout = () => setSignedIn(false)
    addEventListener('yabber:logout', logout)
    return () => removeEventListener('yabber:logout', logout)
  }, [])

  if (!signedIn) return html`<${Login} onLogin=${() => setSignedIn(true)} />`
  const current = '#/' + (hash.replace(/^#\/?/, '').split('/')[0] ?? '')
  return html`
    <header class="topbar">
      <a class="brand" href="#/">yabber</a>
      <nav>
        ${NAV.map(([href, label]) => html`
          <a href=${href} class=${current === href ? 'active' : ''}>${label}</a>`)}
      </nav>
      <button class="link" onClick=${() => token.clear()}>Sign out</button>
    </header>
    <main>${route(hash)}</main>`
}

// A #token=... fragment signs in and is removed from the address bar; the
// fragment never reaches the server.
const fragment = new URLSearchParams(location.hash.slice(1))
if (fragment.has('token')) {
  token.set(fragment.get('token'))
  history.replaceState(null, '', location.pathname + '#/')
}

render(html`<${App} />`, document.getElementById('app'))
