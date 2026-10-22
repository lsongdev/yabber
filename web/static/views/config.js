import { html, useEffect, useState } from '../lib.js'
import { request, useResource } from '../api.js'
import { ErrorBox, Page } from '../ui.js'

// Config edits the whole configuration as JSON.
export function Config () {
  const [state, reload] = useResource('/config')
  const [text, setText] = useState('')
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState('')
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    if (state.data) setText(JSON.stringify(state.data, null, 2))
  }, [state.data])

  async function save (event) {
    event.preventDefault()
    setError(null)
    setNotice('')
    let config
    try {
      config = JSON.parse(text)
    } catch (e) {
      setError(new Error(`Invalid JSON: ${e.message}`))
      return
    }
    setSaving(true)
    try {
      await request('PUT', '/config', { body: config, etag: state.etag })
      setNotice('Applied and saved.')
      reload()
    } catch (e) {
      setError(e)
    } finally {
      setSaving(false)
    }
  }

  return html`
    <${Page} title="Configuration" state=${state}
      actions=${html`<button type="button" onClick=${() => { setError(null); setNotice(''); reload() }}>Reload</button>`}>
      <form class="editor" onSubmit=${save}>
        <textarea class="code" rows="28" spellcheck="false" value=${text} onInput=${(e) => setText(e.target.value)} />
        <small>
          Changes are validated and applied atomically; an invalid configuration changes nothing.
          They are saved to the configuration file, which loses its comments; the previous file is kept as .bak.
        </small>
        <${ErrorBox} error=${error} />
        ${notice && html`<p class="notice" role="status">${notice}</p>`}
        <div class="form-actions">
          <button class="primary" type="submit" disabled=${saving}>${saving ? 'Applying…' : 'Apply'}</button>
        </div>
      </form>
    <//>`
}
