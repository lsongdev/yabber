// Client for the management API. The token lives in localStorage; a 401
// clears it and returns the panel to the login screen.
import { useCallback, useEffect, useState } from './lib.js'

const TOKEN_KEY = 'yabber.token'

export const token = {
  get: () => localStorage.getItem(TOKEN_KEY) || '',
  set: (value) => localStorage.setItem(TOKEN_KEY, value),
  clear: () => {
    localStorage.removeItem(TOKEN_KEY)
    dispatchEvent(new Event('yabber:logout'))
  },
}

export class APIError extends Error {
  constructor (status, message) {
    super(message)
    this.status = status
  }

  // conflict reports a stale If-Match: someone else changed the configuration.
  get conflict () {
    return this.status === 412
  }
}

// request calls the API and returns { data, etag }. Pass etag to make a
// write conditional on the configuration being unchanged since it was read.
export async function request (method, path, { body, etag } = {}) {
  const headers = { Authorization: `Bearer ${token.get()}` }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (etag) headers['If-Match'] = etag
  const response = await fetch(`/api${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (response.status === 401) {
    token.clear()
    throw new APIError(401, 'The token was rejected.')
  }
  const data = response.status === 204 ? null : await response.json().catch(() => null)
  if (!response.ok) {
    throw new APIError(response.status, data?.error || response.statusText)
  }
  return { data, etag: response.headers.get('ETag') }
}

// useResource loads a GET endpoint, optionally refreshing every interval
// milliseconds, and returns [{ data, etag, error, loading }, reload].
export function useResource (path, interval = 0) {
  const [state, setState] = useState({ loading: true })
  const load = useCallback(async () => {
    try {
      const { data, etag } = await request('GET', path)
      setState({ data, etag })
    } catch (error) {
      setState((previous) => ({ ...previous, error, loading: false }))
    }
  }, [path])
  useEffect(() => {
    load()
    if (!interval) return
    const timer = setInterval(load, interval)
    return () => clearInterval(timer)
  }, [load, interval])
  return [state, load]
}
