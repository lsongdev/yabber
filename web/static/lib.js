// The panel's view layer: Preact with htm tagged templates instead of JSX.
// index.html maps these bare specifiers to the vendored files.
import { h, render } from 'preact'
import htm from 'htm'

export { render }
export { useCallback, useEffect, useRef, useState } from 'preact/hooks'
export const html = htm.bind(h)
