# Project website

The public Yabber website lives here, separately from the management panel
in `web/`. It is plain HTML, CSS, and JavaScript with no build dependencies,
external fonts, analytics, or runtime API calls.

## Preview

From the repository root:

```sh
python3 -m http.server 8000 --directory site
```

Open <http://localhost:8000>. Configuration tabs and copy buttons are
progressive enhancements; the default example and installation instructions
are also available without JavaScript. Clipboard access needs HTTPS or localhost.

## GitHub Pages

In the repository's **Settings → Pages → Build and deployment**, select
**GitHub Actions** as the source. Push the website and
`.github/workflows/pages.yml` to `master`, or run **Deploy project website**
from the Actions tab. The workflow uploads only this directory and publishes
it to <https://lsongdev.github.io/yabber/>.

Site changes on `master` deploy automatically. Relative asset paths support
the `/yabber/` project prefix and a custom domain without changing the source.
The site workflow does not build the Go binary or publish a release.

Update `index.html` for page content, `style.css` for presentation, and
`script.js` for the interactive YAML examples. Keep the initial proxy example
in `index.html` in sync with `examples.proxy` in `script.js`. Check examples
against Yabber's configuration schema when changing them.
