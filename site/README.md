# Instrument Workbench demo

`site/` holds the separately deployable browser demonstration linked from the
project README. It has two parts: an interactive simulation built from static
HTML, CSS, and JavaScript with sanitized fixture data, and a screenshot tour of
the real local graphical interface.

The simulation is not a browser version of Dietrich. It cannot select, upload,
inspect, or change local documents; it makes no application network requests
beyond loading its own static assets; it stores no data; and every result is
simulated. The Python package is neither bundled nor invoked.

## Run locally

From the repository root:

```bash
python3 -m http.server 8000 --directory site
```

Open `http://127.0.0.1:8000/`. Asset paths are relative, so the same files work
under the `/dietrich-office-unlock/` GitHub Pages subpath.

## Published files

The Pages workflow validates and publishes only:

- `site/index.html`;
- `site/styles.css`;
- `site/script.js`;
- `site/screenshots/*.png` (the five captures in the screenshot tour).

Other files under `site/` are not part of the deployed artifact unless the
workflow is explicitly updated.

## Design and content contract

Keep the simulation a precise, keyboard-friendly local-instrument tool rather
than a generic service dashboard. Authorization, simulation, and fail-closed
states should stay prominent. Use text with color for every state, preserve
visible focus, respect reduced-motion preferences, and keep the primary
inspect-and-unlock flow usable at narrow viewport sizes.

Do not add file access, uploads, network requests, browser storage, remote fonts,
analytics, or any claim that fixture results were produced by Dietrich. The
screenshot tour shows the real `dietrich-gui` application, so label it as such
and never imply the simulation produced it. Capability language must stay
consistent with [docs/ALPHA.md](../docs/ALPHA.md) and the real CLI behavior.

## Validate changes

Run from the repository root:

```bash
test -f site/index.html
test -f site/styles.css
test -f site/script.js
node --check site/script.js
grep -Fq "Instrument Workbench" site/index.html
grep -Fq "Simulation only." site/index.html
grep -Fiq "sanitized fixture" site/index.html
uv sync --locked --all-extras --group demo
uv run --group demo playwright install chromium
uv run --group demo pytest -q site/tests
```

The browser tests start a loopback static server and exercise all four fixtures,
inspect, signed blocking and opt-in, unlock, export, reset, help, keyboard focus,
normal and reduced motion, focus restoration, and desktop and narrow layouts.
They reject runtime errors, downloads, unexpected requests, and calls to browser
storage, network, or file APIs. Playwright screenshots are written to
`/tmp/dietrich-demo-{width}.png`.

Also verify manually that keyboard controls, focus indicators, narrow layouts,
reduced motion, and the persistent simulation notice remain usable. Deployment
details are in [docs/RELEASE.md](../docs/RELEASE.md).
