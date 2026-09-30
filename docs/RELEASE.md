# Release and distribution

Dietrich 0.4.0a5 is classified as Alpha in `pyproject.toml`. Hatchling builds a
single local Python package with `dietrich`, `dietrich-tui`, and `dietrich-gui`
console entry points. Release publication is a maintainer-operated process; no
PyPI publishing workflow is defined.

## Automated checks

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs four independent
lanes on Ubuntu:

- **Static** — locked dependency validation, Ruff lint and format, and Pyright,
  once.
- **Behavioral tests** — Python 3.11, 3.12, and 3.13 with all package extras.
- **Packaging** — one offline build, archive-boundary and six-stylesheet checks,
  then separate clean wheel and source-distribution installations. All three
  console entry points run from outside the checkout.
- **Demo** — JavaScript syntax, fixture-only static contracts, and local Chromium
  interactions through the dedicated `demo` dependency group. This lane also
  syntax-checks the graphical assets and runs the GUI browser tests.

The workflow runs for pull requests, manual dispatches, and pushes to `main` or
`master`. The source distribution includes maintained source, tests, docs,
examples, brand assets, validation scripts, and the demo with its screenshot
tour. `.impeccable`, design studies, generated captures, caches, and the removed
v2 copy are excluded by its explicit include boundary.

For local package verification, use a fresh output directory:

```bash
build_dir="$(mktemp -d)"
uv build --offline --no-sources --no-create-gitignore --out-dir "$build_dir"
uv run python scripts/check_distributions.py "$build_dir"
```

## Release verification

Before publishing a package release, a maintainer must separately verify:

- `uv lock --check --offline` and the complete automated gate;
- source and wheel builds in a clean supported Python environment;
- installation and all three console entry points from each artifact;
- intended Office and PDF viewer behavior on representative authorized files;
- dependency and vulnerability status;
- the repository tag, artifact checksums, and publication provenance.

The repository does not automate package publication, tagging, signing,
checksums, or provenance. It also contains no container image, hosted Dietrich
runtime, or `hashcat` installer.

## Static demo deployment

[`.github/workflows/pages.yml`](../.github/workflows/pages.yml) deploys the
separate Instrument Workbench demo to GitHub Pages from `main` or a manual
dispatch. Before the first deployment, set the repository's Pages source to
GitHub Actions and restrict the `github-pages` environment to `main`.

The workflow rejects external runtime assets and browser network, storage, or
file-picker APIs. It stages only:

- `site/index.html`;
- `site/styles.css`;
- `site/script.js`;
- `site/screenshots/*.png`.

The deployed artifact is a sanitized fixture simulation plus a static screenshot
tour of the real graphical interface. It does not include, invoke, publish, or
validate the Python application. The workflow's presence in the worktree does not
by itself prove that GitHub Pages is enabled or that a deployment has succeeded.

See [site/README.md](../site/README.md) for local preview and validation.
