# Release and distribution

The package version in `pyproject.toml` is 0.4.0a5 and its classifier is Alpha.
The repository is a source-distributed local CLI and TUI project.

## Automated checks

The GitHub Actions workflow runs on Ubuntu with Python 3.11, 3.12, and 3.13. It
synchronizes the committed lockfile with all extras and runs:

```bash
uv run ruff check src tests examples
uv run ruff format --check src tests examples
uv run pyright
uv run pytest -q --tb=short
uv build --offline --no-sources --no-create-gitignore
```

## Distribution

Hatchling is the configured build backend. The repository does not contain a
package publication workflow, deployment definition, container image, hosted
service configuration, release-signing job, or installer for `hashcat`.

Before publishing a release, a maintainer must separately verify:

- source and wheel builds in a clean supported Python environment;
- installation and entry points from both artifacts;
- intended Office and PDF viewer behavior on representative documents;
- dependency and vulnerability status;
- repository tag, artifact checksum, and publication provenance.
