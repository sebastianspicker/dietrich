# Local examples

`generate_samples.py` creates synthetic Office files under `examples/out/` and
copies the documented public fixtures needed by the walkthrough.

From the repository root:

```bash
python examples/generate_samples.py
bash examples/run_demos.sh
```

The walkthrough exercises inspection, soft-protection removal, encrypted Office
input, PDF input when `pikepdf` is installed, hash export, and selected failure
paths. It expects the `dietrich` entry point from an editable installation.

Files under `examples/out/` are disposable local outputs. The sample builder
creates the directory when needed.

Passwords and provenance for copied fixtures are documented in
`tests/fixtures/README.md`.
