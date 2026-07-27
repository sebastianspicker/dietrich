# Contributing

Contributions should be focused, testable, and limited to authorized document
workflows.

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[full,dev]'
```

## Change workflow

1. Trace the affected format from `src/dietrich/dispatch.py` to its implementation.
2. Reproduce the current behavior with the narrowest relevant test.
3. Change the shared implementation instead of duplicating logic in the CLI or TUI.
4. Add tests for success, failure, and output-safety behavior.
5. Update current documentation when flags, output, dependencies, or support limits change.
6. Run the checks listed below.

Do not add private, licensed, institutional, or identifying documents as fixtures.
Synthetic fixtures belong under `tests/fixtures/`. Public fixture provenance and
passwords must be recorded in the fixture README.

## Code guidelines

- Support Python 3.11 and later.
- Follow the Ruff rules configured in `pyproject.toml`.
- Keep document operations in the format or dispatch modules.
- Keep the TUI limited to state collection and presentation.
- Return explicit errors for unsupported, unsafe, or incomplete operations.
- Preserve ZIP metadata and unrelated document content where the format permits.
- Refuse destructive output replacement unless the caller explicitly requests it.
- Do not add IRM bypasses, signature impersonation, document exploits, or remote
  password-cracking services.

## Verification

```bash
ruff check src tests scripts examples
pytest -q
pytest -m e2e -q
python scripts/capture_screenshots.py --check
```

The suite is grouped by purpose:

- `tests/unit/` contains isolated pure-component checks.
- `tests/integration/` covers format handlers, the CLI, and the TUI together.
- `tests/regression/` preserves safety, fidelity, and compatibility failures.
- `tests/e2e/` invokes command entry points in subprocesses.
- `tests/support/` contains shared builders and fixture paths.

Run `python scripts/capture_screenshots.py` when user-visible CLI or TUI output
changes, then review the changed captures.

To exercise the sample workflow:

```bash
python examples/generate_samples.py
bash examples/run_demos.sh
```

## Pull requests

A pull request should state:

- the behavior changed and the formats affected;
- the security and output-safety implications;
- the checks run and their exact results;
- any dependency, compatibility, or viewer validation that was not performed.

Do not mix unrelated formatting or documentation changes into a functional patch.
