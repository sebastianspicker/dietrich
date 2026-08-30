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

1. Trace the use case in `src/dietrich/application/` to its format implementation.
2. Reproduce the current behavior with the narrowest relevant test.
3. Change the shared implementation instead of duplicating logic in the CLI or TUI.
4. Add tests for success, failure, and output-safety behavior.
5. Update current documentation when flags, output, dependencies, or support limits change.
6. Run the checks listed below.

Do not add private, licensed, institutional, or identifying documents. Tests
must construct only the minimal synthetic data they need at runtime.

## Code guidelines

- Support Python 3.11 and later.
- Follow the Ruff rules configured in `pyproject.toml`.
- Keep workflow policy in `application/` and document semantics in the format package.
- Format writers produce unpublished candidates; only the artifact transaction publishes.
- Keep the TUI limited to state collection and presentation.
- Return explicit errors for unsupported, unsafe, or incomplete operations.
- Preserve ZIP metadata and unrelated document content where the format permits.
- Refuse destructive output replacement unless the caller explicitly requests it.
- Do not add IRM bypasses, signature impersonation, document exploits, or remote
  password-cracking services.

## Verification

```bash
uv run ruff check src tests examples
uv run ruff format --check src tests examples
uv run pyright
uv run pytest -q
```

The test suite separates observable document contracts, adversarial regressions,
and mechanically enforced dependency rules. Manually inspect terminal changes
rather than committing generated captures.

## Pull requests

A pull request should state:

- the behavior changed and the formats affected;
- the security and output-safety implications;
- the checks run and their exact results;
- any dependency, compatibility, or viewer validation that was not performed.

Do not mix unrelated formatting or documentation changes into a functional patch.
