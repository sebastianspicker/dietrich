# Contributing

Thanks for helping with Dietrich. Contributions should be focused, testable, and
limited to authorized document workflows.

## Set up

Install [uv](https://docs.astral.sh/uv/), then from the repository root:

```bash
uv sync --locked --all-extras
```

CI covers Python 3.11, 3.12, and 3.13 on Ubuntu. Do not update `uv.lock` as a
side effect of an unrelated change.

## Make a change

1. Trace the use case in `src/dietrich/application/` to its format
   implementation.
2. Reproduce the current behavior with the narrowest relevant test.
3. Change the shared implementation instead of duplicating policy in the CLI or
   TUI.
4. Add synthetic tests for success, failure, and output safety.
5. Update the documentation that owns any changed flags, fields, dependencies,
   format support, or architectural boundary.
6. Run the repository gate.

### Where changes belong

| Change | Lives in |
| --- | --- |
| A new document semantic for one format | that format package |
| Cross-format workflow policy | `application/` |
| Pure shared records | `domain/` |
| Untrusted I/O limits and final publication | `safety/` |
| Input collection or rendering | `cli.py`, `gui/`, or `tui/` |

Format writers create and validate unpublished candidates. They do not choose
final targets or overwrite policy, and the only publisher is
`safety/artifact_transaction.py`.

### What not to add

Do not add private, licensed, institutional, or identifying documents. Tests must
build the smallest synthetic data they need at runtime. Do not add IRM bypasses,
signature impersonation, document exploits, or remote password-cracking services.

## Verify

Run from the repository root:

```bash
uv lock --check --offline
uv run ruff check src tests examples scripts site/tests
uv run ruff format --check src tests examples scripts site/tests
uv run pyright
uv run pytest -q --tb=short
```

For the offline distribution build, use a fresh output directory:

```bash
build_dir="$(mktemp -d)"
uv build --offline --no-sources --no-create-gitignore --out-dir "$build_dir"
```

Packaging or entry-point changes also require:

```bash
uv run python scripts/check_distributions.py "$build_dir"
```

That script checks archive boundaries and the six TCSS files, installs each
artifact in its own clean environment, and smokes all three console entry points
outside the checkout.

For static demo work, install the demo group and browser, then run its tests:

```bash
uv sync --locked --all-extras --group demo
uv run --group demo playwright install chromium
uv run --group demo pytest site/tests -q
```

The demo dependency group does not change installed package requirements, and
the checks are listed in [site/README.md](site/README.md). Terminal changes need
a manual pass over focus order, labels, narrow layouts, busy states, and failure
messages.

## Open a pull request

State clearly:

- the behavior changed and the formats affected;
- security, compatibility, and output-safety implications;
- the exact checks run and their results;
- dependency, viewer, platform, or clean-install validation you did not perform.

Do not mix unrelated formatting or documentation changes into a functional
patch, and do not commit generated captures.
