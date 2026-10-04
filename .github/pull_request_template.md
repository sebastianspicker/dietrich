## Summary

Describe the behavior changed, formats affected, and reason for the change.

## Verification

List the exact commands and results. Identify checks that were not run.

## Checklist

- [ ] `uv lock --check --offline`
- [ ] `uv run ruff check src examples scripts`
- [ ] `uv run ruff format --check src examples scripts`
- [ ] `uv run pyright`
- [ ] Current documentation reflects changed behavior
- [ ] No fixtures, generated captures, or confidential documents are included
- [ ] Output collision, malformed input, and unsupported cases fail explicitly
- [ ] Security and compatibility limits are stated
