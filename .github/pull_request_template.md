## Summary

Describe the behavior changed, formats affected, and reason for the change.

## Verification

List the exact commands and results. Identify checks that were not run.

## Checklist

- [ ] `ruff check src tests scripts examples`
- [ ] `pytest -q`
- [ ] `python scripts/capture_screenshots.py --check`
- [ ] Current documentation reflects changed behavior
- [ ] User-visible captures were refreshed when output changed
- [ ] Fixtures contain no confidential or identifying material
- [ ] Output collision, malformed input, and unsupported cases fail explicitly
- [ ] Security and compatibility limits are stated
