# Command and terminal captures

Refresh the command text and Textual SVG files with:

```bash
python -m pip install -e '.[full]'
python scripts/capture_screenshots.py
```

| File | Command or state |
|------|------|
| `01-help.txt` | `dietrich --help` |
| `02-inspect-encrypted.txt` | Inspect an Agile-encrypted fixture |
| `03-soft-xlsx.txt` | Remove protection from `.xlsx` |
| `04-soft-binary.txt` | Process a legacy `.xls` fixture |
| `05-password-unlock.txt` | Decrypt with an open password |
| `06-export-hash.txt` | `--export-hash hashcat` (truncated) |
| `07-pdf-permissions.txt` | Remove PDF encryption and permissions |
| `08-json-inspect.txt` | `--inspect --json` |
| `09-worksheets-only.txt` | Use `--worksheets-only` |
| `10-soft-only-error.txt` | Reject encryption with `--soft-only` |
| `11-strip-signatures.txt` | Reject and explicitly strip signatures |

## Textual TUI captures

The script renders these SVGs from fixed application states. Paths and activity
timestamps are normalized:

| File | State |
|------|---------|
| `werkbank-tui-chrome.svg` | Empty interface at 140 by 40 terminal cells |
| `werkbank-tui-smoke.svg` | Inspected protected workbook at 160 by 50 |
| `werkbank-tui-smoke-export.svg` | Encrypted workbook after hash export at 160 by 50 |

The recent-path rail appears in sufficiently wide terminals and stores paths only
for the current process.

Run `dietrich --tui` after installing the `ui` or `full` extra for an interactive
check.

## Fixtures

- `tests/fixtures/example_password.xlsx` (password `Password1234_`)
- `tests/fixtures/plain.xls`
- OOXML and PDF files created in a temporary directory during capture

Captured paths do not contain machine-local absolute paths.
