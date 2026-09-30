# Terminal interface

The optional Textual interface is a thin adapter over the same operations the CLI
uses. It contains no separate document-processing implementation: classification,
password recovery, rewriting, and output publication all stay in the application
services and format packages.

## Module ownership

| Module | Responsibility |
|---|---|
| `tui/app.py` | Application lifecycle, actions, background work, and result display |
| `tui/compose.py` | Widget composition |
| `tui/options_map.py` | Conversion from form state to public operation options |
| `tui/dossier.py` | Inspection and result presentation |
| `tui/session_history.py` | Process-local recent paths, limited to 12 entries |
| `tui/theme.py` | Textual color and style constants |
| `tui/styles/*.tcss` | Layout, component, compact, and session-rail styles |

## Layout and interaction

The interface provides input and output paths, operation controls, an inspection
dossier, progress state, and activity messages. A recent-path rail appears only
when the terminal is at least 120 columns wide and 36 rows high; it stays hidden
in smaller terminals.

Keyboard actions:

| Key | Action |
|---|---|
| `i` | Inspect the selected input |
| `u` | Unlock to the selected output |
| `e` | Export a password hash |
| `?` | Open help |
| `Escape` | Request cancellation of the active operation |
| `q` | Quit after active operation cleanup |

Long-running operations run through Textual workers so the event loop stays
responsive. One active record owns the operation identifier, control, and worker.
Source, destination, options, recent selection, and document actions stay locked
until backend cleanup completes. Cancel requests cooperative cancellation and
shows the current phase; it does not cancel the Textual awaiter. Completion must
match the active identifier. Quit requests cancellation and waits for cleanup; if
publication has begun, it waits for that result. Recent paths and activity state
are never written to disk.

## Styling and packaging

The six TCSS files under `src/dietrich/tui/styles/` are included explicitly in
the Hatchling wheel configuration. If you rename a style file, update
`pyproject.toml` to match.

## Verification

Run:

```bash
uv run pytest tests/test_tui_workbench.py tests/test_tui_lifecycle.py -q
```

When you change the terminal interface, review focus order, labels,
narrow-terminal layout, busy-state behavior, and failure messages manually.
