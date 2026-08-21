# Terminal interface

The optional Textual interface is an adapter over the same operations used by
the CLI. It does not contain a separate document-processing implementation.

## Module ownership

| Module | Responsibility |
|---|---|
| `tui/app.py` | Application lifecycle, actions, background work, and result display |
| `tui/compose.py` | Widget composition |
| `tui/options_map.py` | Conversion from form state to dispatch options |
| `tui/dossier.py` | Inspection and result presentation |
| `tui/session_history.py` | Process-local recent paths, limited to 12 entries |
| `tui/theme.py` | Textual color and style constants |
| `tui/styles/*.tcss` | Layout, component, compact, and session-rail styles |

Document classification, password recovery, rewriting, and output publication
remain under `dietrich.dispatch` and the format packages.

## Layout and interaction

The interface provides input and output paths, operation controls, an inspection
dossier, progress state, and activity messages. A recent-path rail appears only
when the terminal is at least 120 columns wide and 36 rows high. It is hidden in
smaller terminals.

Keyboard actions are:

| Key | Action |
|---|---|
| `i` | Inspect the selected input |
| `u` | Unlock to the selected output |
| `e` | Export a password hash |
| `?` | Open help |
| `q` | Quit |

Long-running operations execute through Textual workers so the event loop remains
responsive. The application disables operation controls while work is active.
Recent paths and activity state are not persisted to disk.

## Styling and packaging

The six TCSS files under `src/dietrich/tui/styles/` are included explicitly in
the Hatchling wheel configuration. Changes to style filenames must be reflected
in `pyproject.toml`.

## Verification

Run:

```bash
pytest -q
```

Review focus order, labels, narrow-terminal layout, busy-state behavior, and
failure messages manually when changing the terminal interface.
