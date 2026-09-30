# Local graphical interface

`dietrich-gui` opens a graphical interface for the existing local document
operations. It serves bundled HTML, CSS, JavaScript, fonts, and pixel artwork
from a short-lived Python process on `127.0.0.1`. The separate `site/`
demonstration remains a static simulation.

The [README screenshot tour](../README.md#screenshot-tour) shows the four-step
flow on a synthetic workbook.

## Start and stop

```bash
dietrich-gui
dietrich-gui /path/to/report.xlsx
dietrich-gui --no-browser
```

The launcher picks an available port unless you pass `--port`. Its URL contains a
random session token, so keep it private: anyone who has the URL can use this
session's file chooser and operations. Do not forward or proxy the port to
another computer.

Press Ctrl+C in the launching terminal to stop. Active work receives a
cooperative cancellation request, and the launcher waits for cleanup; if final
publication has already begun, it waits for the result. Closing the tab does not
stop Python or cancel the operation, but reloading the full session URL
reconnects to it. No separate desktop toolkit is required, and format
dependencies are the same extras used by the command line.

## Task flow

1. **Choose a file.** Use the in-app file chooser or type a full path. The
   chooser lists local directory metadata; it does not upload a document.
2. **Review.** Check the detected protections, encryption, signatures,
   capabilities, and blockers. Select supported protection categories and a
   separate output filename and folder. The default stays `NAME_unprotected.EXT`.
3. **Create the working copy.** The interface shows the backend's current phase
   and waits for validation and publication. Cancel waits for the active
   operation to reach a checkpoint and finish cleanup.
4. **Read the result.** Check the output path, actual removal counts, and
   warnings. Dietrich validates the file structure; it does not verify
   appearance or behavior in Office or other viewers.

Advanced controls keep the known-password input, wordlists, masks, character-set
search, candidate and worker limits, hashcat and its timeout, explicit signature
stripping, experimental VBA verifier clearing, paired re-signing material, and
explicit replacement of a separate existing output. Recovery hashes can be shown
in hashcat or John the Ripper format for manual copying. Recovered passwords are
never included in HTTP results or the completion screen.

## What the adapter refuses

- Rights-management blockers cannot be overridden.
- Signed OOXML requires an explicit choice to create an unsigned copy.
- Missing optional dependencies are reported, not installed.
- A destination that resolves to the source, or that is the same existing file
  including hard links, is rejected.
- The input suffix is preserved to avoid misleading document names.

The graphical flow does not replace the CLI or TUI. Existing entry points,
arguments, output naming, format support, and publication rules all remain
intact.

## Look and interaction

The interface presents one stage at a time. Brass frames and controls, indigo
surfaces, cyan selection indicators, green confirmations, pixel headings, and
lock-and-document artwork follow the approved locksmith design. Text, checkboxes,
fields, navigation, and status indicators are real browser elements; the
decorative artwork never functions as a lock-picking game.

At narrow widths the form, destination controls, and artwork stack vertically,
and full paths wrap when required. Native buttons, labeled inputs, focus
indicators, dialog focus restoration, announced status changes, and
reduced-motion styles support keyboard and assistive-technology use. Recent paths
live in browser memory for the current page only. There is no browser storage,
analytics, remote fonts, or external runtime assets.

The four-panel design reference is a sequence, not four simultaneously visible
windows. Compared with it, the working application drops simulation and
design-concept labels, uses real filenames and counts with the established
default suffix, adds the existing advanced functions, and provides a local
directory dialog instead of an OS-specific file picker.

## Adapter boundaries

Only authenticated JSON requests operate on documents. Requests carry the session
token in a header and are checked against the loopback Host and Origin. The token
begins in the URL fragment so it never appears as an HTTP URL parameter. Static
routes serve an explicit set of bundled assets, not arbitrary local paths, and
API payload and directory listing sizes are bounded.

The Python controller owns one operation and its cancellation control. It calls
`dispatch.py`; format policy, password verification, candidate validation, and
the sole output-publication transaction stay in their existing modules. The
browser polls operation IDs and phases without estimating percentages or
remaining time, and it cannot interrupt the final publication boundary.

This is a trusted local operator interface, not a multi-user service. Its token
does not protect against software that already has access to the user's browser
or local account. Stop the process when you are done.

## Verification

The regular Python gate covers the HTTP adapter and real synthetic-document
operations. Browser tests additionally exercise real file selection, review,
category selection, successful output, collisions, signatures, rights-management
blocking, PDF password retry and hash export, keyboard behavior, and narrow
layouts.

```bash
uv sync --locked --all-extras --group demo
uv run --group demo playwright install chromium
uv run pytest tests/test_gui_backend.py -q
uv run --group demo pytest tests/test_gui_browser.py -q
```

Browser screenshots are written to `/tmp/dietrich-gui-*.png`. Tests are skipped
when Playwright is not installed; CI runs them explicitly in the browser job.
Both built distributions include the graphical assets and font licenses, and
`scripts/check_distributions.py` checks them and starts each installed adapter
outside the checkout.

The bundled Pixelify Sans and VT323 fonts retain their SIL Open Font Licenses,
and asset provenance is recorded in `src/dietrich/gui/assets/SOURCES.md`.
