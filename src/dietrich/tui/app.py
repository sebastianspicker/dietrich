"""Filing Bench TUI shell: compose + dossier + session recent + workers."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from textual import events, on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    Log,
    OptionList,
    Static,
)
from textual.widgets.option_list import Option

from dietrich.brand import PRODUCT_NAME, SUBTITLE
from dietrich.dispatch import export_document_hash, inspect_document, unlock_document
from dietrich.errors import DietrichError
from dietrich.tui.compose import compose_app
from dietrich.tui.dossier import (
    DossierView,
    busy_dossier,
    error_dossier,
    format_dossier_body,
    from_inspection,
    from_unlock_result,
)
from dietrich.tui.options_map import (
    FormState,
    default_output_path,
    form_state_from_widgets,
    validate_and_build,
)
from dietrich.tui.session_history import RecentSession, note_from_inspection
from dietrich.tui.theme import register_dietrich_theme
from dietrich.types import DocumentInspection, UnlockOptions, UnlockResult

# Styles live under tui/styles/ (split for maintainability; loaded relative to this module).
_STYLE_FILES = (
    "styles/base.tcss",
    "styles/chrome.tcss",
    "styles/session.tcss",
    "styles/dossier.tcss",
    "styles/forms.tcss",
    "styles/compact.tcss",
)


class DietrichApp(App[None]):
    """Full-screen Dietrich picklock UI."""

    TITLE = PRODUCT_NAME
    SUB_TITLE = SUBTITLE
    CSS_PATH = list(_STYLE_FILES)

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("i", "inspect", "Inspect"),
        Binding("u", "unlock", "Unlock"),
        Binding("e", "export_hash", "Export hash"),
        Binding("question_mark", "help", "Help"),
    ]

    def __init__(self, initial_path: str | Path | None = None) -> None:
        """Optional initial file path is inspected automatically on mount."""
        super().__init__()
        self._initial_path = str(initial_path) if initial_path else ""
        self._inspection: DocumentInspection | None = None
        self._busy = False
        self._session = RecentSession()

    def compose(self) -> ComposeResult:
        """Build the Filing Bench workbench (see compose.py)."""
        yield from compose_app(self._initial_path)

    def on_mount(self) -> None:
        """Register Werkbank theme, seed the log, auto-inspect when given a path."""
        theme_name = register_dietrich_theme(self)
        self.theme = theme_name
        self._apply_responsive_layout(self.size.width, self.size.height)
        self._refresh_recent_list()
        self._log("Ready · Tab to navigate · i inspect · u unlock · e export hash · q quit")
        if self._initial_path:
            seed = Path(self._initial_path).expanduser()
            if seed.is_file():
                self._session.remember(seed, note="opened")
                self._refresh_recent_list()
            self._suggest_output(seed)
            self.action_inspect()

    def on_resize(self, event: events.Resize) -> None:
        """Adapt secondary chrome and density to the available terminal cells."""
        self._apply_responsive_layout(event.size.width, event.size.height)

    def _apply_responsive_layout(self, width: int, height: int) -> None:
        """Keep the primary workbench usable in ordinary 80-column terminals."""
        self.query_one("#session-rail", Vertical).display = width >= 120 and height >= 36
        self.screen.set_class(height < 36, "-compact-height")
        self.screen.set_class(width < 90, "-compact-width")

    def _log(self, message: str) -> None:
        """Append one line to the activity log."""
        timestamp = datetime.now().time().isoformat(timespec="seconds")
        self.query_one("#log", Log).write_line(f"{timestamp}  {message}")

    def _refresh_recent_list(self) -> None:
        """Rebuild the session rail OptionList from in-memory history."""
        option_list = self.query_one("#recent-list", OptionList)
        empty = self.query_one("#session-empty", Static)
        entries = self._session.items()
        option_list.clear_options()
        if not entries:
            empty.set_class(True, "-visible")
            return
        empty.set_class(False, "-visible")
        option_list.add_options([Option(entry.prompt(), id=entry.option_id) for entry in entries])

    def _remember_path(self, path: Path, *, note: str | None = None) -> None:
        """Pin a path to the session recent list and refresh the rail."""
        self._session.remember(path, note=note)
        self._refresh_recent_list()

    _STATUS_CLASSES = ("-status-info", "-status-ok", "-status-warning", "-status-error")

    def _apply_dossier(self, view: DossierView) -> None:
        """Map a Protection Dossier view-model onto status panel widgets."""
        body = format_dossier_body(view)
        status_text = "\n".join(body) if body else (view.lede or " ")
        self.query_one("#status", Static).update(status_text)
        panel = self.query_one("#status-panel", Vertical)
        panel.remove_class(*self._STATUS_CLASSES)
        panel.add_class(f"-status-{view.state}")
        self.query_one("#status-heading", Static).update(view.heading)
        self.query_one("#status-meta", Static).update(view.metadata)

    def _set_busy(self, busy: bool) -> None:
        """Disable action buttons while a background job runs (visible busy state)."""
        self._busy = busy
        for wid in ("btn-inspect", "btn-unlock", "btn-export"):
            self.query_one(f"#{wid}", Button).disabled = busy
        self.query_one("#session-state", Static).update("WORKING" if busy else "READY")
        foot = "● working · no network" if busy else "● ready · no network"
        self.query_one("#session-foot", Static).update(foot)

    @property
    def is_busy(self) -> bool:
        """Return whether a background document operation is running."""
        return self._busy

    def _input_path(self) -> Path | None:
        """Return a validated existing file path, or log+show an error and return None."""
        raw = self.query_one("#input-path", Input).value.strip()
        if not raw:
            message = "Choose a file path first."
            self._log("error: choose a file path first")
            self._apply_dossier(error_dossier("INPUT REQUIRED", message))
            self.query_one("#input-path", Input).focus()
            return None
        path = Path(raw).expanduser()
        self._update_file_kind(path)
        if not path.is_file():
            message = f"File not found: {path}"
            self._log(f"error: file not found: {path}")
            self._apply_dossier(error_dossier("FILE NOT FOUND", message))
            self.query_one("#input-path", Input).focus()
            return None
        return path

    def _suggest_output(self, input_path: Path) -> None:
        """Fill default stem_unprotected output path when the field is empty."""
        self._update_file_kind(input_path)
        out = self.query_one("#output-path", Input)
        if not out.value.strip():
            out.value = str(default_output_path(input_path))

    def _update_file_kind(self, path: Path) -> None:
        """Show the selected document suffix as compact local metadata."""
        suffix = path.suffix.removeprefix(".").upper()
        self.query_one("#file-kind", Static).update(suffix or "FILE")

    def _form_state(self) -> FormState:
        """Read Advanced + overwrite controls into a FormState snapshot."""

        def val(wid: str) -> str:
            """Read an Input widget value by id."""
            return self.query_one(f"#{wid}", Input).value

        def chk(wid: str) -> bool:
            """Read a Checkbox value by id."""
            return self.query_one(f"#{wid}", Checkbox).value

        return form_state_from_widgets(
            {
                "password": val("password"),
                "wordlist": val("wordlist"),
                "mask": val("mask"),
                "workers": val("workers"),
                "resign-cert": val("resign-cert"),
                "resign-key": val("resign-key"),
                "hashcat-timeout": val("hashcat-timeout"),
            },
            {
                "chk-soft-only": chk("chk-soft-only"),
                "chk-strip-sig": chk("chk-strip-sig"),
                "chk-vba": chk("chk-vba"),
                "chk-hashcat": chk("chk-hashcat"),
                "chk-overwrite": chk("chk-overwrite"),
            },
        )

    def _load_recent_path(self, path: Path) -> None:
        """Put a recent path into the intake fields and inspect it."""
        self.query_one("#input-path", Input).value = str(path)
        self.query_one("#output-path", Input).value = ""
        self._suggest_output(path)
        self._log(f"session: selected {path.name}")
        self.action_inspect()

    @on(OptionList.OptionSelected, "#recent-list")
    def _on_recent_selected(self, event: OptionList.OptionSelected) -> None:
        """Selecting a recent rail entry loads that path and re-inspects."""
        option_id = event.option_id
        if not option_id:
            return
        entry = self._session.get(option_id)
        if entry is None:
            return
        if self._busy:
            self._log("busy: wait for the current job to finish")
            return
        self._load_recent_path(entry.path)

    @on(Button.Pressed, "#btn-inspect")
    def _on_inspect_btn(self) -> None:
        """Inspect button handler."""
        self.action_inspect()

    @on(Button.Pressed, "#btn-unlock")
    def _on_unlock_btn(self) -> None:
        """Unlock button handler."""
        self.action_unlock()

    @on(Button.Pressed, "#btn-export")
    def _on_export_btn(self) -> None:
        """Export-hash button handler."""
        self.action_export_hash()

    @on(Button.Pressed, "#btn-quit")
    def _on_quit_btn(self) -> None:
        """Quit button handler."""
        self.exit()

    @on(Input.Submitted, "#input-path")
    def _on_path_submit(self) -> None:
        """Enter in the path field triggers inspect."""
        self.action_inspect()

    def action_help(self) -> None:
        """Show a short usage reminder in the log."""
        self._log(
            "Help: paste a file path → Inspect → Unlock. "
            "Wide terminals show a session rail of recent local files. "
            "Open Advanced for password/wordlist/mask, strip signatures, hashcat, resign. "
            "Never use on files you are not authorized to modify."
        )

    def action_inspect(self) -> None:
        """Validate path and start a background inspect job."""
        if self._busy:
            self._log("busy: wait for the current job to finish")
            return
        path = self._input_path()
        if path is None:
            return
        self._suggest_output(path)
        self._set_busy(True)
        self._apply_dossier(busy_dossier("INSPECTING", "Reading local document structure…"))
        self._run_inspect(path)

    @work(exclusive=True, thread=True)
    def _run_inspect(self, path: Path) -> None:
        """Worker: call inspect_document and marshal result back to the UI thread."""
        try:
            inspection = inspect_document(path)
        except DietrichError as exc:
            self.call_from_thread(self._inspect_failed, str(exc))
            return
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self.call_from_thread(self._inspect_failed, f"unexpected: {exc}")
            return
        self.call_from_thread(self._inspect_ok, inspection)

    def _inspect_failed(self, message: str) -> None:
        """UI-thread handler for inspect errors."""
        self._inspection = None
        self._set_busy(False)
        self._apply_dossier(error_dossier("INSPECTION FAILED", f"Inspect failed: {message}"))
        self._log(f"inspect error: {message}")

    def _inspect_ok(self, inspection: DocumentInspection) -> None:
        """UI-thread handler for successful inspect; pin path to session rail."""
        self._inspection = inspection
        self._set_busy(False)
        soft_count = sum(p.count for p in inspection.soft_protections)
        note = note_from_inspection(
            encrypted=inspection.encrypted or inspection.user_password_required,
            soft_count=soft_count,
            signed=inspection.signed,
            owner_restrictions=inspection.owner_restrictions,
        )
        self._remember_path(inspection.input_path, note=note)
        self._apply_dossier(from_inspection(inspection))
        self._log(f"inspect ok: {inspection.input_path.name} → {inspection.document_format.value}")

    def action_unlock(self) -> None:
        """Validate form, then start background unlock_document."""
        if self._busy:
            self._log("busy: wait for the current job to finish")
            return
        path = self._input_path()
        if path is None:
            return
        out_raw = self.query_one("#output-path", Input).value.strip()
        output = Path(out_raw).expanduser() if out_raw else default_output_path(path)
        built = validate_and_build(self._form_state())
        if not built.ok or built.options is None:
            self._log(f"error: {built.error}")
            self._apply_dossier(error_dossier("CHECK OPTIONS", f"Cannot unlock: {built.error}"))
            return
        if built.options.strip_signatures:
            self._log("note: strip signatures enabled - output will be an unsigned working copy")
        if built.options.use_hashcat:
            self._log("note: hashcat mode - requires hashcat on PATH and attack material")
        self._set_busy(True)
        self._apply_dossier(busy_dossier("UNLOCKING", f"Writing side-by-side copy → {output}…"))
        self._log(f"unlock starting → {output}")
        self._run_unlock(path, output, built.options)

    @work(exclusive=True, thread=True)
    def _run_unlock(self, source: Path, target: Path, options: UnlockOptions) -> None:
        """Worker: unlock_document then post success/failure to the UI thread."""
        try:
            result = unlock_document(source, target, options)
        except DietrichError as exc:
            self.call_from_thread(self._unlock_failed, str(exc))
            return
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self.call_from_thread(self._unlock_failed, f"unexpected: {exc}")
            return
        self.call_from_thread(self._unlock_ok, result)

    def _unlock_failed(self, message: str) -> None:
        """UI-thread handler for unlock errors; clears busy flag."""
        self._set_busy(False)
        self._apply_dossier(error_dossier("UNLOCK FAILED", f"Unlock failed: {message}"))
        self._log(f"unlock error: {message}")

    def _unlock_ok(self, result: UnlockResult) -> None:
        """UI-thread handler for unlock success; never echoes passwords."""
        self._set_busy(False)
        self._remember_path(result.input_path, note="unlocked")
        view = from_unlock_result(result)
        self._apply_dossier(view)
        for line in format_dossier_body(view):
            self._log(line)

    def action_export_hash(self) -> None:
        """Export a hashcat-format line for the current file (truncated in log)."""
        if self._busy:
            self._log("busy: wait for the current job to finish")
            return
        path = self._input_path()
        if path is None:
            return
        self._set_busy(True)
        self._run_export(path)

    @work(exclusive=True, thread=True)
    def _run_export(self, path: Path) -> None:
        """Worker: export_document_hash and log a truncated line."""
        try:
            line = export_document_hash(path, "hashcat")
        except DietrichError as exc:
            self.call_from_thread(self._export_done, f"export-hash error: {exc}")
            return
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self.call_from_thread(self._export_done, f"export-hash unexpected: {exc}")
            return
        display = line if len(line) <= 160 else line[:140] + "…"
        self.call_from_thread(self._export_done, f"hashcat line: {display}")

    def _export_done(self, message: str) -> None:
        """UI-thread handler for export-hash completion; clears busy flag."""
        self._set_busy(False)
        self._log(message)


def run_tui(initial_path: str | Path | None = None) -> int:
    """Launch the Textual TUI; return process exit code."""
    app = DietrichApp(initial_path=initial_path)
    app.run()
    return 0
