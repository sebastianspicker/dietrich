"""Pure compose helpers for DietrichApp widget tree (Filing Bench layout).

App should call: ``yield from compose_app(self._initial_path)``.
No action handlers live here - only the widget tree and static chrome text.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Collapsible,
    Input,
    Label,
    Log,
    OptionList,
    Static,
)

from dietrich import __version__
from dietrich.brand import AUTHORIZED_PLAQUE, SUBTITLE


def compose_chrome() -> ComposeResult:
    """Brand row and authorized plaque."""
    with Horizontal(id="brand-row"):
        with Vertical(id="brand-block"):
            yield Static("⌁  DIETRICH", id="brand-name")
            yield Static(SUBTITLE.replace(" - ", " · "), id="brand-subtitle")
        yield Static(f"ALPHA {__version__} · LOCAL ONLY", id="brand-meta")
    yield Static(AUTHORIZED_PLAQUE, id="banner")


def compose_session_rail() -> ComposeResult:
    """Left session rail: header, live recent OptionList, footer."""
    with Vertical(id="session-rail"):
        yield Static("SESSION · local", id="session-head")
        yield OptionList(id="recent-list", compact=True)
        yield Static(
            "No recent files yet.\nInspect a path to pin it here.",
            id="session-empty",
            classes="-visible",
        )
        yield Static("● ready · no network", id="session-foot")


def compose_path_row(initial_path: str = "") -> ComposeResult:
    """Document intake: path input, file-kind pill, Inspect."""
    yield Static("DOCUMENT", classes="section-label")
    with Horizontal(id="path-row"):
        yield Input(
            value=initial_path,
            placeholder="Path to .xlsx / .docx / .pptx / .pdf / …",
            id="input-path",
        )
        yield Static("FILE", id="file-kind")
        yield Button("Inspect · I", id="btn-inspect")


def compose_status_panel() -> ComposeResult:
    """Protection dossier: heading, meta chips, multi-line body."""
    with Vertical(id="status-panel"):
        with Horizontal(id="status-header"):
            yield Static("READY TO INSPECT", id="status-heading")
            yield Static("SIGNED  -\nIRM GATE  ACTIVE", id="status-meta")
        yield Static(
            "Paste a document path, then Inspect.\nNext · Open a local file, then Inspect.",
            id="status",
        )


def compose_output_row() -> ComposeResult:
    """Output path, preserve-original hint, Unlock primary."""
    yield Static("OUTPUT", classes="section-label")
    with Horizontal(id="out-row"):
        yield Input(
            placeholder="Leave blank for stem_unprotected…",
            id="output-path",
        )
        with Vertical(id="overwrite-block"):
            yield Checkbox("OVERWRITE", id="chk-overwrite")
            yield Static(
                "Preserve original · side-by-side by default",
                id="overwrite-hint",
            )
        yield Button("Unlock working copy · U", id="btn-unlock", variant="primary")


def compose_advanced() -> ComposeResult:
    """Collapsed Advanced form: password, wordlist, mask, flags, resign."""
    with Collapsible(
        title="Advanced · password · wordlist · signatures · hashcat",
        collapsed=True,
        id="advanced",
    ):
        with VerticalScroll(id="adv-grid"):
            with Horizontal():
                yield Label("Password", classes="field-label")
                yield Input(password=True, placeholder="Open password", id="password")
            with Horizontal():
                yield Label("Wordlist", classes="field-label")
                yield Input(placeholder="Path to wordlist.txt", id="wordlist")
            with Horizontal():
                yield Label("Mask", classes="field-label")
                yield Input(placeholder="e.g. ?d?d?d?d", id="mask")
            with Horizontal():
                yield Checkbox("Soft-only", id="chk-soft-only")
                yield Checkbox("Strip signatures", id="chk-strip-sig")
                yield Checkbox("Unlock VBA", id="chk-vba")
                yield Checkbox("Use hashcat", id="chk-hashcat")
            with Horizontal():
                yield Label("Workers", classes="field-label")
                yield Input(value="1", id="workers")
                yield Label("HC timeout", classes="field-label")
                yield Input(placeholder="seconds", id="hashcat-timeout")
            with Horizontal():
                yield Label("Resign cert", classes="field-label")
                yield Input(placeholder="cert.pem", id="resign-cert")
            with Horizontal():
                yield Label("Resign key", classes="field-label")
                yield Input(placeholder="key.pem", id="resign-key")


def compose_secondary_actions() -> ComposeResult:
    """Export hash and Quit utility buttons."""
    with Horizontal(id="secondary-actions"):
        yield Button("Export hash · E", id="btn-export")
        yield Button("Quit · Q", id="btn-quit")


def compose_activity_panel() -> ComposeResult:
    """Activity ledger: session state + scrollable log."""
    with Vertical(id="activity-panel"):
        with Horizontal(id="activity-header"):
            yield Static("ACTIVITY", classes="section-label")
            yield Static("READY", id="session-state")
        yield Log(id="log", highlight=False, max_lines=500)


def compose_main_column(initial_path: str = "") -> ComposeResult:
    """Main workbench column: path → dossier → output → advanced → activity."""
    with Vertical(id="main-column"):
        yield from compose_path_row(initial_path)
        yield from compose_status_panel()
        yield from compose_output_row()
        with Horizontal(id="utility-row"):
            yield from compose_advanced()
            yield from compose_secondary_actions()
        yield from compose_activity_panel()


def compose_key_footer() -> ComposeResult:
    """Bottom binding strip."""
    yield Static(
        "[b reverse] I [/b reverse] Inspect   "
        "[b reverse] U [/b reverse] Unlock   "
        "[b reverse] E [/b reverse] Export hash   "
        "[b reverse] ? [/b reverse] Help   "
        "[b reverse] Q [/b reverse] Quit",
        id="key-footer",
    )


def compose_app(initial_path: str = "") -> ComposeResult:
    """Yield the full Filing Bench widget tree for DietrichApp.compose()."""
    yield from compose_chrome()
    with Horizontal(id="workbench"):
        # Session rail LEFT (mockup: session drawer then main).
        yield from compose_session_rail()
        yield from compose_main_column(initial_path)
    yield from compose_key_footer()
