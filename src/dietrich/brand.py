"""Shared product strings and terminal-interface color tokens."""

from __future__ import annotations

from typing import TypedDict

PRODUCT_NAME = "Dietrich"
TAGLINE = "the office picklock"
SUBTITLE = f"{TAGLINE} - authorized use only"
HELP_DESCRIPTION = (
    "Inspect document protection, remove soft protection, and recover open passwords "
    "from authorized Office and PDF documents."
)
AUTHORIZED_PLAQUE = (
    "AUTHORIZED USE ONLY · Documents you own or may modify · "
    "Soft locks ≠ encryption · IRM / Purview requires a valid license"
)
HELP_EPILOG = (
    "Use only on documents you own or may modify. IRM/Purview-protected documents "
    "require a valid license and are not modified."
)

NIGHT_SLATE = "#0F141A"  # canvas / background
BENCH_IRON = "#151B23"  # surface / panel
DRAWER = "#1C242F"  # raised / input fill (CSS-only)
OVERLAY = "#232D3A"  # selected / nested surface (CSS-only)
COLD_SEAM = "#2A3442"  # hairline / border (CSS-only)
PAPER_GRAY = "#E4E9F0"  # body ink / foreground
FILING = "#9AA6B6"  # mute / secondary ink (CSS-only)
FILING_FAINT = "#8896A9"  # tertiary ink (CSS-only)
OXIDIZED_BRASS = "#D4B36A"  # action text / primary
BRASS_FILL = "#C4A35A"  # primary action fill (CSS-only)
STAMP_BLUE = "#8FB4DC"  # signal / inspection accent
SIGNAL_FILL = "#35587E"  # signal fill (CSS-only)
OIL_GREEN = "#82B58F"  # success
AMBER_KEY = "#D9A45B"  # warning
SEAL_RED = "#D37C6E"  # error
COOL_LEDGER = "#E8ECF1"  # light canvas (docs optional)
CARBON = "#1A1F27"  # light ink (docs optional)

THEME_NAME = "dietrich"


class WerkbankThemeKwargs(TypedDict):
    """Precisely typed arguments shared with Textual's Theme constructor."""

    name: str
    primary: str
    secondary: str
    accent: str
    foreground: str
    background: str
    surface: str
    panel: str
    error: str
    warning: str
    success: str
    dark: bool


WERKBANK_THEME_KWARGS: WerkbankThemeKwargs = {
    "name": THEME_NAME,
    "primary": OXIDIZED_BRASS,
    "secondary": STAMP_BLUE,
    "accent": STAMP_BLUE,
    "foreground": PAPER_GRAY,
    "background": NIGHT_SLATE,
    "surface": BENCH_IRON,
    "panel": BENCH_IRON,
    "error": SEAL_RED,
    "warning": AMBER_KEY,
    "success": OIL_GREEN,
    "dark": True,
}
