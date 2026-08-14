"""Canonical Dietrich brand strings and Werkbank color tokens.

Import-safe for the zero-dependency CLI core - no Textual/Rich imports.
TUI theming builds on these constants in :mod:`dietrich.tui.theme`.
"""

from __future__ import annotations

from typing import TypedDict

# --- Product identity -------------------------------------------------------

PRODUCT_NAME = "Dietrich"
TAGLINE = "the office picklock"
SUBTITLE = f"{TAGLINE} - authorized use only"
HELP_DESCRIPTION = (
    "Dietrich - the office picklock. Remove soft protection and recover open "
    "passwords from Office and PDF documents you own or are authorized to modify. "
    "(German: Dietrich = picklock; also a classic first name.)"
)
AUTHORIZED_PLAQUE = (
    "AUTHORIZED USE ONLY · Documents you own or may modify · "
    "Soft locks ≠ encryption · IRM / Purview requires a valid license"
)
HELP_EPILOG = (
    "Authorized use only - unlock documents you own or may modify. "
    "Soft locks are not encryption; IRM/Purview cannot be removed without a license."
)

# Interface palette shared with the packaged Textual styles.

NIGHT_SLATE = "#12161C"  # canvas / background
BENCH_IRON = "#1B222C"  # surface / panel
DRAWER = "#252E3A"  # raised / input fill (CSS-only)
COLD_SEAM = "#3A4656"  # hairline / border (CSS-only)
PAPER_GRAY = "#D7DDE6"  # body ink / foreground
FILING = "#8B97A8"  # mute / secondary ink (CSS-only)
OXIDIZED_BRASS = "#C4A35A"  # Action → Textual primary (Unlock)
STAMP_BLUE = "#4F7CAC"  # Signal → Textual secondary + accent (Inspect / plaque)
OIL_GREEN = "#5F8F6B"  # success
AMBER_KEY = "#C9893A"  # warning
SEAL_RED = "#B54A4A"  # error
COOL_LEDGER = "#E8ECF1"  # light canvas (docs optional)
CARBON = "#1A1F27"  # light ink (docs optional)

# Theme name registered with Textual App.
THEME_NAME = "dietrich"


# Kwargs for textual.theme.Theme - brand.py stays free of Textual imports.
# Palette role Action (brass) → primary; Signal (stamp blue) → secondary+accent.
# Never map Textual accent to brass.
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
