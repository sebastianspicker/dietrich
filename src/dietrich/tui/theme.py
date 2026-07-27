"""Werkbank Textual theme for the Dietrich TUI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from textual.theme import Theme

from dietrich.brand import THEME_NAME, WERKBANK_THEME_KWARGS

if TYPE_CHECKING:
    from textual.app import App

DIETRICH_THEME = Theme(**WERKBANK_THEME_KWARGS)


def register_dietrich_theme(app: App) -> str:
    """Register the Werkbank theme on app and return its name."""
    app.register_theme(DIETRICH_THEME)
    return THEME_NAME
