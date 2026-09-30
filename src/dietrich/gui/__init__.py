"""Local graphical adapter for Dietrich."""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from dietrich.gui.server import DietrichHTTPServer


def create_server(initial_path: Path | None = None, *, port: int = 0) -> DietrichHTTPServer:
    """Create a loopback-only GUI server without starting its serving loop."""
    from dietrich.gui.server import create_server as _create_server

    return _create_server(initial_path, port=port)


def main(argv: Sequence[str] | None = None) -> int:
    """Launch the local graphical adapter."""
    from dietrich.gui.__main__ import main as _main

    return _main(argv)


__all__ = ["create_server", "main"]
