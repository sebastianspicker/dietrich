"""Optional Textual terminal interface for Dietrich."""

from __future__ import annotations

import sys
from pathlib import Path

from dietrich.errors import MissingDependencyError

__all__ = ["run_tui", "main"]


def run_tui(initial_path: str | Path | None = None) -> int:
    """Launch the optional Textual UI with a dependency-specific error."""
    try:
        from dietrich.tui.app import run_tui as launch_tui
    except ImportError as exc:
        if exc.name != "textual":
            raise
        raise MissingDependencyError(
            "Terminal UI requires Textual. Install with: pip install 'dietrich[ui]'"
        ) from exc
    return launch_tui(initial_path=initial_path)


def main(argv: list[str] | None = None) -> int:
    """Entry for ``dietrich-tui`` / ``python -m dietrich.tui``."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"-h", "--help"}:
        print("usage: dietrich-tui [INPUT]")
        print("Launch the optional Textual interface, optionally with an initial document path.")
        return 0
    initial = args[0] if args else None
    try:
        return run_tui(initial_path=initial)
    except MissingDependencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
