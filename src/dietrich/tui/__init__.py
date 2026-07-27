"""Terminal UI (Textual) for Dietrich - Werkbank Filing Bench.

Modules: compose · dossier · session_history · options_map · theme ·
styles/*.tcss · app shell.
"""

from __future__ import annotations

from dietrich.tui.app import run_tui

__all__ = ["run_tui", "main"]


def main(argv: list[str] | None = None) -> int:
    """Entry for ``dietrich-tui`` / ``python -m dietrich.tui``."""
    import sys

    from dietrich.errors import MissingDependencyError

    args = list(sys.argv[1:] if argv is None else argv)
    initial = args[0] if args else None
    try:
        return run_tui(initial_path=initial)
    except MissingDependencyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
