"""Console-module entrypoint and optional TUI wrapper contracts."""

from __future__ import annotations

import builtins
import runpy
from typing import Any

import pytest


def test_python_m_dietrich_exits_with_cli_result(monkeypatch: pytest.MonkeyPatch) -> None:
    import dietrich.cli

    monkeypatch.setattr(dietrich.cli, "main", lambda: 7)

    with pytest.raises(SystemExit) as caught:
        runpy.run_module("dietrich.__main__", run_name="__main__")

    assert caught.value.code == 7


def test_python_m_tui_exits_with_tui_result(monkeypatch: pytest.MonkeyPatch) -> None:
    import dietrich.tui

    monkeypatch.setattr(dietrich.tui, "main", lambda: 3)

    with pytest.raises(SystemExit) as caught:
        runpy.run_module("dietrich.tui.__main__", run_name="__main__")

    assert caught.value.code == 3


def test_tui_main_forwards_initial_path(monkeypatch: pytest.MonkeyPatch) -> None:
    import dietrich.tui

    received: list[str | None] = []
    monkeypatch.setattr(
        dietrich.tui,
        "run_tui",
        lambda initial_path=None: received.append(initial_path) or 0,
    )

    assert dietrich.tui.main(["report.xlsx"]) == 0
    assert received == ["report.xlsx"]


def test_tui_main_reports_missing_dependency(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import dietrich.tui
    from dietrich.errors import MissingDependencyError

    def missing(*, initial_path=None):
        del initial_path
        raise MissingDependencyError("install UI support")

    monkeypatch.setattr(dietrich.tui, "run_tui", missing)

    assert dietrich.tui.main([]) == 3
    assert capsys.readouterr().err == "error: install UI support\n"


def test_tui_wrapper_translates_missing_textual_import(monkeypatch: pytest.MonkeyPatch) -> None:
    import dietrich.tui
    from dietrich.errors import MissingDependencyError

    real_import = builtins.__import__

    def import_without_textual(
        name: str,
        globals: dict[str, Any] | None = None,
        locals: dict[str, Any] | None = None,
        fromlist: tuple[str, ...] = (),
        level: int = 0,
    ) -> Any:
        if name == "dietrich.tui.app":
            raise ImportError("missing textual", name="textual")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", import_without_textual)

    with pytest.raises(MissingDependencyError, match=r"dietrich\[ui\]"):
        dietrich.tui.run_tui("report.xlsx")
