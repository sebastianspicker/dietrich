"""End-to-end Textual controller workflows with injected document operations."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Never

import pytest

pytest.importorskip("textual")

from textual.pilot import Pilot  # noqa: E402
from textual.widgets import Input, Static  # noqa: E402

import dietrich.tui.app as app_module  # noqa: E402
from dietrich.types import (  # noqa: E402
    DocumentFormat,
    DocumentInspection,
    RemovalCounts,
    UnlockOptions,
    UnlockResult,
)


def _inspection(path: Path) -> DocumentInspection:
    return DocumentInspection(
        input_path=path,
        document_format=DocumentFormat.EXCEL_OOXML,
        strategies=("soft:sheetProtection",),
    )


@pytest.fixture
def document(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "report.xlsx"
    path.touch()
    monkeypatch.setattr(app_module, "inspect_document", lambda _path: _inspection(path))
    return path


async def _run_app(
    document: Path,
    workflow: Callable[[app_module.DietrichApp, Pilot], Awaitable[None]],
) -> None:
    app = app_module.DietrichApp(initial_path=document)
    async with app.run_test(size=(140, 44)) as pilot:
        await pilot.pause(0.2)
        await workflow(app, pilot)


def test_unlock_workflow_updates_dossier_and_clears_busy_state(
    document: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    expected_output = document.with_name("report_unprotected.xlsx")
    received: list[tuple[Path, Path, UnlockOptions]] = []

    def unlock(source: Path, target: Path, options: UnlockOptions) -> UnlockResult:
        received.append((source, target, options))
        return UnlockResult(
            input_path=source,
            output_path=target,
            document_format=DocumentFormat.EXCEL_OOXML,
            removed=RemovalCounts(worksheet_protections=1),
        )

    monkeypatch.setattr(app_module, "unlock_document", unlock)

    async def workflow(app: app_module.DietrichApp, pilot: Pilot) -> None:
        app.action_unlock()
        await pilot.pause(0.2)

        assert app.is_busy is False
        assert str(app.query_one("#status-heading", Static).content) == "UNLOCK COMPLETE"
        assert received and received[0][:2] == (document, expected_output)
        assert app.query_one("#output-path", Input).value == str(expected_output)

    asyncio.run(_run_app(document, workflow))


def test_unlock_failure_and_invalid_options_leave_controller_ready(
    document: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        app_module,
        "unlock_document",
        lambda _source, _target, _options: _raise(OSError("disk unavailable")),
    )

    async def workflow(app: app_module.DietrichApp, pilot: Pilot) -> None:
        app.action_unlock()
        await pilot.pause(0.2)
        assert app.is_busy is False
        assert str(app.query_one("#status-heading", Static).content) == "UNLOCK FAILED"

        app.query_one("#resign-cert", Input).value = "cert.pem"
        app.action_unlock()
        await pilot.pause()
        assert app.is_busy is False
        assert str(app.query_one("#status-heading", Static).content) == "CHECK OPTIONS"

    asyncio.run(_run_app(document, workflow))


def test_export_hash_workflow_normalizes_vendor_failure(
    document: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        app_module,
        "export_document_hash",
        lambda _path, _fmt: _raise(RuntimeError("backend failed")),
    )

    async def workflow(app: app_module.DietrichApp, pilot: Pilot) -> None:
        messages: list[str] = []
        monkeypatch.setattr(app, "_log", messages.append)
        app.action_export_hash()
        await pilot.pause(0.2)

        assert app.is_busy is False
        assert messages == ["export-hash unexpected: backend failed"]

    asyncio.run(_run_app(document, workflow))


def _raise(error: Exception) -> Never:
    raise error
