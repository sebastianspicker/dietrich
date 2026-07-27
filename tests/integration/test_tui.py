"""TUI option mapping, CLI wiring, composition, and state integration tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from dietrich.tui.copy import format_label, summarize_inspection, summarize_result
from dietrich.tui.options_map import FormState, default_output_path, validate_and_build
from dietrich.types import (
    DocumentFormat,
    DocumentInspection,
    ProtectedPart,
    RemovalCounts,
    UnlockResult,
)


def test_default_output_path() -> None:
    assert default_output_path(Path("a/b/report.xlsx")) == Path("a/b/report_unprotected.xlsx")


def test_validate_password_and_defaults() -> None:
    result = validate_and_build(FormState(password="secret", overwrite=True))
    assert result.ok
    assert result.options is not None
    assert result.options.password == "secret"
    assert result.options.overwrite is True
    assert result.options.strip_signatures is False
    assert result.options.use_hashcat is False


def test_validate_resign_pair_required() -> None:
    result = validate_and_build(FormState(resign_cert="cert.pem"))
    assert not result.ok
    assert result.error and "both" in result.error.lower()


def test_validate_hashcat_needs_material() -> None:
    result = validate_and_build(FormState(use_hashcat=True))
    assert not result.ok
    assert result.error and "hashcat" in result.error.lower()


def test_validate_hashcat_with_mask() -> None:
    result = validate_and_build(FormState(use_hashcat=True, mask="?d?d?d?d"))
    assert result.ok
    assert result.options is not None
    assert result.options.use_hashcat is True
    assert result.options.mask == "?d?d?d?d"


def test_validate_missing_wordlist_path(tmp_path: Path) -> None:
    result = validate_and_build(FormState(wordlist=str(tmp_path / "missing.txt")))
    assert not result.ok
    assert result.error and "not found" in result.error.lower()


def test_summarize_encrypted_inspection() -> None:
    insp = DocumentInspection(
        input_path=Path("secret.xlsx"),
        document_format=DocumentFormat.ENCRYPTED_OOXML,
        strategies=("crypto:ooxml_password",),
        encrypted=True,
        user_password_required=True,
        encryption_scheme="agile",
        encryption_spin_count=100000,
        encryption_cost_class="expensive",
        hashcat_mode=9600,
    )
    lines = "\n".join(summarize_inspection(insp))
    assert "open password" in lines.lower()
    assert "Soft-only" in lines or "soft-only" in lines.lower()
    assert "Authorized use" in lines


def test_summarize_soft_inspection() -> None:
    insp = DocumentInspection(
        input_path=Path("book.xlsx"),
        document_format=DocumentFormat.EXCEL_OOXML,
        strategies=("soft:sheetProtection",),
        soft_protections=(ProtectedPart("xl/worksheets/sheet1.xml", "sheetProtection", 1),),
    )
    lines = "\n".join(summarize_inspection(insp))
    assert "structure locks" in lines.lower() or "sheetProtection" in lines
    assert format_label(DocumentFormat.EXCEL_OOXML)


def test_summarize_result_hides_password() -> None:
    result = UnlockResult(
        input_path=Path("in.xlsx"),
        output_path=Path("out.xlsx"),
        removed=RemovalCounts(worksheet_protections=1),
        password_used="should-not-appear",
        warnings=("note one",),
    )
    text = "\n".join(summarize_result(result))
    assert "should-not-appear" not in text
    assert "not shown" in text.lower() or "successfully" in text.lower()
    assert "out.xlsx" in text


def test_cli_tui_missing_textual(monkeypatch: pytest.MonkeyPatch) -> None:
    import dietrich.tui as tui_pkg
    from dietrich.cli import main
    from dietrich.errors import MissingDependencyError

    def boom(*_a, **_k):
        raise MissingDependencyError(
            "Terminal UI requires Textual. Install with: pip install 'dietrich[ui]'"
        )

    monkeypatch.setattr(tui_pkg, "run_tui", boom)
    code = main(["--tui"])
    assert code == 3


def test_app_constructs() -> None:
    pytest.importorskip("textual")
    from dietrich.tui.app import DietrichApp

    app = DietrichApp(initial_path="examples/out/protected.xlsx")
    assert app.TITLE == "Dietrich"


def test_app_composes_werkbank_workbench() -> None:
    pytest.importorskip("textual")
    from textual.containers import Vertical
    from textual.widgets import Collapsible, OptionList, Static

    from dietrich.tui.app import DietrichApp

    async def exercise() -> None:
        app = DietrichApp()
        async with app.run_test(size=(160, 50)) as pilot:
            assert "DIETRICH" in str(app.query_one("#brand-name", Static).content)
            assert "Export hash" in str(app.query_one("#key-footer", Static).content)
            advanced = app.query_one("#advanced", Collapsible)
            assert advanced.collapsed is True
            assert app.query_one("#session-rail", Vertical).display is True
            assert app.query_one("#recent-list", OptionList) is not None
            assert str(app.query_one("#status-heading", Static).content) == "READY TO INSPECT"

            advanced.collapsed = False
            await pilot.pause()
            assert app.query_one("#password").region.width > 0
            advanced.collapsed = True

            app.action_inspect()
            await pilot.pause()
            assert str(app.query_one("#status-heading", Static).content) == "INPUT REQUIRED"
            assert app.query_one("#status-panel").has_class("-status-error")

            await pilot.resize_terminal(100, 40)
            await pilot.pause()
            assert app.query_one("#session-rail", Vertical).display is False

            await pilot.resize_terminal(100, 30)
            await pilot.pause()
            assert app.screen.has_class("-compact-height")
            assert app.query_one("#activity-panel").region.bottom <= app.size.height - 1
            assert app.query_one("#key-footer").region.bottom == app.size.height

    asyncio.run(exercise())


def test_app_inspection_updates_mockup_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pytest.importorskip("textual")
    from textual.widgets import Input, Static

    import dietrich.tui.app as app_module

    document = tmp_path / "report.xlsx"
    document.touch()
    inspection = DocumentInspection(
        input_path=document,
        document_format=DocumentFormat.EXCEL_OOXML,
        strategies=("soft:sheetProtection",),
        soft_protections=(ProtectedPart("xl/worksheets/sheet1.xml", "sheetProtection", 1),),
    )
    monkeypatch.setattr(app_module, "inspect_document", lambda _path: inspection)

    async def exercise() -> None:
        app = app_module.DietrichApp(initial_path=document)
        async with app.run_test(size=(160, 50)) as pilot:
            await pilot.pause(0.2)
            assert str(app.query_one("#status-heading", Static).content) == ("INSPECTION COMPLETE")
            assert "SIGNED  NO" in str(app.query_one("#status-meta", Static).content)
            assert str(app.query_one("#file-kind", Static).content) == "XLSX"
            assert app.query_one("#output-path", Input).value.endswith("report_unprotected.xlsx")
            # Live session recent list pins the inspected path (MRU).
            assert len(app._session) >= 1
            assert app._session.items()[0].name == "report.xlsx"
            from textual.widgets import OptionList

            recent = app.query_one("#recent-list", OptionList)
            assert recent.option_count >= 1

    asyncio.run(exercise())
