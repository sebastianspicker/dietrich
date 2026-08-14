"""Focused tests for pure TUI background-operation helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Never

from dietrich.errors import DietrichError
from dietrich.tui.tasks import export_hash_message, export_hash_task, inspect_task, unlock_task
from dietrich.types import (
    DocumentFormat,
    DocumentInspection,
    RemovalCounts,
    UnlockOptions,
    UnlockResult,
)


def test_inspect_task_returns_inspection_value() -> None:
    path = Path("report.xlsx")
    expected = DocumentInspection(path, DocumentFormat.EXCEL_OOXML, ())

    result = inspect_task(path, inspect=lambda received: _inspect(received, expected))

    assert result.value is expected
    assert result.failure is None


def test_inspect_task_preserves_known_error_message() -> None:
    result = inspect_task(
        Path("report.xlsx"), inspect=lambda _path: _raise(DietrichError("blocked"))
    )

    assert result.value is None
    assert result.failure is not None
    assert result.failure.message == "blocked"
    assert result.failure.unexpected is False
    assert result.failure.display_message == "blocked"


def test_unlock_task_normalizes_expected_runtime_error() -> None:
    result = unlock_task(
        Path("source.xlsx"),
        Path("output.xlsx"),
        UnlockOptions(),
        unlock=lambda _source, _target, _options: _raise(OSError("disk unavailable")),
    )

    assert result.value is None
    assert result.failure is not None
    assert result.failure.message == "disk unavailable"
    assert result.failure.unexpected is True


def test_unlock_task_normalizes_unclassified_vendor_error() -> None:
    class VendorFailure(Exception):
        pass

    result = unlock_task(
        Path("source.xlsx"),
        Path("output.xlsx"),
        UnlockOptions(),
        unlock=lambda _source, _target, _options: _raise(VendorFailure("vendor failed")),
    )

    assert result.value is None
    assert result.failure is not None
    assert result.failure.message == "vendor failed"
    assert result.failure.unexpected is True


def test_unlock_task_passes_source_target_and_options() -> None:
    source = Path("source.xlsx")
    target = Path("output.xlsx")
    options = UnlockOptions(soft_only=True)
    expected = UnlockResult(source, target, RemovalCounts())
    received: tuple[Path, Path, UnlockOptions] | None = None

    def unlock(input_path: Path, output_path: Path, built_options: UnlockOptions) -> UnlockResult:
        nonlocal received
        received = (input_path, output_path, built_options)
        return expected

    result = unlock_task(source, target, options, unlock=unlock)

    assert result.value is expected
    assert result.failure is None
    assert received == (source, target, options)


def test_export_hash_message_preserves_prefixes_and_truncation() -> None:
    path = Path("report.xlsx")
    line = "h" * 161

    success = export_hash_task(path, export=lambda _path, fmt: _export(fmt, line))
    known_error = export_hash_task(
        path, export=lambda _path, _fmt: _raise(DietrichError("blocked"))
    )
    unexpected_error = export_hash_task(
        path, export=lambda _path, _fmt: _raise(ValueError("bad data"))
    )

    assert export_hash_message(success) == f"hashcat line: {'h' * 140}…"
    assert export_hash_message(known_error) == "export-hash error: blocked"
    assert export_hash_message(unexpected_error) == "export-hash unexpected: bad data"


def _inspect(path: Path, expected: DocumentInspection) -> DocumentInspection:
    """Assert that the task forwards the selected source path."""
    assert path == expected.input_path
    return expected


def _export(fmt: str, line: str) -> str:
    """Assert hash export's fixed format argument."""
    assert fmt == "hashcat"
    return line


def _raise(error: Exception) -> Never:
    """Raise typed test errors from dependency-injected callables."""
    raise error
