"""Stable public facade over Dietrich's application use cases."""

from __future__ import annotations

from pathlib import Path

from dietrich.application.assess import assess_document, assess_excel_workbook
from dietrich.application.hash_export import export_document_hash as _export_document_hash
from dietrich.application.make_editable import make_editable_copy, make_editable_workbook
from dietrich.domain.models import (
    DocumentInspection,
    UnlockOptions,
    UnlockResult,
    WorkbookInspection,
)
from dietrich.errors import UnsupportedFormatError

EXCEL_SUFFIXES = frozenset({".xlsx", ".xlsm"})


def inspect_document(path: Path) -> DocumentInspection:
    """Assess format, protection, capabilities, and local blockers."""
    return assess_document(Path(path))


def inspect_workbook(path: Path) -> WorkbookInspection:
    """Inspect the documented Excel-only compatibility surface."""
    source = Path(path)
    if source.suffix.lower() not in EXCEL_SUFFIXES:
        raise UnsupportedFormatError("Excel workbook helpers support only .xlsx and .xlsm.")
    return assess_excel_workbook(source)


def unlock_workbook(input_path: Path, output_path: Path, options: UnlockOptions) -> UnlockResult:
    """Create an editable copy through the Excel-only compatibility surface."""
    source = Path(input_path)
    if source.suffix.lower() not in EXCEL_SUFFIXES:
        raise UnsupportedFormatError("Excel workbook helpers support only .xlsx and .xlsm.")
    return make_editable_workbook(source, Path(output_path), options)


def unlock_document(
    input_path: Path,
    output_path: Path,
    options: UnlockOptions | None = None,
) -> UnlockResult:
    """Create one validated editable working copy of a supported document."""
    return make_editable_copy(Path(input_path), Path(output_path), options)


def export_document_hash(path: Path, fmt: str = "hashcat") -> str:
    """Export password-recovery material for an Office or PDF document."""
    return _export_document_hash(Path(path), fmt)


__all__ = [
    "export_document_hash",
    "inspect_document",
    "inspect_workbook",
    "unlock_document",
    "unlock_workbook",
]
