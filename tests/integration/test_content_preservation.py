"""Content-preservation tests across supported document formats."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dietrich import UnlockOptions, inspect_document, unlock_document
from dietrich.types import DocumentFormat
from tests.support.ooxml import protected_docx, protected_pptx, protected_xlsx


def test_xlsx_soft_unlock_preserves_cell_text(tmp_path: Path) -> None:
    src = protected_xlsx(tmp_path / "in.xlsx")
    inspection = inspect_document(src)
    assert inspection.document_format == DocumentFormat.EXCEL_OOXML
    assert any(p.kind == "sheetProtection" for p in inspection.soft_protections)

    out = tmp_path / "out.xlsx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.worksheet_protections == 1
    assert result.removed.workbook_protections == 1
    with zipfile.ZipFile(out) as archive:
        sheet = archive.read("xl/worksheets/sheet1.xml")
        assert b"keep-me" in sheet
        assert b"sheetProtection" not in sheet
        assert b"workbookProtection" not in archive.read("xl/workbook.xml")
        assert archive.testzip() is None


def test_docx_soft_unlock_preserves_body(tmp_path: Path) -> None:
    src = protected_docx(tmp_path / "in.docx")
    out = tmp_path / "out.docx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.document_protections == 1
    with zipfile.ZipFile(out) as archive:
        assert b"keep-me" in archive.read("word/document.xml")
        assert b"documentProtection" not in archive.read("word/settings.xml")


def test_pptx_soft_unlock(tmp_path: Path) -> None:
    src = protected_pptx(tmp_path / "in.pptx")
    out = tmp_path / "out.pptx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.modify_verifiers == 1
    with zipfile.ZipFile(out) as archive:
        assert b"modifyVerifier" not in archive.read("ppt/presentation.xml")


def test_pdf_owner_permissions_strip(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    src = tmp_path / "restricted.pdf"
    out = tmp_path / "open.pdf"
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(200, 200))
    pdf.save(
        src,
        encryption=pikepdf.Encryption(
            owner="owner-secret",
            user="",
            allow=pikepdf.Permissions(extract=False, modify_annotation=False),
        ),
    )
    result = unlock_document(src, out, UnlockOptions())
    assert out.is_file()
    assert result.removed.pdf_permission_strips >= 1
    with pikepdf.open(out) as unlocked:
        assert not unlocked.is_encrypted
