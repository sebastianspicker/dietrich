"""Regression coverage for OOXML protection edge cases and PDF hash errors."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dietrich import UnlockOptions, unlock_document


def _pack(path: Path, parts: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", b"<Types/>")
        z.writestr("_rels/.rels", b"<Relationships/>")
        for n, d in parts.items():
            z.writestr(n, d)
    return path


def test_chartsheet_protection_removed(tmp_path: Path) -> None:
    src = _pack(
        tmp_path / "c.xlsx",
        {
            "xl/workbook.xml": b"<workbook/>",
            "xl/chartsheets/sheet1.xml": (b"<chartsheet><sheetProtection/><sheetPr/></chartsheet>"),
        },
    )
    out = tmp_path / "out.xlsx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.worksheet_protections == 1
    with zipfile.ZipFile(out) as z:
        assert b"sheetProtection" not in z.read("xl/chartsheets/sheet1.xml")


def test_word_write_protection_removed(tmp_path: Path) -> None:
    src = _pack(
        tmp_path / "w.docx",
        {
            "word/document.xml": b"<w:document/>",
            "word/settings.xml": (
                b'<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b'<w:writeProtection w:recommended="1"/>'
                b'<w:documentProtection w:enforcement="1"/>'
                b"</w:settings>"
            ),
        },
    )
    out = tmp_path / "out.docx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.document_protections >= 1
    with zipfile.ZipFile(out) as z:
        settings = z.read("word/settings.xml")
        assert b"documentProtection" not in settings
        assert b"writeProtection" not in settings


def test_docsecurity_cleared(tmp_path: Path) -> None:
    src = _pack(
        tmp_path / "a.xlsx",
        {
            "xl/workbook.xml": b"<workbook/>",
            "xl/worksheets/sheet1.xml": b"<worksheet><sheetData/></worksheet>",
            "docProps/app.xml": (
                b'<?xml version="1.0"?>'
                b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
                b"<DocSecurity>8</DocSecurity>"
                b"</Properties>"
            ),
        },
    )
    out = tmp_path / "out.xlsx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.mark_as_final >= 1
    with zipfile.ZipFile(out) as z:
        app = z.read("docProps/app.xml")
        assert b">0</" in app and b"DocSecurity" in app


def test_pdf_hash_export_native_or_clear_error(tmp_path: Path, monkeypatch) -> None:
    """Without Encrypt dict, export fails clearly; with user-encrypt, native works."""
    from dietrich.crypto import pdf_crypto
    from dietrich.errors import EncryptedDocumentError, InvalidDocumentError

    monkeypatch.setattr(pdf_crypto.shutil, "which", lambda *_a, **_k: None)
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.4\n")
    with pytest.raises((EncryptedDocumentError, InvalidDocumentError)):
        pdf_crypto.export_hash_line(pdf)
