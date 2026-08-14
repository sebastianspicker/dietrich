"""Cross-format processing, classification, and optional feature tests."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dietrich import (
    SignedDocumentError,
    UnlockOptions,
    UnsupportedFormatError,
    inspect_document,
    unlock_document,
)
from dietrich.crypto.attack import expand_mask, run_attack
from dietrich.types import AttackOptions, DocumentFormat
from tests.support.ooxml import write_ooxml

_minimal_ooxml = write_ooxml


def test_word_document_protection_removed(tmp_path: Path) -> None:
    settings = b"""<?xml version="1.0" encoding="UTF-8"?>
    <w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
      <w:documentProtection w:edit="readOnly" w:enforcement="1"/>
    </w:settings>
    """
    src = _minimal_ooxml(
        tmp_path / "doc.docx",
        {
            "word/document.xml": b"<w:document/>",
            "word/settings.xml": settings,
        },
    )
    out = tmp_path / "doc_unprotected.docx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.document_protections == 1
    with zipfile.ZipFile(out) as zf:
        assert b"documentProtection" not in zf.read("word/settings.xml")


def test_powerpoint_modify_verifier_removed(tmp_path: Path) -> None:
    presentation = b"""<?xml version="1.0" encoding="UTF-8"?>
    <p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
      <p:modifyVerifier p:algorithmName="SHA-512" p:hashValue="abc"/>
    </p:presentation>
    """
    src = _minimal_ooxml(
        tmp_path / "deck.pptx",
        {"ppt/presentation.xml": presentation},
    )
    out = tmp_path / "deck_unprotected.pptx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.modify_verifiers == 1
    with zipfile.ZipFile(out) as zf:
        assert b"modifyVerifier" not in zf.read("ppt/presentation.xml")


def test_inspect_classifies_excel_zip(tmp_path: Path) -> None:
    src = _minimal_ooxml(
        tmp_path / "book.xlsx",
        {
            "xl/workbook.xml": b"<workbook/>",
            "xl/worksheets/sheet1.xml": b"<worksheet><sheetProtection/></worksheet>",
        },
    )
    inspection = inspect_document(src)
    assert inspection.document_format == DocumentFormat.EXCEL_OOXML
    assert any(p.kind == "sheetProtection" for p in inspection.soft_protections)


def test_signed_package_rejected_without_flag(tmp_path: Path) -> None:
    src = _minimal_ooxml(
        tmp_path / "signed.xlsx",
        {
            "xl/workbook.xml": b"<workbook/>",
            "xl/worksheets/sheet1.xml": b"<worksheet/>",
            "_xmlsignatures/sig1.xml": b"<sig/>",
        },
    )
    with pytest.raises(SignedDocumentError):
        unlock_document(src, tmp_path / "out.xlsx", UnlockOptions())


def test_strip_signatures_allows_unsigned_copy(tmp_path: Path) -> None:
    src = _minimal_ooxml(
        tmp_path / "signed.xlsx",
        {
            "xl/workbook.xml": b'<workbook><workbookProtection lockStructure="1"/></workbook>',
            "xl/worksheets/sheet1.xml": b"<worksheet><sheetProtection/></worksheet>",
            "_xmlsignatures/sig1.xml": b"<sig/>",
        },
    )
    out = tmp_path / "out.xlsx"
    result = unlock_document(src, out, UnlockOptions(strip_signatures=True))
    assert result.removed.signatures_stripped == 1
    assert result.warnings
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert not any(n.startswith("_xmlsignatures/") for n in names)
        assert b"sheetProtection" not in zf.read("xl/worksheets/sheet1.xml")


def test_mask_attack_finds_password() -> None:
    result = run_attack(
        lambda pw: pw == "42",
        AttackOptions(mask="?d?d", try_empty=False, max_candidates=1000),
    )
    assert result.success
    assert result.password == "42"


def test_expand_mask_literals() -> None:
    values = list(expand_mask("ab?d"))
    assert "ab0" in values
    assert "ab9" in values
    assert len(values) == 10


def test_unknown_suffix_rejected(tmp_path: Path) -> None:
    path = tmp_path / "note.txt"
    path.write_text("hello")
    with pytest.raises(UnsupportedFormatError):
        unlock_document(path, tmp_path / "out.txt", UnlockOptions())


def test_vba_unlock_opt_in(tmp_path: Path) -> None:
    vba = b'CMG="AB"\r\nDPB="CD"\r\nGC="EF"\r\n'
    src = _minimal_ooxml(
        tmp_path / "macro.xlsm",
        {
            "xl/workbook.xml": b"<workbook/>",
            "xl/worksheets/sheet1.xml": b"<worksheet/>",
            "xl/vbaProject.bin": vba,
        },
    )
    out = tmp_path / "macro_out.xlsm"
    result = unlock_document(src, out, UnlockOptions(unlock_vba=True))
    assert result.removed.vba_unlocked >= 1
    with zipfile.ZipFile(out) as zf:
        data = zf.read("xl/vbaProject.bin")
        assert b'DPB=""' in data


def test_research_fuzz_generates_files(tmp_path: Path) -> None:
    from dietrich.research.fuzz_gen import generate_ooxml_mutants

    src = _minimal_ooxml(
        tmp_path / "seed.xlsx",
        {"xl/workbook.xml": b"<workbook/>"},
    )
    out_dir = tmp_path / "mutants"
    paths = generate_ooxml_mutants(src, out_dir, count=3, seed=1)
    assert len(paths) == 3
    assert all(p.exists() for p in paths)


def test_pdf_inspect_without_pikepdf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Encrypt 2 0 R >>\nendobj\n")

    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "pikepdf" or name.startswith("pikepdf."):
            raise ImportError("no pikepdf")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    inspection = inspect_document(pdf)
    assert inspection.document_format == DocumentFormat.PDF
    assert inspection.encrypted
