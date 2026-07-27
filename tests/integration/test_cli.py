"""Focused process-level CLI integration tests."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tests.support.fixtures import ENCRYPTED_XLSX, KNOWN_PASSWORD

ROOT = Path(__file__).resolve().parents[2]


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "dietrich", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=check,
    )


def _pack(path: Path, parts: dict[str, bytes]) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        for name, data in parts.items():
            archive.writestr(name, data)
    return path


def test_cli_inspect_and_unlock_xlsx(tmp_path: Path) -> None:
    src = _pack(
        tmp_path / "book.xlsx",
        {
            "xl/workbook.xml": (
                b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<workbookProtection lockStructure="1"/><sheets/></workbook>'
            ),
            "xl/worksheets/sheet1.xml": (
                b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<sheetProtection sheet="1"/><sheetData/></worksheet>'
            ),
        },
    )
    inspect = _run(str(src), "--inspect")
    assert inspect.returncode == 0
    assert "excel_ooxml" in inspect.stdout
    assert (
        "sheetProtection" in inspect.stdout
        or "Worksheet" in inspect.stdout
        or "soft" in inspect.stdout
    )

    out = tmp_path / "book_out.xlsx"
    unlock = _run(str(src), "--output", str(out))
    assert unlock.returncode == 0
    assert "Wrote:" in unlock.stdout
    assert out.is_file()
    with zipfile.ZipFile(out) as archive:
        assert b"sheetProtection" not in archive.read("xl/worksheets/sheet1.xml")
        assert b"workbookProtection" not in archive.read("xl/workbook.xml")


def test_cli_unlock_docx_pptx(tmp_path: Path) -> None:
    docx = _pack(
        tmp_path / "doc.docx",
        {
            "word/document.xml": b"<w:document/>",
            "word/settings.xml": (
                b'<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                b'<w:documentProtection w:enforcement="1"/></w:settings>'
            ),
        },
    )
    pptx = _pack(
        tmp_path / "deck.pptx",
        {
            "ppt/presentation.xml": (
                b'<p:presentation xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
                b'<p:modifyVerifier p:hashValue="x"/></p:presentation>'
            ),
        },
    )
    out_doc = tmp_path / "doc_out.docx"
    out_ppt = tmp_path / "ppt_out.pptx"
    assert _run(str(docx), "--output", str(out_doc)).returncode == 0
    assert _run(str(pptx), "--output", str(out_ppt)).returncode == 0
    with zipfile.ZipFile(out_doc) as zf:
        assert b"documentProtection" not in zf.read("word/settings.xml")
    with zipfile.ZipFile(out_ppt) as zf:
        assert b"modifyVerifier" not in zf.read("ppt/presentation.xml")


def test_cli_worksheets_only_flag(tmp_path: Path) -> None:
    src = _pack(
        tmp_path / "legacy.xlsx",
        {
            "xl/workbook.xml": (
                b'<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<workbookProtection lockStructure="1"/><sheets/></workbook>'
            ),
            "xl/worksheets/sheet1.xml": (
                b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                b'<sheetProtection sheet="1"/><sheetData/></worksheet>'
            ),
        },
    )
    out = tmp_path / "out.xlsx"
    proc = _run(str(src), "--worksheets-only", "--output", str(out))
    assert proc.returncode == 0, proc.stderr
    with zipfile.ZipFile(out) as zf:
        assert b"sheetProtection" not in zf.read("xl/worksheets/sheet1.xml")
        assert b"workbookProtection" in zf.read("xl/workbook.xml")


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_cli_password_and_wordlist(tmp_path: Path) -> None:
    out = tmp_path / "cli_unlocked.xlsx"
    ok = _run(
        str(ENCRYPTED_XLSX),
        "--password",
        KNOWN_PASSWORD,
        "--output",
        str(out),
    )
    assert ok.returncode == 0, ok.stderr
    assert out.is_file()
    assert "Wrote:" in ok.stdout

    wl = tmp_path / "wl.txt"
    wl.write_text(f"nope\n{KNOWN_PASSWORD}\n", encoding="utf-8")
    out2 = tmp_path / "cli_wl.xlsx"
    ok2 = _run(str(ENCRYPTED_XLSX), "--wordlist", str(wl), "--output", str(out2))
    assert ok2.returncode == 0, ok2.stderr
    assert out2.is_file()

    bad = tmp_path / "bad.xlsx"
    fail = _run(
        str(ENCRYPTED_XLSX),
        "--password",
        "wrong",
        "--output",
        str(bad),
        check=False,
    )
    assert fail.returncode != 0
    assert not bad.exists()
