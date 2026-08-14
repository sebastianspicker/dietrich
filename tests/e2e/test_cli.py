"""Full CLI end-to-end matrix for current command paths.

Uses real subprocess entrypoints. Marked ``e2e`` for selective runs:

    pytest -m e2e -q
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from tests.support.cli import (
    make_restricted_pdf,
    make_self_signed_pem,
    make_user_locked_pdf,
    run_dietrich,
    run_module,
    write_irm_like_xlsx,
    write_signed_xlsx,
)
from tests.support.fixtures import (
    ENCRYPTED_DOCX,
    ENCRYPTED_XLSX,
    KNOWN_PASSWORD,
    PLAIN_DOC,
    PLAIN_PPT,
    PLAIN_XLS,
)
from tests.support.ooxml import protected_docx, protected_pptx, protected_xlsx

pytestmark = pytest.mark.e2e


def test_e2e_help() -> None:
    proc = run_dietrich("--help")
    assert proc.returncode == 0
    assert "Dietrich" in proc.stdout
    assert "--export-hash" in proc.stdout
    assert "--hashcat" in proc.stdout


def test_e2e_soft_xlsx_inspect_unlock_reinsect(tmp_path: Path) -> None:
    src = protected_xlsx(tmp_path / "book.xlsx")
    inspect = run_dietrich(str(src), "--inspect")
    assert inspect.returncode == 0
    assert "excel_ooxml" in inspect.stdout
    assert "sheetProtection" in inspect.stdout or "soft" in inspect.stdout

    out = tmp_path / "book_out.xlsx"
    unlock = run_dietrich(str(src), "--output", str(out))
    assert unlock.returncode == 0, unlock.stderr
    assert "Wrote:" in unlock.stdout
    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        assert b"sheetProtection" not in zf.read("xl/worksheets/sheet1.xml")
        assert b"workbookProtection" not in zf.read("xl/workbook.xml")

    after = run_dietrich(str(out), "--inspect")
    assert after.returncode == 0
    assert "excel_ooxml" in after.stdout


def test_e2e_soft_docx_pptx(tmp_path: Path) -> None:
    docx = protected_docx(tmp_path / "doc.docx")
    pptx = protected_pptx(tmp_path / "deck.pptx")
    out_doc = tmp_path / "doc_out.docx"
    out_ppt = tmp_path / "ppt_out.pptx"
    assert run_dietrich(str(docx), "--output", str(out_doc)).returncode == 0
    assert run_dietrich(str(pptx), "--output", str(out_ppt)).returncode == 0
    with zipfile.ZipFile(out_doc) as zf:
        assert b"documentProtection" not in zf.read("word/settings.xml")
    with zipfile.ZipFile(out_ppt) as zf:
        assert b"modifyVerifier" not in zf.read("ppt/presentation.xml")


@pytest.mark.parametrize(
    "fixture,name",
    [
        (PLAIN_XLS, "plain.xls"),
        (PLAIN_DOC, "plain.doc"),
        (PLAIN_PPT, "plain.ppt"),
    ],
)
def test_e2e_binary_soft(tmp_path: Path, fixture: Path, name: str) -> None:
    if not fixture.is_file():
        pytest.skip(f"{name} fixture missing")
    pytest.importorskip("olefile")
    out = tmp_path / f"out_{name}"
    proc = run_dietrich(str(fixture), "--output", str(out))
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()
    assert "Wrote:" in proc.stdout


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_e2e_encrypted_password(tmp_path: Path) -> None:
    pytest.importorskip("msoffcrypto")
    out = tmp_path / "unlocked.xlsx"
    proc = run_dietrich(
        str(ENCRYPTED_XLSX),
        "--password",
        KNOWN_PASSWORD,
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()
    with out.open("rb") as handle:
        assert handle.read(2) == b"PK"
    assert "Password: recovered" in proc.stdout or "Wrote:" in proc.stdout


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_e2e_encrypted_wordlist(tmp_path: Path) -> None:
    pytest.importorskip("msoffcrypto")
    wl = tmp_path / "wl.txt"
    wl.write_text(f"nope\n{KNOWN_PASSWORD}\n", encoding="utf-8")
    out = tmp_path / "wl_out.xlsx"
    proc = run_dietrich(
        str(ENCRYPTED_XLSX),
        "--wordlist",
        str(wl),
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_e2e_export_hash_office() -> None:
    pytest.importorskip("msoffcrypto")
    proc = run_dietrich(str(ENCRYPTED_XLSX), "--export-hash", "hashcat")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith("$office$")


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_e2e_soft_only_refuses_encrypted(tmp_path: Path) -> None:
    out = tmp_path / "should_not_exist.xlsx"
    proc = run_dietrich(
        str(ENCRYPTED_XLSX),
        "--soft-only",
        "--output",
        str(out),
    )
    assert proc.returncode == 2
    assert not out.exists()
    assert "soft-only" in proc.stderr.lower() or "encrypted" in proc.stderr.lower()


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_e2e_wrong_password(tmp_path: Path) -> None:
    pytest.importorskip("msoffcrypto")
    out = tmp_path / "bad.xlsx"
    proc = run_dietrich(
        str(ENCRYPTED_XLSX),
        "--password",
        "definitely-wrong",
        "--output",
        str(out),
    )
    assert proc.returncode == 2
    assert not out.exists()


def test_e2e_pdf_permissions_strip(tmp_path: Path) -> None:
    pytest.importorskip("pikepdf")
    src = make_restricted_pdf(tmp_path / "restricted.pdf")
    out = tmp_path / "open.pdf"
    proc = run_dietrich(str(src), "--output", str(out))
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()
    assert "Wrote:" in proc.stdout


def test_e2e_pdf_user_password(tmp_path: Path) -> None:
    pytest.importorskip("pikepdf")
    src = make_user_locked_pdf(tmp_path / "user.pdf", password="demo")
    out = tmp_path / "open.pdf"
    proc = run_dietrich(
        str(src),
        "--password",
        "demo",
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()


def test_e2e_pdf_export_hash(tmp_path: Path) -> None:
    pytest.importorskip("pikepdf")
    src = make_user_locked_pdf(tmp_path / "user.pdf", password="demo")
    proc = run_dietrich(str(src), "--export-hash", "hashcat")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().startswith("$pdf$")


def test_e2e_strip_signatures(tmp_path: Path) -> None:
    src = write_signed_xlsx(tmp_path / "signed.xlsx")
    blocked = run_dietrich(str(src), "--output", str(tmp_path / "blocked.xlsx"))
    assert blocked.returncode == 2
    assert not (tmp_path / "blocked.xlsx").exists()

    out = tmp_path / "unsigned.xlsx"
    ok = run_dietrich(
        str(src),
        "--strip-signatures",
        "--output",
        str(out),
        "--force",
    )
    assert ok.returncode == 0, ok.stderr
    assert out.is_file()
    with zipfile.ZipFile(out) as zf:
        assert not any(n.startswith("_xmlsignatures/") for n in zf.namelist())


def test_e2e_resign_after_soft_unlock(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    src = protected_xlsx(tmp_path / "book.xlsx")
    cert, key = make_self_signed_pem(tmp_path)
    out = tmp_path / "resigned.xlsx"
    proc = run_dietrich(
        str(src),
        "--output",
        str(out),
        "--resign-cert",
        str(cert),
        "--resign-key",
        str(key),
    )
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()
    assert "Re-signed" in proc.stdout or "resign" in proc.stdout.lower() or "Wrote:" in proc.stdout
    with zipfile.ZipFile(out) as zf:
        assert any(n.startswith("_xmlsignatures/") for n in zf.namelist())


def test_e2e_json_inspect(tmp_path: Path) -> None:
    src = protected_xlsx(tmp_path / "book.xlsx")
    proc = run_dietrich(str(src), "--inspect", "--json")
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout)
    assert "document_format" in data or "format" in data
    # Accept either snake keys from our CLI dict
    assert data.get("document_format") == "excel_ooxml" or "excel" in str(data).lower()


def test_e2e_module_entrypoint_inspect(tmp_path: Path) -> None:
    src = protected_xlsx(tmp_path / "book.xlsx")
    mod = run_module("dietrich", str(src), "--inspect")
    assert mod.returncode == 0, mod.stderr
    assert "excel_ooxml" in mod.stdout or "soft" in mod.stdout


@pytest.mark.skipif(not ENCRYPTED_XLSX.is_file(), reason="encrypted fixture missing")
def test_e2e_hashcat_requires_attack_material(tmp_path: Path) -> None:
    out = tmp_path / "nope.xlsx"
    proc = run_dietrich(
        str(ENCRYPTED_XLSX),
        "--hashcat",
        "--output",
        str(out),
    )
    assert proc.returncode == 2
    assert not out.exists()
    combined = (proc.stderr + proc.stdout).lower()
    assert "hashcat" in combined or "wordlist" in combined or "mask" in combined


def test_e2e_irm_block(tmp_path: Path) -> None:
    src = write_irm_like_xlsx(tmp_path / "irm.xlsx")
    out = tmp_path / "out.xlsx"
    proc = run_dietrich(str(src), "--output", str(out))
    assert proc.returncode == 2
    assert not out.exists()
    msg = proc.stderr.lower()
    assert any(k in msg for k in ("irm", "rms", "purview", "license"))


def test_e2e_encrypted_docx_password(tmp_path: Path) -> None:
    docx = ENCRYPTED_DOCX
    if not docx.is_file():
        pytest.skip("encrypted docx fixture missing")
    pytest.importorskip("msoffcrypto")
    out = tmp_path / "doc_out.docx"
    proc = run_dietrich(
        str(docx),
        "--password",
        KNOWN_PASSWORD,
        "--output",
        str(out),
    )
    assert proc.returncode == 0, proc.stderr
    assert out.is_file()
    with out.open("rb") as handle:
        assert handle.read(2) == b"PK"
