"""Regression coverage for safety, fidelity, and external-tool boundaries."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from dietrich import UnlockOptions, export_document_hash, unlock_document
from dietrich.errors import EncryptedDocumentError, PasswordNotFoundError
from dietrich.legacy.binary_soft import _patch_biff_workbook, unlock_binary_office
from dietrich.legacy.cfb_io import patch_streams, read_streams
from tests.support.fixtures import FIXTURES


@pytest.mark.skipif(not (FIXTURES / "plain.xls").is_file(), reason="plain.xls missing")
def test_plain_xls_reports_zero_protection_removals(tmp_path: Path) -> None:
    """Unprotected sample must not claim spurious BIFF clears."""
    out = tmp_path / "out.xls"
    result = unlock_binary_office(FIXTURES / "plain.xls", out, UnlockOptions())
    assert result.removed.worksheet_protections == 0
    assert result.removed.workbook_protections == 0
    assert out.is_file()
    # Still a readable OLE
    streams = read_streams(out)
    assert "Workbook" in streams or any(k.endswith("Workbook") for k in streams)


@pytest.mark.skipif(not (FIXTURES / "plain.xls").is_file(), reason="plain.xls missing")
def test_injected_biff_protect_clears_exact_record_count(tmp_path: Path) -> None:
    src = FIXTURES / "plain.xls"
    streams = read_streams(src)
    key = "Workbook"
    wb = bytearray(streams[key])
    idx = wb.find(b"\x00" * 16)
    assert idx >= 0
    struct.pack_into("<HH", wb, idx, 0x0012, 2)
    struct.pack_into("<H", wb, idx + 4, 1)
    struct.pack_into("<HH", wb, idx + 6, 0x0013, 2)
    struct.pack_into("<H", wb, idx + 10, 0xABCD)
    # unit
    patched, n = _patch_biff_workbook(bytes(wb))
    assert n == 2  # Protect + Password records
    assert patched[idx + 4 : idx + 6] == b"\x00\x00"
    assert patched[idx + 10 : idx + 12] == b"\x00\x00"
    # e2e
    mod = tmp_path / "mod.xls"
    patch_streams(src, mod, {key: bytes(wb)})
    out = tmp_path / "out.xls"
    result = unlock_binary_office(mod, out, UnlockOptions())
    assert result.removed.worksheet_protections == 2


def test_pdf_aes_hash_uses_128_bits(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    from dietrich.crypto.pdf_hash import export_pdf_hash

    pdf_path = tmp_path / "aes.pdf"
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(72, 72))
    pdf.save(
        pdf_path,
        encryption=pikepdf.Encryption(user="secret", owner="owner", R=4, aes=True),
    )
    line = export_pdf_hash(pdf_path, fmt="hashcat")
    assert line.startswith("$pdf$")
    parts = line.split("*")
    # $pdf$VRbits*...
    bits = int(parts[2])
    assert bits == 128, f"expected 128-bit key field, got {bits} in {line}"


def test_hashcat_requires_attack_material(tmp_path: Path) -> None:
    enc = FIXTURES / "example_password.xlsx"
    if not enc.is_file():
        pytest.skip("encrypted fixture missing")
    with pytest.raises(EncryptedDocumentError, match="wordlist|mask|hashcat-arg"):
        unlock_document(
            enc,
            tmp_path / "o.xlsx",
            UnlockOptions(use_hashcat=True),
        )


def test_hashcat_mask_wired_to_attack_mode_3(monkeypatch: pytest.MonkeyPatch) -> None:
    """--hashcat --mask must invoke hashcat -a 3 with the mask string."""
    from dietrich.crypto import hashcat_runner
    from dietrich.crypto.hashcat_runner import HashcatRunResult

    captured: dict = {}

    def fake_run(_hash_line, *, mode, wordlist=None, mask=None, _extra_args=None, **_k):
        captured["mask"] = mask
        captured["wordlist"] = wordlist
        # Also spy real command builder path via run with mock find + subprocess
        return HashcatRunResult(
            success=True,
            password="42",
            mode=mode,
            command=("hashcat", "-a", "3", mask or ""),
            stdout_tail="",
            message="ok",
        )

    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/usr/bin/hashcat")
    monkeypatch.setattr(hashcat_runner, "run_hashcat_for_office", fake_run)

    # Call through the real dispatch recovery path
    from dietrich.dispatch import _recover_via_hashcat
    enc = FIXTURES / "example_password.xlsx"
    if not enc.is_file():
        pytest.skip("encrypted fixture missing")
    # fake_run ignores hash and returns 42 - we only assert mask wiring
    monkeypatch.setattr(
        "dietrich.crypto.hash_export.export_hash",
        lambda *a, **k: "$office$201310000025616aabb*cc",
    )
    pw = _recover_via_hashcat(
        enc,
        UnlockOptions(use_hashcat=True, mask="?d?d"),
        kind="office",
    )
    assert pw == "42"
    assert captured.get("mask") == "?d?d"
    assert captured.get("wordlist") is None


def test_hashcat_mask_builds_a3_command(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_hashcat_for_office with mask must put -a 3 and mask in the command."""
    from dietrich.crypto import hashcat_runner
    from dietrich.process import ProcessResult

    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/usr/bin/hashcat")
    captured_cmd: list = []

    def fake_run(cmd, **_kwargs):
        captured_cmd.append(list(cmd))

        return ProcessResult(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(hashcat_runner, "run_hashcat_argv_sync", fake_run)
    hashcat_runner.run_hashcat_for_office(
        "$office$201310000025616aabb*ccdddddddddddddddddddddddddddddddd",
        mode=9600,
        mask="?d?d?d?d",
    )
    assert captured_cmd, "hashcat was not invoked"
    cmd = captured_cmd[0]
    assert "-a" in cmd
    assert cmd[cmd.index("-a") + 1] == "3"
    assert "?d?d?d?d" in cmd


def test_potfile_requires_exact_hash_match(tmp_path: Path) -> None:
    """Potfile must not return a password from a different $office$ hash."""
    from dietrich.crypto.hashcat_runner import _read_cracked_password

    pot = tmp_path / "pot"
    target = (
        "$office$201310000025616*"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa*"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb*"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    other = (
        "$office$201310000025616*"
        "dddddddddddddddddddddddddddddddd*"
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee*"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    pot.write_text(f"{other}:WrongPass\n{target}:RightPass\n", encoding="utf-8")
    assert _read_cracked_password(tmp_path / "missing", pot, target) == "RightPass"
    # Only other hash in pot
    pot.write_text(f"{other}:WrongPass\n", encoding="utf-8")
    assert _read_cracked_password(tmp_path / "missing", pot, target) is None


def test_hashcat_mock_success_decrypts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("msoffcrypto")
    enc = FIXTURES / "example_password.xlsx"
    if not enc.is_file():
        pytest.skip("encrypted fixture missing")

    from dietrich.crypto import hashcat_runner
    from dietrich.crypto.hashcat_runner import HashcatRunResult

    def fake_run(*_a, **_k):
        return HashcatRunResult(
            success=True,
            password="Password1234_",
            mode=9600,
            command=("hashcat",),
            stdout_tail="ok",
            message="password found via hashcat",
        )

    monkeypatch.setattr(hashcat_runner, "find_hashcat", lambda: "/usr/bin/hashcat")
    monkeypatch.setattr(hashcat_runner, "run_hashcat_for_office", fake_run)

    wl = tmp_path / "w.txt"
    wl.write_text("Password1234_\n", encoding="utf-8")
    out = tmp_path / "out.xlsx"
    result = unlock_document(
        enc,
        out,
        UnlockOptions(use_hashcat=True, wordlist=wl),
    )
    assert out.is_file()
    assert result.password_used == "Password1234_"
    with zipfile.ZipFile(out) as zf:
        assert any(n.startswith("xl/") for n in zf.namelist())


def test_ooxml_preserves_stored_compression(tmp_path: Path) -> None:
    src = tmp_path / "in.xlsx"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("_rels/.rels", b"<Relationships/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
        info = zipfile.ZipInfo("xl/worksheets/sheet1.xml")
        info.compress_type = zipfile.ZIP_STORED
        zf.writestr(
            info,
            b"<worksheet><sheetProtection/><sheetData/></worksheet>",
        )
    out = tmp_path / "out.xlsx"
    unlock_document(src, out, UnlockOptions())
    with zipfile.ZipFile(out) as zf:
        sheet = next(i for i in zf.infolist() if i.filename.endswith("sheet1.xml"))
        assert sheet.compress_type == zipfile.ZIP_STORED
        assert b"sheetProtection" not in zf.read(sheet)


def test_pdf_user_password_e2e(tmp_path: Path) -> None:
    pikepdf = pytest.importorskip("pikepdf")
    src = tmp_path / "user.pdf"
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(100, 100))
    pdf.save(src, encryption=pikepdf.Encryption(user="testpw", owner="ownerpw", R=4))

    out = tmp_path / "open.pdf"
    unlock_document(src, out, UnlockOptions(password="testpw"))
    assert out.is_file()
    with pikepdf.open(out) as unlocked:
        assert not unlocked.is_encrypted

    bad = tmp_path / "bad.pdf"
    with pytest.raises((EncryptedDocumentError, PasswordNotFoundError)):
        unlock_document(src, bad, UnlockOptions(password="wrong"))
    assert not bad.exists()

    line = export_document_hash(src, "hashcat")
    assert line.startswith("$pdf$")


def test_vba_warns_when_nothing_cleared(tmp_path: Path) -> None:
    src = tmp_path / "m.xlsm"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("_rels/.rels", b"<Relationships/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
        zf.writestr("xl/worksheets/s1.xml", b"<worksheet/>")
        # Binary blob with no CMG/DPB/GC text
        zf.writestr("xl/vbaProject.bin", b"\x00\x01\x02NO_KEYS_HERE\xff")
    out = tmp_path / "out.xlsm"
    result = unlock_document(src, out, UnlockOptions(unlock_vba=True))
    assert result.removed.vba_unlocked == 0
    assert any("no CMG/DPB/GC" in w or "compressed" in w for w in result.warnings)


def test_ooxml_preserves_deflated_compression(tmp_path: Path) -> None:
    src = tmp_path / "in.xlsx"
    with zipfile.ZipFile(src, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("_rels/.rels", b"<Relationships/>")
        zf.writestr("xl/workbook.xml", b"<workbook><workbookProtection/></workbook>")
        zf.writestr(
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetProtection/><sheetData/></worksheet>",
        )
    out = tmp_path / "out.xlsx"
    unlock_document(src, out, UnlockOptions())
    with zipfile.ZipFile(out) as zf:
        sheet = next(i for i in zf.infolist() if i.filename.endswith("sheet1.xml"))
        assert sheet.compress_type == zipfile.ZIP_DEFLATED
        assert b"sheetProtection" not in zf.read(sheet)


def test_missing_wordlist_is_dietrich_error(tmp_path: Path) -> None:
    enc = FIXTURES / "example_password.xlsx"
    if not enc.is_file():
        pytest.skip("encrypted fixture missing")
    with pytest.raises(EncryptedDocumentError, match="wordlist not found"):
        unlock_document(
            enc,
            tmp_path / "o.xlsx",
            UnlockOptions(wordlist=tmp_path / "missing.txt"),
        )


def test_irm_blocks_unlock_with_actionable_message(tmp_path: Path) -> None:
    """Synthetic IRM package part must not soft-unlock as ordinary OOXML."""
    src = tmp_path / "irm.xlsx"
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("_rels/.rels", b"<Relationships/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
        zf.writestr(
            "customXml/item1.xml",
            b"<root>MicrosoftRightsManagement something</root>",
        )
    with pytest.raises(EncryptedDocumentError, match="IRM|RMS|Purview|license"):
        unlock_document(src, tmp_path / "out.xlsx", UnlockOptions())


def test_docsecurity_preserves_prefix_shape(tmp_path: Path) -> None:
    src = tmp_path / "a.xlsx"
    app = (
        b'<?xml version="1.0"?>'
        b'<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">'
        b"<DocSecurity>8</DocSecurity></Properties>"
    )
    with zipfile.ZipFile(src, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("_rels/.rels", b"<Relationships/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
        zf.writestr("xl/worksheets/s1.xml", b"<worksheet/>")
        zf.writestr("docProps/app.xml", app)
    out = tmp_path / "out.xlsx"
    result = unlock_document(src, out, UnlockOptions())
    assert result.removed.mark_as_final >= 1
    with zipfile.ZipFile(out) as archive:
        data = archive.read("docProps/app.xml")
    # Must not invent ns0: prefix rewrite for this simple case
    assert b"<DocSecurity>0</DocSecurity>" in data
    assert b"ns0:" not in data
