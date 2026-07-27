"""Excel OOXML processing, archive safety, publication, and CLI coverage."""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from dietrich import (
    EncryptedDocumentError,
    InvalidDocumentError,
    OutputExistsError,
    SignedDocumentError,
    UnlockOptions,
    UnsafeArchiveError,
    UnsupportedFormatError,
    inspect_workbook,
    unlock_workbook,
)
from dietrich.cli import main

WORKSHEET_XML = """<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData/>
  {protection}
</worksheet>
"""

WORKBOOK_XML = """<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  {protection}
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"
      xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/>
  </sheets>
</workbook>
"""


def worksheet_xml(protected: bool) -> bytes:
    protection = '<sheetProtection sheet="1" objects="1" scenarios="1"/>' if protected else ""
    return WORKSHEET_XML.format(protection=protection).encode()


def workbook_xml(protected: bool) -> bytes:
    protection = '<workbookProtection lockStructure="1"/>' if protected else ""
    return WORKBOOK_XML.format(protection=protection).encode()


def write_workbook(
    path: Path,
    *,
    worksheet_protected: bool = True,
    workbook_protected: bool = False,
    vba_project: bytes | None = None,
) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("_rels/.rels", b"<Relationships/>")
        archive.writestr("xl/_rels/workbook.xml.rels", b"<Relationships/>")
        archive.writestr(
            "xl/workbook.xml",
            workbook_xml(workbook_protected),
        )
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            worksheet_xml(worksheet_protected),
        )
        archive.writestr("xl/theme/theme1.xml", b"<theme><sheetProtection/></theme>")
        if vba_project is not None:
            archive.writestr("xl/vbaProject.bin", vba_project)
    return path


def read_entry(path: Path, name: str) -> bytes:
    with zipfile.ZipFile(path) as archive:
        return archive.read(name)


def mark_zip_entries_encrypted(path: Path) -> None:
    data = bytearray(path.read_bytes())
    local_offset = data.index(b"PK\x03\x04")
    local_flags_offset = local_offset + 6
    local_flags = struct.unpack_from("<H", data, local_flags_offset)[0]
    struct.pack_into("<H", data, local_flags_offset, local_flags | 0x01)

    central_offset = data.index(b"PK\x01\x02")
    central_flags_offset = central_offset + 8
    central_flags = struct.unpack_from("<H", data, central_flags_offset)[0]
    struct.pack_into("<H", data, central_flags_offset, central_flags | 0x01)

    path.write_bytes(data)


def assert_entry_missing(path: Path, name: str, needle: bytes) -> None:
    assert needle not in read_entry(path, name)


def test_unlock_removes_worksheet_protection(tmp_path: Path) -> None:
    source = write_workbook(tmp_path / "protected.xlsx", worksheet_protected=True)
    output = tmp_path / "unlocked.xlsx"

    result = unlock_workbook(source, output, UnlockOptions())

    assert result.removed.worksheet_protections == 1
    assert result.removed.workbook_protections == 0
    assert_entry_missing(output, "xl/worksheets/sheet1.xml", b"sheetProtection")
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None


def test_unprotected_workbook_writes_valid_output_with_zero_removals(tmp_path: Path) -> None:
    source = write_workbook(tmp_path / "plain.xlsx", worksheet_protected=False)
    output = tmp_path / "plain_unprotected.xlsx"

    result = unlock_workbook(source, output, UnlockOptions())

    assert result.removed.worksheet_protections == 0
    assert result.removed.workbook_protections == 0
    with zipfile.ZipFile(output) as archive:
        assert archive.testzip() is None


def test_workbook_protection_is_removed_by_default(tmp_path: Path) -> None:
    source = write_workbook(
        tmp_path / "protected.xlsx",
        worksheet_protected=False,
        workbook_protected=True,
    )
    output = tmp_path / "unlocked.xlsx"

    result = unlock_workbook(source, output, UnlockOptions())

    assert result.removed.workbook_protections == 1
    assert_entry_missing(output, "xl/workbook.xml", b"workbookProtection")


def test_worksheets_only_keeps_workbook_protection(tmp_path: Path) -> None:
    source = write_workbook(
        tmp_path / "protected.xlsx",
        worksheet_protected=True,
        workbook_protected=True,
    )
    output = tmp_path / "worksheets_only.xlsx"

    result = unlock_workbook(
        source,
        output,
        UnlockOptions(remove_workbook_protection=False),
    )

    assert result.removed.worksheet_protections == 1
    assert result.removed.workbook_protections == 0
    assert b"workbookProtection" in read_entry(output, "xl/workbook.xml")


def test_unlock_preserves_non_target_xml_bytes_and_unused_namespaces(tmp_path: Path) -> None:
    worksheet = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n'
        b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        b'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006" '
        b'xmlns:x14ac="http://schemas.microsoft.com/office/spreadsheetml/2009/9/ac" '
        b'xmlns:xr="http://schemas.microsoft.com/office/spreadsheetml/2014/revision" '
        b'xmlns:xr2="http://schemas.microsoft.com/office/spreadsheetml/2015/revision2" '
        b'xmlns:xr3="http://schemas.microsoft.com/office/spreadsheetml/2016/revision3" '
        b'mc:Ignorable="x14ac xr xr2 xr3" '
        b'xr:uid="{00000000-0001-0000-0000-000000000000}">'
        b"<sheetData/>"
        b'<sheetProtection sheet="1" objects="1" scenarios="1"/>'
        b'<pageMargins left="0.7" right="0.7"/>'
        b"</worksheet>"
    )
    source = tmp_path / "protected.xlsx"
    output = tmp_path / "unlocked.xlsx"

    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", b"<Types/>")
        archive.writestr("xl/workbook.xml", workbook_xml(False))
        archive.writestr("xl/worksheets/sheet1.xml", worksheet)

    result = unlock_workbook(source, output, UnlockOptions())

    expected = worksheet.replace(
        b'<sheetProtection sheet="1" objects="1" scenarios="1"/>',
        b"",
    )
    assert result.removed.worksheet_protections == 1
    assert read_entry(output, "xl/worksheets/sheet1.xml") == expected


def test_xlsm_vba_project_is_preserved_byte_identically(tmp_path: Path) -> None:
    vba_project = b"\x00VBA\xffproject"
    source = write_workbook(
        tmp_path / "macro.xlsm",
        worksheet_protected=True,
        vba_project=vba_project,
    )
    output = tmp_path / "macro_unprotected.xlsm"

    result = unlock_workbook(source, output, UnlockOptions())

    assert result.vba_project_present is True
    assert read_entry(output, "xl/vbaProject.bin") == vba_project
    assert_entry_missing(output, "xl/worksheets/sheet1.xml", b"sheetProtection")


def test_invalid_suffix_is_rejected(tmp_path: Path) -> None:
    source = write_workbook(tmp_path / "protected.zip")

    with pytest.raises(UnsupportedFormatError, match=".xlsx and .xlsm"):
        inspect_workbook(source)


def test_corrupt_zip_is_reported_clearly(tmp_path: Path) -> None:
    source = tmp_path / "corrupt.xlsx"
    source.write_bytes(b"not a zip")

    with pytest.raises(InvalidDocumentError, match="not a valid OOXML ZIP"):
        inspect_workbook(source)


def test_encrypted_zip_entry_is_reported_clearly(tmp_path: Path) -> None:
    source = write_workbook(tmp_path / "encrypted.xlsx")
    mark_zip_entries_encrypted(source)

    with pytest.raises(EncryptedDocumentError, match="encrypted ZIP entries"):
        inspect_workbook(source)


def test_archive_with_duplicate_member_names_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "duplicate.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", workbook_xml(False))
        archive.writestr("xl/workbook.xml", workbook_xml(False))

    with pytest.raises(UnsafeArchiveError, match="duplicate member names"):
        inspect_workbook(source)


def test_archive_with_too_many_members_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("dietrich.safety.zip_archive.MAX_ARCHIVE_MEMBERS", 2)
    source = tmp_path / "many-members.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", workbook_xml(False))
        archive.writestr("xl/worksheets/sheet1.xml", worksheet_xml(False))
        archive.writestr("xl/worksheets/sheet2.xml", worksheet_xml(False))

    with pytest.raises(UnsafeArchiveError, match="entries; the limit is 2"):
        inspect_workbook(source)


def test_archive_with_member_larger_than_limit_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("dietrich.safety.zip_archive.MAX_MEMBER_UNCOMPRESSED_BYTES", 8)
    source = tmp_path / "large-member.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", b"x" * 9)

    with pytest.raises(UnsafeArchiveError, match="per-member limit"):
        inspect_workbook(source)


def test_archive_larger_than_total_limit_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("dietrich.safety.zip_archive.MAX_TOTAL_UNCOMPRESSED_BYTES", 12)
    source = tmp_path / "large-total.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", b"x" * 8)
        archive.writestr("xl/worksheets/sheet1.xml", b"x" * 8)

    with pytest.raises(UnsafeArchiveError, match="more than 12 bytes"):
        inspect_workbook(source)


def test_high_compression_ratio_archive_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("dietrich.safety.zip_archive.MAX_COMPRESSION_RATIO", 2)
    source = tmp_path / "compressed.xlsx"
    with zipfile.ZipFile(source, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/workbook.xml", b"x" * 2_048)

    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        inspect_workbook(source)


def test_signed_ooxml_package_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "signed.xlsx"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("xl/workbook.xml", workbook_xml(False))
        archive.writestr("_xmlsignatures/sig1.xml", b"<Signature/>")

    with pytest.raises(SignedDocumentError, match="digitally signed"):
        inspect_workbook(source)


def test_concurrent_output_creation_is_not_clobbered(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = write_workbook(tmp_path / "protected.xlsx")
    output = tmp_path / "unlocked.xlsx"
    original_link = os.link

    def create_competing_output(temp_path: Path, target_path: Path) -> None:
        target_path.write_bytes(b"competing output")
        original_link(temp_path, target_path)

    monkeypatch.setattr(os, "link", create_competing_output)

    with pytest.raises(OutputExistsError):
        unlock_workbook(source, output, UnlockOptions())

    assert output.read_bytes() == b"competing output"


def test_inspect_reports_counts_and_writes_no_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = write_workbook(
        tmp_path / "protected.xlsx",
        worksheet_protected=True,
        workbook_protected=True,
        vba_project=b"macro",
    )

    exit_code = main(["--inspect", str(source)])

    assert exit_code == 0
    assert not (tmp_path / "protected_unprotected.xlsx").exists()
    captured = capsys.readouterr()
    assert "excel_ooxml" in captured.out
    assert "sheetProtection" in captured.out
    assert "workbookProtection" in captured.out
    assert "VBA project: present" in captured.out


def test_output_collision_fails_without_force(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = write_workbook(tmp_path / "protected.xlsx")
    output = tmp_path / "protected_unprotected.xlsx"
    output.write_bytes(b"existing")

    exit_code = main([str(source)])

    assert exit_code == 2
    assert output.read_bytes() == b"existing"
    captured = capsys.readouterr()
    assert "--force" in captured.err


def test_cli_force_overwrites_existing_output(tmp_path: Path) -> None:
    source = write_workbook(tmp_path / "protected.xlsx")
    output = tmp_path / "protected_unprotected.xlsx"
    output.write_bytes(b"existing")

    exit_code = main([str(source), "--force"])

    assert exit_code == 0
    assert read_entry(output, "xl/worksheets/sheet1.xml")


def test_python_module_entrypoint_inspects(tmp_path: Path) -> None:
    source = write_workbook(tmp_path / "protected.xlsx")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")

    result = subprocess.run(
        [sys.executable, "-m", "dietrich", "--inspect", str(source)],
        check=False,
        capture_output=True,
        env=env,
        text=True,
    )

    assert result.returncode == 0
    assert "excel_ooxml" in result.stdout
    assert "sheetProtection" in result.stdout
