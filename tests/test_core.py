"""Small direct safety contracts for document transformations."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from dietrich import UnlockOptions, inspect_workbook, unlock_document
from dietrich.dispatch import _verify_decrypted_output
from dietrich.errors import (
    InvalidDocumentError,
    OutputExistsError,
    SignedDocumentError,
    UnsafeArchiveError,
)
from dietrich.legacy.binary_soft import _patch_biff_workbook
from dietrich.ooxml.xml_strip import count_elements
from dietrich.safety.bounded_io import read_file_limited
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.safety.zip_archive import validate_archive_safety


def test_ooxml_unlock_removes_protection_from_synthetic_package(tmp_path: Path) -> None:
    source = tmp_path / "protected.xlsx"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("xl/workbook.xml", b"<workbook/>")
        archive.writestr(
            "xl/worksheets/sheet1.xml",
            b"<worksheet><sheetProtection/><sheetData/></worksheet>",
        )
        archive.writestr(
            "docProps/app.xml",
            b"<Properties><DocSecurity>8</DocSecurity></Properties>",
        )

    output = tmp_path / "unlocked.xlsx"
    result = unlock_document(source, output, UnlockOptions())

    assert result.removed.worksheet_protections == 1
    assert result.removed.mark_as_final == 1
    with zipfile.ZipFile(output) as archive:
        assert b"sheetProtection" not in archive.read("xl/worksheets/sheet1.xml")
        assert b"<DocSecurity>0</DocSecurity>" in archive.read("docProps/app.xml")


def test_xml_entities_and_oversized_pdf_inputs_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(InvalidDocumentError):
        count_elements(
            b'<!DOCTYPE x [<!ENTITY payload "expanded">]><x>&payload;</x>',
            "x",
            "untrusted.xml",
        )

    source = tmp_path / "large.pdf"
    source.write_bytes(b"%PDF" + b"x" * 8)
    with pytest.raises(ValueError, match="8-byte processing limit"):
        read_file_limited(source, 8)


def test_legacy_protection_marker_is_cleared_without_fixture_file() -> None:
    stream = bytearray(b"malformed")
    stream.extend(struct.pack("<HHH", 0x0012, 2, 1))

    patched, cleared = _patch_biff_workbook(bytes(stream))

    assert cleared == 1
    assert patched[-2:] == b"\x00\x00"


def test_atomic_publish_never_overwrites_without_permission(tmp_path: Path) -> None:
    target = tmp_path / "result.bin"
    target.write_bytes(b"existing")
    with temporary_output_path(target) as temporary:
        temporary.write_bytes(b"candidate")
        with pytest.raises(OutputExistsError):
            publish_output(temporary, target, overwrite=False)
    assert target.read_bytes() == b"existing"

    with pytest.raises(RuntimeError, match="verification failed"):
        with temporary_output_path(target) as temporary:
            temporary.write_bytes(b"unverified")
            raise RuntimeError("verification failed")
    assert target.read_bytes() == b"existing"
    assert list(tmp_path.glob(f".{target.name}.*.tmp")) == []


def test_ooxml_rejects_zip_bombs_duplicate_members_and_signatures(tmp_path: Path) -> None:
    bomb = tmp_path / "bomb.xlsx"
    with zipfile.ZipFile(bomb, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("xl/workbook.xml", b"x" * 200_000)
    with zipfile.ZipFile(bomb) as archive, pytest.raises(UnsafeArchiveError, match="ratio"):
        validate_archive_safety(archive)

    duplicate = tmp_path / "duplicate.xlsx"
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("xl/workbook.xml", b"first")
        with pytest.warns(UserWarning, match="Duplicate name"):
            archive.writestr("xl/workbook.xml", b"second")
    with (
        zipfile.ZipFile(duplicate) as archive,
        pytest.raises(UnsafeArchiveError, match="duplicate"),
    ):
        validate_archive_safety(archive)

    signed = tmp_path / "signed.xlsx"
    with zipfile.ZipFile(signed, "w") as archive:
        archive.writestr("xl/workbook.xml", b"<workbook/>")
        archive.writestr("_xmlsignatures/sig1.xml", b"<Signature/>")
    with pytest.raises(SignedDocumentError):
        inspect_workbook(signed)


def test_invalid_zip_and_magic_only_cfb_are_rejected(tmp_path: Path) -> None:
    invalid_zip = tmp_path / "not-a-workbook.xlsx"
    invalid_zip.write_bytes(b"not a ZIP")
    with pytest.raises(InvalidDocumentError, match="valid OOXML ZIP"):
        inspect_workbook(invalid_zip)

    truncated_cfb = tmp_path / "truncated.xls"
    truncated_cfb.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    with pytest.raises(InvalidDocumentError, match="CFB payload failed validation"):
        _verify_decrypted_output(truncated_cfb)
