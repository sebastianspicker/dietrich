"""Adversarial parser and publication regressions."""

from __future__ import annotations

import struct
import zipfile
from pathlib import Path

import pytest

from dietrich.crypto.hashcat_runner import _hashcat_command, _HashcatFiles, _HashcatOptions
from dietrich.errors import (
    EncryptedDocumentError,
    InvalidDocumentError,
    OutputExistsError,
    UnsafeArchiveError,
    UnsupportedFormatError,
)
from dietrich.legacy.binary_soft import _build_patches, _patch_biff_workbook
from dietrich.ooxml.xml_strip import count_elements
from dietrich.safety.bounded_io import read_file_limited
from dietrich.safety.cfb import validate_cfb
from dietrich.safety.publish import publish_output, temporary_output_path
from dietrich.safety.zip_archive import validate_archive_safety


def test_xml_entities_are_rejected() -> None:
    with pytest.raises(InvalidDocumentError):
        count_elements(
            b'<!DOCTYPE x [<!ENTITY payload "expanded">]><x>&payload;</x>',
            "x",
            "untrusted.xml",
        )


def test_bounded_reader_rejects_oversized_input(tmp_path: Path) -> None:
    source = tmp_path / "large.pdf"
    source.write_bytes(b"%PDF" + b"x" * 8)
    with pytest.raises(ValueError, match="8-byte processing limit"):
        read_file_limited(source, 8)


def test_biff_protection_record_is_cleared() -> None:
    stream = bytearray(struct.pack("<HHHHHHII", 0x0809, 16, 0x0600, 0x0005, 0, 0, 0, 0))
    stream.extend(struct.pack("<HHH", 0x0012, 2, 1))
    stream.extend(struct.pack("<HH", 0x000A, 0))
    patched, cleared = _patch_biff_workbook(bytes(stream))
    assert cleared == 1
    assert patched != stream


def test_malformed_biff_marker_is_rejected_instead_of_scanned() -> None:
    stream = b"ordinary content" + struct.pack("<HHH", 0x0012, 2, 1)
    with pytest.raises(InvalidDocumentError, match="BIFF"):
        _patch_biff_workbook(stream)


@pytest.mark.parametrize(
    "stream",
    [
        struct.pack("<HHH", 0x0012, 2, 1),
        struct.pack("<HHHHHHII", 0x0809, 16, 0x0600, 0x0005, 0, 0, 0, 0)
        + struct.pack("<HHH", 0x0012, 2, 1),
        struct.pack("<HH", 0x000A, 0),
    ],
)
def test_biff_requires_complete_bof_eof_substreams(stream: bytes) -> None:
    with pytest.raises(InvalidDocumentError, match="BIFF"):
        _patch_biff_workbook(stream)


@pytest.mark.parametrize("second_type", [0xFFFF, 0x0005])
def test_biff_rejects_invalid_later_substream_types(second_type: int) -> None:
    globals_bof = struct.pack("<HHHHHHII", 0x0809, 16, 0x0600, 0x0005, 0, 0, 0, 0)
    second_bof = struct.pack("<HHHHHHII", 0x0809, 16, 0x0600, second_type, 0, 0, 0, 0)
    stream = (
        globals_bof
        + struct.pack("<HH", 0x000A, 0)
        + second_bof
        + struct.pack("<HHH", 0x0012, 2, 1)
        + struct.pack("<HH", 0x000A, 0)
    )
    with pytest.raises(InvalidDocumentError, match="BIFF"):
        _patch_biff_workbook(stream)


def test_legacy_word_table_text_is_never_heuristically_zeroed() -> None:
    fib = bytearray(0x20)
    struct.pack_into("<H", fib, 0, 0xA5EC)
    ordinary_table = b"Protordinary-content-that-must-survive"
    patches, counts = _build_patches(
        Path("document.doc"),
        {"WordDocument": bytes(fib), "0Table": ordinary_table},
    )
    assert patches == {}
    assert counts.document_protections == 0


def test_legacy_powerpoint_rewrite_fails_without_verified_parser() -> None:
    with pytest.raises(UnsupportedFormatError, match="verified record parser"):
        _build_patches(
            Path("deck.ppt"),
            {"PowerPoint Document": b"Protect ordinary-content-that-must-survive"},
        )


def test_atomic_publish_never_overwrites_without_permission(tmp_path: Path) -> None:
    target = tmp_path / "result.bin"
    target.write_bytes(b"existing")
    with temporary_output_path(target) as temporary:
        temporary.write_bytes(b"candidate")
        with pytest.raises(OutputExistsError):
            publish_output(temporary, target, overwrite=False)
    assert target.read_bytes() == b"existing"


@pytest.mark.parametrize("kind", ["bomb", "duplicate", "alias"])
def test_unsafe_archive_metadata_is_rejected(tmp_path: Path, kind: str) -> None:
    source = tmp_path / f"{kind}.xlsx"
    with zipfile.ZipFile(source, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        if kind == "bomb":
            archive.writestr("xl/workbook.xml", b"x" * 200_000)
        elif kind == "duplicate":
            archive.writestr("xl/workbook.xml", b"first")
            with pytest.warns(UserWarning, match="Duplicate name"):
                archive.writestr("xl/workbook.xml", b"second")
        else:
            archive.writestr("word/settings.xml", b"first")
            archive.writestr("word\\settings.xml", b"alias")
    with zipfile.ZipFile(source) as archive, pytest.raises(UnsafeArchiveError):
        validate_archive_safety(archive)


def test_magic_only_cfb_is_rejected(tmp_path: Path) -> None:
    source = tmp_path / "truncated.xls"
    source.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
    with pytest.raises((OSError, ValueError)):
        validate_cfb(source)


def test_hashcat_arguments_cannot_override_private_outputs(tmp_path: Path) -> None:
    options = _HashcatOptions(
        mode=9600,
        wordlist=None,
        mask="?d",
        extra_args=("--outfile=/tmp/leak",),
        workload="2",
        timeout=None,
    )
    files = _HashcatFiles(
        pot=tmp_path / "pot",
        output=tmp_path / "out",
        hash_input=tmp_path / "hash",
    )
    with pytest.raises(EncryptedDocumentError, match="managed option"):
        _hashcat_command("/usr/bin/hashcat", options, files)
