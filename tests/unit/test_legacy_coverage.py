"""Deterministic coverage for legacy CFBF inspection and rewrite contracts."""

from __future__ import annotations

import struct
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from dietrich.errors import InvalidDocumentError, OutputExistsError, UnsupportedFormatError
from dietrich.legacy import binary_soft, cfbf
from dietrich.legacy.cfb_io import patch_streams
from dietrich.types import DocumentFormat, RemovalCounts, UnlockOptions


class _FakeStream:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self) -> bytes:
        return self._data


class _FakeDirectoryEntry:
    def __init__(self, name: str, sector_chain: list[int], *, is_minifat: bool = False) -> None:
        self.name = name
        self.sect_chain = sector_chain
        self.is_minifat = is_minifat


class _FakeOle:
    def __init__(self, streams: dict[str, bytes]) -> None:
        self._streams = streams
        self.sectorsize = 512
        self.minisectorsize = 64
        self.direntries = [
            _FakeDirectoryEntry("Root Entry", []),
            _FakeDirectoryEntry("Workbook", [0]),
        ]

    def __enter__(self) -> _FakeOle:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def exists(self, _name: str) -> bool:
        return False

    def listdir(self, **_kwargs: object) -> list[list[str]]:
        return [name.split("/") for name in self._streams]

    def openstream(self, entry: str | list[str]) -> _FakeStream:
        name = "/".join(entry) if isinstance(entry, list) else entry
        return _FakeStream(self._streams[name])


def test_is_cfbf_checks_the_full_magic_prefix(tmp_path: Path) -> None:
    valid = tmp_path / "valid.xls"
    valid.write_bytes(cfbf.CFBF_MAGIC + b"payload")
    truncated = tmp_path / "truncated.xls"
    truncated.write_bytes(cfbf.CFBF_MAGIC[:7] + b"payload")

    assert cfbf.is_cfbf(valid) is True
    assert cfbf.is_cfbf(truncated) is False


def test_inspect_cfbf_reports_encrypted_ooxml_streams(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "encrypted.bin"
    candidate.write_bytes(b"synthetic")

    class InspectOle:
        def __init__(self, _path: str) -> None:
            pass

        def __enter__(self) -> InspectOle:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def listdir(self) -> list[list[str]]:
            return [["EncryptionInfo"], ["EncryptedPackage"]]

    monkeypatch.setitem(
        sys.modules,
        "olefile",
        SimpleNamespace(isOleFile=lambda _path: True, OleFileIO=InspectOle),
    )

    inspection = cfbf.inspect_cfbf(candidate)

    assert inspection.document_format is DocumentFormat.ENCRYPTED_OOXML
    assert inspection.encrypted is True
    assert inspection.user_password_required is True
    assert inspection.strategies == (
        "crypto:ooxml_password",
        "crypto:wordlist",
        "crypto:export_hash",
    )
    assert "streams=2" in inspection.notes
    assert "kind=encrypted_ooxml" in inspection.notes


def test_inspect_cfbf_rejects_non_ole_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = tmp_path / "not-ole.bin"
    candidate.write_bytes(b"not an OLE file")
    monkeypatch.setitem(
        sys.modules,
        "olefile",
        SimpleNamespace(isOleFile=lambda _path: False),
    )

    with pytest.raises(UnsupportedFormatError, match="not a valid CFBF/OLE"):
        cfbf.inspect_cfbf(candidate)


def test_patch_streams_rewrites_resolved_stream_at_cfb_sector_offset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.xls"
    source.write_bytes(b"H" * 512 + b"a" * 512)
    output = tmp_path / "patched.xls"
    ole = _FakeOle({"Storage/Workbook": b"abcd"})
    monkeypatch.setitem(sys.modules, "olefile", SimpleNamespace(OleFileIO=lambda _path: ole))

    applied = patch_streams(source, output, {"Workbook": b"WXYZ"})

    assert applied == ["Storage/Workbook"]
    assert output.read_bytes()[512:516] == b"WXYZ"


def test_patch_streams_rejects_length_changes_before_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.xls"
    source.write_bytes(b"H" * 1024)
    output = tmp_path / "patched.xls"
    ole = _FakeOle({"Storage/Workbook": b"abcd"})
    monkeypatch.setitem(sys.modules, "olefile", SimpleNamespace(OleFileIO=lambda _path: ole))

    with pytest.raises(ValueError, match="in-place patch requires equal length"):
        patch_streams(source, output, {"Workbook": b"too long"})

    assert not output.exists()


def test_build_patches_handles_document_and_presentation_streams() -> None:
    word_document = bytearray(0x20)
    struct.pack_into("<H", word_document, 0x0A, 0x000C)
    struct.pack_into("<I", word_document, 0x0E, 0xAABBCCDD)
    doc_patches, doc_counts = binary_soft._build_patches(
        Path("locked.doc"),
        {"Storage/WordDocument": bytes(word_document), "1Table": b"ProtABCD"},
    )
    ppt_atom = struct.pack("<HHI", 0, 0x0FF5, 3) + b"abc"
    ppt_patches, ppt_counts = binary_soft._build_patches(
        Path("locked.ppt"),
        {"PowerPoint Document": ppt_atom},
    )

    assert doc_counts.document_protections == 6
    assert doc_patches["Storage/WordDocument"][0x0A:0x0C] == b"\x00\x00"
    assert doc_patches["Storage/WordDocument"][0x0E:0x12] == b"\x00" * 4
    assert doc_patches["1Table"] == b"Prot" + b"\x00" * 4
    assert ppt_counts.modify_verifiers == 3
    assert ppt_patches["PowerPoint Document"] == ppt_atom[:8] + b"\x00" * 3


def test_build_patches_rejects_unknown_stream_families() -> None:
    with pytest.raises(UnsupportedFormatError, match=r"unrecognized binary Office streams.*Other"):
        binary_soft._build_patches(Path("unknown.bin"), {"Other": b"data"})


def test_unlock_binary_office_preserves_no_patch_copy_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "unprotected.xls"
    source.write_bytes(b"unchanged legacy document")
    output = tmp_path / "output.xls"
    monkeypatch.setattr(binary_soft, "read_streams", lambda _path: {"Workbook": b""})
    monkeypatch.setattr(
        binary_soft,
        "_build_patches",
        lambda _source, _streams: ({}, RemovalCounts()),
    )

    result = binary_soft.unlock_binary_office(source, output, UnlockOptions())

    assert output.read_bytes() == source.read_bytes()
    assert result.removed == RemovalCounts()
    assert result.warnings == ("No binary protection records found; wrote unchanged copy.",)


def test_unlock_binary_office_maps_read_failures_and_refuses_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source.xls"
    source.write_bytes(b"legacy")
    output = tmp_path / "output.xls"

    def fail_read(_path: Path) -> dict[str, bytes]:
        raise OSError("broken CFB")

    monkeypatch.setattr(binary_soft, "read_streams", fail_read)
    with pytest.raises(InvalidDocumentError, match="not a readable OLE/CFB file: broken CFB"):
        binary_soft.unlock_binary_office(source, output, UnlockOptions())

    output.write_bytes(b"existing")
    with pytest.raises(OutputExistsError, match="already exists"):
        binary_soft.unlock_binary_office(source, output, UnlockOptions())
