"""Focused contracts for bounded legacy CFB validation and BIFF patching."""

from __future__ import annotations

import struct
from pathlib import Path

import olefile
import pytest
from olefile.olefile import NotOleFileError

from dietrich.legacy.binary_soft import _patch_biff_workbook
from dietrich.legacy.cfb_io import validate_cfb
from tests.support.fixtures import FIXTURES


def test_biff_marker_scan_clears_unaligned_protection_records() -> None:
    """Marker recovery handles a valid protection record after malformed bytes."""
    stream = bytearray(b"malformed")
    stream.extend(struct.pack("<HHH", 0x0012, 2, 1))

    patched, cleared = _patch_biff_workbook(bytes(stream))

    assert cleared == 1
    assert patched[-2:] == b"\x00\x00"


@pytest.mark.skipif(not (FIXTURES / "plain.xls").is_file(), reason="plain.xls missing")
def test_validate_cfb_reads_metadata_without_opening_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Publication validation parses CFB metadata but never consumes stream data."""

    def fail_openstream(*_args, **_kwargs):
        raise AssertionError("validate_cfb must not open OLE streams")

    monkeypatch.setattr(olefile.OleFileIO, "openstream", fail_openstream)

    assert validate_cfb(FIXTURES / "plain.xls") is None


def test_validate_cfb_rejects_magic_only_file(tmp_path: Path) -> None:
    """A CFB signature alone is not sufficient to pass metadata validation."""
    candidate = tmp_path / "truncated.xls"
    candidate.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"truncated")

    with pytest.raises(NotOleFileError):
        validate_cfb(candidate)
