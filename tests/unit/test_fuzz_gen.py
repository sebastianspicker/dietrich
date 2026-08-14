"""Focused tests for reproducible research mutant generation."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from dietrich.errors import UnsafeArchiveError
from dietrich.research.fuzz_gen import generate_xml_part_mutants
from dietrich.safety import zip_archive


def test_xml_mutants_preserve_members_and_are_reproducible(tmp_path: Path) -> None:
    seed = tmp_path / "seed.docx"
    with zipfile.ZipFile(seed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", b"<document><body/></document>")
        archive.writestr("word/media/image.bin", b"unchanged")

    first = generate_xml_part_mutants(seed, tmp_path / "first", count=2, seed=7)
    second = generate_xml_part_mutants(seed, tmp_path / "second", count=2, seed=7)

    assert [path.read_bytes() for path in first] == [path.read_bytes() for path in second]
    with zipfile.ZipFile(first[0]) as archive:
        assert set(archive.namelist()) == {"word/document.xml", "word/media/image.bin"}
        assert b"fuzz='1'" in archive.read("word/document.xml")
        assert archive.read("word/media/image.bin") == b"unchanged"


def test_non_zip_seed_falls_back_to_binary_mutants(tmp_path: Path) -> None:
    seed = tmp_path / "seed.docx"
    seed.write_bytes(b"not a zip archive" * 8)

    outputs = generate_xml_part_mutants(seed, tmp_path / "out", count=2, seed=3)

    assert len(outputs) == 2
    assert all(path.name.startswith("mutant_3_") for path in outputs)


def test_xml_mutants_reject_oversized_seed_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = tmp_path / "oversized.docx"
    with zipfile.ZipFile(seed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("word/document.xml", b"<document>" + b"x" * 64 + b"</document>")
    monkeypatch.setattr(zip_archive, "MAX_MEMBER_UNCOMPRESSED_BYTES", 32)

    with pytest.raises(UnsafeArchiveError, match="per-member limit"):
        generate_xml_part_mutants(seed, tmp_path / "out", count=1)
