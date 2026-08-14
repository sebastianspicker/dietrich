"""Focused safety tests for OOXML re-signing."""

from __future__ import annotations

import zipfile
from pathlib import Path

from dietrich.signatures import resign


def test_unsigned_parts_validate_metadata_before_member_reads(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "input.docx"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("word/document.xml", b"<document/>")

    calls: list[str] = []
    original_read = zipfile.ZipFile.read
    monkeypatch.setattr(
        resign,
        "validate_archive_safety",
        lambda _archive, *, allow_signed: calls.append(f"validate:{allow_signed}"),
    )

    def recording_read(archive, member, *args, **kwargs):
        calls.append(f"read:{member.filename}")
        return original_read(archive, member, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "read", recording_read)

    assert resign._unsigned_package_parts(path) == {"word/document.xml": b"<document/>"}
    assert calls == ["validate:True", "read:word/document.xml"]
