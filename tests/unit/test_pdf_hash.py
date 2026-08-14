"""Focused tests for bounded native PDF hash extraction."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from dietrich.crypto import pdf_hash
from dietrich.errors import InvalidDocumentError


def test_pikepdf_parser_error_falls_back_to_raw_trailer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "encrypted.pdf"
    path.write_bytes(b"%PDF-1.7\n")
    expected = {"R": "4"}

    class ParserError(Exception):
        pass

    fake_pikepdf = SimpleNamespace(
        PasswordError=type("PasswordError", (Exception,), {}),
        PdfError=ParserError,
        open=lambda _path: (_ for _ in ()).throw(ParserError("unsupported structure")),
    )
    monkeypatch.setattr(pdf_hash, "_encrypt_from_raw_trailer", lambda _path: expected)

    assert pdf_hash._pikepdf_encrypt_or_raw(path, fake_pikepdf) == expected


def test_export_pdf_hash_rejects_input_over_native_parser_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "oversized.pdf"
    path.write_bytes(b"%PDF")
    limits: list[int] = []

    def reject(_path: Path, limit: int) -> bytes:
        limits.append(limit)
        raise ValueError("too large")

    monkeypatch.setattr(pdf_hash, "read_file_limited", reject)

    with pytest.raises(InvalidDocumentError, match="native PDF hash parser limit"):
        pdf_hash.export_pdf_hash(path)
    assert limits == [pdf_hash.MAX_NATIVE_PDF_HASH_BYTES]
