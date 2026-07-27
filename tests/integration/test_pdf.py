"""PDF inspection and permission-removal integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

pikepdf = pytest.importorskip("pikepdf")

from dietrich import UnlockOptions, inspect_document, unlock_document  # noqa: E402
from dietrich.types import DocumentFormat  # noqa: E402


def test_pdf_permissions_strip(tmp_path: Path) -> None:
    src = tmp_path / "restricted.pdf"
    out = tmp_path / "open.pdf"

    # Create a simple PDF and re-save with owner password / restrictions.
    pdf = pikepdf.new()
    pdf.add_blank_page(page_size=(72, 72))
    pdf.save(
        src,
        encryption=pikepdf.Encryption(
            owner="owner-secret",
            user="",
            allow=pikepdf.Permissions(extract=False, modify_annotation=False),
        ),
    )

    inspection = inspect_document(src)
    assert inspection.document_format == DocumentFormat.PDF

    result = unlock_document(src, out, UnlockOptions())
    assert out.exists()
    assert result.removed.pdf_permission_strips >= 1

    # Unlocked copy should open without password and without encryption.
    with pikepdf.open(out) as unlocked:
        assert not unlocked.is_encrypted
